"""
Necessary tools for sending/receiving messages using BCHMessage protocol.

This only works with a standard P2PKH hot wallet (it needs the private key).

Warnings:

- **Do not use this with automated systems!**
This code has **numerous** timing attack weaknesses that have severity ranging
from ability to extract your private key, to ability to forge/replay messages.
Timing weaknesses have been marked in the code with #WEAKNESS.

- **There is no forward security nor anonymity!**

-- The channel keys are deliberately designed to be easy to calculate from a
given name, so they are only secure if you use a long high-entropy name.

-- All private messages use static diffie-hellman and are permanently
recorded on blockchain, which means anyone in the future, with a private
key *from either participant*, can read the message.

-- All of your conversation partners are permanently recorded on chain.
Social network analysis will be trivial as your partners can be linked
together by you.

-- This is the ultimate 'on the record' encryption, opposite in spirit of
the "Off-the-Record Messaging" protocol.
"""

import hashlib
import hmac
import time
import threading
from functools import partial

from hmac import compare_digest  # constant time compare!

try:
    # python 3.6 +
    from secrets import token_bytes
except ImportError:
    from os import urandom as token_bytes


from .address import Address, ScriptOutput, Script, ScriptError, OpCodes
from . import bitcoin
from . import transaction
from .util import NotEnoughFunds

from .wallet import ImportedAddressWallet, Abstract_Wallet
from .storage import WalletStorage


class ParseError(Exception):
    pass

class AuthenticationError(Exception):
    pass


###
# Elliptic curve signature/Diffie-Hellman services -- uses the slow pure python ecdsa library.
###

import ecdsa
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point, INFINITY
from ecdsa.ecdsa import generator_secp256k1
secp_order = generator_secp256k1.order()

def point_to_ser(P, compressed):
    """ Convert Point to serialized format """
    #WEAKNESS - to_bytes not constant time (this is used in ECDH)
    if P == INFINITY:
        return b'\x00'
    if compressed:
        return bytes((2 + (P.y()&1),)) + P.x().to_bytes(32, 'big')
    else:
        return b'\x04' + P.x().to_bytes(32, 'big') + P.y().to_bytes(32, 'big')

def ser_to_point(Aser, allow_infinity=False):
    """Convert secp256k1 serialized point (compressed or uncompressed) to a
    Point object.

    Ensures point coordinate are in field, and that point is on curve.

    See "Octet-String-to-Elliptic-Curve-Point Conversion"
    http://www.secg.org/sec1-v2.pdf#page=17
    """
    #WEAKNESS (kinda) -- generally don't care since input is public
    p     = SECP256k1.curve.p()
    order = secp_order
    if Aser == b'\x00':
        # point at infinity
        assert allow_infinity
        return INFINITY
    elif len(Aser) == 33:
        # compressed point
        firstbyte = Aser[0]
        assert firstbyte in (2,3)

        x = int.from_bytes(Aser[1:], 'big')
        assert x < p

        # reconstruct square of y coordinate
        y2 = (x*x*x + 7) % p
        # attempt to get square root of y2 using trick for p%4==3
        y  = pow(y2, (p+1)>>2, p)
        # for quadratic non-residue the result is nonsense, so check its square
        # actually not necessary since the Point constructor checks if it's on curve.
        #assert pow(y, 2, p) == y2

        # flip y if needed to match the encoded parity
        if firstbyte-2 != y&1:
            y = p - y
    elif len(Aser) == 65:
        # uncompressed point
        assert Aser[0] == 0x04
        x = int.from_bytes(Aser[1:33], 'big')
        assert x < p
        y = int.from_bytes(Aser[33:], 'big')
        assert y < p

        # Not necessary since the Point constructor checks if it's on curve.
        # assert ecdsa.ecdsa.point_is_valid(SECP256k1.generator, x, y)
    else:
        raise AssertionError("cannot decode point")

    return Point(SECP256k1.curve, x, y, order)

def privkey_to_serpub(privkey, compressed):
    """Convert private key integer to serialized public key"""
    return point_to_ser(privkey * generator_secp256k1, compressed)

# Make sure the point constructor refuses bad points.
try:
    # example of bad uncompressed point
    Point(SECP256k1.curve, 1, 1, secp_order)
    raise RuntimeError("insecure! ecdsa is not refusing off-curve points!")
except AssertionError:
    pass
try:
    # example of bad compressed point
    Point(SECP256k1.curve, 5, 0x350ae3b48047adacdeea49fb8a0b289a94f726801078408aba79631fa7a1b6ba, secp_order)
    raise RuntimeError("insecure! ecdsa is not refusing off-curve points!")
except AssertionError:
    pass

def ecdh(privkey, theirpubkey):
    """
    Ellipic curve Diffie Hellman on secp256k1.

    For a given counterparty public key (bytes; compressed/uncompressed),
    calculate the shared secret (33 byte compressed point) and then hash
    it using sha256. This fails if the counterparty key is not a valid
    curve point.

    This method for calculating shared secret is equivalent to what
    happens in libsecp256k1's `secp256k1_ecdh` function.

    Returns 32 byte shared secret.
    """
    #WEAKNESS - not constant time
    pk = ser_to_point(theirpubkey)
    ecdh_point = point_to_ser(privkey * pk, True)
    return hashlib.sha256(ecdh_point).digest()

###
# Encryption services -- uses the incredibly slow pure python pyaes library.
###

import pyaes

def aes_encrypt(key, plaintext, iv=None):
    """AES encrypt arbitrary length message. (uses CTR mode with big-endian increment)

    Returns iv_ciphertext which is 16 bytes longer than the input plaintext.

    If iv not supplied, uses random 16 bytes.
    Generally you should not provide iv (reuse of iv on two different messages will leak plaintext!).
    """
    #WEAKNESS -- unknown if pyaes is constant time
    if iv is None:
        iv = token_bytes(16)
    else:
        assert len(iv) == 16
    counter = pyaes.Counter(int.from_bytes(iv,'big'))
    cipher = pyaes.AESModeOfOperationCTR(key, counter)
    return iv + cipher.encrypt(plaintext)

def aes_decrypt(key, iv_ciphertext):
    """AES decrypt arbitrary length message. (uses CTR mode)

    Returns plaintext, which is 16 bytes shorter than iv_ciphertext.

    iv_ciphertext must be >= 16 bytes. (i.e., needs to have 16 byte IV)
    """
    assert len(iv_ciphertext) >= 16
    #WEAKNESS -- unknown if pyaes is constant time
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    counter = pyaes.Counter(int.from_bytes(iv,'big'))
    cipher = pyaes.AESModeOfOperationCTR(key, counter)
    return cipher.decrypt(ciphertext)

###
# Transaction parsing (based on electron cash Transaction objects)
###

def parse_tx(tx):
    """
    Check a BCHMessage transaction to ensure that the first spent input
    has P2PKH form of scriptsig, AND it has a correct signature over the
    transaction.

    Returns 4-tuple:
    - the source pubkey (input 0),
    - the address of the intended recipient (output 1),
    - the data (output 0 op_return single push)
    - a callback to check signature (returns True/False)

    Other inputs and outputs are ignored.

    Important: before you call the callback, you need to make sure the
    inputs have correct info on them (use wallet.add_input_info()) otherwise
    the signature checking will fail.
    """
    if len(tx.outputs()) < 1 or len(tx.inputs()) < 1:
        raise ParseError('too few inputs/outputs')

    # Extract data
    outscript0 = tx.outputs()[0][1].to_script()
    try:
        ops = Script.get_ops(outscript0)
        assert len(ops) == 2
        assert ops[0] == OpCodes.OP_RETURN
        data = ops[1][1]
    except:
        raise ParseError('cannot read op_return data from first output')

    # We rely on the way that transaction.py parse_scriptSig() works to detect
    # P2PKH. Since the scriptCode includes the P2PKH script, this will get
    # ultimately tested when we check the signature.
    txin = tx.inputs()[0]
    if txin['type'] != 'p2pkh':
        raise ParseError('first input not p2pkh')

    # extract signature (first push)
    try:
        sig = Script.get_ops(bytes.fromhex(txin['scriptSig']))[0][1]
    except:
        raise ParseError('cannot get signature')
    if not sig or len(sig) < 6 or sig[0] != 0x30:
        raise ParseError('cannot get signature')
    hashbyte = sig[-1]
    if hashbyte != (tx.nHashType() & 0xff):
        raise ParseError('incorrect hashtype')
    sigder = sig[:-1]

    pubkey = bytes.fromhex(txin['pubkeys'][0])
    try:
        pubkey_point = ser_to_point(pubkey)
    except:
        raise ParseError('bad pubkey')

    if len(tx.outputs()) > 1:
        destinationaddr = tx.outputs()[1][1]
    else:
        # only output of op_return -- means that this was message-to-self
        # which had no change
        destinationaddr = Address.from_pubkey(pubkey)

    def verify_sig_callback():
        try:
            pre_hash = bitcoin.Hash(bytes.fromhex(tx.serialize_preimage(0)))
            verkey = ecdsa.VerifyingKey.from_public_point(pubkey_point, SECP256k1)
            return verkey.verify_digest(sigder, pre_hash, sigdecode = ecdsa.util.sigdecode_der)
        except transaction.InputValueMissing:
            raise
        except:
            return False

    return pubkey, destinationaddr, data, verify_sig_callback

def make_opreturn(data):
    """Turn data bytes into a single-push opreturn script"""
    if len(data) < 76:
        return bytes((OpCodes.OP_RETURN, len(data))) + data
    elif len(data) < 256:
        return bytes((OpCodes.OP_RETURN, 76, len(data))) + data
    else:
        raise ValueError(data)

class Channel:
    """Represents a public bulletin board. Transactions are sent to board
    with notification sent to an anyone-can-spend P2SH address.

    Channels are fundamentally identified with a 256-bit AES encryption key,
    however you can also generate them by name (see `from_name` constructor).

    Channels have a short small ID (generally 3 bytes) to determine the
    address. This makes 16 million notification addresses, which can be
    simply enumerated by anyone who wants to collect the notification dust.
    (dust collection is profitable: with only 47 bytes per spent input, and
    540 satoshis per input)

    (Why not just use one notification address for all channels? That makes
    it too easy to spam all channels and overload light wallets. Why only 16
    million? That makes it easy for dust sweepers to discover all notification
    dust, which keeps the utxo set clean.)

    The fact that channel IDs collide is not a concern, since channel messages
    use an HMAC in order to prove that the sender knows the key.

    P2SH address: redeemscript = push['C'+chanid]
    """
    def __init__(self, chankey):
        self.chankey = bytes(chankey)
        assert len(self.chankey) == 32

        # to find 3-byte channel ID:
        # - take left 8 bytes of sha512('ThreeByteChanIDFromKey:' + key).
        # - treat it as a little-endian 64-byte integer and calculate its modulo 0xfffffe
        # - add 1
        # - if result is greater than or equal to 0x800000 then add 1 again.
        # - convert this integer to 3-byte little-endian integer.
        # (this process avoids 0x000000 and 0x800000 which are zeros for bitcoin -- unspendable!)
        h = hashlib.sha512()
        h.update(b'BCHMessage.ChanID3FromKey:')
        h.update(self.chankey)
        digest = h.digest()
        i = int.from_bytes(digest[:8], 'little') % 0xfffffe + 1
        if i >= 0x800000:
            i += 1
        self.chanid = i.to_bytes(3, 'little')

        # redeemscript = PUSH(chanid)
        self.redeemscript = bytes((len(self.chanid), )) + self.chanid
        self.address = Address.from_multisig_script(self.redeemscript)

    def auth_encrypt(self, message, source_pubkey):
        """Authenticated encrypt; adds 32 bytes (IV, MAC).

        The source_pubkey is included in the MAC to prevent replay.
        """
        iv_ciphertext = aes_encrypt(self.chankey, message)
        h = hmac.new(self.chankey, b'BCHMessage.ChanMAC:', 'sha256')
        h.update(source_pubkey)
        h.update(iv_ciphertext)
        mac = h.digest()[:16]
        return iv_ciphertext + mac

    def auth_decrypt(self, data, source_pubkey):
        """Authenticated decrypt; removes 32 bytes (IV, MAC).

        If the MAC is not valid, this raises AuthenticationError.
        (indicates message encrypted with another key, or, just malicious/corrupted data)
        """
        if len(data) < 32:
            raise ValueError("too short")
        iv_ciphertext = data[:-16]
        mac1 = data[-16:]

        h = hmac.new(self.chankey, b'BCHMessage.ChanMAC:', 'sha256')
        h.update(source_pubkey)
        h.update(iv_ciphertext)
        mac2 = h.digest()[:16]

        if not compare_digest(mac1, mac2):
            raise AuthenticationError
        return aes_decrypt(self.chankey, iv_ciphertext)

    @classmethod
    def from_name(cls, name, index=0):
        """Construct channel from unicode string `name` and nonnegative
        integer `index`.

        The index (up to 256 bit) can be used for 'frequency hopping' the
        channel, e.g., daily changes.
        """
        namebytes = str(name).encode('utf8')
        index = int(index)
        h = hashlib.sha512()
        h.update(b'BCHMessage.ChanKeyFromName:')
        h.update(index.to_bytes(32,'big'))
        h.update(namebytes)
        digest = h.digest()
        chankey = digest[32:]
        self = cls(chankey)
        self.name = name
        return self


class MessagingKey:
    """Holder for single unlocked private key, used to create and read private
    messages."""

    def __init__(self, privkey, compressed):
#        self.pubkey = bytes(pubkey)
        self.privkey = int(privkey)
        self.compressed = compressed

        self.signingkey = ecdsa.SigningKey.from_secret_exponent(self.privkey, SECP256k1)

        self.pubkey = point_to_ser(self.signingkey.verifying_key.pubkey.point, compressed)

        self.address = Address.from_pubkey(self.pubkey)

    @classmethod
    def from_wallet(cls, wallet, address, password):
        index = wallet.get_address_index(address)
        privkeybytes, compressed = wallet.keystore.get_private_key(index, password)
        privkey = int.from_bytes(privkeybytes,'big')

        self = cls(privkey, compressed)
        assert self.address == address
        return self

    def create_message(self, wallet, dest_address, data, config, fee=None):
        """
        Create and sign a transaction that holds a message addressed to dest_address.

        Max message length to fit in 223 byte op_return relay limit: 204 bytes

        This can fail with electroncash.util.NotEnoughFunds
        """
        assert wallet.txin_type == 'p2pkh'

        askedoutputs = [ (transaction.TYPE_SCRIPT, ScriptOutput(make_opreturn(data)), 0),
                         (transaction.TYPE_ADDRESS, dest_address, 546),
                         ]
        if dest_address == self.address:
            # Send-to-self is valid&secure (may be useful for 'note to self').
            # For send-to-self we don't need a dust output.
            askedoutputs = askedoutputs[:1]
        change_addr = self.address

        # only spend coins from this address
        domain = [self.address]
        # config['confirmed_only'] is used in the following call:
        coins = wallet.get_spendable_coins(domain, config)
        # make the tx
        tx = wallet.make_unsigned_transaction(coins, askedoutputs, config, fee, change_addr)

        # unfortunately, the outputs might be in wrong order due to BIPLI01
        # output sorting, so we remake it.
        outputs = tx.outputs()
        outputs = askedoutputs + [o for o in outputs if o not in askedoutputs]
        tx = transaction.Transaction.from_io(tx.inputs(), outputs, tx.locktime)
        tx.cryptocurrency = wallet.cryptocurrency

        # get the 'x_pubkey' which for HD wallets is not the same as pubkey.
        in0 = tx.inputs()[0]
        assert in0['address'] == self.address
        xpub, = in0['x_pubkeys']

        # now, we can sign the tx immediately since we know the key for the inputs.
        keypairs = {xpub : (self.privkey.to_bytes(32,'big'), self.compressed)}
        tx.sign(keypairs)

        return tx

    def encrypt_private_message(self, message, other_pubkey):
        """
        Attempts to reads a private message from opreturn data. You need
        to provide the pubkey of the counterparty.

        (see `parse_tx` for the reverse of create_private_message, but
        it doesn't give you the pubkey of the recipient)

        Returns message (16 bytes less than data)
        """
        key = ecdh(self.privkey, other_pubkey)
        return aes_encrypt(key, message)

    def read_private_message(self, data, other_pubkey):
        """
        Attempts to reads a private message from opreturn data. You need
        to provide the pubkey of the counterparty.

        (see `parse_tx` for the reverse of create_private_message, but
        it doesn't give you the pubkey of the recipient)

        Returns message (16 bytes less than data)
        """
        key = ecdh(self.privkey, other_pubkey)
        return aes_decrypt(key, data)

class AddrMessageWatcher:
    """
    Watches for updates on wallet transactions for a specific address.
    Extracts out the appropriate BCHMessage transactions and then passes
    them off to a decoder (if subclassed).

    If you provide a Network object for wallet_or_network, then a single-
    address in-memory-only wallet is created.
    """
    def __init__(self, wallet_or_network, address):
        self.address = address
        self.known_pubkeys = {}  # address -> bytes
        self.messageinfo = {} # txhash -> dict
        self.processing_hashes = set()

        if isinstance(wallet_or_network, Abstract_Wallet):
            wallet = wallet_or_network
            self._my_wallet_network = None
        else:
            network = wallet_or_network
            self._my_wallet_network = network
            # create an in-memory storage that is never saved anywhere
            wstorage = WalletStorage(None)  # path = None
            wallet = ImportedAddressWallet(wstorage)
            wallet.import_address(self.address)
            self._my_wallet = True

        assert wallet.is_mine(address)
        self.wallet = wallet

    def add_pubkey(self,pubkey):
        self.known_pubkeys[Address.from_pubkey(pubkey)] = pubkey

    def start(self,):
        if self._my_wallet_network:
            self.wallet.start_threads(self._my_wallet_network)
        self.network = self.wallet.network
        self.network.register_callback(self.on_network, ['updated'])
        self.update_messages()

    def stop(self,):
        self.network.unregister_callback(self.on_network)
        if self._my_wallet_network:
            self.wallet.stop_threads()

    def exclude(self, info):
        return False

    def update_messages(self,):
        # first iteration - find new txes
        for tx_hash, height in self.wallet.get_address_history(self.address):
            if tx_hash in self.messageinfo:
                continue
            try:
                tx = self.wallet.transactions[tx_hash]
            except KeyError:
                # tx in history, but hasn't been downloaded yet.
                continue
            try:
                sourcekey,destaddr,data,verifycallback = parse_tx(tx)
                self.known_pubkeys[Address.from_pubkey(sourcekey)] = sourcekey
            except ParseError:
                # this gets thrown when it's not a message-style tx
                self.messageinfo[tx_hash] = None
                continue
            in0 = tx.inputs()[0]
            prevhash = in0['prevout_hash']
            prevn    = in0['prevout_n']
            info = dict(status='processing',
                        tx=tx, src=sourcekey, dst=destaddr,
                        data = data,
                        procinfo = (prevhash, prevn, verifycallback),
                        proctime = 0,
                        proctries = 0,
                        )
            if self.exclude(info):
                self.messageinfo[tx_hash] = None
                continue
            self.messageinfo[tx_hash] = info
            self.processing_hashes.add(tx_hash)

        # second iteration - try to decode
        for tx_hash in list(self.processing_hashes):
            info = self.messageinfo[tx_hash]
            if not info or info['status'] != 'processing':
                continue
            if info['proctime'] + 30 < time.monotonic():  # retry every 30 seconds
                info['proctime'] = time.monotonic()
            if info['proctries'] >= 10:  # don't try more than 10 times
                info['status'] = 'failed'
            info['proctries'] += 1
            prevhash, prevn, verifycallback = info['procinfo']
            prevtx = self.wallet.transactions.get(prevhash)
            if not prevtx:
                request = ('blockchain.transaction.get', [prevhash])
                self.wallet.network.send([request], partial(self.tx_response, tx_hash))
            else:
                self.verify_tx(tx_hash, prevtx)

    def tx_response(self, tx_hash, response):
        # Callback from network.
        if response.get('error'):
            # Should handle non-existent parent txes here.
            # Set to failed?
            return
        #prev_tx_hash = response['params'][0]
        prevtx = transaction.Transaction(response['result'])
        self.verify_tx(tx_hash, prevtx)

    def verify_tx(self, tx_hash, prevtx):
        # Called once prevtx is obtained.
        info = self.messageinfo[tx_hash]
        if not info or info['status'] == 'verified':
            return
        prevhash, prevn, verifycallback = info['procinfo']
        if prevhash != prevtx.txid():
            return
        self.processing_hashes.discard(tx_hash)
        try:
            prevout_type, prevout_addr, prevout_value = prevtx.outputs()[prevn]
            assert prevout_addr == Address.from_pubkey(info['src'])
            tx = info['tx']
            txin = tx.inputs()[0]
            txin['address'] = prevout_addr
            txin['value'] = prevout_value
            info = dict(status='verified',
                        tx=info['tx'], src=info['src'], dst=info['dst'],
                        data=info['data'])
            if not verifycallback():
                raise Exception('bad signature')
        except Exception as e:
            print("Verify fail", e)
            # verification process showed bad result: chuck away message.
            info = None
        self.messageinfo[tx_hash] = info
        if info:
            self.on_verified(tx_hash)
        # ping update here

    def on_verified(self, tx_hash):
        """ override in subclass to do something """
        pass

    def on_network(self,event,*args):
        self.update_messages()


class PrivMessageWatcher(AddrMessageWatcher):
    def __init__(self, wallet_or_network, key):
        super().__init__(wallet_or_network, key.address)
        self.key = key
        self.pubkey = key.pubkey
        self.missing_pubkeys = {}
        self.mplock = threading.Lock()
        self.callbacks_decrypted = []

    def exclude(self, info):
        if len(info['data']) < 16:
            return True
        dst = info['dst']
        if not isinstance(dst, Address) or dst.kind != Address.ADDR_P2PKH:
            return True
        if info['src'] != self.pubkey and dst != self.address:
            return True
        return False

    def on_verified(self, tx_hash):
        # this is called once the input signature has been verified.
        self.try_decrypt_tx(tx_hash)

    def try_decrypt_tx(self, tx_hash):
        info = self.messageinfo[tx_hash]
        if not info:
            return
        s = info['src']
        d = info['dst']

        if d == self.key.address:
            # to me
            other_pubkey = s
        elif s == self.key.pubkey:
            # from me
            other_pubkey = self.known_pubkeys.get(d)
            if not other_pubkey:
                with self.mplock:
                    l = self.missing_pubkeys.setdefault(d, [])
                    l.append(tx_hash)
        else:
            # this should not happen since non-involved messages should have
            # already been filtered out.
            raise Exception("non-involved message")

        if other_pubkey:
            info['message'] = self.key.read_private_message(info['data'], other_pubkey)

        for cb in list(self.callbacks_decrypted):
            cb(tx_hash)

    def retry_missing(self,):
        with self.mplock:
            alist = list(a for a in self.missing_pubkeys if a in self.known_pubkeys)
        for addr in alist:
            txhashes = self.missing_pubkeys.get(addr)
            if not txhashes:
                continue
            for txhash in txhashes:
                self.try_decrypt_tx(txhash)


class ChanMessageWatcher(AddrMessageWatcher):
    def __init__(self, wallet_or_network, channel):
        super().__init__(wallet_or_network, channel.address)
        self.channel = channel
        self.callbacks_decrypted = []

    def exclude(self, info):
        if len(info['data']) < 32:
            return True
        return (info['dst'] != self.address)

    def on_verified(self, tx_hash):
        # this is called once the input signature has been verified.
        self.try_decrypt_tx(tx_hash)

    def try_decrypt_tx(self, tx_hash):
        info = self.messageinfo[tx_hash]
        if not info:
            return
        s = info['src']
        assert info['dst'] == self.address

        try:
            info['message'] = self.channel.auth_decrypt(info['data'], s)
        except AuthenticationError:
            pass

        for cb in list(self.callbacks_decrypted):
            cb(tx_hash)
