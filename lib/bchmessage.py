"""
Necessary tools for sending/receiving messages using BCHMessage protocol.

This only works with a standard P2PKH hot wallet (it needs the private key).

Warnings:

- **Do not use this with automated systems!**
The pure-python ecdsa module here is known to have timing attack weaknesses
which will allow someone to extract your private key if you provide them
with a high speed encrypt/decrypt oracle.

- **There is no forward security nor anonymity!**

-- The channel keys are deliberately designed to be easy to calculate from a
given name, so they are only secure if you use a long high-entropy name.

-- All private messages use static diffie-hellman and are permanently
recorded on blockchain, which means anyone in the future, with a private
key *from either participant*, can read the message.

-- All of your conversation partners are permanently recorded on chain.

-- This is the ultimate 'on the record' encryption, opposite in spirit of
the "Off-the-Record Messaging" protocol.
"""

from .address import Address, ScriptOutput
from . import util
from . import bitcoin

import hashlib
import hmac

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

def point_to_ser(P, compressed):
    """ Convert Point to serialized format """
    if P == INFINITY:
        return b'\x00'
    if compressed:
        return bytes((2 + (P.y()&1),)) + P.x().to_bytes(32, 'big')
    else:
        return b'\x04' + P.x().to_bytes(32, 'big') + P.y().to_bytes(32, 'big')

def ser_to_point(Aser):
    """Convert secp256k1 serialized point (compressed or uncompressed) to a
    Point object.

    Ensures point coordinate are in field, and that point is on curve.

    See "Octet-String-to-Elliptic-Curve-Point Conversion"
    http://www.secg.org/sec1-v2.pdf#page=17
    """
    p     = SECP256k1.curve.p()
    order = SECP256k1.order
    if Aser == b'\x00':
        # point at infinity
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
        assert pow(y, 2, p) == y2

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

# Make sure the point constructor refuses bad points.
try:
    Point(SECP256k1.curve, 1, 1, SECP256k1.order)
except AssertionError:
    pass
else:
    raise RuntimeError("insecure! ecdsa is not refusing off-curve points!")

def ser_to_pubkey(Aser):
    # Deserializes and makes sure input is valid pubkey.
    assert Aser != b'\x00'  # point at infinity not allowed for pubkey
    P = ser_to_point(Aser)
    return P

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
    pk = ser_to_pubkey(theirpubkey)
    ecdh_point = point_to_ser(privkey * pk, True)
    return hashlib.sha256(ecdh_point).digest()

###
# Encryption services -- uses the incredibly slow pure python pyaes library.
###

import pyaes
import secrets

def aes_encrypt(key, plaintext, iv=None):
    """AES encrypt arbitrary length message. (uses CTR mode with big-endian increment)

    Returns iv_ciphertext which is 16 bytes longer than the input plaintext.

    If iv not supplied, uses random 16 bytes from `secrets` module.
    Generally you should not provide iv (reuse of iv on two different messages will leak plaintext!).
    """
    if iv is None:
        iv = secrets.token_bytes(16)
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
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    counter = pyaes.Counter(int.from_bytes(iv,'big'))
    cipher = pyaes.AESModeOfOperationCTR(key, counter)
    return cipher.decrypt(ciphertext)

###
# Transaction parsing (based on electron cash Transaction objects)
###

from . import transaction
from .address import Script, ScriptError, OpCodes

def parse_tx(tx):
    """
    Check a BCHMessage transaction to ensure that the first spent input
    has P2PKH form of scriptsig, AND it has a correct signature over the
    transaction.

    Important: you need to call wallet.add_input_info() on each of the
    inputs before running this. Otherwise the signature checking will
    fail.

    Returns the source pubkey (input 0), the message (output 0 op_return),
    and the address of the intended recipient (output 1). Other inputs
    and outputs are ignored.
    """
    if len(tx.outputs()) < 2 or len(tx.inputs()) < 1:
        raise ParseError('too few inputs/outputs')

    # Extract message
    outscript0 = tx.outputs()[0][1].to_script()
    try:
        ops = Script.get_ops(outscript0)
        assert len(ops) == 2
        assert ops[0] == OpCodes.OP_RETURN
        message = ops[1][1]
    except:
        raise ParseError('cannot read message from first output')

    destinationaddr = tx.outputs()[1][1]

    # We rely on the way that transaction.py parse_scriptSig() works to detect
    # P2PKH. Since the scriptCode includes the P2PKH script, this gets
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
        pubkey_point = ser_to_pubkey(pubkey)
    except:
        raise ParseError('bad pubkey')

    pre_hash = bitcoin.Hash(util.bfh(tx.serialize_preimage(0)))

    verkey = ecdsa.VerifyingKey.from_public_point(pubkey_point, SECP256k1)

    try:
        if not verkey.verify_digest(sigder, pre_hash, sigdecode = ecdsa.util.sigdecode_der):
            raise ParseError('bad signature')
    except:
        raise ParseError('signature verification failure')
    return pubkey, destinationaddr, message

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
    540 byte dust per input)

    (Why not just use one notification address for all channels? That makes
    it too easy to spam all channels and overload light wallets. Why only 16
    million? That makes it easy for dust sweepers to discover all notification
    dust, which keeps the utxo set clean.)

    The fact that channel IDs collide is not a concern, since channel messages
    use authenticated encryption (Encrypt-then-MAC) in order to prove that the
    sender knows the key.

    P2SH address: redeemscript = push['C'+chanid]
    """
    def __init__(self, chankey):
        self.chankey = bytes(chankey)
        assert len(self.chankey) == 32

        # channel ID is left 3 bytes of sha512('BMChanID' + key), unless this
        # produces an unspendable 'zero push' in which case the next 3 bytes
        # are taken, and so on.
        h = hashlib.sha512()
        h.update(b'ChanIDFromKey:')
        h.update(self.chankey)
        digest = h.digest()
        for i in range(3,64,3):
            self.chanid = digest[i-3:i]
            # there are two unspendable zeros: +0 and -0
            if self.chanid != b'\x00\x00\x00' and self.chanid != b'\x00\x00\x80':
                break
        else:
            raise RuntimeError("Unlucky!", chankey.hex()) # 10^-146 chance

        # redeemscript = PUSH(chanid)
        self.redeemscript = bytes((len(self.chanid), )) + self.chanid
        self.address = Address.from_multisig_script(self.redeemscript)

    def auth_encrypt(self, message):
        """Authenticated encrypt; adds 32 bytes (IV, MAC)."""
        iv_ciphertext = aes_encrypt(self.chankey, message)
        mac = hmac.new(self.chankey, iv_ciphertext, 'sha256').digest()
        return iv_ciphertext + mac[:16]

    def auth_decrypt(self, message):
        """Authenticated decrypt; removes 32 bytes (IV, MAC).

        If the MAC is not valid, this raises AuthenticationError.
        (indicates message encrypted with another key, or, just malicious/corrupted data)
        """
        if len(message) < 32:
            raise ValueError("too short")
        iv_ciphertext = message[:-16]
        mac1 = message[-16:]
        mac2 = hmac.new(self.chankey, iv_ciphertext, 'sha256').digest()
        if mac1 != mac2:
            raise AuthenticationError
        return aes_decrypt(self.chankey, iv_ciphertext)

    @classmethod
    def from_name(cls, name, index=0):
        """Construct channel from unicode string `name` and nonnegative
        integer `index`.

        The index (up to 128 bit) can be used for 'frequency hopping' the
        channel, e.g., daily changes.
        """
        name = str(name)
        index = int(index)
        h = hashlib.sha512()
        h.update(b'ChanKeyFromName:')
        h.update(index.to_bytes(16,'big'))
        h.update(name.encode('utf8'))
        digest = h.digest()
        chankey = digest[32:]
        self = cls.__init__(chankey)
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

    def create_private_message(self, wallet, dest_pubkey, message, config, fee=None):
        """
        Creates a transaction that holds a message addressed to dest_pubkey.

        Max message length to fit in 223 byte op_return relay limit: 204 bytes
        """
        assert wallet.txin_type == 'p2pkh'

        key = ecdh(self.privkey, dest_pubkey)
        iv_ciphertext = aes_encrypt(key, message)

        dest_address = Address.from_pubkey(dest_pubkey)

        askedoutputs = [ (transaction.TYPE_SCRIPT, ScriptOutput(make_opreturn(iv_ciphertext)), 0),
                         (transaction.TYPE_ADDRESS, dest_address, 546),
                         ]
        if dest_address == self.address:
            # Send-to-self is valid&secure (may be useful for 'note to self').
            # For send-to-self we just make a change addr.
            outputs = outputs[:1]
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
        tx.cryptocurrency='BCH'

        # get the 'x_pubkey' which for HD wallets is not the same as pubkey.
        in0 = tx.inputs()[0]
        assert in0['address'] == self.address
        xpub, = in0['x_pubkeys']

        # now, we can sign the tx immediately since we know the key for the inputs.
        keypairs = {xpub : (self.privkey.to_bytes(32,'big'), self.compressed)}
        tx.sign(keypairs)

        return tx


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
