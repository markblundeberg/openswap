"""
OpenSwap tooling
"""

from collections import namedtuple, defaultdict
import hashlib
from time import time
import struct

try:
    # python 3.6 +
    from secrets import token_bytes
except ImportError:
    from os import urandom as token_bytes

from . import bitcoin
from . import bchmessage
from .address import OpCodes, Address, Script, hash160
from .transaction import Transaction, TYPE_ADDRESS
from .util import format_satoshis_plain_nofloat

from ecdsa.ecdsa import generator_secp256k1
from .bchmessage import point_to_ser

# Below this number, nLockTime and OP_CHECKLOCKTIMEVERIFY input are defined
# using the block number. Othewise using epoch timestamp.
LOCKTIME_THRESHOLD = 500000000
# (In bitcoind, found in script/script.h)
# Note that BIP113 changed how nLockTime interacts with block time. Beware!

def joinbytes(iterable):
    """Joins an iterable of bytes and/or integers into a single byte string"""
    return b''.join((bytes((x,)) if isinstance(x,int) else x) for x in iterable)

def privkey_to_serpub(privkey, compressed):
    """Convert private key integer to serialized public key"""
    return point_to_ser(privkey * generator_secp256k1, True)

class SwapContract:
    """Atomic swapping contract for bitcoin script.
    Hash lock with time-locked refund."""
    def __init__(self,
                 redeem_pubkey, secret_hash, secret_size,
                 refund_pubkey, refund_time):
        self.redeem_pubkey = bytes(redeem_pubkey)
        self.secret_hash = bytes(secret_hash)
        self.secret_size = int(secret_size)
        self.refund_pubkey = bytes(refund_pubkey)
        self.refund_time = int(refund_time)

        assert len(self.redeem_pubkey) == 33
        assert len(self.secret_hash) == 20
        assert 1 <= self.secret_size <= 76
        assert len(self.refund_pubkey) == 33
        assert self.refund_time >= LOCKTIME_THRESHOLD  # don't allow blocktime-based times.
        # assert self.refund_time >= 0x800000  # prevent 3-byte time forms -- redundant
        assert self.refund_time < 0x8000000000 # disallow times that would encode to negative

        # figure out minimal encoding of our time
        if self.refund_time < 0x80000000:
            # until year 2038 use 4 byte form
            rtime_bytes = self.refund_time.to_bytes(4,'little')
        else:
            # from 2038 onwards our number cannot fit into 4 bytes since the high
            # bit is used for sign, in bitcoin script.
            rtime_bytes = self.refund_time.to_bytes(5,'little')
        # Ensure minimal encoding (MSB is not zero), and
        # also ensure we didn't accidentally make a negative.
        assert rtime_bytes[-1] != 0 and not rtime_bytes[-1] & 0x80


        if 1 <= self.secret_size <= 16:
            sspush = 0x50 + self.secret_size  # put as OP_N
        else:
            sspush = bytes((1, self.secret_size))

        self.redeemscript = joinbytes([
            OpCodes.OP_IF,
                # check transaction sig from redemption key
                33, self.redeem_pubkey, OpCodes.OP_CHECKSIGVERIFY,
                # size check per https://gist.github.com/markblundeberg/7a932c98179de2190049f5823907c016
                OpCodes.OP_SIZE, sspush, OpCodes.OP_EQUALVERIFY,
                # check hash lock
                OpCodes.OP_HASH160, 20, self.secret_hash, OpCodes.OP_EQUAL,
            OpCodes.OP_ELSE,
                # check transaction sig from refund key
                33, self.refund_pubkey, OpCodes.OP_CHECKSIGVERIFY,
                # check locktime
                len(rtime_bytes), rtime_bytes, OpCodes.OP_CHECKLOCKTIMEVERIFY,
                # normally one should OP_DROP after OP_CHECKLOCKTIMEVERIFY,
                # however in this case we can use the nonzero time value
                # to complete the script with nonzero value.
            OpCodes.OP_ENDIF,
            ])
        assert len(self.redeemscript) <= 0xff  # simplify push in scriptsig; note len is around 100.

        self.address = Address.from_multisig_script(self.redeemscript)

        # must be equal for two smart contracts to be compatible.
        self.secret_form = (self.secret_size, 'HASH160', self.secret_hash)

        # make dummy scripts of correct size
        self.dummy_scriptsig_redeem = '01'*(5 + self.secret_size + 72 + len(self.redeemscript))
        self.dummy_scriptsig_refund = '00'*(4 + 72 + len(self.redeemscript))

    def extract(self, tx):
        """
        Try to extract the secret from a spent SwapContract's scriptSig.

        The solution here iterates over all pushes in the script, seeing if
        any of them hash to produce the right value.

        Trickiness: scriptSig is allowed to have many different opcodes,
        which may be used to confuse the detection algorithm.

        In Bitcoin Cash in particular, from May-November 2018 it is possible
        (with miner support) to have *highly* obfuscated scripsSigs using
        OP_CAT and OP_SPLIT. Starting from November, the scriptSig push-only
        rule will prevent such obfuscations.

        In non-BCH also some obfuscation is possible using hash functions.
        This obfuscation is however limited to producing 20 or 32 byte values,
        so by excluding these secret sizes it can be avoided.

        If no matching secret found, this raises KeyError
        """
        for txin in tx.inputs():
            ops = Script.get_ops(bytes.fromhex(txin['scriptSig']))
            # first check if the last push is the redeemscript for this contract
            if not isinstance(ops[-1], tuple) or ops[-1][1] != self.redeemscript:
                continue
            # found match -- iterate over all pushes to see if we get a match
            for o in ops:
                if not isinstance(o,tuple):
                    continue  # skip non-push
                op, data = o
                if not data or len(data) != self.secret_size:
                    continue  # skip wrong length
                if hash160(data) == self.secret_hash:
                    return data
        raise KeyError

    def makeinput(self, prevout_hash, prevout_n, value, mode):
        """
        Construct an unsigned input for adding to a transaction. scriptSig is
        set to a dummy value, for size estimation.

        (note: Transaction object will may it is complete, but it will
        fail to broadcast until you sign and run `completetx`)
        """
        if mode == 'redeem':
            scriptSig = self.dummy_scriptsig_redeem
            pubkey = self.redeem_pubkey
        elif mode == 'refund':
            scriptSig = self.dummy_scriptsig_refund
            pubkey = self.refund_pubkey
        else:
            raise ValueError(mode)

        txin = dict(
            prevout_hash = prevout_hash,
            prevout_n = prevout_n,
            sequence = 0,
            scriptSig = scriptSig,

            type = 'unknown',
            address = self.address,
            scriptCode = self.redeemscript.hex(),
            num_sig = 1,
            signatures = [None],
            x_pubkeys = [pubkey.hex()],
            value = value,
            )
        return txin

    def signtx(self, tx, privatekey):
        """generic tx signer for compressed pubkey"""
        pubkey = privkey_to_serpub(privatekey, True)
        keypairs = {pubkey.hex() : (privatekey.to_bytes(32, 'big'), True)}
        tx.sign(keypairs)

    def completetx(self, tx, secret):
        """
        Completes transaction by creating scriptSig. You need to sign the
        transaction before using this (see `signtx`). `secret` may be bytes
        (if redeeming) or None (if refunding).

        This works on multiple utxos if needed.
        """
        if secret:
            # redeem mode
            assert len(secret) == self.secret_size
            assert hash160(secret) == self.secret_hash
        else:
            assert tx.locktime >= self.refund_time

        for txin in tx.inputs():
            # find matching inputs
            if txin['address'] != self.address:
                continue
            sig = txin['signatures'][0]
            sig = bytes.fromhex(sig)
            if not sig:
                continue
            # construct the correct scriptsig
            if secret:
                if txin['scriptSig'] != self.dummy_scriptsig_redeem:
                    continue
                script = [
                    len(secret), secret,
                    len(sig), sig,
                    OpCodes.OP_1,
                    0x4c, len(self.redeemscript), self.redeemscript,
                    ]
            else:
                if txin['scriptSig'] != self.dummy_scriptsig_refund:
                    continue
                script = [
                    len(sig), sig,
                    OpCodes.OP_0,
                    0x4c, len(self.redeemscript), self.redeemscript,
                    ]
            txin['scriptSig'] = joinbytes(script).hex()

from .wallet import ImportedAddressWallet
from .storage import WalletStorage

class HalfSwapController:
    """
    Associated with a half-swap (one of two smart contracts in an atomic swap)

    This creates an in-memory wallet object to watch the relevant address, and
    attaches it to the provided network object. Make sure to call .shutdown()
    when you're done with me.
    """
    secret = None
    notify_secret = None

    def __init__(self, contract, network):
        self.contract = contract
        self.network = network
        self.address = contract.address

        # create an in-memory storage that is never saved anywhere
        wstorage = WalletStorage(None)  # path = None

        wallet = ImportedAddressWallet(wstorage)
        wallet.import_address(self.contract.address)
        self.wallet = wallet

        # get some debug info printed to console
        #interests = ['updated', 'new_transaction']

        #self.network.register_callback(self.on_network, interests)

        self.coins = {}  # all coins that have been on this address, spent or not
        self.spent = {}  #
        self.checked_txes = set()  # which txids we have checked for containing secret

    def start(self,):
        self.wallet.start_threads(self.network)

    def shutdown(self):
        self.wallet.stop_threads()
        #self.network.unregister_callback(self.on_network)

    def get_coins(self,):
        """Update the coins -- similar logic to wallet.get_addr_io except
        that wallet.txi does not function properly (address recognition
        is not functioning)
        """
        wallet = self.wallet
        address = self.address
        h = wallet.get_address_history(address)

        coins = {}
        spent = {}

        for tx_hash, height in h:
            for n, v, is_cb in wallet.txo.get(tx_hash, {}).get(address, []):
                if is_cb:
                    continue
                coin = tx_hash + ':%d'%n
                coins[coin] = (height, v)

        # We can't use txi (see bug #895)
        for tx_hash, height in h:
            tx = wallet.transactions.get(tx_hash)
            if not tx:
                # sometimes tx_hash is in history but not yet downloaded.
                continue
            for inp in tx.inputs():
                coin = inp['prevout_hash'] + ':%d'%(inp['prevout_n'])
                if coin in coins:
                    spent[coin] = tx_hash

        for tx_hash in spent.values():
            self._check_extract(tx_hash)

        return coins, spent

    def _check_extract(self, tx_hash):
        if self.secret:
            return
        if tx_hash in self.checked_txes:
            return
        self.checked_txes.add(tx_hash)
        try:
            self.secret = self.contract.extract(self.wallet.transactions[tx_hash])
        except KeyError:
            return
        fun = self.notify_secret
        if fun:
            fun(self.secret)

    #def on_network(self, event, *args):
        #pass
#        self.update_coins()

    def estimate_time_remaining(self, ):
        """Returns estimate of remaining time until refund can be broadcast.
        (assumes BIP113 mechanics for nLockTime)

        MTP lags on avg 3000 seconds behind the most recent timestamp, with
        standard deviation of ~1350 seconds. Some tricky points: blocks
        could come in 2 hours into the future, the timestamps don't have
        to be monotonic, and our clock might be wrong!

        Possible values:

        0 : can refund right now
        600 : can refund once next block is mined
        >600 : estimate in seconds of remaining time
        """
        blockchain = self.network.blockchain()
        curheight = blockchain.height()
        rtime = self.contract.refund_time
        now = int(time())  # computer clock time

        if curheight < 10:
            raise RuntimeError('blockchain too short')

        # get last 11 times
        times = [blockchain.read_header(h, None)['timestamp']
                 for h in range(curheight - 10, curheight + 1)
                 ]
        if len(times) != 11:
            raise RuntimeError('error calculating MTP')
        mtp_now = sorted(times)[5]

        # check if refund can be done right now
        d = rtime - mtp_now
        if d < 0:
            return 0

        if d > 7200:
            return d

        # Calculate MTP for next block, assuming it comes in 10 minutes and will be timestamped properly.
        mtp_next = sorted(times[1:] + [now+600])[5]
        d2 = rtime - mtp_next
        return max(600, d2+600)

    def mktx(self, coins, address, privkey, secret, estimate_fee):
        """Make and sign a refund/redeem to given address

        If secret is None, it's refund mode. Otherwise it's redeem mode.
        """
        mode = 'redeem' if secret else 'refund'

        outputs = [(TYPE_ADDRESS, address, 0)]
        invalue = 0
        inputs = []
        for c, (h, v) in coins.items():
            ph, pn = c.split(':')
            inputs.append(self.contract.makeinput(ph, int(pn), v, mode))
            invalue += v

        if secret:
            locktime = 0
        else:
            locktime = self.contract.refund_time

        # make once to estimate size
        tx1 = Transaction.from_io(inputs,outputs,locktime)
        txsize = len(tx1.serialize(True))//2
        fee = estimate_fee(txsize)

        outputs = [(TYPE_ADDRESS, address, invalue - fee)]
        tx = Transaction.from_io(inputs,outputs,locktime)
        pubkey = privkey_to_serpub(privkey, True)
        keypairs = {pubkey.hex() : (privkey.to_bytes(32,'big'), True)}
        tx.sign(keypairs)
        self.contract.completetx(tx, secret)
        return tx

class AtomicSwap:
    def __init__(self,
                 contract1, contract2,
                 network1, network2,
                 i_am_party_A,
                 privkey1, privkey2, secret):
        self.contract1 = contract1
        self.contract2 = contract2

        assert contract1.secret_form == contract2.secret_form

        self.network1 = network1
        self.network2 = network2

        self.i_am_party_A = bool(i_am_party_A)

        self.privkey1 = privkey1
        self.privkey2 = privkey2
        self.secret = secret

        self.sc1 = HalfSwapController(contract1, network1)
        self.sc1.notify_secret = self.got_secret
        self.sc2 = HalfSwapController(contract2, network2)
        self.sc2.notify_secret = self.got_secret

        self.sc1.start()
        self.sc2.start()

    def shutdown(self,):
        self.sc1.shutdown()
        self.sc2.shutdown()

    def got_secret(self, secret):
        # this won't get called if we already know the secret
        assert hash160(secret) == self.contract1.secret_hash
        self.secret = secret

    @classmethod
    def from_packets(cls, privkey, other_pubkey,
                     offer_packet, accept_packet, accept_from_me,
                     network1, network2):
        """ Initialize from offer+accept packets """
        assert offer_packet or not accept_from_me

        offer_info = accept_packet.offer_info

        ssize = accept_packet.secret_size
        shash = accept_packet.secret_hash

        want_refundkey = accept_packet.key1
        give_redeemkey = accept_packet.key2

        if accept_from_me:
            assert offer_packet.offer_info == offer_info
            want_redeemkey = offer_packet.key1
            give_refundkey = offer_packet.key2

            priv1, priv2, secret = derive_secrets_recipient(privkey, other_pubkey, offer_info, size=ssize)
            assert shash == hash160(secret)
            assert want_refundkey == privkey_to_serpub(priv1, True)
            assert give_redeemkey == privkey_to_serpub(priv2, True)
        else:
            priv1, priv2 = derive_secrets_sender(privkey, other_pubkey, offer_info)
            secret = None
            want_redeemkey = privkey_to_serpub(priv1, True)
            give_refundkey = privkey_to_serpub(priv2, True)

        # contract1 WANT
        contract1 = SwapContract(
                want_redeemkey, shash, ssize,
                want_refundkey, offer_info.want_rtime)
        # contract2 GIVE
        contract2 = SwapContract(
                give_redeemkey, shash, ssize,
                give_refundkey, offer_info.give_rtime)

        self = cls(
                 contract1, contract2,
                 network1, network2,
                 accept_from_me,
                 priv1, priv2, secret)

        return self

###
# Negotiation system
###

class OfferInfo(namedtuple('cls', 'salt want_rtime give_rtime want_amount want_ticker give_amount give_ticker')):
    """
    Encodes / decodes an offer as a byte string. Offers have a unique encoding.

    In general we need want_rtime > give_rtime since the offerer is the second
    party.
    """
    __slots__ = ()

    def to_bytes(self):
        """returns bytes object"""
        salt = bytes(self.salt)
        assert len(salt) == 8

        return b''.join([
            salt,
            self.want_rtime.to_bytes(4,'big'),
            self.give_rtime.to_bytes(4,'big'),
            self.ser_amount_ticker(self.want_amount, self.want_ticker),
            self.ser_amount_ticker(self.give_amount, self.give_ticker),
            ])

    @staticmethod
    def ser_amount_ticker(amount, ticker):
        ticker = bytes(ticker)
        alen = (amount.bit_length() + 7) // 8
        if alen == 0:
            alen = 1
        tlen = len(ticker)
        assert alen <= 32
        assert tlen < 8
        qtl = (alen-1 << 3) + tlen

        return bytes((qtl,)) + amount.to_bytes(alen, 'big') + ticker

    @classmethod
    def from_bytes(cls, raw, n = 0):
        """returns (offerinfo, n_after)"""
        salt = raw[n:n+8] ; n += 8
        want_rtime = int.from_bytes(raw[n:n+4], 'big') ; n += 4
        give_rtime = int.from_bytes(raw[n:n+4], 'big') ; n += 4

        # want amount:
        qtl = raw[n] ; n += 1
        alen = (qtl >> 3) + 1
        tlen = qtl & 0x07
        if alen > 1:
            assert raw[n] != 0  # not allowed non-minimal encoding
        want_amount = int.from_bytes(raw[n:n + alen], 'big') ; n += alen
        want_ticker = raw[n:n + tlen] ; n += tlen

        # give amount:
        qtl = raw[n] ; n += 1
        alen = (qtl >> 3) + 1
        tlen = qtl & 0x07
        if alen > 1:
            assert raw[n] != 0  # not allowed non-minimal encoding
        give_amount = int.from_bytes(raw[n:n + alen], 'big') ; n += alen
        give_ticker = raw[n:n + tlen] ; n += tlen

        if n > len(raw):
            raise IndexError

        self = cls(salt, want_rtime, give_rtime, want_amount, want_ticker, give_amount, give_ticker)
        return self, n

def privkey_from_seed(seed, order = generator_secp256k1.order()):
    """Create a private key deterministically from seed bytes. Returns an
    integer in range of 1 ... order-1, uniformly distributed to within 1/2^256.
    """
    digest = hashlib.sha512(seed).digest()
    dint = int.from_bytes(digest, 'big')
    return 1 + (dint % (order-1))

def derive_seed(privkey, other_pubkey, offer_info):
    """ Derive personal seed from a given offer info, counterparty
    pubkey, and own messaging key. This will be used to construct
    per-swap private keys and secrets."""
    mykey = privkey.to_bytes(32,'big')
    obytes = offer_info.to_bytes()
    h = hashlib.sha512()
    h.update(b'OpenSwapDeriveSwapSeed')
    h.update(mykey)
    h.update(other_pubkey)
    h.update(len(obytes).to_bytes(4,'big'))
    h.update(obytes)
    h.update(mykey)
    return h.digest()

def derive_secrets_sender(privkey, other_pubkey, offer_info):
    seed = derive_seed(privkey, other_pubkey, offer_info)

    return (privkey_from_seed(seed + b'skey1'),
            privkey_from_seed(seed + b'skey2')
            )

def derive_secrets_recipient(privkey, other_pubkey, offer_info, size=16):
    seed = derive_seed(privkey, other_pubkey, offer_info)

    return (privkey_from_seed(seed + b'rkey1'),
            privkey_from_seed(seed + b'rkey2'),
            hashlib.sha512(seed + b'secret').digest()[:size],
            )

###
# Packets system for messaging
###

class PacketText(namedtuple('cls', 'text_bytes')):
    __slots__ = ()
    typebyte = 0

    def to_bytes(self):
        tb = bytes(self.text_bytes)
        assert len(tb) < 0xf0  # 0xf0 - 0xff are reserved for some kind of varint coding (to be decided on a later date)
        return bytes((len(tb),)) + tb

    @classmethod
    def from_body(cls, raw, n):
        l = raw[n] ; n += 1
        assert l < 0xf0
        text_bytes = raw[n:n+l] ; n += l
        assert n <= len(raw)
        self = cls(text_bytes)
        return self, n

    def to_ui_string(self):
        try:
            s = repr(self.text_bytes.decode('utf8'))
        except:
            s = self.text_bytes.hex()
        return 'Msg:'+s

class PacketOffer(namedtuple('cls', 'offer_info, expire_time, key1, key2')):
    __slots__ = ()
    typebyte = 1

    def to_bytes(self):
        return joinbytes([
            self.offer_info.to_bytes(),
            self.expire_time.to_bytes(4,'big'),
            len(self.key1),
            self.key1,
            len(self.key2),
            self.key2
            ])

    @classmethod
    def from_body(cls, raw, n):
        offer_info, n = OfferInfo.from_bytes(raw, n)
        expire_time = int.from_bytes(raw[n:n+4],'big') ; n += 4
        l = raw[n] ; n += 1
        key1 = raw[n:n+l] ; n += l
        l = raw[n] ; n += 1
        key2 = raw[n:n+l] ; n += l
        assert n <= len(raw)
        self = cls(offer_info, expire_time, key1, key2)
        return self, n

    @classmethod
    def make(cls, privkey, other_pubkey, offer_info, exptime_delta = 600):
        """Create offer packet including derived pubkeys."""
        priv1, priv2 = derive_secrets_sender(privkey, other_pubkey, offer_info)

        self = cls(offer_info, int(time() + exptime_delta),
                   privkey_to_serpub(priv1, True), privkey_to_serpub(priv2, True))
        return self

    def to_ui_string(self):
        remain = self.expire_time - time()
        if remain < 0:
            expstr = 'expired'
        elif remain < 3600:
            expstr = '<1 hr remains'
        else:
            expstr = '%d hr remains'%(round(remain))
        return 'Offer:%s%s for %s%s (%s)'%(
            format_satoshis_plain_nofloat(self.offer_info.give_amount),
            self.offer_info.give_ticker.decode('utf8'),
            format_satoshis_plain_nofloat(self.offer_info.want_amount),
            self.offer_info.want_ticker.decode('utf8'),
            expstr,
            )

class PacketAccept(namedtuple('cls', 'offer_info, secret_size, secret_hash, key1, key2')):
    __slots__ = ()
    typebyte = 2

    def to_bytes(self):
        sh = bytes(self.secret_hash)
        assert len(sh) == 20
        return joinbytes([
            self.offer_info.to_bytes(),
            self.secret_size,
            sh,
            len(self.key1),
            self.key1,
            len(self.key2),
            self.key2
            ])

    @classmethod
    def from_body(cls, raw, n):
        offer_info, n = OfferInfo.from_bytes(raw, n)
        secret_size = raw[n] ; n += 1
        secret_hash = raw[n:n+20] ; n += 20
        l = raw[n] ; n += 1
        key1 = raw[n:n+l] ; n += l
        l = raw[n] ; n += 1
        key2 = raw[n:n+l] ; n += l
        assert n <= len(raw)
        self = cls(offer_info, secret_size, secret_hash, key1, key2)
        return self, n

    @classmethod
    def make(cls, privkey, other_pubkey, offer_info):
        """Create acceptance packet including derived pubkeys and secret info."""
        priv1, priv2, secret = derive_secrets_recipient(privkey, other_pubkey, offer_info)

        self = cls(offer_info,
                   len(secret), hash160(secret),
                   privkey_to_serpub(priv1, True), privkey_to_serpub(priv2, True))
        return self

    def to_ui_string(self):
        return 'ACCEPT:%s%s for %s%s'%(
            format_satoshis_plain_nofloat(self.offer_info.give_amount),
            self.offer_info.give_ticker.decode('utf8'),
            format_satoshis_plain_nofloat(self.offer_info.want_amount),
            self.offer_info.want_ticker.decode('utf8'),
            )

class PacketPad(namedtuple('cls', 'pad_bytes')):
    """Used for padding to end. This has to be last packet since it snarfs
    all remaining bytes upon reading."""
    __slots__ = ()
    typebyte = 0xff

    def to_bytes(self):
        return self.pad_bytes

    @classmethod
    def from_body(cls, raw, n):
        pad_bytes = raw[n:]
        n = len(raw)
        self = cls(pad_bytes)
        return self, n

    def to_ui_string(self):
        return 'padding'

known_packet_types = {c.typebyte : c for c in [PacketText, PacketOffer, PacketAccept, PacketPad]}

class OpenSwapMessage:
    """
    Message structure:

        'OS'
        <packet type byte><packet body bytes>
        <packet type byte><packet body bytes>
        ...
        <packet type byte><packet body bytes>
    """
    def __init__(self, packets, autopad = None):
        self.packets = list(packets)
        if autopad:
            l = len(self.to_bytes())
            if l < autopad:
                self.packets.append(PacketPad(token_bytes(autopad - l - 1)))

    @classmethod
    def from_bytes(cls, raw):
        if not raw:
            return
        if raw[:2] != b'OS':
            raise ValueError('not OpenSwap message')
        n = 2

        # parse packets
        packets = []
        while n < len(raw):
            ptype = raw[n] ; n += 1
            try:
                pclass = known_packet_types[ptype]
            except KeyError:
                raise ValueError('unknown packet type', ptype) from None
            packet, n = pclass.from_body(raw, n)
            packets.append(packet)
        assert n == len(raw) # make sure we didn't run past end for some reason
        self = cls(packets)
        return self

    def to_bytes(self,):
        ba = bytearray(b'OS')
        for i,packet in enumerate(self.packets):
            if packet.typebyte == 0xff and i < len(self.packets) - 1:
                raise ValueError("pad packet only allowed as last packet")
            ba.append(packet.typebyte)
            ba.extend(packet.to_bytes())
        return bytes(ba)

