"""
Necessary tools for sending/receiving messages using BCHMessage protocol.

Note: BCHMessage private messages only work with a standard P2PKH hot wallet
(it needs the private key).


Warning:
**Do not use this with automated systems!**
The pure-python ecdsa module here is known to have timing attack weaknesses
which will allow someone to extract your private key.
"""

from .address import Address
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
from ecdsa.ellipticcurve import Point

def point_to_ser(p, compressed):
    """ Convert Point to serialized format """
    if compressed:
        return bytes((2 + (p.y()&1),)) + p.x().to_bytes(32, 'big')
    else:
        return b'\x04' + p.x().to_bytes(32, 'big') + p.y().to_bytes(32, 'big')

def ser_to_point(Aser):
    """Convert secp256k1 serialized point (compressed or uncompressed) to a
    Point object. This does not handle 'point at infinity'.

    Does not check if point is on curve but *does* ensure points are in field.

    See http://www.secg.org/sec1-v2.pdf#page=17 "Octet-String-to-Elliptic-Curve-Point Conversion"
    """
    p     = SECP256k1.curve.p()
    order = SECP256k1.order
    assert Aser[0] in [0x02, 0x03, 0x04]
    if Aser[0] == 0x04:
        # uncompressed key
        assert len(Aser) == 65
        x = int.from_bytes(Aser[1:33], 'big')
        y = int.from_bytes(Aser[33:], 'big')
        assert x < p
        assert y < p
    else:
        # compressed key
        assert len(Aser) == 33
        x = int.from_bytes(Aser[1:], 'big')
        assert x < p

        y2 = (x*x*x + 7) % p

        # attempt to get square root of y
        y  = pow(y2, (p+1)//4, p)
        # for quadratic non-residue the result is nonsense, so we check:
        if pow(y, 2, p) != y2:
            raise ValueError('not a point')

        # flip parity of y if it doesn't match the encoded parity
        if (Aser[0]-2) != (y&1):
            y = p - y
    return Point(SECP256k1.curve, x, y, order)

def ser_to_pubkey(ASer):
    P = ser_to_point(ASer)
    # this is important to avoid private key leakage in ECDH
    assert ecdsa.ecdsa.point_is_valid(SECP256k1.generator, P.x(), P.y())
    return P

def ecdh(privkey, theirpubkey):
    """
    Ellipic curve Diffie Hellman on secp256k1.

    For a given counterparty public key (bytes; compressed/uncompressed),
    calculate the shared secret (33 byte compressed point) and then hash
    it using sha256.

    This is equivalent to what happens in libsecp256k1's `secp256k1_ecdh`
    function.

    Returns 32 byte shared secret.
    """
    pk = ser_to_pubkey(theirpubkey)

    ecdh_point = point_to_ser(privkey * pk, True)

    h = hashlib.sha256()
    h.update(ecdh_point)
    return h.digest()

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
    cipher = AESModeOfOperationCTR(key, counter)
    return iv + cipher.encrypt(plaintext)

def aes_decrypt(key, iv_ciphertext):
    """AES decrypt arbitrary length message. (uses CTR mode)

    Returns plaintext, which is 16 bytes shorter than iv_ciphertext.

    iv_ciphertext must be >= 16 bytes. (i.e., IV should be 16 bytes)
    """
    assert len(iv_ciphertext) >= 16
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    counter = pyaes.Counter(int.from_bytes(iv,'big'))
    cipher = AESModeOfOperationCTR(key, counter)
    return cipher.decrypt(ciphertext)

###
# Transaction parsing (based on electron cash Transaction objects)
###

def parse_tx(tx):
    """
    Check a BCHMessage transaction to ensure that the first spent input
    has P2PKH form of scriptsig, AND it has a correct signature over the
    transaction.

    Returns the source pubkey, the address of the target, and the op_return message.
    """
    # Check inputs and outputs
    # Check input 0 has P2PKH type of scriptsig.
    # Examine signature and confirm it is a valid signature on tx.
    # Make sure the hashtype by covers the op_return output.

    # we rely on the way that transaction.py parse_scriptSig() works to detect P2PKH
    txin = tx.inputs()[0]
    if txin['type'] != 'p2pkh':
        raise ParseError('first input not p2pkh')

    sig = bytes.fromhex(txin['signatures'][0])
    hashbyte = sig[-1]
    if hashbyte != (tx.nHashType() & 0xff):
        raise ParseError('not a valid hashbyte')
    sigder = sig[:-1]

    pubkey = bytes.fromhex(txin['x_pubkeys'][0])
    try:
        pubkey_point = ser_to_pubkey(pubkey)
    except:
        raise ParseError('bad pubkey')

    verkey = ecdsa.VerifyingKey.from_public_point(pubkey_point, SECP256k1)

    pre_hash = bitcoin.Hash(util.bfh(tx.serialize_preimage(0)))

    if not verkey.verify_digest(sigder, pre_hash, sigdecode = ecdsa.util.sigdecode_der):
        raise ParseError('bad signature')

    ## Extract message here
    ## Extract destinationaddr here

    return sourcepubkey, destinationaddr, message


class Channel:
    """Represents a public bulletin board. Transactions are sent to board
    with notification sent to an anyone-can-spend P2SH address.

    Channels have a short small ID (generally 3 bytes) to determine the
    address. This makes 16 million notification addresses, which can be
    simply enumerated by anyone who wants to collect the notification dust.
    (dust collection is profitable: with only 47 bytes per input

    Collisions
    between channels are not a problem, because each channel also has
    a 256-bit encryption key that both encrypts channel messages and

    encryption key. Unlike with private messages, channel messages use
    authenticated encryption (Encrypt-then-MAC) in order to prove that
    the sender knows the key.

    P2SH address: redeemscript = push['C'+chanid]
    """
    def __init__(self, chanid, chankey):
        self.chanid = bytes(chanid)   # generally 3 bytes but not always.
        assert len(self.chanid) < 75  # simplify redeem script + scriptsig
        self.chankey = bytes(chankey)
        assert len(self.chankey) == 32

        self.redeemscript = bytes((len(self.chanid)+1, 0x43)) + self.chanid
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
    def from_name(cls, name):
        """Construct channel from unicode `name`."""
        name = str(name)
        h = hashlib.sha512()
        h.update(name.encode('utf8'))
        digest = h.digest()
        chanid = digest[:4]
        chankey = digest[32:]
        self = cls.__init__(chanid, chankey)
        self.name = name
        return self


class MessagingKey:
    """Holder for single unlocked private key, used to create and read private
    messages."""
    ecdh_hasher = hashlib.sha256

    def __init__(self, pubkey, privkey):
        self.pubkey = bytes(pubkey)
        self.privkey = int(privkey)

        self.address = address.Address.from_pubkey(pubkey)
        #self.signingkey =

    @classmethod
    def from_wallet(cls, wallet, address, password):
        raise NotImplementedError

    def create_private_message(self, wallet, dest_pubkey, message, config, fee=None):
        """
        Creates a transaction that holds a message addressed to dest_pubkey.

        """
        self.wallet = wallet
        assert wallet.txin_type = 'p2pkh'

        # domain = address
        #coins = wallet.get_spendable_coins(domain, config)
        #tx = wallet.make_unsigned_transaction(coins, outputs, config, fee, change_addr)

    def read_private_message(self, tx):
        """
        Reads a private message. Returns source_pubkey, message.

        Note: this extracts the pubkey *and checks the signature*. Since
        we don't use auth encryption this is important.
        """


# Wallet make tx from password:
    #def mktx(self, outputs, password, config, fee=None, change_addr=None, domain=None):
        #coins = self.get_spendable_coins(domain, config)
        #tx = self.make_unsigned_transaction(coins, outputs, config, fee, change_addr)
        #self.sign_transaction(tx, password)
        #return tx

