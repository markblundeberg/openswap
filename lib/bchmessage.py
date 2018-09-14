"""
Necessary tools for sending/receiving messages using BCHMessage protocol.

Note: BCHMessage private messages only work with a standard P2PKH hot wallet
(it needs the private key).


Warning:
**Do not use this with automated systems!**
The pure-python ecdsa module here is known to have timing attack weaknesses
which will allow someone to extract your private key.
"""

from . import address

import ecdsa
import hashlib
import pyaes

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

def point_to_ser(p, compressed):
    """ Convert Point to serialized format """
    if compressed:
        return bytes((2 + (p.y()&1),)) + p.x().to_bytes(32, 'big')
    else:
        return b'\x04' + p.x().to_bytes(32, 'big') + p.y().to_bytes(32, 'big')

def ser_to_point(Aser):
    """Convert compressed or uncompressed serialized point to a Point object.
    Does not check if it's on curve."""
    p     = SECP256k1.curve.p()
    order = SECP256k1.order
    assert Aser[0] in [0x02, 0x03, 0x04]
    if Aser[0] == 0x04:
        # uncompressed key
        assert len(Aser) == 65
        x = int.from_bytes(Aser[1:33], 'big')
        y = int.from_bytes(Aser[33:], 'big')
    else:
        # compressed key
        assert len(Aser) == 33
        x = int.from_bytes(Aser[1:], 'big')

        y2 = pow(x, 3, p) + 7

        # attempt to get quadratic residue
        y  = pow(y2, (p+1)//4, p)
        if pow(y, 2, p) != y2:
            raise ValueError('not a point')

        if (Aser[0]-2) != (y&1):
            # flip parity
            y = p - y
    return Point(SECP256k1.curve, x, y, order)

def parse_tx(tx):
    """
    Check a BCHMessage transaction to ensure that the first spent input
    is a P2PKH one, and it has a correct signature over the outputs.
    """
    return pubkey, message

class Channel:
    """Represents a public bulletin board.

    P2SH address: redeemscript = push['C'+chanid]
    """
    def __init__(self, chanid, chankey):
        self.chanid = bytes(chanid)
        self.chankey = bytes(chankey)
        assert len(self.chankey) == 32

    @classmethod
    def from_name(cls, name):
        name = str(name)
        h = hashlib.sha512()
        h.update(name.encode('utf8'))
        digest = h.digest()
        chanid = digest[:16]
        chankey = digest[32:]
        self = cls.__init__(chanid, chankey)
        self.name = name
        return self

class MessagingKey:
    """Holder for single unlocked private key, used to encrypt/decrypt messages,
    and more."""
    ecdh_hasher = hashlib.sha256

    def __init__(self, pubkey, privkey):
        self.pubkey = bytes(pubkey)
        self.privkey = int(privkey)

        self.address = address.Address.from_pubkey(pubkey)
        #self.signingkey =

    @classmethod
    def from_wallet(cls, wallet, address, password):
        raise NotImplementedError

    def ecdh(self, theirpubkey):
        """
        Ellipic curve Diffie Hellman on secp256k1.

        For a given counterparty public key (bytes; compressed/uncompressed),
        calculate the shared secret (33 byte compressed point) and then hash
        it using the hashlib factory found in self.ecdh_hasher (sha256).

        Returns 32 byte shared secret.
        """
        pk = ser_to_point(theirpubkey)
        if not ecdsa.ecdsa.point_is_valid(SECP256k1.generator, pk.x(), pk.y()):
            raise Exception('invalid pubkey')

        ecdh_point = point_to_ser(self.privkey * pk, True)

        h = self.ecdh_hasher()
        h.update(ecdh_point)
        return h.digest()

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

