"""
OpenSwap tooling

- Atomic swaps


Note on smart contracts:

Electron cash's Transaction objects aren't made to easily handle P2SH
addresses other than multisig ones.

- To sign using Transaction.sign(), you need to manually construct txin dicts:
    - 'type': 'unknown'
    - 'scriptCode': set to the redeemscript.
    - 'scriptSig': set to nominal value (so serialize() can work)
    - 'num_sig': set to the right number.
    - provide 'x_pubkeys' which matches the `keypairs` dict keys.
- After calling .sign(), reconstitute the correct scriptSig and then call .serialize() again.


Protocol for basic swap:

- Alice posts advertisement including:
    - [header byte: offer v0]
    - wanted amount, ticker1
    - offered amount, ticker2
    - expiry time
- Bob replies with counteroffer:
    - [header byte: trade v0]
    - Alice offer ID
    - subID [~ 2 byte]
    - wanted amount, ticker1
    - offered amount, ticker2
    - expiry time
    - swapcontract info:
        - Acceptable smartcontract types
        - Bob pubkey for ticker1
        - (Bob pubkey for ticker2 - not needed if both use secp256k1)
- Alice replies:
    - [header byte: accept v0]
    - Alice offer ID
    - subID [~ 2 byte]
    - swapcontract info:
        - Smartcontract type
        - Alice refund time
        - Secret hash
        - Secret size
        - Alice pubkey for ticker1
        - (Alice pubkey for ticker2 - not needed if both use secp256k1)

Questions:
- Who goes first?
- Use padding?
"""

from . import bitcoin
from . import bchmessage
from .address import OpCodes, Address, hash160
from .transaction import Transaction

from ecdsa.ecdsa import generator_secp256k1

# Below this number, nLockTime and OP_CHECKLOCKTIMEVERIFY input are defined
# using the block number. Othewise using epoch timestamp.
LOCKTIME_THRESHOLD = 500000000
# (In bitcoind, found in script/script.h)
# Note that BIP113 changed how nLockTime interacts with block time. Beware!

def mkscript(iterable):
    return b''.join((bytes((x,)) if isinstance(x,int) else x) for x in iterable)

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
        assert self.refund_time < 0x8000000000 # cannot encode times after year 15451

        if self.refund_time < 0x80000000:
            # until year 2038 use 4 byte form
            rtime_bytes = self.refund_time.to_bytes(4,'little')
        else:
            # from 2038-2106 our number cannot fit into 4 bytes since the high
            # bit is used for sign, in bitcoin script.
            rtime_bytes = self.refund_time.to_bytes(5,'little')


        if 1 <= self.secret_size <= 16:
            sspush = 0x50 + self.secret_size  # put as OP_N
        else:
            sspush = bytes((1, self.secret_size))

        self.redeemscript = mkscript([
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

        self.dummy_scriptsig_redeem = '01'*(5 + self.secret_size + 71 + len(self.redeemscript))
        self.dummy_scriptsig_refund = '00'*(4 + 71 + len(self.redeemscript))

    def extract(self, tx, index):
        """
        Extract the secret from a spent SwapContract's scriptSig.

        Trickiness: scriptSig is allowed to have many different opcodes,
        which may be used to confuse the detection algorithm.

        In Bitcoin Cash in particular, from May-November 2018 it is possible
        (with miner support) to have *highly* obfuscated scripsSigs using
        OP_CAT and OP_SPLIT. Starting from November, the scriptSig push-only
        rule will prevent such obfuscations.

        The solution here iterates over all pushes in the script, seeing if
        any of them hash to produce the right value. This handles all the other
        kinds of obfuscation (not involving CAT/SPLIT).

        If no matching secret found, this returns None.
        """
        txin = tx.inputs()[index]

        if txin['address'] != self.address:
            raise RuntimeError('address mismatch')

        ops = Script.get_ops(txin['scriptSig'])

        for o in ops:
            if not isinstance(o,tuple):
                continue  # skip non-push
            op, data = o
            if not data or len(data) != self.secret_size:
                continue  # skip wrong length
            if hash160(data) == self.secret_hash:
                return data

    def makeinput(self, prevout_hash, prevout_n, value, mode):
        """
        Construct an unsigned input for adding to a transaction. scriptSig is
        set to all zeros, for size estimation.

        (note: Transaction object will think it is complete)
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
        pubkey = bchmessage.point_to_ser(privatekey * generator_secp256k1, True)
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
                print(script)
            txin['scriptSig'] = mkscript(script).hex()
