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
"""

from . import bitcoin
from . import bchmessage
from .address import OpCodes, Address, hash160
from .transaction import Transaction

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
        assert 16 <= self.secret_size <= 76
        assert len(self.refund_pubkey) == 33
        assert self.refund_time >= LOCKTIME_THRESHOLD  # don't allow blocktime-based times.
        assert self.refund_time < 2**32  # keep it within 4 bytes for now.

        if self.secret_size <= 16:
            sspush = self.secret_size
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
                5, self.refund_time.to_bytes(5,'little'), OpCodes.OP_CHECKLOCKTIMEVERIFY,
                # normally one should OP_DROP after OP_CHECKLOCKTIMEVERIFY,
                # however in this case we can use the nonzero time value
                # to complete the script with nonzero value.
            OpCodes.OP_ENDIF,
            ])
        self.address = Address.from_multisig_script(self.redeemscript)

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

    def spend(self, tx, index, privatekey, secret):
        """
        Spend this input in transaction `tx` on input `index`. For redeem
        mode you must provide the private key corresponding to redeem_key,
        and the secret bytes. For refund mode you must provide the private
        key corresponding to refund_key, and set secret to None.

        This function modifies `tx` and completes the signature.

        privatekey is 32 bytes (big-endian integer); secret is N bytes or None.

        Notes:
        - you will have to fill in the following fields on the txin:
        prevout_hash, prevout_n, value, address.
        - the transaction has to be otherwise complete since this signs
        with SIGHASH_ALL.
        - this will set the locktime for refund. If you happen to be doing
        multiple refunds in one tx, there will be a problem.
        - this sets sequence number to 0.
        """

        txin = tx.inputs()[index]
        assert txin['address'] == self.address

        # See bip65 -- sequence must not be 0xffffffff, for CLTV.
        # We use 0 here to enable RBF on the redemption, just in case
        # it's desired for some reason. (for applicable chains)
        txin['sequence'] = 0

        if secret:
            assert len(secret) == self.secret_size
            assert hash160(secret) == self.secret_hash
        else:
            tx.locktime = self.refund_time

        pubkey = self.redeem_pubkey if secret else self.refund_pubkey
        # could check here whether privkey is correct.
        pubkey_hex = pubkey.hex()

        txin['type'] = 'unknown'
        txin['scriptCode'] = self.redeemscript
        txin['scriptSig'] = b'' # just an empty one for stand-in
        txin['num_sig'] = 1
        txin['x_pubkeys'] = [pubkey_hex]
        txin['signatures'] = [None]
        keypairs = {pubkey_hex : (privatekey, True)}

        tx.sign(keypairs)
        sig = bytes.from_hex(txin['signatures'][0])

        # construct the correct scriptsig
        if secret:
            script = [
                len(secret), secret,
                len(sig), sig,
                OpCodes.OP_1,
                ]
        else:
            script = [
                len(sig), sig,
                OpCodes.OP_0,
                ]
        txin['scriptSig'] = mkscript(script).hex()




    #@classmethod
    #def from_redeemscript(self, ):
        #pass
