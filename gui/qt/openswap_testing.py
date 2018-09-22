
from electroncash.i18n import _
from electroncash.address import Address, ScriptOutput
from electroncash.transaction import Transaction,TYPE_ADDRESS
import electroncash.web as web

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from .util import *
from .qrtextedit import ShowQRTextEdit

from electroncash import bchmessage
from electroncash import openswap

from .transaction_dialog import show_transaction

import time

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_dialog(main_window, key):
    d = SwapDialog(main_window, key)
    dialogs.append(d)
    d.show()

#class BCHMessagePrepare(WindowModalDialog):


class SwapDialog(QDialog):
    def __init__(self, parent, key):
        # top level window
        QDialog.__init__(self, parent=None)
        self.key = key
        self.address = key.address
        pubkey = key.pubkey.hex()
        self.contract = None

        self.parent = parent
        self.config = parent.config
        self.wallet = parent.wallet
        self.network = parent.network
        self.app = parent.app

        self.setWindowTitle(_("OpenSwap testing"))

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Mypubkey:")))
        self.mypubkey_e = ButtonsLineEdit(key.pubkey.hex())
        self.mypubkey_e.addCopyButton(self.app)
        self.mypubkey_e.setReadOnly(True)
        vbox.addWidget(self.mypubkey_e)

        vbox.addWidget(QLabel(_("Alice pubkey") + ':'))
        self.apubkey_e = ButtonsLineEdit('0393cf5fe816e17df367be43d4f079e4f6480848982e0175818f8a4bc76944d23b')
        #self.apubkey_e.addCopyButton(self.app)
        vbox.addWidget(self.apubkey_e)

        vbox.addWidget(QLabel(_("Bob pubkey") + ':'))
        self.bpubkey_e = ButtonsLineEdit('02c3f2feffb3cb7f218a38c004002d22680bcd5d2b29952b9d4e69b6956b288a6e')
        #self.bpubkey_e.addCopyButton(self.app)
        vbox.addWidget(self.bpubkey_e)

        vbox.addWidget(QLabel(_("Alice refund time") + ':'))
        self.rtime_e = QLineEdit()
        vbox.addWidget(self.rtime_e)
        self.rtime_e.setText('1537491000') #str(int(time.time())))

        vbox.addWidget(QLabel(_("Alice's secret") + ':'))
        self.secret_e = QLineEdit('openswap')
        vbox.addWidget(self.secret_e)

        vbox.addWidget(QLabel(_("Secret size, secret hash") + ':'))
        self.secrethash_e = QLineEdit()
        self.secrethash_e.setReadOnly(True)
        vbox.addWidget(self.secrethash_e)
        self.secretsize_e = QLineEdit()
        self.secretsize_e.setReadOnly(True)
        vbox.addWidget(self.secretsize_e)

        vbox.addWidget(QLabel(_("Address") + ':'))
        self.address_e = QLineEdit()
        self.address_e.setReadOnly(True)
        vbox.addWidget(self.address_e)

        def upd_secret():
            secret_bytes = self.secret_e.text().encode('utf8')
            secret_bytes += b'\x00'*(16 - len(secret_bytes)) # pad up to minimum 16
            self.secret_bytes = secret_bytes
            h = openswap.hash160(secret_bytes)
            self.secretsize_e.setText(str(len(secret_bytes)))
            self.secrethash_e.setText(h.hex())
            upd_contract()
        self.secret_e.textChanged.connect(upd_secret)

        def upd_contract():
            try:
                apubkey = bytes.fromhex(self.apubkey_e.text())
                bpubkey = bytes.fromhex(self.bpubkey_e.text())
                rtime = int(self.rtime_e.text())
                secsize = int(self.secretsize_e.text())
                sechash = bytes.fromhex(self.secrethash_e.text())
                self.contract = openswap.SwapContract(bpubkey, sechash, secsize, apubkey, rtime)
                self.address_e.setText(str(self.contract.address))
            except Exception as e:
                self.contract = None
                self.address_e.setText(str(e))
        self.apubkey_e.textChanged.connect(upd_contract)
        self.bpubkey_e.textChanged.connect(upd_contract)
        self.rtime_e.textChanged.connect(upd_contract)

        upd_secret()

        b = QPushButton(_("Show RedeemScript"))
        b.clicked.connect(self.showscript)
        vbox.addWidget(b)

        vbox.addWidget(QLabel(_("UTXO hash") + ':'))
        self.utxo_hash_e = QLineEdit('')
        vbox.addWidget(self.utxo_hash_e)

        vbox.addWidget(QLabel(_("UTXO out") + ':'))
        self.utxo_out_e = QLineEdit('0')
        vbox.addWidget(self.utxo_out_e)

        vbox.addWidget(QLabel(_("UTXO value") + ':'))
        self.utxo_val_e = QLineEdit('10000000')
        vbox.addWidget(self.utxo_val_e)

        hbox = QHBoxLayout()

        b = QPushButton(_("Redeem"))
        b.clicked.connect(self.redeem)
        hbox.addWidget(b)

        b = QPushButton(_("Refund"))
        b.clicked.connect(self.refund)
        hbox.addWidget(b)

        b = QPushButton(_("Spy secret"))
        b.clicked.connect(self.spy)
        hbox.addWidget(b)

        hbox.addStretch(1)

        hbox.addWidget(CloseButton(self))

        vbox.addLayout(hbox)

        #self.hw.update()

    def showscript(self,):
        if not self.contract:
            return
        script = self.contract.redeemscript
        schex = script.hex()

        try:
            sco = ScriptOutput(script)
            decompiled = sco.to_ui_string()
        except:
            decompiled = "decompiling error"

        d = WindowModalDialog(self, _('Swap contract script'))
        d.setMinimumSize(610, 490)

        layout = QGridLayout(d)

        script_bytes_e = QTextEdit()
        layout.addWidget(QLabel(_('Bytes')), 1, 0)
        layout.addWidget(script_bytes_e, 1, 1)
        script_bytes_e.setText(schex)
        script_bytes_e.setReadOnly(True)
        #layout.setRowStretch(2,3)

        decompiled_e = QTextEdit()
        layout.addWidget(QLabel(_('ASM')), 3, 0)
        layout.addWidget(decompiled_e, 3, 1)
        decompiled_e.setText(decompiled)
        decompiled_e.setReadOnly(True)
        #layout.setRowStretch(3,1)

        hbox = QHBoxLayout()

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)

        layout.addLayout(hbox, 4, 1)
        d.exec_()
            #self.app.clipboard().setText(scr)
            #QToolTip.showText(QCursor.pos(), _("Text copied to clipboard"), self)

    def redeem(self,):
        assert self.key.pubkey == self.contract.redeem_pubkey
        tx = self.mktx('redeem')
        self.contract.signtx(tx, self.key.privkey)
        self.contract.completetx(tx, self.secret_bytes)
        show_transaction(tx, self.parent)

    def refund(self,):
        assert self.key.pubkey == self.contract.refund_pubkey
        tx = self.mktx('refund')
        self.contract.signtx(tx, self.key.privkey)
        self.contract.completetx(tx, None)
        show_transaction(tx, self.parent)

    def mktx(self,mode):
        val = int(self.utxo_val_e.text())
        inps = [self.contract.makeinput(self.utxo_hash_e.text(),
                                        int(self.utxo_out_e.text()),
                                        val,
                                        mode)
                ]
        outs = [(TYPE_ADDRESS,
                 Address.from_cashaddr_string('bchtest:qrzeh82j6gv4se3ska395j0gnghpc00ltv9cp7llcn'),
                 val-300)]
        tx = Transaction.from_io(inps, outs)
        if mode == 'refund':
            tx.locktime = self.contract.refund_time
        return tx

    def spy(self,):
        d = QInputDialog(self)
        d.setLabelText("TXID of spend")
        d.setTextValue('1a32969e2c2928cb1f337f67d06eae47ba046e48cce27190dca40027fa2858e0')
        d.exec_()
        txid = d.textValue()

        raw = self.network.synchronous_get(('blockchain.transaction.get', [txid]), timeout=3)
        if raw:
            tx = Transaction(raw)
            secret = self.contract.extract(tx)
            if secret:
                print("GOT", secret)
                self.secret_e.setText(secret.decode('utf8'))


