
from electroncash.i18n import _
from electroncash.address import Address, ScriptOutput
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

        self.parent = parent
        self.config = parent.config
        self.wallet = parent.wallet
        self.network = parent.network
        self.app = parent.app
        self.saved = True

        self.setWindowTitle(_("OpenSwap playing"))

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Mypubkey:")))
        self.mypubkey_e = ButtonsLineEdit(key.pubkey.hex())
        self.mypubkey_e.addCopyButton(self.app)
        self.mypubkey_e.setReadOnly(True)
        vbox.addWidget(self.mypubkey_e)

        vbox.addWidget(QLabel(_("Alice pubkey") + ':'))
        self.apubkey_e = ButtonsLineEdit()
        #self.apubkey_e.addCopyButton(self.app)
        vbox.addWidget(self.apubkey_e)

        vbox.addWidget(QLabel(_("Bob pubkey") + ':'))
        self.bpubkey_e = ButtonsLineEdit()
        #self.bpubkey_e.addCopyButton(self.app)
        vbox.addWidget(self.bpubkey_e)

        vbox.addWidget(QLabel(_("Alice refund time") + ':'))
        self.rtime_e = QLineEdit()
        vbox.addWidget(self.rtime_e)
        self.rtime_e.setText(str(int(time.time())))

        vbox.addWidget(QLabel(_("Alice's secret") + ':'))
        self.secret_e = QLineEdit()
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

        b = QPushButton(_("Show RedeemScript"))
        b.clicked.connect(self.showscript)
        vbox.addWidget(b)

        vbox.addWidget(QLabel(_("UTXO hash") + ':'))
        utxo_hash_e = QLineEdit()
        vbox.addWidget(utxo_hash_e)

        vbox.addWidget(QLabel(_("UTXO out") + ':'))
        utxo_out_e = QLineEdit()
        vbox.addWidget(utxo_out_e)

        vbox.addWidget(QLabel(_("UTXO value") + ':'))
        utxo_val_e = QLineEdit()
        vbox.addWidget(utxo_val_e)

        hbox = QHBoxLayout()

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
