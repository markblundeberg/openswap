
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
    net_signal = pyqtSignal()
    need_update=True

    def __init__(self, parent, key):
        # top level window
        QDialog.__init__(self, parent=None)
        self.parent = parent
        self.config = parent.config
#        self.wallet = parent.wallet
        self.network = parent.network
        self.app = parent.app

        self.key = key
        self.net_signal.connect(self.do_update)

        secret = b"OpenswapOpenswap"
        sechash = openswap.hash160(secret)

        # recovery pubkey
        apubkey = bytes.fromhex('02c3f2feffb3cb7f218a38c004002d22680bcd5d2b29952b9d4e69b6956b288a6e')

        self.contract = openswap.SwapContract(
                key.pubkey, sechash, len(secret),
                apubkey,
                1537491000
                )
        self.sc = openswap.HalfSwapController(self.contract,self.network)
        self.sc.set_privkey(key.privkey)
        self.sc.set_secret(secret)

        self.wallet = self.sc.wallet


        self.setWindowTitle(_("OpenSwap testing2"))

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Swap contract address") + ':'))
        self.address_e = QLineEdit(str(self.contract.address))
        self.address_e.setReadOnly(True)
        vbox.addWidget(self.address_e)

        vbox.addWidget(QLabel(_("Coins at this address") + ':'))
        self.utxolist = SwapUTXOList(self, self.parent)
        vbox.addWidget(self.utxolist)

        hbox = QHBoxLayout()

        hbox.addWidget(QLabel(_("Time remaining to refund") + ':'))
        self.time_remaining_e = QLabel()
        f = QFont()
        f.setWeight(QFont.Bold)
        self.time_remaining_e.setFont(f)
        hbox.addWidget(self.time_remaining_e)
        hbox.addStretch(1)
        vbox.addLayout(hbox)

        hbox = QHBoxLayout()

        self.redeem_button = QPushButton(_("Redeem"))
        self.redeem_button.clicked.connect(self.redeem)
        hbox.addWidget(self.redeem_button)

        self.refund_button = QPushButton(_("Refund"))
        self.refund_button.clicked.connect(self.refund)
        hbox.addWidget(self.refund_button)

        hbox.addStretch(1)

        hbox.addWidget(CloseButton(self))

        vbox.addLayout(hbox)

        self.network.register_callback(self.on_network, ['updated'])
        self.do_update()

    def on_network(self, event, *args):
        self.need_update = True
        self.net_signal.emit()

    def do_update(self):
        if not self.need_update:
            return
        self.need_update = False
        try:
            tr = self.sc.estimate_time_remaining()
            if tr >= 174600:  # when at least 48.5 hours
                trint  = round(tr/86400.)
                trunit = _("days")
            elif tr >= 5970:  # when at least 99.5 minutes
                trint = round(tr/3600.)
                trunit = _("hours")
            else:
                trint = round(tr/60.)
                trunit = _("minutes")
            trstr = '%d %s'%(trint, trunit)
            if tr == 0:
                trstr = _("none (can refund now)")
            elif tr <= 600:
                trstr += _(" (next block)")
        except Exception as e:
            trstr = "ERROR" + str(e)
        self.time_remaining_e.setText(trstr)
        self.utxolist.update()
        self.redeem_button.setDisabled(not self.sc.can_redeem())
        self.refund_button.setDisabled(not self.sc.can_refund())

    def closeEvent(self, event):
        self.network.unregister_callback(self.on_network)
        self.sc.shutdown()

    def redeem(self,):
        coins = self.utxolist.get_coins()
        if not coins:
            QMessageBox.information(self, "", _("No coins!"))
            return
        d = QInputDialog(parent=self)
        d.setLabelText(_("Enter the address where you want to redeem these coins.\n\nNote that the process of redeeming will reveal the secret value."))
        d.exec_()
        if not d.result():
            return  # user cancelled
        self.mktx(coins, d.textValue(), 'redeem')

    def refund(self,):

        d = QInputDialog(parent=self)
        label = _("Enter the address where you want to refund the coins.")
        try:
            tr = str(self.sc.estimate_time_remaining())
        except:
            tr = 'unknown'
        if tr != '0':
            label += '\n\n' + _("It is not possible to broadcast this refund transaction\nyet, but you may save it for later.")
        d.setLabelText(label)
        d.exec_()
        if not d.result():
            return  # user cancelled
        self.mktx(coins, d.textValue(), 'refund')

    def mktx(self, coins, addr_str, mode):
        print(addr_str)
        try:
            outaddr = Address.from_string(addr_str)
        except Exception as e:
            QMessageBox.critical(self, "", "Invalid address: %s"%(str(e)))
            return
        outputs = [(TYPE_ADDRESS, outaddr, 0)]
        invalue = 0
        inputs = []
        for c in coins:
            inputs.append(self.contract.makeinput(c['prevout_hash'], c['prevout_n'], c['value'], mode))
            invalue += c['value']

        if mode == 'refund':
            locktime = self.contract.refund_time
        else:
            locktime = 0

        # make once to estimate size
        tx1 = Transaction.from_io(inputs,outputs,locktime)
        txsize = len(tx1.serialize(True))//2
        fee = self.config.estimate_fee(txsize)

        outputs = [(TYPE_ADDRESS, outaddr, invalue - fee)]
        tx = Transaction.from_io(inputs,outputs,locktime)
        keypairs = {self.sc.pubkey.hex() : (self.sc.privkey.to_bytes(32,'big'), True)}
        tx.sign(keypairs)
        if mode == 'refund':
            self.contract.completetx(tx, None)
        else:
            self.contract.completetx(tx, self.sc.secret)

        self.parent.show_transaction(tx, mode)


class SwapUTXOList(MyTreeWidget):
#    filter_columns = [0, 2]  # Address, Label

    def __init__(self, parent, main_window):
        MyTreeWidget.__init__(self, parent, self.create_menu, [ _('Amount'), _('Height'), _('Output point')], 2)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.main_window = main_window
        self.setTextElideMode(Qt.ElideMiddle)

    def get_name(self, x):
        return x.get('prevout_hash') + ":%d"%x.get('prevout_n')

    def on_update(self):
        self.wallet = self.parent.wallet
        self.clear()
        self.utxos = self.wallet.get_utxos()
        for x in self.utxos:
            height = x['height']
            name = self.get_name(x)
            amount = self.main_window.format_amount(x['value'])
            utxo_item = SortableTreeWidgetItem([amount,
                                         str(height),
                                         name])
            utxo_item.setFont(0, QFont(MONOSPACE_FONT))
            utxo_item.setFont(2, QFont(MONOSPACE_FONT))
            utxo_item.setData(0, Qt.UserRole, name)


            self.addTopLevelItem(utxo_item)

    def get_coins(self):
        selected = [x.data(0, Qt.UserRole) for x in self.selectedItems()]
        if selected:
            return filter(lambda x: self.get_name(x) in selected, self.utxos)
        else:
            return self.utxos

    def create_menu(self, position):
        selected = self.selectedItems()
        if not selected:
            return
        menu = QMenu()

#        menu.addAction(_("Redeem"), self.parent.redeem)
        if len(selected) == 1:
            txid = selected[0].data(0, Qt.UserRole).split(':')[0]
            tx = self.wallet.transactions.get(txid)
            menu.addAction(_("Details"), lambda: self.main_window.show_transaction(tx))
        else:
            return

        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item, column):
        # disable editing fields in this tab (labels)
        return False
