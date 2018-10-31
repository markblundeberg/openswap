
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

from electroncash.util import format_satoshis_plain_nofloat
from electroncash.util import print_error, print_stderr

from .transaction_dialog import show_transaction

import time

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_dialog(*args, **kwargs):
    d = SwapDialog(*args, **kwargs)
    dialogs.append(d)
    d.show()

TX_ICONS = [
    "warning.png",
    "warning.png",
    "unconfirmed.png",
    "unconfirmed.png",
    "clock1.png",
    "clock2.png",
    "clock3.png",
    "clock4.png",
    "clock5.png",
    "confirmed.png",
]

def format_time(tr):
    try:

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
    return trstr

class SwapDialog(QDialog, MessageBoxMixin):
    need_update=True

    def __init__(self, app, config, swapper):
        # probably need config
        # top level window
        QDialog.__init__(self, parent=None)
#        self.wallet = parent.wallet

        self.app = app
        self.config = config
        self.swapper = swapper

        self.setWindowTitle(_("Atomic Swap"))

        self.setMinimumWidth(800)
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        self.party_info_label = QLabel(_("You are party A.") if swapper.i_am_party_A else _("You are party B."))
        self.party_info_label.setAlignment(Qt.AlignCenter)
        self.party_info_label.setTextFormat(Qt.RichText)
        vbox.addWidget(self.party_info_label)
        self.phase_info_label = QLabel("")
        self.phase_info_label.setAlignment(Qt.AlignCenter)
        self.phase_info_label.setTextFormat(Qt.RichText)
        vbox.addWidget(self.phase_info_label)
        self.instruction_label = QLabel("")
        self.instruction_label.setAlignment(Qt.AlignCenter)
        self.instruction_label.setTextFormat(Qt.RichText)
        vbox.addWidget(self.instruction_label)


        ##
        # Split parts below
        ##

        hbox = QHBoxLayout()
        vbox.addLayout(hbox)

        vboxleft = QVBoxLayout()
        hbox.addLayout(vboxleft)
        vboxright = QVBoxLayout()
        hbox.addLayout(vboxright)


        vboxleft.addWidget(QLabel(_("NET1 Swap contract address") + ':'))
        addr_e = QLineEdit(str(self.swapper.contract1.address))
        addr_e.setReadOnly(True)
        vboxleft.addWidget(addr_e)

        vboxleft.addWidget(QLabel(_("Coins at this address") + ':'))
        self.leftutxolist = SwapUTXOList(self, swapper.sc1)
        vboxleft.addWidget(self.leftutxolist)

        self.time_remaining_1_e = QLabel()
        vboxleft.addWidget(self.time_remaining_1_e)

        hbox = QHBoxLayout()
        vboxleft.addLayout(hbox)

        if swapper.i_am_party_A:
            b = QPushButton(_("Refund"))
            b.clicked.connect(self.refund)
            hbox.addWidget(b)
        else:
            self.redeem_button = QPushButton(_("Redeem"))
            self.redeem_button.clicked.connect(self.redeem)
            hbox.addWidget(self.redeem_button)


        vboxright.addWidget(QLabel(_("NET2 Swap contract address") + ':'))
        addr_e = QLineEdit(str(self.swapper.contract2.address))
        addr_e.setReadOnly(True)
        vboxright.addWidget(addr_e)

        vboxright.addWidget(QLabel(_("Coins at this address") + ':'))
        self.rightutxolist = SwapUTXOList(self, swapper.sc2)
        vboxright.addWidget(self.rightutxolist)

        self.time_remaining_2_e = QLabel()
        vboxright.addWidget(self.time_remaining_2_e)

        hbox = QHBoxLayout()
        vboxright.addLayout(hbox)

        if swapper.i_am_party_A:
            self.redeem_button = QPushButton(_("Redeem"))
            self.redeem_button.clicked.connect(self.redeem)
            hbox.addWidget(self.redeem_button)
        else:
            b = QPushButton(_("Refund"))
            b.clicked.connect(self.refund)
            hbox.addWidget(b)


        swapper.network1.register_callback(self.leftutxolist.on_network, ['updated', 'verified'])
        swapper.network2.register_callback(self.rightutxolist.on_network, ['updated', 'verified'])

        self.timer = QTimer()
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.timed_update)
        self.timer.start()

        self.timed_update()  # call once to start

    def closeEvent(self, event):
        event.accept()
        try:
            dialogs.remove(self)
        except ValueError:
            pass
        self.swapper.network1.unregister_callback(self.leftutxolist.on_network)
        self.swapper.network2.unregister_callback(self.rightutxolist.on_network)
        self.swapper.shutdown()
        self.timer.stop()

    def reject(self,):
        self.close()

    def timed_update(self):
        self.redeem_button.setDisabled(not self.swapper.secret)
        self.tr1 = self.swapper.sc1.estimate_time_remaining()
        self.tr2 = self.swapper.sc2.estimate_time_remaining()
        self.time_remaining_1_e.setText(_("Time to refund: ") + format_time(self.tr1))
        self.time_remaining_2_e.setText(_("Time to refund: ") + format_time(self.tr2))

        phase, instruction = self.figure_out_phase()
        self.phase_info_label.setText('<b>%s</b>'%(phase,))
        self.instruction_label.setText('<em>%s</em>'%(instruction,))

    def figure_out_phase(self):
        # Figure out what phase of swap we are in and recommend what user should do.
        iamA = self.swapper.i_am_party_A
        known_secret = bool(self.swapper.sc1.secret) or bool(self.swapper.sc2.secret)
        unspentL = bool(self.leftutxolist.unspent)
        unspentR = bool(self.rightutxolist.unspent)

        # Deal with actively refundable utxos
        if unspentL and self.tr1 <= 0:
            if unspentR:
                p = _("Party A STEAL phase.")
                if iamA:
                    return p, _("You may refund your coins and also steal counterparty coins.")
                else:
                    return p, _("WARNING: Party A can steal all the unspent coins! Refund your coins now!")
            p = _("Party A refund phase.")
            if iamA:
                return p, _("Refund your coins now.")
            else:
                if known_secret:
                    return p, _("Party A can refund these unspent coins! Redeem them now!")
                else:
                    return p, _("Party A can refund coins at any time.")
        # cont'd
        if unspentR and self.tr2 <= 0:
            p = _("Party B refund phase.")
            if iamA:
                if known_secret:
                    return p, _("Party B can refund the unspent coins at any time.")
                else:
                    return p, _("Avoid claiming unspent coins at this point to avoid a double-spend attack. Fall back to your refund period.")
            else:
                return p, _("Refund your coins now, to avoid stealing attack from party A.")

        # Now start dealing with some normal things.

        # Once secret is revealed we are committed to redeem.
        if known_secret:
            if unspentL:
                if unspentR:
                    p = _("PHASE 4: Party A/B redeem")
                    if iamA:
                        return p, _("Don't forget to redeem all the right-side coins too.")
                    else:
                        return p, _("Redeem the coins!")
                else:
                    p = _("PHASE 4: Party B redeem")
                    if iamA:
                        return p, _("You're done!")
                    else:
                        return p, _("Redeem the coins!")
            elif unspentR:
                p = _("PHASE 4: Party A redeem")
                if iamA:
                    return p, _("Don't forget to redeem all the right-side coins too.")
                else:
                    return p, _("You're done!")
            else:
                return _("PHASE 5: Complete"), _("You're done!")

        # below this point, secret is not yet revealed

        if unspentL:
            if unspentR:
                p = _("PHASE 3: Party A decision - redeem or refund")
                if iamA:
                    return p, _("You can redeem once there are sufficient confirmations, or delay until refund time.")
                else:
                    return p, _("Wait for Party A.")
            else:
                p = _("PHASE 2: Party B decision - funding or retreat")
                if iamA:
                    return p, _("Wait for Party B.")
                else:
                    return p, _("After sufficient confirmations on left contract funding, you can fund the right-side contract.")
        elif unspentR:
            p = _("Party B vulnerable!")
            if iamA:
                return p, _("You may freely take the unspent coins.")
            else:
                return p, _("Your funded coins can be freely taken by party A at any time! :-(")

        donotuse = _("Do not use this swap.")
        notrecommend = _("Not recommended to start using this swap.")
        if self.tr2 <= 0:
            return _("Refund period active."), donotuse
        if self.tr1 - self.tr2 < 3600:
            return _("Badly formed swap! Left contract should refund well after right contract."), donotuse
        if self.tr1 - self.tr2 > 86400:
            return _("Badly formed swap! Left contract refunds way too late (>24 h) after right contract."), notrecommend
        if self.tr2 < 3600:
            # No action yet and
            return _("Less than an hour to party B refund."), notrecommend

        if self.leftutxolist.coins or self.rightutxolist.coins:
            return _("Previously used addresses"), donotuse

        p = _("PHASE 1: Party A decision - funding or retreat")
        if iamA:
            return p, _("Send funds to the left contract to begin the swap process.")
        else:
            return p, _("Wait for party A to provide funds.")

    def redeem(self,):
        swapper = self.swapper
        utxolist = self.rightutxolist if swapper.i_am_party_A else self.leftutxolist
        privkey = swapper.privkey2 if swapper.i_am_party_A else swapper.privkey1

        secret = swapper.secret
        if not secret:
            self.show_error(_("Can't redeem: secret not yet known."))
            return

        t = _("Enter the address where you want to redeem these coins.")
        if swapper.i_am_party_A and not self.rightutxolist.spent:
            # contracts haven't been spent yet.
            t += '\n'
            t += _("The process of redeeming will reveal the secret value and allow the counterparty to claim your funding.\nDo not redeem until their funding transaction has been sufficiently confirmed.")

        self.mktx(utxolist, t, privkey, secret)

    def refund(self,):
        swapper = self.swapper
        utxolist = self.leftutxolist if swapper.i_am_party_A else self.rightutxolist
        privkey = swapper.privkey1 if swapper.i_am_party_A else swapper.privkey2

        t = _("Enter the address where you want to refund these coins.\nNote that the refund can only be broadcast and mined after the set refund time.")

        self.mktx(utxolist, t, privkey, None)

    def mktx(self, utxolist, dialog_str, privkey, secret):
        sc = utxolist.halfswapcon
        coins = utxolist.get_selected_coins()

        if not coins:
            self.show_error(_("No coins selected."))
            return

        t = '\n'.join(list(coins) + ['', dialog_str])
        while True:
            d = QInputDialog(parent=self)
            d.setLabelText(t)
            d.setWindowModality(Qt.WindowModal)
            d.exec_()
            if not d.result():
                return  # user cancelled
            try:
                addr = Address.from_string(d.textValue())
                break
            except Exception as e:
                self.show_error(_("Invalid address: ") + str(e))

        tx = sc.mktx(coins, addr, privkey, secret, self.config.estimate_fee)

        def callback(response):
            err = response.get('error')
            if err:
                try:
                    print_stderr("Transaction broadcast error", err['code'], err['message'])
                except:
                    print_stderr("Transaction broadcast error:", err)
            else:
                print_error("Transaction broadcast result:", response)  # --verbose only
        sc.network.broadcast_transaction(tx)

class SwapUTXOList(MyTreeWidget):
#    filter_columns = [0, 2]  # Address, Label
    net_signal = pyqtSignal()

    def __init__(self, parent, halfswapcon):
        MyTreeWidget.__init__(self, parent, self.create_menu, [ '', _('Amount'), _('Output point'), _('Spent')], 2)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.halfswapcon = halfswapcon
        self.setTextElideMode(Qt.ElideMiddle)

        self.setColumnWidth(0,10)
        self.setColumnWidth(3,10)

        self.statusIcons = {}

        self.net_signal.connect(self.update)
        self.update()

    def on_network(self, event, *args):
        self.net_signal.emit()

    def on_update(self):
        self.clear()
        self.coins, self.spent = self.halfswapcon.get_coins()
        self.unspent = self.coins.copy()
        for c in self.spent:
            self.unspent.pop(c)

        wallet = self.halfswapcon.wallet

        def conf_info(tx_hash):
            height, conf, timestamp = wallet.get_tx_height(tx_hash)
            status, status_str = wallet.get_tx_status(tx_hash, height, conf, timestamp)
            if status not in self.statusIcons:
                self.statusIcons[status] = QIcon(":icons/" + TX_ICONS[status])
            return self.statusIcons[status], status, conf

        for c, (height, v) in self.coins.items():
            amount = format_satoshis_plain_nofloat(v)
            item = SortableTreeWidgetItem(['',
                                         amount,
                                         c,
                                         ''])
            icon, status, conf = conf_info(c.split(':')[0])

            item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))
            item.setIcon(0, icon)
            item.setFont(1, QFont(MONOSPACE_FONT))
            item.setFont(2, QFont(MONOSPACE_FONT))
            item.setData(0, Qt.UserRole, c)

            tx_hash_spent = self.spent.get(c)
            item.setData(3, Qt.UserRole, tx_hash_spent)

            if tx_hash_spent:
                icon, status, conf = conf_info(tx_hash_spent)
                item.setIcon(3, icon)
                item.setToolTip(3, str(conf) + " confirmation" + ("s" if conf != 1 else ""))

            self.addTopLevelItem(item)

    def get_selected_coins(self,):
        selected = self.selectedItems()
        if not selected:
            return self.unspent
        coins = [item.data(0, Qt.UserRole) for item in selected]
        return {i : self.coins[i] for i in coins}

    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return

        coin = item.data(0, Qt.UserRole)
        #if not coin:
            #return

        column = self.currentColumn()
        if column is 0:
            column_title = "ID"
            column_data = coin
        else:
            column_title = self.headerItem().text(column)
            column_data = item.text(column)

        menu = QMenu()

        menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))

        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item, column):
        # disable editing fields in this tab (labels)
        return False
