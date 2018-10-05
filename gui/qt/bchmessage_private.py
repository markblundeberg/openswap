
from electroncash.i18n import _
from electroncash.address import Address
import electroncash.web as web

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from .util import *
from .qrtextedit import ShowQRTextEdit

from electroncash import bchmessage

from .transaction_dialog import show_transaction

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_dialog(main_window, key):
    d = BCHMessageDialog(main_window, key)
    dialogs.append(d)
    d.show()

#class BCHMessagePrepare(WindowModalDialog):


class BCHMessageDialog(QDialog):
    gotDecrypt = pyqtSignal(str)

    def __init__(self, parent, pmw):
        # top level window
        QDialog.__init__(self, parent=None)
        self.pmw = pmw
        self.key = pmw.key
        self.address = self.key.address
        pubkey = self.key.pubkey.hex()

        self.parent = parent
        self.config = parent.config
        self.wallet = parent.wallet
        self.network = parent.network
        self.app = parent.app
        self.saved = True

        self.setWindowTitle(_("BCHMessage Private"))

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Address:")))
        self.addr_e = ButtonsLineEdit()
        self.addr_e.addCopyButton(self.app)
        icon = ":icons/qrcode_white.png" if ColorScheme.dark_scheme else ":icons/qrcode.png"
        self.addr_e.addButton(icon, self.show_qr, _("Show QR Code"))
        self.addr_e.setReadOnly(True)
        self.parent.cashaddr_toggled_signal.connect(self.update_addr)
        vbox.addWidget(self.addr_e)
        self.update_addr()

        vbox.addWidget(QLabel(_("Public key") + ':'))
        pubkey_e = ButtonsLineEdit(pubkey)
        pubkey_e.addCopyButton(self.app)
        vbox.addWidget(pubkey_e)

        vbox.addWidget(QLabel(_("History")))
        self.hw = BMHistoryList(self)
        vbox.addWidget(self.hw)

        hbox = QHBoxLayout()

        b = QPushButton(_("Write"))
        b.clicked.connect(lambda: self.write_message())
        hbox.addWidget(b)

        hbox.addStretch(1)

        hbox.addWidget(CloseButton(self))

        vbox.addLayout(hbox)

        self.show()

        self.gotDecrypt.connect(self.hw.got_decrypted)

        def on_success(result):
            pmw.callbacks_decrypted.append(self.gotDecrypt.emit)
            self.hw.update()

        d = WaitingDialog(self, _('Opening...'), pmw.start,
                          on_success, None)
        d.show()

    def update_addr(self):
        self.addr_e.setText(self.address.to_full_ui_string())

    def get_domain(self):
        return [self.address]

    def show_qr(self):
        text = self.address.to_ui_string()
        try:
            self.parent.show_qrcode(text, 'Address', parent=self)
        except Exception as e:
            self.show_message(str(e))

    def write_message(self, to_pubkey=''):
        d = WindowModalDialog(self, _('Write New BCHMessage'))
        d.setMinimumSize(610, 290)

        layout = QGridLayout(d)

        message_e = QTextEdit()
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2,3)

        address_e = QLineEdit()
        layout.addWidget(QLabel(_('Recipient pubkey')), 2, 0)
        layout.addWidget(address_e, 2, 1)
        address_e.setText(to_pubkey)

        hbox = QHBoxLayout()

        def prev():
            dest_pubkey = bytes.fromhex(address_e.text())
            messagebytes = message_e.toPlainText().encode('utf8')
            tx = self.key.create_private_message(self.wallet, dest_pubkey, messagebytes, self.config, fee=None)
            show_transaction(tx, self.parent)
            d.accept()

        b = QPushButton(_("Preview"))
        b.clicked.connect(prev)
        hbox.addWidget(b)

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)
        layout.addLayout(hbox, 3, 1)

        d.exec_()



class BMHistoryList(MyTreeWidget):
    filter_columns = [2, 3, 4]  # Date, Description, Amount

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 3)
        self.address = parent.key.address

        self.refresh_headers()
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.AscendingOrder)

        self.monospaceFont = QFont(MONOSPACE_FONT)
        self.invoiceIcon = QIcon(":icons/seal")
        self.statusIcons = {}

    def refresh_headers(self):
        headers = [_('Height'), _('Who'), _('Message') ]
        self.update_headers(headers)

    def got_decrypted(self, tx_hash):
        self.update()

    def on_update(self):
        item = self.currentItem()
        current_tx = item.data(0, Qt.UserRole) if item else None
        self.clear()

        self.wallet = self.parent.wallet
        pmw = self.parent.pmw
        key = self.parent.key
        mypubkey  = key.pubkey
        myaddress = self.address

        # first iteration - parse txes and gather pubkeys
        messages = []
        for tx_hash, height in self.wallet.get_address_history(myaddress):
            info = pmw.messageinfo.get(tx_hash)
            if not info:
                continue
            s = info['src']
            d = info['dst']
            if info['status'] == 'processing':
                messagebytes = b'processing'
            else:
                messagebytes = info.get('message')
            # Figure out message sender/recipient
            from_me = (s == mypubkey)
            to_me   = (d == myaddress)
            if from_me and to_me:
                # this is fine.
                who = "self"
                otherpubkey = mypubkey
            elif from_me:
                otherpubkey = pmw.known_pubkeys.get(d, None)
                if otherpubkey:
                    who = "X\u2190"
                else:
                    who = "?\u2190"
            elif to_me:
                who = "X\u2192"
                otherpubkey = s
            else:
                # this can happen for example if we are output=2
#                otherpubkey = None
                continue

            if messagebytes:
                try:
                    message = repr(messagebytes.decode('utf8'))
                except:
                    message = messagebytes.hex()
            else:
                message = "???"

            entry = [str(height), who, message]
            item = SortableTreeWidgetItem(entry)
#            item.setIcon(0, icon)
#            item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))
#            item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            item.setData(0, Qt.UserRole, tx_hash)
            item.setData(1, Qt.UserRole, otherpubkey)
            self.insertTopLevelItem(0, item)
            if current_tx == tx_hash:
                self.setCurrentItem(item)

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            super().on_doubleclick(item, column)
        else:
            tx_hash = item.data(0, Qt.UserRole)
            tx = self.wallet.transactions.get(tx_hash)
            self.parent.parent.show_transaction(tx)

    def update_item(self, tx_hash, height, conf, timestamp):
        status, status_str = self.wallet.get_tx_status(tx_hash, height, conf, timestamp)
        icon = QIcon(":icons/" +  TX_ICONS[status])
        items = self.findItems(tx_hash, Qt.UserRole|Qt.MatchContains|Qt.MatchRecursive, column=1)
        if items:
            item = items[0]
            item.setIcon(0, icon)
            item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            item.setText(2, status_str)

    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return
        column = self.currentColumn()
        tx_hash = item.data(0, Qt.UserRole)
        if not tx_hash:
            return
        if column is 0:
            column_title = "ID"
            column_data = tx_hash
        else:
            column_title = self.headerItem().text(column)
            column_data = item.text(column)

        tx_URL = web.BE_URL(self.config, 'tx', tx_hash)
        height, conf, timestamp = self.wallet.get_tx_height(tx_hash)
        tx = self.wallet.transactions.get(tx_hash)

        otherpubkey = item.data(1, Qt.UserRole)

        menu = QMenu()

        if otherpubkey:
            menu.addAction(_("Reply"), lambda: self.parent.write_message(otherpubkey.hex()))

        menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.parent.app.clipboard().setText(column_data))
        if column in self.editable_columns:
            # We grab a fresh reference to the current item, as it has been deleted in a reported issue.
            menu.addAction(_("Edit {}").format(column_title),
                lambda: self.currentItem() and self.editItem(self.currentItem(), column))

        menu.addAction(_("Details"), lambda: self.parent.parent.show_transaction(tx))
        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: webbrowser.open(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))
