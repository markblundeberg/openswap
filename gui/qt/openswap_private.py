"""
OpenSwap main private messaging -- all messages
"""

import time
from html import escape

try:
    # python 3.6 +
    from secrets import token_bytes
except ImportError:
    from os import urandom as token_bytes

from electroncash.i18n import _
from electroncash.address import Address
import electroncash.web as web

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from .util import *
from .qrtextedit import ShowQRTextEdit

from electroncash import bchmessage
from electroncash import openswap
from electroncash.util import print_error

from .transaction_dialog import show_transaction

from .openswap_offerinfo import OfferInfoDialog

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_dialog(main_window, key):
    d = OpenSwapDialog(main_window, key)
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

class OpenSwapDialog(QDialog, MessageBoxMixin):
    gotDecryptSig = pyqtSignal(str)

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

        self.setWindowTitle(_("OpenSwap Private Messages"))

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Address") + ': ' + self.address.to_ui_string()))

        vbox.addWidget(QLabel(_("Public key") + ':'))
        pubkey_e = ButtonsLineEdit(pubkey)
        pubkey_e.setReadOnly(True)
        pubkey_e.addCopyButton(self.app)
        vbox.addWidget(pubkey_e)

        vbox.addWidget(QLabel(_("History")))
        self.hw = MyHistoryList(self)
        vbox.addWidget(self.hw)

        hbox = QHBoxLayout()

        b = QPushButton(_("Write"))
        b.clicked.connect(lambda: self.write_message())
        hbox.addWidget(b)

        b = QPushButton(_("Offer"))
        b.clicked.connect(lambda: self.make_offer())
        hbox.addWidget(b)

        hbox.addStretch(1)

        hbox.addWidget(CloseButton(self))

        vbox.addLayout(hbox)

        self.show()

        self.gotDecryptSig.connect(self.hw.got_decrypted)

        def on_success(result):
            pmw.callbacks_decrypted.append(self.gotDecryptSig.emit)
            self.hw.update()

        d = WaitingDialog(self, _('Opening...'), pmw.start,
                          on_success, None)

    def closeEvent(self, event):
        event.accept()
        try:
            dialogs.remove(self)
        except ValueError:
            pass
        self.pmw.stop()

    def reject(self,):
        self.close()

    def get_domain(self):
        return [self.address]

    def write_message(self, to_pubkey=''):
        d = WindowModalDialog(self, _('Write New BCHMessage'))
        d.setMinimumSize(700, 290)

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

        def send():
            try:
                messagebytes = message_e.toPlainText().encode('utf8')
            except Exception as e:
                self.show_error("Unable to encode message.")
                return

            try:
                dest_pubkey = bytes.fromhex(address_e.text())
                _ = bchmessage.ser_to_point(dest_pubkey)  # attempt to
            except Exception as e:
                self.show_error("Invalid pubkey.")
                return

            if len(messagebytes) > 220:
                self.show_warning("Message bytesize (%d) is over 220, unlikely to broadcast."%(len(messagebytes)))
                pass

            if self.broadcast_message(dest_pubkey, messagebytes):
                d.accept()

        b = QPushButton(_("Send"))
        b.clicked.connect(send)
        hbox.addWidget(b)

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)
        layout.addLayout(hbox, 3, 1)

        d.exec_()

    def broadcast_message(self, dest_pubkey, messagebytes):
        def callback(response):
            err = response.get('error')
            if err:
                try:
                    print_stderr("Transaction broadcast error", err['code'], err['message'])
                except:
                    print_stderr("Transaction broadcast error:", err)
            else:
                print_error("Transaction broadcast result:", response)  # --verbose only

        try:
            tx = self.key.create_private_message(self.wallet, dest_pubkey, messagebytes, self.config)
            self.network.broadcast_transaction(tx.serialize(), callback=callback)
            return True
        except bchmessage.NotEnoughFunds:
            self.show_error("Not enough funds on this address.")
        except Exception as e:
            self.show_error("Error: %s"%(str(e)))
        return False

    def make_offer(self, other_pubkey=None, offer=None):
        now = int(time.time())
        if not other_pubkey:
            d = QInputDialog(parent=self)
            d.setWindowModality(Qt.WindowModal) # don't freeze all windows
            d.setLabelText(_("Counterparty pubkey"))
#            d.setTextValue()
            d.exec_()
            if not d.result():
                return  # user cancelled
            other_pubkey = bytes.fromhex(d.textValue())

        if not offer:
            offer = openswap.OfferInfo(
                    salt = token_bytes(8),
                    want_rtime = now + 10*3600,
                    give_rtime = now + 5*3600,
                    want_amount = None,
                    want_ticker = b'BCH',
                    give_amount = None,
                    give_ticker = b'BTC',
                    )
        d = OfferInfoDialog(self, offer, mode='create')

        res = d.exec_()
        if res:
            try:
                offerinfo = d.get_offerinfo()
                pak = openswap.PacketOffer.make(self.key.privkey, other_pubkey, offerinfo)
                offermsg = openswap.OpenSwapMessage([pak], autopad=204)
                messagebytes = offermsg.to_bytes()
                self.broadcast_message(other_pubkey, messagebytes)
            except Exception as e:
                self.show_error(str(e))

    def view_offer_as_sender(self, other_pubkey, packet):
        d = OfferInfoDialog(self, packet.offer_info, mode='view_as_sender')
        res = d.exec_()
        if res == 2:  # edit
            now = int(time.time())
            # make new offer_info with new salt and new time
            offer = d.get_offerinfo()._replace(
                    salt = token_bytes(8),
                    want_rtime = now + 10*3600,
                    give_rtime = now + 5*3600,
                    )
            self.make_offer(other_pubkey, offer)

    def view_offer_as_recipient(self, other_pubkey, packet):
        d = OfferInfoDialog(self, packet.offer_info, mode='view_as_recipient')
        res = d.exec_()
        if res == 1:  # accept
            offerinfo = d.get_offerinfo()
            accept_packet = openswap.PacketAccept.make(self.key.privkey, other_pubkey, offerinfo)
            offermsg = openswap.OpenSwapMessage([accept_packet], autopad=204)
            messagebytes = offermsg.to_bytes()
            if self.broadcast_message(other_pubkey, messagebytes):
                self.start_swap(True, other_pubkey, packet, accept_packet)
        elif res == 2:  # edit
            oo = d.get_offerinfo()
            # make new offer_info with swapped want/give and new salt.
            now = int(time.time())
            offer = openswap.OfferInfo(
                    salt = token_bytes(8),
                    want_rtime = now + 10*3600,
                    give_rtime = now + 5*3600,
                    want_amount = oo.give_amount,
                    want_ticker = oo.give_ticker,
                    give_amount = oo.want_amount,
                    give_ticker = oo.want_ticker,
                    )
            self.make_offer(other_pubkey, offer)

    def start_swap(self, accept_from_me, other_pubkey, offer_packet, accept_packet):
        network1 = self.network # should be based on offer_info.want_ticker
        network2 = self.network # should be based on offer_info.give_ticker

        swapper = openswap.AtomicSwap.from_packets(self.key.privkey, other_pubkey,
                                                   offer_packet, accept_packet, accept_from_me,
                                                   network1, network2)

        from .openswap_swapping import show_dialog
        show_dialog(self.app, self.config, swapper)

class MyHistoryList(MyTreeWidget):
#    filter_columns = [2, 3, 4]  # Date, Description, Amount

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu,
                              ['', _('From'), _('To'), _('Type'), _('Data') ],
                              4, [])
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.AscendingOrder)

        self.monospaceFont = QFont(MONOSPACE_FONT)
        self.statusIcons = {}
        self.wallet = parent.wallet
        self.incoming_offers = {}  # saved incoming offer packets

    def got_decrypted(self, tx_hash):
        self.update()

    def on_update(self):
        item = self.currentItem()
        current_tx, current_i = item.data(0, Qt.UserRole) if item else (None, None)
        self.clear()

        wallet = self.parent.wallet
        pmw = self.parent.pmw
        key = self.parent.key
        mypubkey  = key.pubkey
        myaddress = key.address

        # internal function to be called within loop below
        def putitem(i, typ, datastr):
            if to_me:
                to_str = 'me'
            elif to_pubkey:
                to_str = to_pubkey[-3:].hex()
            else:
                to_str = 'unk'
            item = SortableTreeWidgetItem([
                '',
                'me' if from_me else from_pubkey[-3:].hex(),
                to_str,
                typ,
                datastr,
                ])

            if status not in self.statusIcons:
                self.statusIcons[status] = QIcon(":icons/" + TX_ICONS[status])
            icon = self.statusIcons[status]
            item.setIcon(0, icon)
            item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))

            item.setData(0, Qt.UserRole, (tx_hash, i))
            item.setData(1, Qt.UserRole, from_pubkey)
            item.setData(2, Qt.UserRole, to_pubkey)
            item.setToolTip(4, '<p>%s</p>'%(escape(datastr),))
            self.insertTopLevelItem(0, item)
            if current_tx == tx_hash and current_i == i:
                self.setCurrentItem(item)
            return item


        messages = []
        for tx_hash, height in wallet.get_address_history(myaddress):
            info = pmw.messageinfo.get(tx_hash)
            if not info:
                continue
            height, conf, timestamp = wallet.get_tx_height(tx_hash)
            status, status_str = wallet.get_tx_status(tx_hash, height, conf, timestamp)

            from_pubkey = info['src']
            dest_addr = info['dst']
            from_me = (from_pubkey == mypubkey)
            to_me   = (dest_addr == myaddress)

            if to_me:
                to_pubkey = mypubkey
            else:
                to_pubkey = pmw.known_pubkeys.get(dest_addr)

            if info['status'] == 'processing':
                # tx needs to be verified
                putitem(0, '-', 'verifying')
                continue

            messagebytes = info.get('message')

            if messagebytes is None:
                putitem(0, '?', '')
                continue

            try:
                osm = openswap.OpenSwapMessage.from_bytes(messagebytes)
            except:
                try:
                    message = repr(messagebytes.decode('utf8'))
                except:
                    message = messagebytes.hex()
                putitem(0, 'raw', message)
                continue
            for i,pak in enumerate(osm.packets):
                if isinstance(pak, openswap.PacketPad): # skip padding
                    continue
                if isinstance(pak, openswap.PacketOffer) and not from_me:
                    # save incoming offer packets
                    self.incoming_offers[(from_pubkey, pak.offer_info)] = pak
                try:
                    datastr = pak.to_ui_string()
                except Exception as e:
                    print(e)
                    datastr = str(pak)
                item = putitem(i, 'OS', datastr)
                item.setData(4, Qt.UserRole, pak)

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            super().on_doubleclick(item, column)
        else:
            tx_hash, i = item.data(0, Qt.UserRole)
            tx = self.wallet.transactions.get(tx_hash)
            self.parent.parent.show_transaction(tx)

    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return

        tx_hash, i = item.data(0, Qt.UserRole)
        if not tx_hash:
            return
        column = self.currentColumn()
        if column is 0:
            column_title = "ID"
            column_data = tx_hash
        else:
            column_title = self.headerItem().text(column)
            column_data = item.text(column)

        key = self.parent.key
        mypubkey  = key.pubkey

        from_pubkey = item.data(1, Qt.UserRole)
        to_pubkey = item.data(2, Qt.UserRole)
        from_me = (from_pubkey == mypubkey)
        to_me   = (to_pubkey == mypubkey)

        if from_me:
            other_pubkey = to_pubkey
        else:
            other_pubkey = from_pubkey
        packet = item.data(4, Qt.UserRole)

        menu = QMenu()

        if isinstance(packet, openswap.PacketOffer):
            if from_me:
                menu.addAction(_("View/Re-offer"), lambda: self.parent.view_offer_as_sender(to_pubkey, packet))
            else:
                menu.addAction(_("View/Counter-offer/Accept"), lambda: self.parent.view_offer_as_recipient(from_pubkey, packet))


        if isinstance(packet, openswap.PacketAccept):
            if from_me:
                offerpacket = self.incoming_offers.get((to_pubkey, packet.offer_info))
            else:
                offerpacket = None
            act = menu.addAction(_("Atomic Swap"), lambda: self.parent.start_swap(from_me, other_pubkey, offerpacket, packet))
            if from_me and not offerpacket:
                # If we have accepted other party's offer but we don't have their
                # offer packet, then we can't do a swap as the keys are not
                # available!
                act.setEnabled(False)

        if to_me:
            menu.addAction(_("Reply raw message"), lambda: self.parent.write_message(from_pubkey.hex()))
        elif to_pubkey:
            menu.addAction(_("Write another message"), lambda: self.parent.write_message(to_pubkey.hex()))

        menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.parent.app.clipboard().setText(column_data))

        def showtx():
            tx = self.wallet.transactions.get(tx_hash)
            self.parent.parent.show_transaction(tx)
        menu.addAction(_("View Tx"), showtx)

        menu.exec_(self.viewport().mapToGlobal(position))
