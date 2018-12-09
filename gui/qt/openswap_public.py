"""
OpenSwap main public messaging
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

from .openswap_offerinfo import OfferInfoDialog

from electroncash.util import format_satoshis_plain_nofloat, get_satoshis_nofloat

from electroncash.openswap import cryptos, crypto_list_by_bytes, crypto_list_by_str
from .openswap_priceinfo import PriceInfoBox


dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def prompt_dialog(main_window, c1, c2, pmw=None):
    # Make a selector dialog then use it to start up the public channel
    #
    tb1 = crypto_list_by_bytes[c1]
    tb2 = crypto_list_by_bytes[c2]
    if tb1 > tb2:
        # make sure they are ordered properly
        c1, c2, tb1, tb2 = c2, c1, tb2, tb1
    channame = "OpenSwap Offers %s %s"%(tb1.hex(), tb2.hex())
    channel = bchmessage.Channel.from_name(channame)
    network = main_window.network
    cmw = bchmessage.ChanMessageWatcher(network, channel)

    show_dialog(main_window, cmw, c1, c2, pmw=pmw)

def show_dialog(*args, **kwargs):
    d = OpenSwapPublicDialog(*args, **kwargs)
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

class OpenSwapPublicDialog(QDialog, MessageBoxMixin):
    gotDecryptSig = pyqtSignal(str)

    def __init__(self, main_window, cmw, c1, c2, pmw=None):
        # cmw - ChanMessageWatcher
        # c1, c2 - indices of cryptos 1 and 2
        # pmw - optional PrivMessageWatcher to write messages (if None, just view)
        # top level window
        QDialog.__init__(self, parent=None)
        self.cmw = cmw
        self.c1 = c1
        self.c2 = c2
        self.pmw = pmw
        self.address = self.cmw.address
        self.channel = self.cmw.channel

        self.wallet = cmw.wallet

        self.main_window = main_window
        self.config = main_window.config
        self.app = main_window.app

        self.n1 = crypto_list_by_str[self.c1]
        self.n2 = crypto_list_by_str[self.c2]
        self.b1 = crypto_list_by_bytes[self.c1]
        self.b2 = crypto_list_by_bytes[self.c2]
        self.setWindowTitle(_("OpenSwap advertisements") + " %s \u2014 %s"%(self.n1, self.n2))

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        try:
            vbox.addWidget(QLabel(_("Channel name") + ': ' + repr(self.channel.name)))
        except:
            pass
        vbox.addWidget(QLabel(_("Key") + ': ' + self.channel.chankey.hex()))
        l = QLabel(_("Address") + ': ' + self.address.to_ui_string())
        vbox.addWidget(l)
        l.setTextInteractionFlags(Qt.TextSelectableByMouse)

        vbox.addWidget(QLabel(_("History")))
        self.hw = MyHistoryList(self)
        vbox.addWidget(self.hw)

        hbox = QHBoxLayout()

        #b = QPushButton(_("Write"))
        #b.clicked.connect(lambda: self.write_message())
        #hbox.addWidget(b)

        b = QPushButton(_("Offer") + " " + self.n1)
        b.clicked.connect(lambda: self.make_public_offer(self.c2, self.c1))
        if not self.pmw:
            b.setDisabled(True)
        hbox.addWidget(b)

        b = QPushButton(_("Offer") + " " + self.n2)
        b.clicked.connect(lambda: self.make_public_offer(self.c1, self.c2))
        if not self.pmw:
            b.setDisabled(True)
        hbox.addWidget(b)

        hbox.addStretch(1)

        hbox.addWidget(CloseButton(self))

        vbox.addLayout(hbox)

        self.show()

        self.gotDecryptSig.connect(self.hw.got_decrypted)

        def on_success(result):
            self.network = cmw.network
            cmw.callbacks_decrypted.append(self.gotDecryptSig.emit)
            self.hw.update()

        d = WaitingDialog(self, _('Opening...'), cmw.start,
                          on_success, None)

    def closeEvent(self, event):
        event.accept()
        try:
            dialogs.remove(self)
        except ValueError:
            pass
        self.cmw.stop()

    def reject(self,):
        self.close()

    def get_domain(self):
        return [self.address]

    def broadcast_tx(self, tx):
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
            self.network.broadcast_transaction(tx.serialize(), callback=callback)
            return True
        except Exception as e:
            self.show_error("Error: %s"%(str(e)))
        return False

    def make_public_offer(self, c1, c2):
        d = QDialog(self)
        d.setWindowTitle(_("Make Public Offer"))

        wallet = self.pmw.wallet
        key = self.pmw.key
        mypubkey = key.pubkey

        layout = QVBoxLayout()
        d.setLayout(layout)

        pi = PriceInfoBox(self, True)
        pi.want_crypto_cb.setCurrentIndex(c1)
        pi.want_crypto_cb.setDisabled(True)
        pi.give_crypto_cb.setCurrentIndex(c2)
        pi.give_crypto_cb.setDisabled(True)
        layout.addWidget(pi)

        hbox = QHBoxLayout()
        layout.addLayout(hbox)

        hbox.addStretch(1)

        b = QPushButton(_("Cancel"))
        b.clicked.connect(d.reject)
        hbox.addWidget(b)

        b = QPushButton(_("Send"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)

        d.setWindowModality(Qt.WindowModal)

        if not d.exec_():
            return
        try:
            amtw = get_satoshis_nofloat(pi.want_amount_e.text())
            amtg = get_satoshis_nofloat(pi.give_amount_e.text())
        except Exception as e:
            self.show_error(_("Cannot parse amount:") + str(e))

        if c1 == self.c1 and c2 == self.c2:
            msgbytes = b'\x00\x00' + amtw.to_bytes(8,'big') + amtg.to_bytes(8,'big')
        elif c1 == self.c2 and c2 == self.c1:
            msgbytes = b'\x00\x01' + amtg.to_bytes(8,'big') + amtw.to_bytes(8,'big')
        data = self.channel.auth_encrypt(msgbytes, mypubkey)

        try:
            tx = key.create_message(wallet, self.channel.address, data, self.config)
            self.broadcast_tx(tx)
        except bchmessage.NotEnoughFunds:
            self.show_error("Not enough funds on this address.")

    def make_private_offer(self, dest_pubkey, order_12, amtw, amtg):
        # Used for start of negotiation
        wallet = self.pmw.wallet
        key = self.pmw.key

        now = int(time.time())
        offer = openswap.OfferInfo(
                salt = token_bytes(8),
                want_rtime = now + 10*3600,
                give_rtime = now + 5*3600,
                want_amount = amtg,
                want_ticker = self.b1 if order_12 else self.b2,
                give_amount = amtw,
                give_ticker = self.b2 if order_12 else self.b1,
                )
        d = OfferInfoDialog(self, offer, dest_pubkey, mode='create')
        res = d.exec_()
        if res:
            try:
                offerinfo = d.get_offerinfo()
                pak = openswap.PacketOffer.make(key.privkey, dest_pubkey, offerinfo)
                offermsg = openswap.OpenSwapMessage([pak], autopad=204)
                messagebytes = offermsg.to_bytes()

                data = key.encrypt_private_message(messagebytes, dest_pubkey)
                tx = key.create_message(wallet, Address.from_pubkey(dest_pubkey), data, self.config)
                self.broadcast_tx(tx)
            except bchmessage.NotEnoughFunds:
                self.show_error("Not enough funds on this address.")
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.show_error(str(e))

class MyHistoryList(MyTreeWidget):
#    filter_columns = [2, 3, 4]  # Date, Description, Amount

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu,
                              ['', _('Date'), _('From'), _('Data') ],
                              3, [])
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
        current_tx = item.data(0, Qt.UserRole) if item else None
        self.clear()

        cmw = self.parent.cmw
        wallet = self.wallet
        chanaddress = cmw.address
        pmw = self.parent.pmw
        if pmw:
            mypubkey = pmw.key.pubkey
        else:
            mypubkey = None

        # internal function to be called within loop below
        def putitem(i, datastr):
            item = SortableTreeWidgetItem([
                '',
                status_str,
                'me' if from_me else from_pubkey[-3:].hex(),
                datastr,
                ])

            if status not in self.statusIcons:
                self.statusIcons[status] = QIcon(":icons/" + TX_ICONS[status])
            icon = self.statusIcons[status]
            item.setIcon(0, icon)
            item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))

            item.setData(0, Qt.UserRole, tx_hash)
            item.setData(1, Qt.UserRole, from_pubkey)
            item.setToolTip(3, '<p>%s</p>'%(escape(datastr),))
            self.insertTopLevelItem(0, item)
            if current_tx == tx_hash:
                self.setCurrentItem(item)
            return item

        for tx_hash, height in wallet.get_address_history(chanaddress):
            info = cmw.messageinfo.get(tx_hash)
            if not info:
                continue
            height, conf, timestamp = wallet.get_tx_height(tx_hash)
            status, status_str = wallet.get_tx_status(tx_hash, height, conf, timestamp)

            from_pubkey = info['src']
            from_me = (from_pubkey == mypubkey)

            if info['status'] == 'processing':
                # tx needs to be verified
                putitem(0, 'verifying')
                continue

            messagebytes = info.get('message')

            if messagebytes is None:
                putitem(0, '?')
                continue

            try:
                tag = messagebytes[:2]
                assert len(messagebytes) == 18
                if tag == b'\0\0':
                    amtw = int.from_bytes(messagebytes[2:10], 'big')
                    amtg = int.from_bytes(messagebytes[10:18], 'big')
                    nw = self.parent.n1
                    ng = self.parent.n2
                    data = (False, amtw, amtg)
                elif tag == b'\0\1':
                    amtg = int.from_bytes(messagebytes[2:10], 'big')
                    amtw = int.from_bytes(messagebytes[10:18], 'big')
                    ng = self.parent.n1
                    nw = self.parent.n2
                    data = (True, amtw, amtg)
                item = putitem(0, 'Wants %s %s for %s %s'%(format_satoshis_plain_nofloat(amtw), nw,
                                                           format_satoshis_plain_nofloat(amtg), ng,
                                                           ))
                item.setData(3, Qt.UserRole, data)
            except:
                item = putitem(0, 'raw:' + messagebytes.hex())

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            super().on_doubleclick(item, column)
        else:
            tx_hash = item.data(0, Qt.UserRole)
            tx = self.wallet.transactions.get(tx_hash)
            self.parent.main_window.show_transaction(tx)

    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return

        tx_hash = item.data(0, Qt.UserRole)
        if not tx_hash:
            return
        column = self.currentColumn()
        if column is 0:
            column_title = "ID"
            column_data = tx_hash
        else:
            column_title = self.headerItem().text(column)
            column_data = item.text(column)

        pmw = self.parent.pmw
        if pmw:
            mypubkey = pmw.key.pubkey
        else:
            mypubkey = None

        from_pubkey = item.data(1, Qt.UserRole)
        from_me = (from_pubkey == mypubkey)

        oinfo = item.data(3, Qt.UserRole)

        menu = QMenu()

        if not (from_me or oinfo is None):
            menu.addAction(_("Negotiate"), lambda: self.parent.make_private_offer(from_pubkey, *oinfo))

        menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))

        def showtx():
            tx = self.wallet.transactions.get(tx_hash)
            self.parent.main_window.show_transaction(tx)
        menu.addAction(_("View Tx"), showtx)

        menu.exec_(self.viewport().mapToGlobal(position))
