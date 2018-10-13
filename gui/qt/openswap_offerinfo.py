from functools import partial

import math

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
from electroncash.util import format_satoshis_plain_nofloat, get_satoshis_nofloat

from .transaction_dialog import show_transaction

cryptos = [(b'BCH', 'BCH', 3000),
           (b'BTC', 'BTC', 3000)
           ]

crypto_list_by_bytes = [c[0] for c in cryptos]
crypto_list_by_str = [c[1] for c in cryptos]

def invert(x):
    """ Because python does not allow division by zero"""
    try:
        return 1./x
    except ZeroDivisionError:
        return math.copysign(math.inf, x)

class OfferInfoDialog(QDialog):
    price_sigfigs = 6  # how many significant figures to use in price calculations

    # Dialog for creating / editing / viewing OpenSwap offers
    def __init__(self, parent, offerinfo, mode="create"):
        QDialog.__init__(self, parent=parent)

        if mode == "create":
            self.editable = True
            cancel_text = _("Cancel")
            edit_text = None
            ok_text = _("Send")
            title = _("Create Offer")
        elif mode == "view":
            self.editable = False
            cancel_text = _("Close")
            edit_text = None
            ok_text = None
            title = _("Offer info")
        elif mode == "view_as_sender":
            self.editable = False
            cancel_text = _("Close")
            edit_text = _("Re-offer")
            ok_text = None
            title = _("Offer sent")
        elif mode == "view_as_recipient":
            self.editable = False
            cancel_text = _("Cancel")
            edit_text = _("Counter-offer")
            ok_text = _("Accept")
            title = _("Offer received")
        else:
            raise ValueError(mode)

#        self.setMinimumSize(610, 290)
        self.setWindowTitle(title)

        layout = QGridLayout(self)

        layout.addWidget(QLabel(_("Want")), 1, 0)
        hbox = QHBoxLayout()
        layout.addLayout(hbox, 1, 1)
        self.want_amount_e = QLineEdit()
        self.want_amount_e.textEdited.connect(self.amount_edited)
        hbox.addWidget(self.want_amount_e)
        self.want_crypto_cb = QComboBox()
        self.want_crypto_cb.addItems(crypto_list_by_str)
        hbox.addWidget(self.want_crypto_cb)
        self.want_price_cb = QCheckBox(_("by price"))
        self.want_price_cb.clicked.connect(partial(self.clicked_byprice, 1))
        hbox.addWidget(self.want_price_cb)
        if not self.editable:
            self.want_price_cb.setHidden(True)
            self.want_crypto_cb.setDisabled(True)
        hbox.addStretch(1)

        layout.addWidget(QLabel(_('Give')), 2, 0)
        hbox = QHBoxLayout()
        layout.addLayout(hbox, 2, 1)
        self.give_amount_e = QLineEdit()
        self.give_amount_e.textEdited.connect(self.amount_edited)
        hbox.addWidget(self.give_amount_e)
        self.give_crypto_cb = QComboBox()
        self.give_crypto_cb.addItems(crypto_list_by_str)
        hbox.addWidget(self.give_crypto_cb)
        self.give_price_cb = QCheckBox(_("by price"))
        self.give_price_cb.clicked.connect(partial(self.clicked_byprice, 2))
        hbox.addWidget(self.give_price_cb)
        if not self.editable:
            self.give_price_cb.setHidden(True)
            self.give_crypto_cb.setDisabled(True)
        hbox.addStretch(1)

        layout.addWidget(QLabel(_('Price')), 3,0)
        vbox = QVBoxLayout()
        layout.addLayout(vbox, 3, 1)
        hbox = QHBoxLayout()
        vbox.addLayout(hbox)
        hbox.addStretch(1)
        self.price1_e = QLineEdit()
        self.price1_e.textEdited.connect(partial(self.price_edited,1))
        hbox.addWidget(self.price1_e)
        self.price1_label = QLabel()
        hbox.addWidget(self.price1_label)
        hbox = QHBoxLayout()
        vbox.addLayout(hbox)
        hbox.addStretch(1)
        self.price2_e = QLineEdit()
        self.price2_e.textEdited.connect(partial(self.price_edited,2))
        hbox.addWidget(self.price2_e)
        self.price2_label = QLabel()
        hbox.addWidget(self.price2_label)

        layout.addWidget(QLabel(_('Refunds')), 4,0)
        hbox = QHBoxLayout()
        layout.addLayout(hbox, 4, 1)
        hbox.addStretch(1)
        self.refundtime_want_label = QLabel()
        hbox.addWidget(self.refundtime_want_label)
        hbox.addStretch(1)
        self.refundtime_give_label = QLabel()
        hbox.addWidget(self.refundtime_give_label)

        hbox = QHBoxLayout()
        layout.addLayout(hbox, 5, 1)

        hbox.addStretch(1)

        if cancel_text:
            b = QPushButton(cancel_text)
            b.clicked.connect(self.reject)
            hbox.addWidget(b)

        if edit_text:
            b = QPushButton(edit_text)
            b.clicked.connect(lambda:self.done(2))
            hbox.addWidget(b)

        if ok_text:
            b = QPushButton(ok_text)
            b.clicked.connect(self.accept)
            hbox.addWidget(b)

        self.primaryprice = 1

        self.read_from_offerinfo(offerinfo)
        self.update_cryptos()
        self.update_editable()
        self.update_constants()
        self.update_amounts()

        self.want_crypto_cb.currentIndexChanged[int].connect(self.update_cryptos)
        self.give_crypto_cb.currentIndexChanged[int].connect(self.update_cryptos)

        #self.give_price_cb.setDisabled(True)
        #self.want_price_cb.setDisabled(True)

    def get_offerinfo(self):
        """
        Calculate offer info from displayed values
        """
        offer = openswap.OfferInfo(
                    salt = self.salt,
                    want_rtime = self.want_rtime,
                    give_rtime = self.give_rtime,
                    want_amount = get_satoshis_nofloat(self.want_amount_e.text()),
                    want_ticker = crypto_list_by_bytes[self.want_crypto_cb.currentIndex()],
                    give_amount = get_satoshis_nofloat(self.give_amount_e.text()),
                    give_ticker = crypto_list_by_bytes[self.give_crypto_cb.currentIndex()],
                    )
        return offer

    def clicked_byprice(self, i, checked):
        if not checked:
            pass
        elif i == 1:
            self.give_price_cb.setChecked(False)  # make sure other is unchecked
            self.price1_e.setFocus(Qt.MouseFocusReason)
        elif i == 2:
            self.want_price_cb.setChecked(False)  # make sure other is unchecked
            self.price1_e.setFocus(Qt.MouseFocusReason)
        self.update_editable()

    def format_price(self, p):
        return '%.*g'%(self.price_sigfigs, p)

    def amount_edited(self, s):
        self.update_amounts()

    def price_edited(self, n, s):
        if n == 1:
            self.primaryprice = self.price1_e
        else:
            self.primaryprice = self.price2_e
        self.update_amounts()

    def update_amounts(self,):
        # Update the other two dependent amounts based on user-provided ones.
        # This uses floats.

        wbyprice = self.want_price_cb.isChecked()
        gbyprice = self.give_price_cb.isChecked()
        if wbyprice or gbyprice:
            if self.primaryprice is self.price1_e:
                try:
                    price = float(self.price1_e.text())
                    iprice = invert(price)
                except:
                    self.price2_e.setText('')
                    price = None
                else:
                    self.price2_e.setText(self.format_price(iprice))
            else:
                try:
                    iprice = float(self.price2_e.text())
                    price = invert(iprice)
                except:
                    self.price1_e.setText('')
                    price = None
                else:
                    self.price1_e.setText(self.format_price(price))
            if wbyprice:
                try:
                    a = price * 1e8 * float(self.give_amount_e.text())
                    self.want_amount_e.setText(format_satoshis_plain_nofloat(a))
                except:
                    self.want_amount_e.setText('')
            else:
                try:
                    a = iprice * 1e8 * float(self.want_amount_e.text())
                    self.give_amount_e.setText(format_satoshis_plain_nofloat(a))
                except:
                    self.give_amount_e.setText('')
        else:
            try:
                wa = float(self.want_amount_e.text())
                ga = float(self.give_amount_e.text())
            except:
                self.price1_e.setText('')
                self.price2_e.setText('')
            else:
                self.price1_e.setText(self.format_price(wa*invert(ga)))
                self.price2_e.setText(self.format_price(ga*invert(wa)))

    def update_editable(self,):
        """ Based on the state of 'by price' checkboxes, update read_only-ness
        """
        if not self.editable:
            self.give_amount_e.setReadOnly(True)
            self.want_amount_e.setReadOnly(True)
            self.price1_e.setReadOnly(True)
            self.price2_e.setReadOnly(True)
        elif self.give_price_cb.isChecked():
            self.give_amount_e.setReadOnly(True)
            self.want_amount_e.setReadOnly(False)
            self.price1_e.setReadOnly(False)
            self.price2_e.setReadOnly(False)
        elif self.want_price_cb.isChecked():
            self.give_amount_e.setReadOnly(False)
            self.want_amount_e.setReadOnly(True)
            self.price1_e.setReadOnly(False)
            self.price2_e.setReadOnly(False)
        else:
            self.give_amount_e.setReadOnly(False)
            self.want_amount_e.setReadOnly(False)
            self.price1_e.setReadOnly(True)
            self.price2_e.setReadOnly(True)

    def update_cryptos(self,):
        tick1 = self.want_crypto_cb.currentText()
        tick2 = self.give_crypto_cb.currentText()
        self.price1_label.setText(tick1 + '/' + tick2)
        self.price2_label.setText(tick2 + '/' + tick1)

    def update_constants(self,):
        """update salt, refund time displays"""
        import time
        now = time.time()

        ci = self.want_crypto_cb.currentIndex()
        rtime_est = round((self.want_rtime + cryptos[ci][2] - now) / 3600.)
        self.refundtime_want_label.setText(_('Want \u2248 %+d hours')%(rtime_est))
        self.refundtime_want_label.setToolTip('MTP'+str(self.want_rtime))

        ci = self.give_crypto_cb.currentIndex()
        rtime_est = round((self.give_rtime + cryptos[ci][2] - now) / 3600.)
        self.refundtime_give_label.setText(_('Give \u2248 %+d hours')%(rtime_est))
        self.refundtime_give_label.setToolTip('MTP'+str(self.give_rtime))

    def read_from_offerinfo(self, offerinfo):
        tick1 = offerinfo.want_ticker
        tick2 = offerinfo.give_ticker
        self.want_crypto_cb.setCurrentIndex(crypto_list_by_bytes.index(tick1))
        self.give_crypto_cb.setCurrentIndex(crypto_list_by_bytes.index(tick2))
        if offerinfo.want_amount is not None:
            self.want_amount_e.setText(format_satoshis_plain_nofloat(offerinfo.want_amount))
        if offerinfo.give_amount is not None:
            self.give_amount_e.setText(format_satoshis_plain_nofloat(offerinfo.give_amount))
        self.want_rtime = offerinfo.want_rtime
        self.give_rtime = offerinfo.give_rtime
        self.salt = offerinfo.salt
