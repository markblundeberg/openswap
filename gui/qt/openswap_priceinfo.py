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

from electroncash.openswap import cryptos, crypto_list_by_bytes, crypto_list_by_str

def invert(x):
    """ Because python does not allow division by zero"""
    try:
        return 1./x
    except ZeroDivisionError:
        return math.copysign(math.inf, x)

class PriceInfoBox(QGroupBox):
    # how many significant figures to use in price calculations
    # cryptocurrency amounts always use full precision
    price_sigfigs = 6

    # Dialog for creating / editing / viewing OpenSwap offers
    def __init__(self, parent, editable=True):
        self.parent = parent
        self.editable = bool(editable)

        QGroupBox.__init__(self, _("Pricing"), parent=parent)

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

        self.primaryprice = self.price1_e

        self.update_cryptos()
        self.update_editable()
        self.update_amounts()

        self.want_crypto_cb.currentIndexChanged[int].connect(self.update_cryptos)
        self.give_crypto_cb.currentIndexChanged[int].connect(self.update_cryptos)

    def clicked_byprice(self, i, checked):
        if not checked:
            pass
        elif i == 1:
            self.give_price_cb.setChecked(False)  # make sure other is unchecked
            self.price1_e.setFocus(Qt.MouseFocusReason)
        elif i == 2:
            self.want_price_cb.setChecked(False)  # make sure other is unchecked
            self.price1_e.setFocus(Qt.MouseFocusReason)
        self.update_amounts()
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
