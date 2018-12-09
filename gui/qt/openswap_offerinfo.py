"""
Dialog for displaying / editing an offer during private negotiation
"""
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

from .openswap_priceinfo import PriceInfoBox

class OfferInfoDialog(QDialog):
    price_sigfigs = 6  # how many significant figures to use in price calculations

    # Dialog for creating / editing / viewing OpenSwap offers
    def __init__(self, parent, offerinfo, other_pubkey, mode="create"):
        QDialog.__init__(self, parent=parent)

        if mode == "create":
            self.from_me = True
            self.editable = True
            cancel_text = _("Cancel")
            edit_text = None
            ok_text = _("Send")
            title = _("Private offer (new)")
        #elif mode == "view":
            #self.from_me =
            #self.editable = False
            #cancel_text = _("Close")
            #edit_text = None
            #ok_text = None
            #title = _("Offer info")
        elif mode == "view_as_sender":
            self.from_me = True
            self.editable = False
            cancel_text = _("Close")
            edit_text = _("Re-offer")
            ok_text = None
            title = _("Private offer (sent)")
        elif mode == "view_as_recipient":
            self.from_me = False
            self.editable = False
            cancel_text = _("Cancel")
            edit_text = _("Counter-offer")
            ok_text = _("Accept")
            title = _("Private offer (received)")
        else:
            raise ValueError(mode)

#        self.setMinimumSize(610, 290)
        self.setWindowTitle(title)

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(_('Pubkeys')))
        grid = QGridLayout()
        layout.addLayout(grid)

        grid.addWidget(QLabel(_("From")), 0, 0)
        grid.addWidget(QLabel(_("To")), 1, 0)

        grid.addWidget(QLabel(_("me")), 0 if self.from_me else 1, 1)

        self.counterparty_pubkey_e = QLineEdit()
        if other_pubkey:
            self.counterparty_pubkey_e.setText(other_pubkey.hex())
            self.counterparty_pubkey_e.setReadOnly(True)
        grid.addWidget(self.counterparty_pubkey_e, 1 if self.from_me else 0, 1)


        self.pi = PriceInfoBox(self, self.editable)
        layout.addWidget(self.pi)

        hbox = QHBoxLayout()
        layout.addLayout(hbox)
        hbox.addWidget(QLabel(_('Refunds')))
        hbox.addStretch(1)
        self.refundtime_want_label = QLabel()
        hbox.addWidget(self.refundtime_want_label)
        hbox.addStretch(1)
        self.refundtime_give_label = QLabel()
        hbox.addWidget(self.refundtime_give_label)

        hbox = QHBoxLayout()
        layout.addLayout(hbox)

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
        self.update_constants()

    def get_counterparty_pubkey(self):
        return bytes.fromhex(self.counterparty_pubkey_e.text())

    def get_offerinfo(self):
        """
        Calculate offer info from displayed values
        """
        offer = openswap.OfferInfo(
                    salt = self.salt,
                    want_rtime = self.want_rtime,
                    give_rtime = self.give_rtime,
                    want_amount = get_satoshis_nofloat(self.pi.want_amount_e.text()),
                    want_ticker = crypto_list_by_bytes[self.pi.want_crypto_cb.currentIndex()],
                    give_amount = get_satoshis_nofloat(self.pi.give_amount_e.text()),
                    give_ticker = crypto_list_by_bytes[self.pi.give_crypto_cb.currentIndex()],
                    )
        return offer

    def update_constants(self,):
        """update salt, refund time displays"""
        import time
        now = time.time()

        ci = self.pi.want_crypto_cb.currentIndex()
        rtime_est = round((self.want_rtime + cryptos[ci][2] - now) / 3600.)
        self.refundtime_want_label.setText(_('Want \u2248 %+d hours')%(rtime_est))
        self.refundtime_want_label.setToolTip('MTP'+str(self.want_rtime))

        ci = self.pi.give_crypto_cb.currentIndex()
        rtime_est = round((self.give_rtime + cryptos[ci][2] - now) / 3600.)
        self.refundtime_give_label.setText(_('Give \u2248 %+d hours')%(rtime_est))
        self.refundtime_give_label.setToolTip('MTP'+str(self.give_rtime))

    def read_from_offerinfo(self, offerinfo):
        tick1 = offerinfo.want_ticker
        tick2 = offerinfo.give_ticker
        self.pi.want_crypto_cb.setCurrentIndex(crypto_list_by_bytes.index(tick1))
        self.pi.give_crypto_cb.setCurrentIndex(crypto_list_by_bytes.index(tick2))
        if offerinfo.want_amount is not None:
            self.pi.want_amount_e.setText(format_satoshis_plain_nofloat(offerinfo.want_amount))
        if offerinfo.give_amount is not None:
            self.pi.give_amount_e.setText(format_satoshis_plain_nofloat(offerinfo.give_amount))
        self.want_rtime = offerinfo.want_rtime
        self.give_rtime = offerinfo.give_rtime
        self.salt = offerinfo.salt

        self.pi.update_amounts()
