# -*- coding: utf-8 -*-

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import (QLineEdit, QStyle, QStyleOptionFrame)

from decimal import Decimal
from electroncash.util import format_satoshis_plain


class MyLineEdit(QLineEdit):
    frozen = pyqtSignal()

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setFrame(not b)
        self.frozen.emit()

class AmountEdit(MyLineEdit):
    shortcut = pyqtSignal()

    def __init__(self, base_unit, is_int = False, parent=None):
        QLineEdit.__init__(self, parent)
        # This seems sufficient for hundred-BTC amounts with 8 decimals
        self.setFixedWidth(140)
        self.base_unit = base_unit
        self.textChanged.connect(self.numbify)
        self.is_int = is_int
        self.is_shortcut = False
        self.help_palette = QPalette()

    def decimal_point(self):
        return 8

    def numbify(self):
        text = self.text().strip()
        if text == '!':
            self.shortcut.emit()
            return
        pos = self.cursorPosition()
        chars = '0123456789'
        if not self.is_int: chars +='.'
        s = ''.join([i for i in text if i in chars])
        if not self.is_int:
            if '.' in s:
                p = s.find('.')
                s = s.replace('.','')
                s = s[:p] + '.' + s[p:p+self.decimal_point()]
        self.setText(s)
        # setText sets Modified to False.  Instead we want to remember
        # if updates were because of user modification.
        self.setModified(self.hasFocus())
        self.setCursorPosition(pos)

    def paintEvent(self, event):
        QLineEdit.paintEvent(self, event)
        if self.base_unit:
            panel = QStyleOptionFrame()
            self.initStyleOption(panel)
            textRect = self.style().subElementRect(QStyle.SE_LineEditContents, panel, self)
            textRect.adjust(2, 0, -10, 0)
            painter = QPainter(self)
            painter.setPen(self.help_palette.brush(QPalette.Disabled, QPalette.Text).color())
            painter.drawText(textRect, Qt.AlignRight | Qt.AlignVCenter, self.base_unit())

    def get_amount(self):
        try:
            return (int if self.is_int else Decimal)(str(self.text()))
        except:
            return None


class BTCAmountEdit(AmountEdit):

    def __init__(self,currency, decimal_point, is_int = False, parent=None):

        AmountEdit.__init__(self, self._base_unit, is_int, parent)
        self.decimal_point = decimal_point
        self.currency = currency

    def _base_unit(self):
        p = self.decimal_point()
        assert p in [0, 2, 5, 8]
        if p == 0 and self.currency == 'BTC':
            return 'sat'
        if p == 2:
            if self.currency == 'BTC':
                return 'bits'
            elif self.currency == 'BCH':
                return 'cash'
        if p == 5:
            return 'm'+self.currency
        if p == 8:
            return self.currency

        raise Exception('Unknown base unit')

    def get_amount(self):
        try:
            x = Decimal(str(self.text()))
        except:
            return None
        p = pow(10, self.decimal_point())
        return int( p * x )

    def setAmount(self, amount):
        if amount is None:
            self.setText(" ") # Space forces repaint in case units changed
        else:
            self.setText(format_satoshis_plain(amount, self.decimal_point()))


class BTCkBEdit(BTCAmountEdit):
    def _base_unit(self):
        return BTCAmountEdit._base_unit(self) + '/kB'


class BTCSatsByteEdit(BTCAmountEdit):
    def __init__(self,currency, parent=None):
        BTCAmountEdit.__init__(self,currency, decimal_point = lambda: 2, is_int = False, parent = parent)

    def _base_unit(self):
        return 'sats' + '/B'

    def get_amount(self):
        try:
            x = float(Decimal(str(self.text())))
        except:
            return None
        return x if x > 0.0 else None

    def setAmount(self, amount):
        if amount is None:
            self.setText(" ") # Space forces repaint in case units changed
        else:
            self.setText(str(round(amount*100.0)/100.0))
