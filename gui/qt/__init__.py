#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITN
# ESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import signal
import sys
import traceback


try:
    import PyQt5
except Exception:
    sys.exit("Error: Could not import PyQt5 on Linux systems, you may try 'sudo apt-get install python3-pyqt5'")

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import PyQt5.QtCore as QtCore

from electroncash.i18n import _, set_language
from electroncash.plugins import run_hook
from electroncash import WalletStorage
# from electroncash.synchronizer import Synchronizer
# from electroncash.verifier import SPV
# from electroncash.util import DebugMem
from electroncash.util import UserCancelled, print_error
# from electroncash.wallet import Abstract_Wallet

from .installwizard import InstallWizard, GoBack


try:
    from . import icons_rc
except Exception as e:
    print(e)
    print("Error: Could not find icons file.")
    print("Run 'pyrcc5 icons.qrc -o gui/qt/icons_rc.py', and re-run Electron Cash")
    sys.exit(1)

from .util import *   # * needed for plugins
from .main_window import ElectrumWindow
from .network_dialog import NetworkDialog


class OpenFileEventFilter(QObject):
    def __init__(self, windows):
        self.windows = windows
        super(OpenFileEventFilter, self).__init__()

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.FileOpen:
            if len(self.windows['BTC']) >= 1 and len(self.windows['BCH']) >= 1:
                self.windows['BTC'][0].pay_to_URI(event.url().toString())
                self.windows['BCH'][0].pay_to_URI(event.url().toString())
                return True
            elif not len(self.windows['BTC']) >= 1 and len(self.windows['BCH']) >= 1:
                self.windows['BCH'][0].pay_to_URI(event.url().toString())
                return True
        return False


class QElectrumApplication(QApplication):
    new_window_signal = pyqtSignal(str,object, object)


class QNetworkUpdatedSignalObject(QObject):
    network_updated_signal = pyqtSignal(str, object)


class ElectrumGui:

    def __init__(self, config, plugins):
        set_language(config.get('language'))
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])
        QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_X11InitThreads)
        if hasattr(QtCore.Qt, "AA_ShareOpenGLContexts"):
            QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electrum.desktop')
        self.config = config
        self.plugins = plugins
        self.windows = {'BTC':list([]), 'BCH': list([])}
        self.efilter = OpenFileEventFilter(self.windows)
        self.app = QElectrumApplication(sys.argv)
        self.app.installEventFilter(self.efilter)
        self.timer = Timer()
        self.nd = {}
        self.tray = {}
        self.network_updated_signal_obj = {'BCH': QNetworkUpdatedSignalObject(), 'BTC': QNetworkUpdatedSignalObject()}
        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        self.build_tray("BTC")
        self.build_tray("BCH")
        self.currency_daemon = {}
        self.app.new_window_signal.connect(self.start_new_window)
        run_hook('init_qt', self)
        ColorScheme.update_from_widget(QWidget())

    def build_tray(self, currency):
        self.tray[currency] = QSystemTrayIcon(self.tray_icon(), None)
        self.tray[currency].setToolTip('Electrum')
        self.tray[currency].activated.connect(self.tray_activated)
        self.build_tray_menu(currency)
        self.tray[currency].show()

    def build_tray_menu(self, currency):
        # Avoid immediate GC of old menu when window closed via its action
        if self.tray[currency].contextMenu() is None:
            m = QMenu()
            self.tray[currency].setContextMenu(m)
        else:
            m = self.tray[currency].contextMenu()
            m.clear()
        for window in self.windows[currency]:
            submenu = m.addMenu(window.wallet.basename())
            submenu.addAction(_("Show/Hide"), window.show_or_hide)
            submenu.addAction(_("Close"), window.close)
        m.addAction(_("Dark/Light"), self.toggle_tray_icon)
        m.addSeparator()
        m.addAction(_("Exit Electron Cash"), self.close)
        self.tray[currency].setContextMenu(m)

    def tray_icon(self):
        if self.dark_icon:
            return QIcon(':icons/electron_dark_icon.png')
        else:
            return QIcon(':icons/electron_light_icon.png')

    def toggle_tray_icon(self):
        self.dark_icon = not self.dark_icon
        self.config.set_key("dark_icon", self.dark_icon, True)
        self.tray.setIcon(self.tray_icon())

    def tray_activated(self, reason, currency):
        if reason == QSystemTrayIcon.DoubleClick:
            if all([w.is_hidden() for w in self.windows[currency]]):
                for w in self.windows[currency]:
                    w.bring_to_top()
            else:
                for w in self.windows[currency]:
                    w.hide()

    def close(self, currency):
        for window in self.windows[currency]:
            window.close()

    def new_window(self, path, daemon, uri=None ):
        # Use a signal as can be called from daemon thread
        self.app.new_window_signal.emit(path, uri, daemon)

    def show_network_dialog(self, parent, daemon):
        currency = daemon.currency
        if not daemon.network:
            parent.show_warning(_('You are using Electron Cash in offline mode; restart Electron Cash if you want to get connected'), title=_('Offline'))
            return
        if self.nd.get(currency) is not None:
            self.nd[currency].on_update()
            self.nd[currency].show()
            self.nd[currency].raise_()
            return
        self.nd[currency] = NetworkDialog(daemon.network, self.config, self.network_updated_signal_obj[currency], currency)
        self.nd[currency].show()

    def create_window_for_wallet(self, wallet, currency):
        w = ElectrumWindow(self, wallet, currency, self.plugins)
        self.windows[currency].append(w)
        self.build_tray_menu(currency)
        # FIXME: Remove in favour of the load_wallet hook
        run_hook('on_new_window', w)
        return w

    def start_new_window(self, path, uri, daemon):
        '''Raises the window for the wallet if it is open.  Otherwise
        opens the wallet and creates a new window for it.'''
        for w in self.windows[daemon.currency]:
            if w.wallet.storage.path == path:
                w.bring_to_top()
                break
        else:
            try:

                wallet = daemon.load_wallet(path, None)
                if not wallet:
                    storage = WalletStorage(path, manual_upgrades=True)
                    wizard = InstallWizard(self.config, self.app, self.plugins, daemon.currency, storage)
                    try:
                        wallet = wizard.run_and_get_wallet()
                    except UserCancelled:
                        pass
                    except GoBack as e:
                        print_error('[start_new_window] Exception caught (GoBack)', e)
                    finally:
                        wizard.terminate()
                    if not wallet:
                        return
                    wallet.start_threads(daemon.network)
                    daemon.add_wallet(wallet)
            except BaseException as e:
                traceback.print_exc(file=sys.stdout)
                if '2fa' in str(e):
                    d = QMessageBox(QMessageBox.Warning, _('Error'), '2FA wallets for Bitcoin Cash are currently unsupported by <a href="https://api.trustedcoin.com/#/">TrustedCoin</a>. Follow <a href="https://github.com/Electron-Cash/Electron-Cash/issues/41#issuecomment-357468208">this guide</a> in order to recover your funds.')
                    d.exec_()
                else:
                    d = QMessageBox(QMessageBox.Warning, _('Error'), 'Cannot load wallet:\n' + str(e))
                    d.exec_()
                return
            w = self.create_window_for_wallet(wallet, daemon.currency)
        if uri:
            w.pay_to_URI(uri)
        w.bring_to_top()
        w.setWindowState(w.windowState() & ~QtCore.Qt.WindowMinimized | QtCore.Qt.WindowActive)

        # this will activate the window
        w.activateWindow()

        return w

    def close_window(self, window, daemon):
        self.windows[daemon.currency].remove(window)
        self.build_tray_menu(daemon.currency)
        # save wallet path of last open window
        if not self.windows:
            self.config.save_last_wallet(window.wallet, daemon.currency)
        run_hook('on_close_window', window)

    def init_network(self, daemon):
        # Show network dialog if config does not exist
        if daemon.network:
            if self.config.get('auto_connect_'+daemon.currency) is None:
                wizard = InstallWizard(self.config, self.app, self.plugins, daemon.currency, None)
                wizard.init_network(daemon.network)
                wizard.terminate()

    def set_currency_daemon(self, currency, daemon):
        self.currency_daemon[currency] = daemon

    def main(self, daemon):
        try:
            self.init_network(daemon)
        except UserCancelled:
            return
        except GoBack:
            return
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            return
        self.timer.start()
        self.config.open_last_wallet(daemon.currency)
        path = self.config.get_wallet_path(daemon.currency)
        if not self.start_new_window(path, self.config.get('url'), daemon):
            return
        signal.signal(signal.SIGINT, lambda *args: self.app.quit())

        def quit_after_last_window():
            # on some platforms, not only does exec_ not return but not even
            # aboutToQuit is emitted (but following this, it should be emitted)
            if self.app.quitOnLastWindowClosed():
                self.app.quit()

        self.app.lastWindowClosed.connect(quit_after_last_window)

        def clean_up():
            # Shut down the timer cleanly
            self.timer.stop()
            # clipboard persistence. see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
            event = QtCore.QEvent(QtCore.QEvent.Clipboard)
            self.app.sendEvent(self.app.clipboard(), event)
            self.tray.hide()

        self.app.aboutToQuit.connect(clean_up)

        # main loop
        self.app.exec_()
        # on some platforms the exec_ call may not return, so use clean_up()
