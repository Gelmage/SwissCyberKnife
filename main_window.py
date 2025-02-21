import time

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QTabWidget, QPlainTextEdit,
    QLineEdit, QLabel, QComboBox, QMessageBox, QSplitter
)
from PyQt6.QtCore import Qt

from bettercap_panel import BettercapPanel
from nmap_panel import NmapPanel  # QTree-based categories
from ettercap_panel import EttercapPanel
from responder_panel import ResponderPanel
from driftnet_panel import DriftnetPanel  # <--- Import our new Driftnet panel

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Swiss Cyber Knife")
        self.resize(1000, 600)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        #
        # GLOBAL OPTIONS (Target, Ports, Interface)
        #
        global_options_layout = QHBoxLayout()
        main_layout.addLayout(global_options_layout)

        lbl_target = QLabel("Target(s):")
        global_options_layout.addWidget(lbl_target)

        self.global_target_input = QLineEdit()
        self.global_target_input.setPlaceholderText("e.g. 192.168.1.0/24 or Hostname")
        global_options_layout.addWidget(self.global_target_input)

        lbl_ports = QLabel("Ports:")
        global_options_layout.addWidget(lbl_ports)

        self.global_ports_input = QLineEdit()
        self.global_ports_input.setPlaceholderText("Optional ports, e.g. 80,443")
        global_options_layout.addWidget(self.global_ports_input)

        lbl_iface = QLabel("Interface:")
        global_options_layout.addWidget(lbl_iface)

        self.global_iface_combo = QComboBox()
        self.global_iface_combo.addItems(["eth0", "wlan0", "any"])
        global_options_layout.addWidget(self.global_iface_combo)

        #
        # SPLITTER: top area vs bottom logs
        #
        self.vertical_splitter = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(self.vertical_splitter, stretch=1)

        #
        # TOP SPLITTER: side nav + stacked widget
        #
        self.top_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.top_splitter.setChildrenCollapsible(False)

        self.nav_list = QListWidget()
        self.top_splitter.addWidget(self.nav_list)

        from PyQt6.QtWidgets import QStackedWidget
        self.stack = QStackedWidget()
        self.top_splitter.addWidget(self.stack)

        self.vertical_splitter.addWidget(self.top_splitter)

        #
        # BOTTOM TABBED LOGS
        #
        self.tabbed_logs_container = QWidget()
        logs_layout = QVBoxLayout(self.tabbed_logs_container)
        self.tabbed_logs_container.setLayout(logs_layout)

        self.log_tabs = QTabWidget()
        logs_layout.addWidget(self.log_tabs)

        self.tab_bettercap = QPlainTextEdit()
        self.tab_bettercap.setReadOnly(True)
        self.tab_bettercap.setPlaceholderText("Bettercap Output...")
        self.log_tabs.addTab(self.tab_bettercap, "Bettercap")

        self.tab_nmap = QPlainTextEdit()
        self.tab_nmap.setReadOnly(True)
        self.tab_nmap.setPlaceholderText("Nmap Output...")
        self.log_tabs.addTab(self.tab_nmap, "Nmap")

        self.tab_ettercap = QPlainTextEdit()
        self.tab_ettercap.setReadOnly(True)
        self.tab_ettercap.setPlaceholderText("Ettercap Output...")
        self.log_tabs.addTab(self.tab_ettercap, "Ettercap")

        self.tab_responder = QPlainTextEdit()
        self.tab_responder.setReadOnly(True)
        self.tab_responder.setPlaceholderText("Responder Output...")
        self.log_tabs.addTab(self.tab_responder, "Responder")

        # -----------------------------
        # ADD DRIFTNET LOG TAB
        # -----------------------------
        self.tab_driftnet = QPlainTextEdit()
        self.tab_driftnet.setReadOnly(True)
        self.tab_driftnet.setPlaceholderText("Driftnet Output...")
        self.log_tabs.addTab(self.tab_driftnet, "Driftnet")

        self.vertical_splitter.addWidget(self.tabbed_logs_container)

        # Optionally adjust the split ratio
        self.vertical_splitter.setStretchFactor(0, 4)
        self.vertical_splitter.setStretchFactor(1, 2)

        self.MAX_LOG_LINES = 1000

        #
        # Create Panels
        #
        self.bettercap_panel = BettercapPanel(parent_main=self)
        self.nmap_panel = NmapPanel(parent_main=self)   # QTree categories
        self.ettercap_panel = EttercapPanel(parent_main=self)
        self.responder_panel = ResponderPanel(parent_main=self)
        self.driftnet_panel = DriftnetPanel(parent_main=self)

        # Add them in the order we want to appear in nav_list
        self.stack.addWidget(self.bettercap_panel)   # index 0
        self.stack.addWidget(self.nmap_panel)        # index 1
        self.stack.addWidget(self.ettercap_panel)    # index 2
        self.stack.addWidget(self.responder_panel)   # index 3
        self.stack.addWidget(self.driftnet_panel)    # index 4

        # Nav items (sidebar). Must match the order we added panels
        nav_items = ["Bettercap", "Nmap", "Ettercap", "Responder", "Driftnet"]
        for i, label in enumerate(nav_items):
            item = QListWidgetItem(label)
            self.nav_list.addItem(item)

        self.nav_list.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav_list.setCurrentRow(0)

    #
    # Logging
    #
    def log_bettercap(self, message: str):
        if self.tab_bettercap.blockCount() > self.MAX_LOG_LINES:
            self.tab_bettercap.clear()
            self.tab_bettercap.appendPlainText("...[older logs truncated]...\n")
        self.tab_bettercap.appendPlainText(message)

    def log_nmap(self, message: str):
        if self.tab_nmap.blockCount() > self.MAX_LOG_LINES:
            self.tab_nmap.clear()
            self.tab_nmap.appendPlainText("...[older logs truncated]...\n")
        self.tab_nmap.appendPlainText(message)

    def log_ettercap(self, message: str):
        if self.tab_ettercap.blockCount() > self.MAX_LOG_LINES:
            self.tab_ettercap.clear()
            self.tab_ettercap.appendPlainText("...[older logs truncated]...\n")
        self.tab_ettercap.appendPlainText(message)

    def log_responder(self, message: str):
        if self.tab_responder.blockCount() > self.MAX_LOG_LINES:
            self.tab_responder.clear()
            self.tab_responder.appendPlainText("...[older logs truncated]...\n")
        self.tab_responder.appendPlainText(message)

    # -------------------------------------------------
    # ADD A DRIFTNET LOGGING METHOD
    # -------------------------------------------------
    def log_driftnet(self, message: str):
        if self.tab_driftnet.blockCount() > self.MAX_LOG_LINES:
            self.tab_driftnet.clear()
            self.tab_driftnet.appendPlainText("...[older logs truncated]...\n")
        self.tab_driftnet.appendPlainText(message)

    #
    # Global Accessors
    #
    def get_global_target(self) -> str:
        return self.global_target_input.text().strip()

    def get_global_ports(self) -> str:
        return self.global_ports_input.text().strip()

    def get_global_interface(self) -> str:
        return self.global_iface_combo.currentText()

    #
    # closeEvent for graceful thread stop
    #
    def closeEvent(self, event):
        threads_active = []

        # Nmap
        if hasattr(self.nmap_panel, 'process_thread') and self.nmap_panel.process_thread:
            threads_active.append('Nmap')

        # Bettercap
        if getattr(self.bettercap_panel, 'running_commands', None):
            if self.bettercap_panel.running_commands:
                threads_active.append('Bettercap')

        # Ettercap
        if getattr(self.ettercap_panel, 'running_commands', None):
            if self.ettercap_panel.running_commands:
                threads_active.append('Ettercap')

        # Responder
        if getattr(self.responder_panel, 'running_commands', None):
            if self.responder_panel.running_commands:
                threads_active.append('Responder')

        # Driftnet
        if getattr(self.driftnet_panel, 'running_commands', None):
            if self.driftnet_panel.running_commands:
                threads_active.append('Driftnet')

        if threads_active:
            reply = QMessageBox.question(
                self,
                "Tools Running",
                f"{', '.join(threads_active)} still running. Stop them & exit?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
            else:
                if 'Nmap' in threads_active and self.nmap_panel.process_thread:
                    self.nmap_panel.stop_scan()

                if 'Bettercap' in threads_active:
                    for _, thr in list(self.bettercap_panel.running_commands.items()):
                        thr.stop()
                    self.bettercap_panel.running_commands.clear()

                if 'Ettercap' in threads_active:
                    for _, thr in list(self.ettercap_panel.running_commands.items()):
                        thr.stop()
                    self.ettercap_panel.running_commands.clear()

                if 'Responder' in threads_active:
                    for _, thr in list(self.responder_panel.running_commands.items()):
                        thr.stop()
                    self.responder_panel.running_commands.clear()

                if 'Driftnet' in threads_active:
                    for _, thr in list(self.driftnet_panel.running_commands.items()):
                        thr.stop()
                    self.driftnet_panel.running_commands.clear()

                time.sleep(1)

        super().closeEvent(event)
