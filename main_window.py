from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QStackedWidget,
    QPlainTextEdit
)
from PyQt6.QtCore import Qt

# Import our new panel classes
from bettercap_panel import BettercapPanel
from nmap_panel import NmapPanel

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Swiss Cyber Knife")
        self.resize(1000, 600)

        # Central widget for the main window
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main vertical layout
        main_layout = QVBoxLayout(central_widget)

        # Top area: horizontal split between side nav & stack
        top_layout = QHBoxLayout()
        main_layout.addLayout(top_layout, stretch=2)

        # Left nav: a QListWidget to pick which tool to show
        self.nav_list = QListWidget()
        top_layout.addWidget(self.nav_list, stretch=1)

        # QStackedWidget on the right: holds BettercapPanel, NmapPanel, etc.
        self.stack = QStackedWidget()
        top_layout.addWidget(self.stack, stretch=3)

        # Bottom area: two logs side-by-side for Bettercap / Nmap
        logs_layout = QHBoxLayout()
        main_layout.addLayout(logs_layout, stretch=1)

        self.bettercap_log = QPlainTextEdit()
        self.bettercap_log.setReadOnly(True)
        self.bettercap_log.setPlaceholderText("Bettercap Output...")
        logs_layout.addWidget(self.bettercap_log)

        self.nmap_log = QPlainTextEdit()
        self.nmap_log.setReadOnly(True)
        self.nmap_log.setPlaceholderText("Nmap Output...")
        logs_layout.addWidget(self.nmap_log)

        # === Panels (instead of separate windows) ===
        self.bettercap_panel = BettercapPanel(parent_main=self)
        self.nmap_panel = NmapPanel(parent_main=self)

        # Add these panels to the QStackedWidget
        self.stack.addWidget(self.bettercap_panel)  # index 0
        self.stack.addWidget(self.nmap_panel)       # index 1

        # Populate the side nav
        # The order we add items should correspond to the widget indexes above
        nav_items = ["Bettercap", "Nmap"]
        for i, label in enumerate(nav_items):
            item = QListWidgetItem(label)
            self.nav_list.addItem(item)

        # When the user clicks an item, switch stack pages
        self.nav_list.currentRowChanged.connect(self.stack.setCurrentIndex)
        # Default to the first item
        self.nav_list.setCurrentRow(0)

    def log_bettercap(self, text: str):
        """Append text to the Bettercap log box."""
        self.bettercap_log.appendPlainText(text)

    def log_nmap(self, text: str):
        """Append text to the Nmap log box."""
        self.nmap_log.appendPlainText(text)
