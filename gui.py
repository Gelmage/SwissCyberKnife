# gui.py
from PyQt6.QtWidgets import QMainWindow, QPlainTextEdit, QLineEdit, QPushButton, QVBoxLayout, QWidget
from PyQt6.QtCore import Qt
from bettercap_controller import BettercapSession
from nmap_runner import NmapScanner

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Swiss Cyber Knife")

        # Central widget + layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Target input
        self.targetInput = QLineEdit()
        self.targetInput.setPlaceholderText("Enter target IP or host...")
        layout.addWidget(self.targetInput)

        # Start scan button
        self.startScanButton = QPushButton("Start Nmap Scan")
        layout.addWidget(self.startScanButton)

        # Nmap Output box
        self.nmapOutput = QPlainTextEdit()
        self.nmapOutput.setReadOnly(True)
        layout.addWidget(self.nmapOutput)

        # Connect button to action
        self.startScanButton.clicked.connect(self.on_start_scan)

        # Prepare Bettercap session (example uses interface="eth0")
        self.bettercapSession = BettercapSession(interface="eth0")
        self.bettercapSession.log_signal.connect(self.append_bettercap_log)

    def on_start_scan(self):
        target = self.targetInput.text().strip()
        if target:
            options = "-sV"  # Example Nmap options
            self.nmapScanner = NmapScanner(target, options)
            self.nmapScanner.output_signal.connect(self.append_nmap_log)
            self.nmapScanner.finished_signal.connect(self.on_scan_finished)
            self.nmapScanner.start()
        else:
            self.nmapOutput.appendPlainText("No target specified.")

    def append_nmap_log(self, text_line):
        self.nmapOutput.appendPlainText(text_line)

    def on_scan_finished(self, code):
        self.append_nmap_log(f"\nScan completed (exit code: {code}).")

    def append_bettercap_log(self, text_line):
        # You could create a separate QPlainTextEdit for bettercap logs,
        # or reuse self.nmapOutput for simplicity:
        self.nmapOutput.appendPlainText(f"[Bettercap] {text_line}")
