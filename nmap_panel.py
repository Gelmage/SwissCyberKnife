from PyQt6.QtWidgets import QWidget, QVBoxLayout, QListWidget, QPushButton, QLineEdit, QHBoxLayout
from PyQt6.QtCore import Qt

from external_process_thread import ExternalProcessThread

class NmapPanel(QWidget):
    """
    Panel containing Nmap scanning options. Embedded in the main window via QStackedWidget.
    """
    def __init__(self, parent_main):
        super().__init__()
        self.parent_main = parent_main  # reference to MainWindow for logging
        self.process_thread = None      # track the active Nmap process
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        # A list of common scans
        self.nmap_list = QListWidget()
        layout.addWidget(self.nmap_list)

        scans = [
            "Ping Scan (-sn)",
            "Quick Scan (-T4 -F)",
            "Full Port Scan (-p-)",
            "Service/OS Detect (-A)",
            "UDP Scan (-sU)"
        ]
        self.nmap_list.addItems(scans)

        # Target / Ports input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter Target IP/Host")
        layout.addWidget(self.target_input)

        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("Enter Ports (Optional)")
        layout.addWidget(self.ports_input)

        # Button row
        btn_layout = QHBoxLayout()
        layout.addLayout(btn_layout)

        self.btn_run = QPushButton("Run Scan")
        self.btn_run.clicked.connect(self.run_selected)
        btn_layout.addWidget(self.btn_run)

        self.btn_stop = QPushButton("Stop Scan")
        self.btn_stop.clicked.connect(self.stop_scan)
        btn_layout.addWidget(self.btn_stop)

    def run_selected(self):
        """Run the chosen Nmap scan in a background thread."""
        selected_item = self.nmap_list.currentItem()
        if not selected_item:
            self.parent_main.log_nmap("Please select an Nmap scan type.")
            return

        target = self.target_input.text().strip()
        if not target:
            self.parent_main.log_nmap("Please enter a target IP/host.")
            return

        ports = self.ports_input.text().strip()

        # e.g. "Quick Scan (-T4 -F)" -> parse out "-T4 -F"
        text = selected_item.text()
        options_part = ""
        if "(" in text and ")" in text:
            options_part = text.split("(")[-1].split(")")[0].strip()

        cmd_list = ["nmap"]
        if options_part:
            cmd_list.extend(options_part.split())
        cmd_list.append(target)

        # If user specified ports
        if ports:
            cmd_list.extend(["-p", ports])

        self.parent_main.log_nmap(f"[*] Running: {' '.join(cmd_list)}")

        # Start background thread
        self.process_thread = ExternalProcessThread(cmd_list)
        self.process_thread.output_signal.connect(self.parent_main.log_nmap)
        self.process_thread.finished_signal.connect(self.on_nmap_finished)
        self.process_thread.start()

    def on_nmap_finished(self, exit_code):
        """Called when the Nmap process finishes."""
        self.parent_main.log_nmap(f"[+] Nmap scan finished with exit code {exit_code}\n")
        self.process_thread = None

    def stop_scan(self):
        """Stop/kill the active Nmap process if it's running."""
        if self.process_thread is not None:
            self.parent_main.log_nmap("[*] Stopping Nmap scan...")
            self.process_thread.stop()
            self.process_thread = None
        else:
            self.parent_main.log_nmap("No Nmap scan is running.")
