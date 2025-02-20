from PyQt6.QtWidgets import QWidget, QVBoxLayout, QListWidget, QPushButton, QHBoxLayout, QListWidgetItem
from PyQt6.QtCore import Qt

from external_process_thread import ExternalProcessThread

class BettercapPanel(QWidget):
    """
    Panel containing the Bettercap commands list, run/stop buttons, etc.
    This is embedded in the main window via QStackedWidget.
    """
    def __init__(self, parent_main):
        super().__init__()
        self.parent_main = parent_main  # reference to MainWindow for logging
        self.running_commands = {}      # track running commands (str->thread)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        # List widget for Bettercap modules
        self.bettercap_list = QListWidget()
        layout.addWidget(self.bettercap_list)

        # Populate the list with potential modules
        # Each entry has (display_text, tooltip_text)
        bettercap_items = [
            (
                "Network Recon (net.recon on)",
                "Scans the local network for devices (passively) and collects info about them."
            ),
            (
                "Network Sniffing (net.sniff on)",
                "Captures and displays network traffic in real time."
            ),
            (
                "Network Probing (net.probe on)",
                "Actively probes discovered hosts to identify hidden or unresponsive devices."
            ),
            (
                "ARP Spoofing (arp.spoof on)",
                "Intercept traffic between the gateway and hosts by poisoning ARP caches."
            ),
            (
                "DNS Spoofing (dns.spoof on)",
                "Redirect DNS queries to a chosen IP, often used in MITM to serve fake sites."
            ),
            (
                "HTTP Proxy (http.proxy on)",
                "Intercept and modify HTTP traffic (inject scripts, capture credentials, etc.)."
            ),
            (
                "HTTPS Proxy (https.proxy on)",
                "Attempt SSL stripping or interception of HTTPS traffic (risky, advanced)."
            )
        ]

        for display_text, tooltip_text in bettercap_items:
            item = QListWidgetItem(display_text)
            item.setToolTip(tooltip_text)
            self.bettercap_list.addItem(item)

        # Double-click toggles run/stop
        self.bettercap_list.itemDoubleClicked.connect(self.on_item_double_clicked)

        # Horizontal layout for run/stop buttons
        btn_layout = QHBoxLayout()
        layout.addLayout(btn_layout)

        self.btn_run = QPushButton("Run Selected")
        self.btn_run.clicked.connect(self.run_selected_command)
        btn_layout.addWidget(self.btn_run)

        self.btn_stop = QPushButton("Stop Selected")
        self.btn_stop.clicked.connect(self.stop_selected_command)
        btn_layout.addWidget(self.btn_stop)

    def on_item_double_clicked(self, item):
        """Double-click toggles run/stop for that command."""
        if not item:
            return
        command_part = self.parse_command(item.text())
        if not command_part:
            self.parent_main.log_bettercap("Error: can't parse item text.")
            return

        # If it’s running, stop it; otherwise start
        if command_part in self.running_commands:
            self.stop_command(command_part)
        else:
            self.run_command(command_part)

    def run_selected_command(self):
        """Run the currently selected command."""
        item = self.bettercap_list.currentItem()
        if not item:
            self.parent_main.log_bettercap("No command selected.")
            return
        command_part = self.parse_command(item.text())
        if not command_part:
            self.parent_main.log_bettercap("Error: can't parse command text.")
            return
        self.run_command(command_part)

    def stop_selected_command(self):
        """Stop the currently selected command if it's running."""
        item = self.bettercap_list.currentItem()
        if not item:
            self.parent_main.log_bettercap("No command selected.")
            return
        command_part = self.parse_command(item.text())
        if not command_part:
            self.parent_main.log_bettercap("Error: can't parse command text.")
            return

        if command_part in self.running_commands:
            self.stop_command(command_part)
        else:
            self.parent_main.log_bettercap(f"'{command_part}' is not currently running.")

    def run_command(self, command_part: str):
        """Spawn a Bettercap subprocess in a background thread."""
        if command_part in self.running_commands:
            self.parent_main.log_bettercap(f"'{command_part}' is already running.")
            return

        cmd_list = ["bettercap", "-eval", command_part]
        self.parent_main.log_bettercap(f"[*] Starting: {' '.join(cmd_list)}")

        thread = ExternalProcessThread(cmd_list)
        thread.output_signal.connect(self.parent_main.log_bettercap)
        thread.finished_signal.connect(lambda code, c=command_part: self.on_command_finished(code, c))
        thread.start()

        self.running_commands[command_part] = thread

    def stop_command(self, command_part: str):
        """Kill the process for a running command."""
        thread = self.running_commands.get(command_part)
        if thread:
            self.parent_main.log_bettercap(f"[*] Stopping: {command_part}")
            thread.stop()
            # Remove from dict once we forcibly kill it
            del self.running_commands[command_part]
        else:
            self.parent_main.log_bettercap(f"No thread found for '{command_part}'")

    def on_command_finished(self, exit_code, command_part):
        """Called when a Bettercap command process exits on its own."""
        if command_part in self.running_commands:
            del self.running_commands[command_part]
        self.parent_main.log_bettercap(f"[+] '{command_part}' finished (exit code {exit_code}).")

    @staticmethod
    def parse_command(full_text: str) -> str:
        """Extract the portion in parentheses, e.g. '(net.sniff on)' -> 'net.sniff on'."""
        if "(" in full_text and ")" in full_text:
            return full_text.split("(")[-1].split(")")[0].strip()
        return ""
