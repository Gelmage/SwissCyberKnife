from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QPushButton, QHBoxLayout,
    QListWidgetItem
)
from PyQt6.QtCore import Qt

from external_process_thread import ExternalProcessThread

class BettercapPanel(QWidget):
    """
    Large set of Bettercap commands for v2.33. Some might not exist, open bettercap to check.
    Hover for tooltips describing each command.
    """
    def __init__(self, parent_main):
        super().__init__()
        self.parent_main = parent_main
        self.running_commands = {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        self.bettercap_list = QListWidget()
        layout.addWidget(self.bettercap_list)

        commands = [
            (
                "Net Probe (bettercap -eval net.probe on)",
                "Actively probe the network for hidden hosts."
            ),
            (
                "ARP Spoof (bettercap -eval arp.spoof on)",
                "Perform ARP poisoning, intercept traffic on LAN."
            ),
            (
                "DNS Spoof (bettercap -eval dns.spoof on)",
                "Redirect DNS queries to a chosen IP. Usually combine with ARP spoof."
            ),
            (
                "Net Sniff (bettercap -eval net.sniff on)",
                "Capture packets in real time, might require 'net.probe' on some versions."
            ),
            (
                "Any Proxy (bettercap -eval any.proxy on)",
                "Intercept TCP/UDP traffic for any protocol. Potentially advanced usage."
            ),
            (
                "HTTP Proxy (bettercap -eval http.proxy on)",
                "Intercept/modify HTTP traffic. Great for injecting scripts or capturing data."
            ),
            (
                "HTTPS Proxy (bettercap -eval https.proxy on)",
                "Attempt SSL stripping or intercept TLS. Risky, advanced usage."
            ),
            (
                "Wifi Recon (bettercap -eval wifi.recon on)",
                "Scan for nearby Wi-Fi networks/clients (requires a Wi-Fi interface)."
            ),
            (
                "Ticker (bettercap -eval ticker on)",
                "Periodically prints a small summary of discovered endpoints."
            )
        ]

        for display_text, tip in commands:
            item = QListWidgetItem(display_text)
            item.setToolTip(tip)
            self.bettercap_list.addItem(item)

        self.bettercap_list.itemDoubleClicked.connect(self.on_item_double_clicked)

        btn_layout = QHBoxLayout()
        layout.addLayout(btn_layout)

        self.btn_run = QPushButton("Run Selected")
        self.btn_run.clicked.connect(self.run_selected_command)
        btn_layout.addWidget(self.btn_run)

        self.btn_stop = QPushButton("Stop Selected")
        self.btn_stop.clicked.connect(self.stop_selected_command)
        btn_layout.addWidget(self.btn_stop)

    def on_item_double_clicked(self, item):
        if not item:
            return
        cmd_str = self.parse_command(item.text())
        if cmd_str in self.running_commands:
            self.stop_command(cmd_str)
        else:
            self.run_command(cmd_str)

    def run_selected_command(self):
        item = self.bettercap_list.currentItem()
        if not item:
            self.parent_main.log_bettercap("No command selected.")
            return
        cmd_str = self.parse_command(item.text())
        self.run_command(cmd_str)

    def stop_selected_command(self):
        item = self.bettercap_list.currentItem()
        if not item:
            self.parent_main.log_bettercap("No command selected.")
            return
        cmd_str = self.parse_command(item.text())
        if cmd_str in self.running_commands:
            self.stop_command(cmd_str)
        else:
            self.parent_main.log_bettercap(f"'{cmd_str}' not currently running.")

    def run_command(self, cmd_str):
        if cmd_str in self.running_commands:
            self.parent_main.log_bettercap(f"'{cmd_str}' is already running.")
            return

        self.parent_main.log_bettercap(f"[*] Starting: {cmd_str}")
        cmd_list = cmd_str.split()

        thread = ExternalProcessThread(cmd_list)
        thread.output_signal.connect(self.parent_main.log_bettercap)
        thread.finished_signal.connect(lambda code, c=cmd_str: self.on_command_finished(code, c))
        thread.start()

        self.running_commands[cmd_str] = thread

    def stop_command(self, cmd_str):
        thr = self.running_commands.get(cmd_str)
        if thr:
            self.parent_main.log_bettercap(f"[*] Stopping: {cmd_str}")
            thr.stop()
            del self.running_commands[cmd_str]
        else:
            self.parent_main.log_bettercap(f"No thread found for '{cmd_str}'")

    def on_command_finished(self, exit_code, cmd_str):
        if cmd_str in self.running_commands:
            del self.running_commands[cmd_str]
        self.parent_main.log_bettercap(f"[+] '{cmd_str}' finished (exit code {exit_code}).")

    @staticmethod
    def parse_command(full_text: str) -> str:
        # e.g. "ARP Spoof (bettercap -eval arp.spoof on)" => "bettercap -eval arp.spoof on"
        if "(" in full_text and ")" in full_text:
            return full_text.split("(")[-1].split(")")[0].strip()
        return ""
