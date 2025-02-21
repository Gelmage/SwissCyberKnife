from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QPushButton, QHBoxLayout,
    QListWidgetItem
)
from PyQt6.QtCore import Qt

from external_process_thread import ExternalProcessThread

class EttercapPanel(QWidget):
    """
    Ettercap commands with hover tooltips. Adjust interface or commands as needed.
    """
    def __init__(self, parent_main):
        super().__init__()
        self.parent_main = parent_main
        self.running_commands = {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        self.ettercap_list = QListWidget()
        layout.addWidget(self.ettercap_list)

        commands = [
            (
                "Unified Sniff (ettercap -T -i eth0)",
                "Text mode sniff on eth0. ARP by default."
            ),
            (
                "ARP MITM (ettercap -T -M arp -i eth0)",
                "ARP poisoning for MITM on eth0."
            ),
            (
                "Bridged Sniff (ettercap -T -q -i eth0 --iface2 wlan0)",
                "Sniff bridging traffic between two interfaces."
            ),
            (
                "DNS Spoof Plugin (ettercap -T -i eth0 -P dns_spoof)",
                "Enable DNS spoof plugin while sniffing on eth0."
            )
        ]

        for display_text, tip in commands:
            item = QListWidgetItem(display_text)
            item.setToolTip(tip)
            self.ettercap_list.addItem(item)

        self.ettercap_list.itemDoubleClicked.connect(self.on_item_double_clicked)

        btn_layout = QHBoxLayout()
        layout.addLayout(btn_layout)

        self.btn_run = QPushButton("Run Selected")
        self.btn_run.clicked.connect(self.run_selected)
        btn_layout.addWidget(self.btn_run)

        self.btn_stop = QPushButton("Stop Selected")
        self.btn_stop.clicked.connect(self.stop_selected)
        btn_layout.addWidget(self.btn_stop)

    def on_item_double_clicked(self, item):
        if item:
            cmd_str = self.parse_command(item.text())
            if cmd_str in self.running_commands:
                self.stop_command(cmd_str)
            else:
                self.run_command(cmd_str)

    def run_selected(self):
        item = self.ettercap_list.currentItem()
        if not item:
            self.parent_main.log_ettercap("No command selected.")
            return
        cmd_str = self.parse_command(item.text())
        self.run_command(cmd_str)

    def stop_selected(self):
        item = self.ettercap_list.currentItem()
        if not item:
            self.parent_main.log_ettercap("No command selected.")
            return
        cmd_str = self.parse_command(item.text())
        if cmd_str in self.running_commands:
            self.stop_command(cmd_str)
        else:
            self.parent_main.log_ettercap(f"'{cmd_str}' not running.")

    def run_command(self, cmd_str):
        if cmd_str in self.running_commands:
            self.parent_main.log_ettercap(f"'{cmd_str}' already running.")
            return

        self.parent_main.log_ettercap(f"[*] Starting: {cmd_str}")
        cmd_list = cmd_str.split()

        thread = ExternalProcessThread(cmd_list)
        thread.output_signal.connect(self.parent_main.log_ettercap)
        thread.finished_signal.connect(lambda code, c=cmd_str: self.on_command_finished(code, c))
        thread.start()

        self.running_commands[cmd_str] = thread

    def stop_command(self, cmd_str):
        thr = self.running_commands.get(cmd_str)
        if thr:
            self.parent_main.log_ettercap(f"[*] Stopping: {cmd_str}")
            thr.stop()
            del self.running_commands[cmd_str]
        else:
            self.parent_main.log_ettercap(f"No thread found for '{cmd_str}'")

    def on_command_finished(self, exit_code, cmd_str):
        if cmd_str in self.running_commands:
            del self.running_commands[cmd_str]
        self.parent_main.log_ettercap(f"[+] '{cmd_str}' finished (exit code {exit_code}).")

    @staticmethod
    def parse_command(full_text: str) -> str:
        # e.g. "ARP MITM (ettercap -T -M arp -i eth0)"
        if "(" in full_text and ")" in full_text:
            return full_text.split("(")[-1].split(")")[0].strip()
        return ""
