from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QPushButton, QHBoxLayout,
    QListWidgetItem
)
from PyQt6.QtCore import Qt

from external_process_thread import ExternalProcessThread

class ResponderPanel(QWidget):
    """
    Responder commands with hover tooltips.
    Adjust if your environment differs.
    """
    def __init__(self, parent_main):
        super().__init__()
        self.parent_main = parent_main
        self.running_commands = {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        self.responder_list = QListWidget()
        layout.addWidget(self.responder_list)

        commands = [
            (
                "Basic (responder -I eth0)",
                "Start Responder on eth0 with default poisoning (LLMNR, NBT-NS, MDNS)."
            ),
            (
                "All Flags (responder -I eth0 -rdwv)",
                "Respond to many protocols, verbose logging, etc."
            ),
            (
                "Analyze Only (responder -I eth0 -A)",
                "No poisoning, just analyzing requests on eth0."
            ),
            (
                "All but NetBIOS (responder -I eth0 -N)",
                "Disable NetBIOS, only respond to LLMNR/MDNS."
            ),
            (
                "Any (responder -I any -dw)",
                "Listen on all interfaces, for some advanced setups."
            )
        ]

        for display_text, tip in commands:
            item = QListWidgetItem(display_text)
            item.setToolTip(tip)
            self.responder_list.addItem(item)

        self.responder_list.itemDoubleClicked.connect(self.on_item_double_clicked)

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
        item = self.responder_list.currentItem()
        if not item:
            self.parent_main.log_responder("No command selected.")
            return
        cmd_str = self.parse_command(item.text())
        self.run_command(cmd_str)

    def stop_selected(self):
        item = self.responder_list.currentItem()
        if not item:
            self.parent_main.log_responder("No command selected.")
            return
        cmd_str = self.parse_command(item.text())
        if cmd_str in self.running_commands:
            self.stop_command(cmd_str)
        else:
            self.parent_main.log_responder(f"'{cmd_str}' not running.")

    def run_command(self, cmd_str):
        if cmd_str in self.running_commands:
            self.parent_main.log_responder(f"'{cmd_str}' is already running.")
            return

        self.parent_main.log_responder(f"[*] Starting: {cmd_str}")
        cmd_list = cmd_str.split()

        thread = ExternalProcessThread(cmd_list)
        thread.output_signal.connect(self.parent_main.log_responder)
        thread.finished_signal.connect(lambda code, c=cmd_str: self.on_command_finished(code, c))
        thread.start()

        self.running_commands[cmd_str] = thread

    def stop_command(self, cmd_str):
        thr = self.running_commands.get(cmd_str)
        if thr:
            self.parent_main.log_responder(f"[*] Stopping: {cmd_str}")
            thr.stop()
            del self.running_commands[cmd_str]
        else:
            self.parent_main.log_responder(f"No thread found for '{cmd_str}'")

    def on_command_finished(self, exit_code, cmd_str):
        if cmd_str in self.running_commands:
            del self.running_commands[cmd_str]
        self.parent_main.log_responder(f"[+] '{cmd_str}' finished (exit code {exit_code}).")

    @staticmethod
    def parse_command(full_text: str) -> str:
        # e.g. "All Flags (responder -I eth0 -rdwv)" => "responder -I eth0 -rdwv"
        if "(" in full_text and ")" in full_text:
            return full_text.split("(")[-1].split(")")[0].strip()
        return ""
