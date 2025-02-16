# bettercap_controller.py
from PyQt6.QtCore import QObject, pyqtSignal

class BettercapSession(QObject):
    log_signal = pyqtSignal(str)
    
    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface or "default"
        self.proc = None

    def start(self):
        # Example logic (stub)
        # e.g. start bettercap as a subprocess, connect signals, etc.
        pass

    def send_command(self, cmd_str):
        # e.g. send commands to bettercap process
        pass

    def stop(self):
        # e.g. gracefully stop bettercap
        pass
