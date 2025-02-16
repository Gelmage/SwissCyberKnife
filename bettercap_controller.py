# In bettercap_controller.py
class BettercapSession(QObject):
    log_signal = pyqtSignal(str)
    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface or "default"
        self.proc = None

    def start(self):
        # Launch Bettercap as a subprocess
        cmd = ["bettercap"]
        if self.interface:
            cmd += ["-iface", self.interface]
        # Start in interactive mode. We'll send commands via stdin.
        self.proc = QProcess()
        self.proc.setProcessChannelMode(QProcess.MergedChannels)  # combine stdout & stderr
        self.proc.startDetached(" ".join(cmd))  # Alternatively, use start() and readyRead
        # (For actual implementation, QProcess.readyReadStandardOutput signal should be connected to a slot that reads self.proc.readAllStandardOutput and emits log_signal)

    def send_command(self, cmd_str):
        if self.proc:
            self.proc.write((cmd_str + "\n").encode())

    def stop(self):
        if self.proc:
            self.send_command("exit")  # tell bettercap to quit
            self.proc = None

    # ... (slot to handle output reading and emit log_signal)
