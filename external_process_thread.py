import subprocess
import signal
import time
import re
from PyQt6.QtCore import QThread, pyqtSignal

class ExternalProcessThread(QThread):
    """
    Runs a shell command in a background thread, emitting each line of output.
    Strips ANSI color codes. 'stop()' => SIGINT, wait 2s, then kill if needed.
    """
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)

    ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    def __init__(self, cmd_list):
        super().__init__()
        self.cmd_list = cmd_list
        self.proc = None

    def run(self):
        try:
            self.proc = subprocess.Popen(
                self.cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    break
                clean_line = self.ANSI_ESCAPE.sub('', line)
                self.output_signal.emit(clean_line.rstrip('\n'))
            exit_code = self.proc.wait()
            self.finished_signal.emit(exit_code)
        except Exception as e:
            self.output_signal.emit(f"Error running command: {e}")
            self.finished_signal.emit(-1)

    def stop(self):
        """Send SIGINT, wait 2s, kill if still alive."""
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            time.sleep(2)
            if self.proc.poll() is None:
                self.proc.kill()
        self.quit()
        self.wait()
