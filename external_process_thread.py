import subprocess
from PyQt6.QtCore import QThread, pyqtSignal

class ExternalProcessThread(QThread):
    """
    Runs a shell command in a background thread, emitting each line of output.
    Keeps the GUI responsive and allows real-time logging.
    """
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)

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
            # Read output line-by-line
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    break
                self.output_signal.emit(line.rstrip("\n"))
            exit_code = self.proc.wait()
            self.finished_signal.emit(exit_code)
        except Exception as e:
            self.output_signal.emit(f"Error running command: {e}")
            self.finished_signal.emit(-1)

    def stop(self):
        """Terminate the underlying process if it's still running."""
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
        self.quit()
        self.wait()
