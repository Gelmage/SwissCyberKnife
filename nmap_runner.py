from PyQt6.QtCore import pyqtSignal, QThread
import subprocess
import shlex

class NmapScanner(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)  # exit code

    def __init__(self, target, options):
        super().__init__()
        self.target = target
        self.options = options  # e.g., "-sV -O"

    def run(self):
        cmd = f"nmap {self.options} {self.target}"
        proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        # Read output line by line
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            self.output_signal.emit(line.rstrip())
        exit_code = proc.wait()
        self.finished_signal.emit(exit_code)
