#!/usr/bin/env python3
import sys
import os

from PyQt6.QtWidgets import QApplication
from main_window import MainWindow

def ensure_privileges():
    """
    If not running as root, relaunch with sudo.
    Adjust or remove if you already run 'sudo python3 main.py'.
    """
    if os.geteuid() != 0:
        print("Re-launching with sudo for root privileges...")
        os.execvp('sudo', ['sudo', sys.executable] + sys.argv)

if __name__ == "__main__":
    ensure_privileges()
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
