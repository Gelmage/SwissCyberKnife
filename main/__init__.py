# main.py
import sys

from PyQt6.QtWidgets import QApplication

from gui import MainWindow

if __name__ == "__main__":
    app = QApplication(sys.argv)     # Must come BEFORE creating any widgets
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
