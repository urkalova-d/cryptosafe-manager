import sys
import time
from PyQt6.QtWidgets import QApplication
from src.gui.main_window import MainWindow


def start_app():
    time.sleep(0.1)
    app = QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec())


if __name__ == "__main__":
    start_app()