# main.py
from src.gui.main_window import MainWindow
from src.gui.setup_wizard import SetupWizard
import os
def start_app():
    """Функция для запуска приложения."""
    app = MainWindow()
    app.mainloop()

if __name__ == "__main__":
    start_app()