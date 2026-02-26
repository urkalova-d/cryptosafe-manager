# main.py
from src.gui.main_window import MainWindow
from src.gui.setup_wizard import SetupWizard
import os

def start_app():
    app = MainWindow()
    app.mainloop()

if __name__ == "__main__":
    # Для теста: если базы нет, запускаем мастер
    if not os.path.exists("vault.db"):
        root = tk.Tk()
        root.withdraw() # Прячем основное окно на время настройки
        wizard = SetupWizard(callback=start_app)
        root.mainloop()
    else:
        start_app()