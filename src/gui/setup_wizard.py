import tkinter as tk
from .widgets.password_entry import PasswordEntry

class SetupWizard(tk.Toplevel):
    def __init__(self, callback):
        super().__init__()
        self.title("Первая настройка")
        self.callback = callback  # Функция, которую вызовем по завершении

        tk.Label(self, text="Установите Мастер-пароль:").pack(pady=5)
        self.pass1 = PasswordEntry(self)
        self.pass1.pack(padx=20)

        tk.Label(self, text="Подтвердите пароль:").pack(pady=5)
        self.pass2 = PasswordEntry(self)
        self.pass2.pack(padx=20)

        tk.Button(self, text="Завершить настройку", command=self.finish).pack(pady=20)

    def finish(self):
        if self.pass1.get() == self.pass2.get() and len(self.pass1.get()) > 0:
            self.callback()
            self.destroy()
        else:
            print("Пароли не совпадают!")