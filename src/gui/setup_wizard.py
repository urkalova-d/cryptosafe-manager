# src/gui/setup_wizard.py
import tkinter as tk
from tkinter import ttk, messagebox


class SetupWizard(tk.Toplevel):
    def __init__(self, parent=None, callback=None): # Добавь callback=None
        super().__init__(parent)
        self.callback = callback
        self.title("Первая настройка")
        self.geometry("400x300")

        # Делаем окно модальным
        self.transient(parent)
        self.grab_set()

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Придумайте мастер-пароль", font=("Arial", 12, "bold")).pack(pady=15)

        # Создаем структуру, которую ждет тест (атрибут.entry)
        self.pass1 = tk.Frame(self)
        self.pass1.entry = ttk.Entry(self, show="*")
        self.pass1.entry.pack(pady=10, fill=tk.X, padx=40)

        ttk.Label(self, text="Повторите пароль:").pack()
        self.pass2 = tk.Frame(self)
        self.pass2.entry = ttk.Entry(self, show="*")
        self.pass2.entry.pack(pady=10, fill=tk.X, padx=40)

        ttk.Button(self, text="Завершить настройку", command=self.save_and_exit).pack(pady=20)

    def save_and_exit(self):
        # Берем данные из новых имен переменных, которые ожидает тест
        p1 = self.pass1.entry.get()
        p2 = self.pass2.entry.get()  # Исправлено с self.confirm_entry на self.pass2.entry

        if len(p1) < 8:
            messagebox.showerror("Ошибка", "Пароль слишком короткий (мин. 8 символов)")
            return

        if p1 != p2:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return

        if self.callback:
            self.callback(p1)

        self.destroy()

    def finish(self):
        # Просто перенаправляем вызов на твой существующий метод
        self.save_and_exit()