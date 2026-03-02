# src/gui/login_window.py
import tkinter as tk
from tkinter import ttk, messagebox
from src.gui.widgets.password_entry import PasswordEntry


class LoginWindow(tk.Toplevel):
    def __init__(self, parent, check_password_callback):
        super().__init__(parent)
        self.title("Вход")
        self.geometry("300x200")
        self.check_password_callback = check_password_callback

        # Модальное окно (блокирует родительское)
        self.transient(parent)
        self.grab_set()

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Введите мастер-пароль", font=("Arial", 11)).pack(pady=20)

        self.password_entry = PasswordEntry(self)
        self.password_entry.pack(fill=tk.X, padx=20)
        self.password_entry.focus_set()

        ttk.Button(self, text="Войти", command=self.check_password).pack(pady=20)

        # Закрытие программы при закрытии окна логина
        self.protocol("WM_DELETE_WINDOW", self.parent_quit)

    def check_password(self):
        password = self.password_entry.get()
        if self.check_password_callback(password):
            self.destroy()  # Закрываем окно логина
        else:
            messagebox.showerror("Ошибка", "Неверный мастер-пароль!")

    def parent_quit(self):
        self.master.quit()