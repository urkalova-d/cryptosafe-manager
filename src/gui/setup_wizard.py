# src/gui/setup_wizard.py
import tkinter as tk
from tkinter import ttk, messagebox


class SetupWizard(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Первая настройка")
        self.geometry("400x300")

        # Делаем окно модальным
        self.transient(parent)
        self.grab_set()

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Придумайте мастер-пароль", font=("Arial", 12, "bold")).pack(pady=15)
        ttk.Label(self, text="Этот пароль будет защищать все ваши данные.\nНе забудьте его!", justify=tk.CENTER).pack(
            pady=5)

        self.pass_entry = ttk.Entry(self, show="*")
        self.pass_entry.pack(pady=10, fill=tk.X, padx=40)

        ttk.Label(self, text="Повторите пароль:").pack()
        self.confirm_entry = ttk.Entry(self, show="*")
        self.confirm_entry.pack(pady=10, fill=tk.X, padx=40)

        ttk.Button(self, text="Завершить настройку", command=self.save_and_exit).pack(pady=20)

    def save_and_exit(self):
        p1 = self.pass_entry.get()
        p2 = self.confirm_entry.get()

        if len(p1) < 8:
            messagebox.showerror("Ошибка", "Пароль должен быть не короче 8 символов!")
            return

        if p1 != p2:
            messagebox.showerror("Ошибка", "Пароли не совпадают!")
            return

        # СОХРАНЯЕМ В БАЗУ (то, чего нам не хватало)
        self.parent.db_helper.save_master_password(p1)
        messagebox.showinfo("Успех", "Мастер-пароль успешно установлен!")
        self.destroy()