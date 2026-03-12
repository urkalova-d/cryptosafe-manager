import tkinter as tk
from tkinter import ttk, messagebox


class SetupWizard(tk.Toplevel):
    def __init__(self, parent=None, callback=None):
        super().__init__(parent)
        self.callback = callback
        self.title("Первая настройка")
        self.geometry("400x350")

        # делает окно поверх другого
        if parent:
            self.transient(parent)
            self.grab_set()

        self.create_widgets()

    def create_widgets(self):
        #загаловки
        ttk.Label(self, text="Придумайте мастер-пароль", font=("Arial", 12, "bold")).pack(pady=15)
        ttk.Label(self, text="Этот пароль защищает все ваши данные.", justify=tk.CENTER).pack(pady=5)

        # ПОЛЕ 1 (Структура для теста: self.pass1.entry)
        self.pass1 = tk.Frame(self)
        self.pass1.pack(fill=tk.X, padx=40)

        ttk.Label(self.pass1, text="Новый пароль:").pack(anchor=tk.W)
        self.pass1.entry = ttk.Entry(self.pass1, show="*")
        self.pass1.entry.pack(pady=5, fill=tk.X)

        # ПОЛЕ 2 (Структура для теста: self.pass2.entry)
        self.pass2 = tk.Frame(self)
        self.pass2.pack(fill=tk.X, padx=40, pady=10)

        ttk.Label(self.pass2, text="Повторите пароль:").pack(anchor=tk.W)
        self.pass2.entry = ttk.Entry(self.pass2, show="*")
        self.pass2.entry.pack(pady=5, fill=tk.X)

        #кнопка завершения
        self.btn_finish = ttk.Button(self, text="Завершить настройку", command=self.save_and_exit)
        self.btn_finish.pack(pady=20)

    def save_and_exit(self):
        #получаю текст из вложенных полей
        p1 = self.pass1.entry.get()
        p2 = self.pass2.entry.get()

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

        self.save_and_exit()#метод для вызова из тестов