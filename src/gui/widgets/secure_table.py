from tkinter import ttk

class SecureTable(ttk.Treeview):
    def __init__(self, master, **kwargs):
        columns = ("service", "username", "password")
        super().__init__(master, columns=columns, show="headings", **kwargs)

        self.heading("service", text="Сервис")
        self.heading("username", text="Логин")
        self.heading("password", text="Пароль")

        # Добавим тестовую строку (заполнитель)
        self.insert("", "end", values=("Google", "darya@mail.ru", "********"))