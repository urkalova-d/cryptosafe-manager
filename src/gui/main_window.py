import tkinter as tk
from .widgets.secure_table import SecureTable


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSafe Manager")
        self.geometry("800x500")

        self.create_menu()
        self.create_widgets()
        self.create_status_bar()

    def create_menu(self):
        menubar = tk.Menu(self)

        # Меню Файл
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Создать")
        file_menu.add_command(label="Открыть")
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.quit)
        menubar.add_cascade(label="Файл", menu=file_menu)

        # Меню Правка
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить")
        edit_menu.add_command(label="Редактировать")
        edit_menu.add_command(label="Удалить")
        menubar.add_cascade(label="Правка", menu=edit_menu)

        self.config(menu=menubar)

    def create_widgets(self):
        # Центральный виджет таблицы
        self.table = SecureTable(self)
        self.table.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    def create_status_bar(self):
        self.status_bar = tk.Label(self, text="Статус: Вход выполнен | Таймер: 00:00",
                                   bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)