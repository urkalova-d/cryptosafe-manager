import tkinter as tk
from tkinter import ttk


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSafe Manager - Sprint 1")
        self.geometry("600x400")

        # Меню (Requirement GUI-1)
        menu_bar = tk.Menu(self)
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="New Database")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)
        self.config(menu=menu_bar)

        # Таблица (Central Widget)
        self.table = ttk.Treeview(self, columns=("Title", "User"), show='headings')
        self.table.heading("Title", text="Title")
        self.table.heading("User", text="Username")
        self.table.pack(fill=tk.BOTH, expand=True)


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()