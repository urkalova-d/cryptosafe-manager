# src/gui/settings_dialog.py
import tkinter as tk
from tkinter import ttk


class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Настройки")
        self.geometry("500x400")
        self.transient(parent)
        self.grab_set()

        self.create_widgets()

    def create_widgets(self):
        tab_control = ttk.Notebook(self)

        # Вкладки (ГИ-4)
        security_tab = ttk.Frame(tab_control)
        appearance_tab = ttk.Frame(tab_control)
        advanced_tab = ttk.Frame(tab_control)

        tab_control.add(security_tab, text='Безопасность')
        tab_control.add(appearance_tab, text='Внешний вид')
        tab_control.add(advanced_tab, text='Расширенные')

        tab_control.pack(expand=1, fill="both")

        # Наполнение Вкладки Безопасность (ГИ-4)
        ttk.Label(security_tab, text="Время ожидания буфера (с):").pack(pady=10)
        ttk.Spinbox(security_tab, from_=5, to=60).pack()
        ttk.Checkbutton(security_tab, text="Автоматическая блокировка").pack(pady=10)

        # Наполнение Вкладки Внешний вид (ГИ-4)
        ttk.Label(appearance_tab, text="Тема:").pack(pady=10)
        ttk.Combobox(appearance_tab, values=["Light", "Dark"]).pack()

        # Наполнение Вкладки Расширенные (ГИ-4)
        ttk.Button(advanced_tab, text="Экспорт БД", command=lambda: print("Экспорт")).pack(pady=10)
        ttk.Button(advanced_tab, text="Резервная копия", command=lambda: print("Бэкап")).pack(pady=10)