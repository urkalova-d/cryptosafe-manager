# src/gui/add_record_window.py
import tkinter as tk
from tkinter import messagebox
from src.gui.widgets.password_entry import PasswordEntry


class AddRecordWindow(tk.Toplevel):
    def __init__(self, parent, save_callback):
        """
        Окно для добавления новой записи в хранилище.
        :param parent: Родительское окно (MainWindow)
        :param save_callback: Функция для сохранения данных в БД
        """
        super().__init__(parent)
        self.title("Добавить новую запись")
        self.geometry("350x450")
        self.save_callback = save_callback

        # Делаем окно модальным (пользователь не может взаимодействовать с главным окном, пока не закроет это)
        self.transient(parent)
        self.grab_set()

        self.create_widgets()

    def create_widgets(self):
        # Отступы для элементов
        pad_x = 15
        pad_y = 5

        # --- Поля ввода ---

        # Название сервиса
        tk.Label(self, text="Сервис (напр. Google):", font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=pad_x,
                                                                                       pady=(15, 0))
        self.service_entry = tk.Entry(self)
        self.service_entry.pack(fill=tk.X, padx=pad_x, pady=pad_y)
        self.service_entry.focus_set()  # Фокус на первом поле

        # Логин
        tk.Label(self, text="Логин / Email:", font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=pad_x, pady=(10, 0))
        self.login_entry = tk.Entry(self)
        self.login_entry.pack(fill=tk.X, padx=pad_x, pady=pad_y)

        # Пароль (используем наш виджет с "глазиком")
        tk.Label(self, text="Пароль:", font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=pad_x, pady=(10, 0))
        self.password_entry = PasswordEntry(self)
        self.password_entry.pack(fill=tk.X, padx=pad_x, pady=pad_y)

        # Примечания
        tk.Label(self, text="Примечания:", font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=pad_x, pady=(10, 0))
        self.notes_text = tk.Text(self, height=4, font=("Arial", 9))
        self.notes_text.pack(fill=tk.BOTH, padx=pad_x, pady=pad_y)

        # --- Кнопки ---
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X, pady=20)

        self.save_btn = tk.Button(btn_frame, text="Сохранить", command=self.on_save, bg="#4CAF50", fg="white",
                                  font=("Arial", 10, "bold"))
        self.save_btn.pack(side=tk.RIGHT, padx=pad_x)

        self.cancel_btn = tk.Button(btn_frame, text="Отмена", command=self.destroy)
        self.cancel_btn.pack(side=tk.RIGHT, padx=pad_x)

    def on_save(self):
        """Обработка нажатия кнопки Сохранить (СЕК-2)"""
        service = self.service_entry.get().strip()
        login = self.login_entry.get().strip()
        password = self.password_entry.get()
        notes = self.notes_text.get("1.0", tk.END).strip()

        # --- Валидация данных (СЕК-2) ---
        if not service or not login or not password:
            messagebox.showwarning("Ошибка", "Заполните все обязательные поля (Сервис, Логин, Пароль)!", parent=self)
            return

        if len(password) < 8:
            messagebox.showwarning("Ошибка", "Пароль должен содержать минимум 8 символов!", parent=self)
            return

        # Если валидация прошла успешно, отправляем данные дальше
        self.save_callback(service, login, password, notes)
        self.destroy()  # Закрываем окно