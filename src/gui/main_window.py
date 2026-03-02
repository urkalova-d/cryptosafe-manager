
import tkinter as tk
from tkinter import ttk, messagebox
from src.database.db import DatabaseHelper
from src.core.key_manager import KeyManager
from src.core.crypto.placeholder import AES256Placeholder
from src.gui.add_record_window import AddRecordWindow
from src.gui.widgets.secure_table import SecureTable
from src.gui.setup_wizard import SetupWizard
from src.gui.settings_dialog import SettingsDialog
from src.gui.login_window import LoginWindow  # Импортируем окно логина


class MainWindow(tk.Tk):
    # src/gui/main_window.py (метод __init__)
    def __init__(self):
        super().__init__()
        self.title("CryptoSafe Password Manager")
        self.geometry("1000x650")

        self.db_helper = DatabaseHelper()
        self.current_master_password = None

        # 1. Сначала инициализируем все элементы
        self.create_app_menu()
        self.create_toolbar()
        self.create_table_area()
        self.create_status_bar()

        # 2. Потом делаем проверки первого запуска
        self.check_first_run()

        # 3. ТОЛЬКО ТЕПЕРЬ ПОКАЗЫВАЕМ ОКНО
        self.deiconify()

    def show_login_window(self):
        """Вызывает окно логина (Привязка функций!)"""
        LoginWindow(self, self.check_password)

    def check_password(self, password):
        """Реальная проверка пароля через базу данных"""
        # Используем метод, который мы только что успешно протестировали
        if self.db_helper.verify_master_password(password):
            self.current_master_password = password
            self.load_data()
            return True
        else:
            return False

    def create_app_menu(self):
        """Панель меню (Графический интерфейс-1)"""
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        # Файл
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Создать", command=lambda: print("Создать"))
        file_menu.add_command(label="Открыть", command=lambda: print("Открыть"))
        file_menu.add_separator()
        file_menu.add_command(label="Создать резервную копию", command=lambda: print("Резервная копия"))
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.quit)
        menu_bar.add_cascade(label="Файл", menu=file_menu)

        # Правка (Привязка функций!)
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        edit_menu.add_command(label="Добавить", command=self.open_add_window)
        edit_menu.add_command(label="Редактировать", command=lambda: print("Редактировать"))
        edit_menu.add_command(label="Удалить выбранное", command=self.delete_selected)
        menu_bar.add_cascade(label="Правка", menu=edit_menu)

        # Просмотр (Привязка функций!)
        view_menu = tk.Menu(menu_bar, tearoff=0)
        view_menu.add_command(label="Журналы", command=lambda: print("Журналы"))
        view_menu.add_command(label="Настройки", command=self.open_settings)
        menu_bar.add_cascade(label="Просмотр", menu=view_menu)

    def create_toolbar(self):
        """Панель инструментов с кнопками (Привязка функций!)"""
        toolbar = tk.Frame(self, bd=1, relief=tk.RAISED, bg="#f0f0f0")

        # Кнопки действий (Привязка функций!)
        tk.Button(toolbar, text="➕ Добавить", command=self.open_add_window, bg="#e1e1e1").pack(side=tk.LEFT, padx=2,
                                                                                               pady=5)
        tk.Button(toolbar, text="🗑️ Удалить", command=self.delete_selected, bg="#e1e1e1").pack(side=tk.LEFT, padx=2,
                                                                                               pady=5)
        tk.Button(toolbar, text="📋 Копировать логин", command=self.copy_login, bg="#e1e1e1").pack(side=tk.LEFT, padx=2,
                                                                                                  pady=5)

        # Поиск (Фильтрация данных)
        tk.Label(toolbar, text="  🔍 Поиск:", bg="#f0f0f0").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda name, index, mode: self.load_data())
        self.search_entry = tk.Entry(toolbar, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        toolbar.pack(side=tk.TOP, fill=tk.X)

    def create_table_area(self):
        """Центральная таблица (ГИ-2)"""
        self.table_container = tk.Frame(self)
        self.table_container.pack(expand=True, fill=tk.BOTH)
        self.table = SecureTable(self.table_container)
        self.table.pack(expand=True, fill=tk.BOTH)

    def create_status_bar(self):
        """Строка состояния (Графический интерфейс-1)"""
        self.status_frame = tk.Frame(self, bd=1, relief=tk.SUNKEN)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_var = tk.StringVar(value="Система готова")
        self.status_label = tk.Label(self.status_frame, textvariable=self.status_var, anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, padx=5)

        self.timer_label = tk.Label(self.status_frame, text="Таймер: 0s", anchor=tk.E)
        self.timer_label.pack(side=tk.RIGHT, padx=5)

    # --- ЛОГИКА И ФУНКЦИИ (BINDING) ---

    def check_first_run(self):
        """Проверка первого запуска"""
        if not self.db_helper.get_setting("master_salt"):
            wizard = SetupWizard(self)
            self.wait_window(wizard)  # Ждем строго до закрытия окна

        # ПРОВЕРКА: Если после визарда соль так и не появилась - значит была ошибка
        if not self.db_helper.get_setting("master_salt"):
            messagebox.showerror("Ошибка", "Мастер-пароль не был сохранен!")
            self.destroy()
            return

        self.deiconify()
        self.show_login_window()

    def open_settings(self):
        """Открыть настройки (ГИ-4)"""
        SettingsDialog(self)

    def load_data(self):
        """Загрузка с учетом фильтра поиска"""
        query = self.search_var.get().lower()

        for item in self.table.get_children():
            self.table.delete(item)

        entries = self.db_helper.get_all_entries()
        count = 0
        for entry in entries:
            # Фильтрация
            if query in entry['title'].lower() or query in entry['username'].lower():
                self.table.insert("", "end", values=(entry['title'], entry['username'], "********"))
                count += 1

        self.status_var.set(f"Отображено записей: {count}")

    def delete_selected(self):
        """Удаление записи"""
        selected_item = self.table.selection()
        if not selected_item:
            messagebox.showwarning("Внимание", "Выберите запись для удаления")
            return

        if messagebox.askyesno("Подтверждение", "Вы уверены, что хотите удалить эту запись?"):
            values = self.table.item(selected_item)['values']
            # Здесь будет вызов db_helper.delete_entry(values[0]) (для Спринта 2)
            self.status_var.set(f"Удалено: {values[0]}")
            self.table.delete(selected_item)

    def copy_login(self):
        """Копирование логина в буфер обмена"""
        selected_item = self.table.selection()
        if selected_item:
            login = self.table.item(selected_item)['values'][1]
            self.clipboard_clear()
            self.clipboard_append(login)
            self.status_var.set("Логин скопирован в буфер")

    def open_add_window(self):
        """Открыть окно добавления"""
        AddRecordWindow(self, self.handle_save)

    def handle_save(self, service, login, password, notes):
        """Шифрование и сохранение (СЕК-2, ДБ-2)"""
        km = KeyManager()
        salt_str = self.db_helper.get_setting("master_salt")

        if not salt_str:
            salt = km.salt
            self.db_helper.save_setting("master_salt", salt.hex())
        else:
            salt = bytes.fromhex(salt_str)

        encryption_key = km.derive_key(self.current_master_password, salt)
        crypto = AES256Placeholder()
        encrypted_pass = crypto.encrypt(password.encode(), encryption_key)

        self.db_helper.add_entry(service, login, encrypted_pass.decode('latin-1'), notes=notes)
        self.load_data()