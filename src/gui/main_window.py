import sys
from PyQt6.QtGui import QAction

from src.database.db import DatabaseHelper
from src.gui.setup_wizard import SetupWizard
from src.gui.add_record_window import AddRecordWindow
from src.gui.widgets.secure_table import SecureTable
from PyQt6.QtCore import Qt, QTimer

from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QMessageBox,
                             QTableWidget,QApplication, QTableWidgetItem, QHeaderView,
                             QMenuBar, QMenu, QStatusBar, QToolBar, QLabel)

from PyQt6.QtCore import QObject, pyqtSignal, QThread

from src.core.crypto.key_manager import KeyManager
from src.core.crypto.authentication import AuthenticationService
from src.core.crypto.encryption_service import EncryptionService
from PyQt6.QtCore import QEvent

class LoadDataWorker(QObject):
    # Сигнал передает список расшифрованных записей
    finished = pyqtSignal(list)
    # Сигнал для передачи ошибок, если что-то пойдет не так
    error = pyqtSignal(str)

    def __init__(self, db_manager):
        super().__init__()
        self.db = db_manager

    def run(self):
        try:
            records = self.db.get_all_entries()
            self.finished.emit(records)
        except Exception as e:
            self.error.emit(str(e))
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptoSafe Password Manager")
        self.resize(1000, 650)

        # инициализация базы данных и переменных
        from src.database.db import db_manager
        self.db_helper = db_manager
        self.current_master_password = None

        # настройка таймера очистки
        self.clipboard_timer = QTimer()
        self.clipboard_timer.timeout.connect(self.update_timer_label)
        self.remaining_time = 0

        # построение интерфейса
        self.init_ui()

        QTimer.singleShot(100, self.check_first_run)

        self.loading_thread = None
        #инициализация криптостека
        self.key_manager = KeyManager(self.db_helper)
        self.auth_service = AuthenticationService(self.key_manager,self.db_helper, timeout_seconds=60)# завершение сессии через минуту
        self.encryption_service = EncryptionService(self.key_manager)


        self.session_timer = QTimer(self)
        self.session_timer.timeout.connect(self.check_user_session)
        self.session_timer.start(5000)  # проверка каждые 5 секунд
        # установка фильтр на все приложение
        QApplication.instance().installEventFilter(self)


    def init_ui(self):  #Инициализация всех графических компонентов

        #центральный виджет
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # создание компонентов по порядку
        self.create_app_menu()
        self.create_toolbar()
        self.create_table_area()
        self.create_status_bar()
        self.start_clipboard_timer(30)

    def eventFilter(self, obj, event):
        # обработка только кликов мыши и нажатия клавиш
        if event.type() in [QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress]:
            if hasattr(self, 'auth_service'):
                self.auth_service.update_activity()
                # print("активность зафиксирована")

        return super().eventFilter(obj, event)

    def create_app_menu(self):

        menubar = self.menuBar()

        # файл
        file_menu = menubar.addMenu("Файл")
        file_menu.addAction("Создать")
        file_menu.addAction("Открыть")
        file_menu.addAction("Резервное копирование")
        file_menu.addSeparator()
        exit_action = file_menu.addAction("Выход")
        exit_action.triggered.connect(self.close)

        # редактирование
        edit_menu = menubar.addMenu("Редактирование")
        add_action = edit_menu.addAction("Добавить")
        add_action.triggered.connect(self.open_add_window)
        edit_menu.addAction("Редактировать")
        edit_menu.addAction("Удалить")

        # просмотр
        view_menu = menubar.addMenu("Просмотр")
        view_menu.addAction("Журналы")
        view_menu.addAction("Настройки")

        # справка
        help_menu = menubar.addMenu("Справка")
        help_menu.addAction("О программе")

    def create_toolbar(self):
        #создание панели инструментов
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)

        add_action = QAction("Добавить", self)
        add_action.triggered.connect(self.open_add_window)
        toolbar.addAction(add_action)

    def create_table_area(self):
        #Создание таблицы
        self.table = SecureTable()
        self.main_layout.addWidget(self.table)

        #  данные для теста
        #self.table.add_record("Google", "user@gmail.com", "****", "Основная почта")
        #self.table.add_record("GitHub", "dev_daria", "****", "Рабочий аккаунт")

    def copy_to_clipboard(self, password):
        from PyQt6.QtWidgets import QApplication

        #роверка,что пароль дошел до функции
        if not password or password == "****":
            print("Ошибка: Пароль пуст или замаскирован")
            return

        clipboard = QApplication.clipboard()
        clipboard.setText(password)

        self.statusBar().showMessage("Пароль скопирован в буфер!", 5000)

        # если есть таймер то запуск
        if hasattr(self, 'start_clipboard_timer'):
            self.start_clipboard_timer(30)

    def create_status_bar(self):
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Система готова")

        self.timer_label = QLabel("")
        self.status_bar.addPermanentWidget(self.timer_label)

    def start_clipboard_timer(self, seconds=30):
        #  обратный отсчет для очистки буфера
        self.remaining_time = seconds
        self.update_timer_label()

        # срабатывание каждую секунду для обновления текста
        self.clipboard_timer.start(1000)

    def update_timer_label(self):
        if self.remaining_time > 0:
            self.timer_label.setText(f"Буфер очистится через: {self.remaining_time}с  ")
            self.remaining_time -= 1
        else:
            self.clear_clipboard()

    def clear_clipboard(self):
        # очистка буфера и сброс интерфейса таймера
        self.clipboard_timer.stop()
        QApplication.clipboard().clear()
        self.timer_label.setText("")
        self.status_bar.showMessage("Буфер обмена очищен", 3000)


    def copy_password(self, password):#функция копирования запускающая процесс
        QApplication.clipboard().setText(password)
        self.status_bar.showMessage("Пароль скопирован в буфер", 5000)
        self.start_clipboard_timer(30)

    def check_first_run(self):
        #проверка хеша мастер пароля в базе
        master_hash = self.db_helper.get_setting("master_hash")

        if not master_hash:
            # если хеша нет запуск регистрации
            QTimer.singleShot(100, self.show_setup_wizard)
        else:
            # если хеш есть показываем вход
            QTimer.singleShot(100, self.show_login_dialog)

    def show_setup_wizard(self):
        from src.gui.setup_wizard import SetupWizard
        wizard = SetupWizard(self)
        wizard.setup_finished.connect(self.on_setup_complete)

        if not wizard.exec():
            sys.exit()  # закрытие через крестик

    def _run_logic(self):
        if not self.db_helper.get_setting("master_hash"):
            self.show_setup_wizard()
        else:
            self.show_login_dialog()

    def show_login_dialog(self):
        from src.gui.login_window import LoginWindow
        self.login_win = LoginWindow(self)
        self.login_win.login_attempt.connect(self.verify_login)

        if not self.login_win.exec():
            sys.exit()

    def verify_login(self, password):
        # вход через сервис аутентификации
        if self.auth_service.login(password):
            self.current_master_password = password

            self.login_win.accept()

            # таймер проверки сессии после входа
            if hasattr(self, 'session_timer'):
                self.session_timer.start(5000)  # проверка каждые 5 секудн


            QTimer.singleShot(100, self.finalize_login)
        else:
            QMessageBox.critical(self, "Ошибка", "Неверный мастер-пароль!")
            self.login_win.password_input.clear()

    def finalize_login(self):
        # метод для безопасного отображения интерфейса после логина
        try:
            self.load_data_from_db()
            self.show()
            self.statusBar().showMessage(f"Сессия активна. Добро пожаловать!")
        except Exception as e:
            print(f"Ошибка при загрузке данных: {e}")

    def on_setup_complete(self, password):
        try:
            self.db_helper.save_master_password(password)
            self.current_master_password = password

            # активация сессии
            if self.auth_service.login(password):
                self.load_data_from_db()
                self.show()

                # запуск таймера проверки сессии
                if hasattr(self, 'session_timer'):
                    self.session_timer.start(5000)  # Проверка каждые 5 секунд

                QMessageBox.information(self, "Успех", "Сессия активирована!")
        except Exception as e:
            print(f"Ошибка при завершении настройки: {e}")


    def open_add_window(self):
        try:
            from src.gui.add_record_window import AddRecordWindow
            self.add_win = AddRecordWindow(self)

            # подключение сигнала к обработчику
            self.add_win.record_saved.connect(self.handle_save)

            # Используем exec() для модального окна (блокирует основное окно)
            self.add_win.exec()

        except Exception as e:
            print(f"Критическая ошибка при открытии окна: {e}")

    def handle_save(self, service, login, password, notes):
        try:
            # 1сохранение в базу
            self.db_helper.add_entry(service, login, password, notes)

            #2 обновление таблицы на экране
            self.table.add_record(service, login, password, notes, self.copy_to_clipboard)

            #3обновление статуса
            self.statusBar().showMessage(f"Запись {service} добавлена", 5000)

        except Exception as e:
            QMessageBox.critical(self, "Ошибка БД", f"Не удалось сохранить: {e}")

    def load_data_from_db(self):
        try:
            # очистка таблицы перед загрузкой
            self.table.setRowCount(0)

            records = self.db_helper.get_all_entries()

            if not records:
                self.statusBar().showMessage("База данных пуста", 5000)
                return

            for rec in records:
                service_name = rec.get('service', 'Unknown')
                username = rec.get('username', '')
                password = rec.get('encrypted_password', '')
                notes = rec.get('notes', '')

                # Добавляем в таблицу, передавая callback для копирования
                self.table.add_record(
                    service_name,
                    username,
                    password,
                    notes,
                    self.copy_to_clipboard
                )

            self.statusBar().showMessage(f"Загружено записей: {len(records)}", 5000)

        except Exception as e:
            print(f"Критическая ошибка при загрузке данных: {e}")
            self.statusBar().showMessage("Ошибка загрузки данных из БД")

    def load_data(self):
        #Запуск процесса загрузки в фоновом потоке
        self.statusBar().showMessage("Загрузка данных...")

        # создание поток
        self.loading_thread = QThread()
        self.worker = LoadDataWorker(self.db)
        self.worker.moveToThread(self.loading_thread)

        # соединяем сигналы
        self.loading_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_load_finished)
        self.worker.error.connect(lambda e: print(f"Worker Error: {e}"))

        # очистка памяти после завершения
        self.worker.finished.connect(self.loading_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.loading_thread.finished.connect(self.loading_thread.deleteLater)

        self.loading_thread.start()

    def on_load_finished(self, records):
        self.table.setRowCount(0)
        for row in records:
            try:
                if isinstance(row, dict):
                    service = row.get('service', '')
                    login = row.get('username', row.get('login', ''))
                    password = row.get('encrypted_password', row.get('password', ''))
                    notes = row.get('notes', '')
                else:
                    service = row[1]
                    login = row[2]
                    password = row[3]
                    notes = row[4] if len(row) > 4 else ""

                self.table.add_record(service, login, password, notes, self.copy_to_clipboard)

            except Exception as e:
                print(f"Ошибка при чтении строки: {e}")

        self.statusBar().showMessage(f"Загружено записей: {len(records)}", 5000)

    def on_load_error(self, error_message):
        self.statusBar().showMessage(f"Ошибка: {error_message}")

    def check_user_session(self):
        # проверка для блокировки
        if not self.auth_service.check_session():
            if hasattr(self, 'session_timer'):
                self.session_timer.stop()

            QMessageBox.warning(self, "Сессия истекла", "Время ожидания вышло. Приложение будет закрыто.")
            self.close()
            QApplication.quit()

