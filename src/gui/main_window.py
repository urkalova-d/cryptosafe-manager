import sys
import time
import traceback
from PyQt6.QtGui import QAction

from src.database.db import DatabaseHelper
from src.gui.setup_wizard import SetupWizard
from src.gui.add_record_window import AddRecordWindow
from src.gui.widgets.secure_table import SecureTable
from PyQt6.QtCore import Qt, QTimer, QEvent, QObject, pyqtSignal, QThread

from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QMessageBox,
                             QTableWidget, QApplication, QTableWidgetItem, QHeaderView,
                             QMenuBar, QMenu, QStatusBar, QToolBar, QLabel,
                             QProgressDialog) 

from src.core.crypto.key_manager import KeyManager
from src.core.crypto.authentication import AuthenticationService
from src.core.vault.encryption_service import EncryptionService



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

        #инициализация бд
        from src.database.db import db_manager
        self.db_helper = db_manager
        self.current_master_password = None

        # таймер
        self.clipboard_timer = QTimer()
        self.clipboard_timer.timeout.connect(self.update_timer_label)
        self.remaining_time = 0

        # кр
        self.key_manager = KeyManager(self.db_helper)
        self.auth_service = AuthenticationService(self.key_manager, self.db_helper, timeout_seconds=3600)
        self.encryption_service = EncryptionService(self.key_manager)
        # Подключение сигналов
        self.auth_service.UserLoggedIn.connect(self.on_user_logged_in)
        self.auth_service.UserLoggedOut.connect(self.on_user_logged_out)

        # таймер сессии
        self.session_timer = QTimer(self)
        self.session_timer.timeout.connect(self.check_user_session)
        self.session_timer.start(5000)

        # фильтр событий
        QApplication.instance().installEventFilter(self)

        self.init_ui()
        self.hide()
        #проверка первого запуска
        QTimer.singleShot(100, self.check_first_run)


    def init_ui(self):

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
        # активность на экране для таймера
        if event.type() in [QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress]:
            if hasattr(self, 'auth_service') and self.auth_service.is_authenticated():
                self.auth_service.update_activity()

        return super().eventFilter(obj, event)

    def closeEvent(self, event):
        print("Закрытие приложения -> Очистка памяти")
        self.auth_service.logout()
        super().closeEvent(event)

    def on_user_logged_in(self):
        print("Событие: UserLoggedIn")
        # Проверяем, что ключи загружены
        auth_key = self.key_manager.get_auth_key()
        enc_key = self.key_manager.get_encryption_key()

        print(f"Auth key present: {auth_key is not None}")
        print(f"Encryption key present: {enc_key is not None}")

        if enc_key is None:
            print("ОШИБКА: Ключ шифрования не загружен после входа!")
            QMessageBox.critical(self, "Ошибка", "Не удалось загрузить ключи шифрования")
            return

        self.load_data_from_db()

        # показ главного окна
        self.show()

        self.statusBar().showMessage("Вы успешно вошли в систему")

    def on_user_logged_out(self):
        # для события выхода
        print("Событие: UserLoggedOut")
        self.hide()
        QMessageBox.information(self, "Сессия завершена", "Вы были автоматически вышли из системы.")
        self.show_login_dialog()

    def check_user_session(self):
        # проверка тайминга сессии
        if not self.auth_service.check_session():
            pass

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
        change_pwd_action = edit_menu.addAction("Сменить мастер-пароль")
        change_pwd_action.triggered.connect(self.open_password_change_dialog)

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
        #создание таблицы
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
        #переключение setup login
        master_hash = self.db_helper.get_setting("master_hash")
        if not master_hash:
            self.show_setup_wizard()
        else:
            self.show_login_dialog()

    def show_setup_wizard(self):
        from src.gui.setup_wizard import SetupWizard
        wizard = SetupWizard(self)
        wizard.setup_finished.connect(self.on_setup_complete)

        if not wizard.exec():
            sys.exit()# закрытиче крестиком

    def show_login_dialog(self):
        from src.gui.login_window import LoginWindow
        self.hide()

        self.login_win = LoginWindow(self)
        self.login_win.login_attempt.connect(self.verify_login)

        if not self.login_win.exec():
            sys.exit(0) # закрытие через крестик

    def _run_logic(self):
        if not self.db_helper.get_setting("master_hash"):
            self.show_setup_wizard()
        else:
            self.show_login_dialog()

    def verify_login(self, password):
        #Вызывается при попытке входа
        self.hide()

        print(" ДИАГНОСТИКА ВХОДА")
        print(f"Пароль получен, длина: {len(password)}")

        # Проверяем наличие хеша
        stored_hash = self.db_helper.get_setting("master_hash")
        print(f"Хеш в БД: {stored_hash is not None}")
        if stored_hash:
            print(f"Хеш (первые 50 символов): {stored_hash[:50]}...")

        success = self.auth_service.login(password)

        if success:
            print("Вход успешен!")
            self.login_win.accept()
        else:
            print("Вход не удался!")
            attempts = self.auth_service._failed_attempts
            msg = "Неверный мастер-пароль!"
            if attempts < 5:
                msg += f"\nОсталось попыток: {5 - attempts}"
            else:
                delay = self.auth_service._calculate_delay()
                msg += f"\nЗадержка перед следующей попыткой: {delay} сек."

            if hasattr(self.login_win, 'show_error'):
                self.login_win.show_error(msg)
            else:
                QMessageBox.critical(self, "Ошибка входа", msg)

            self.login_win.password_input.clear()

    def finalize_login(self):
        # метод для безопасного отображения интерфейса после логина
        try:
            self.load_data_from_db()
            self.show()
            self.statusBar().showMessage(f"Сессия активна. Добро пожаловать!")
        except Exception as e:
            print(f"Ошибка при загрузке данных: {e}")

    def open_add_window(self):
        try:
            # Убедимся, что импорт актуален
            from src.gui.add_record_window import AddRecordWindow
            self.add_win = AddRecordWindow(self)

            self.add_win.record_saved.connect(
                lambda s, l, p, u, c, n: self.handle_save(s, l, p, u, c, n)
            )

            self.add_win.exec()
        except Exception as e:
            print(f"Критическая ошибка при открытии окна: {e}")
            traceback.print_exc()


    def handle_save(self, service, login, password, url, category, notes):
        try:
            # 1подготовка данных
            entry_data = {
                'service': service,
                'username': login,
                'category': category,
                'password': password,
                'url': url,
                'notes': notes
            }

            # 2шифрование всей записи (AES-GCM JSON Blob)
            encrypted_blob = self.encryption_service.encrypt_entry(entry_data)

            # 3сохранение в БД
            self.db_helper.add_entry(encrypted_blob)

            # 4обновление таблицы
            self.table.add_record(service, login, category, password, notes, self.copy_to_clipboard)
            self.statusBar().showMessage(f"Запись {service} добавлена", 5000)

        except Exception as e:
            print(f"Ошибка при сохранении: {e}")
            traceback.print_exc()
            QMessageBox.critical(self, "Ошибка БД", f"Не удалось сохранить: {e}")

    def load_data_from_db(self):
        try:
            self.table.setRowCount(0)

            # Получение списка BLOB-ов из БД
            records = self.db_helper.get_all_entries()
            if not records:
                self.statusBar().showMessage("База данных пуста", 5000)
                return

            if not self.key_manager.get_encryption_key():
                return

            for rec in records:
                enc_blob = rec.get('encrypted_data')

                try:
                    # Расшифровка JSON
                    data = self.encryption_service.decrypt_entry(enc_blob)

                    # Извлечение поля
                    service_name = data.get('title', 'Unknown')
                    username = data.get('username', '')
                    category = data.get('category', 'Uncategorized')
                    password = data.get('password', '')
                    notes = data.get('notes', '')


                    self.table.add_record(service_name, username, category, password, notes, self.copy_to_clipboard)
                except ValueError as ve:
                    # Ошибка целостности (Invalid Tag)
                    self.table.add_record("ОШИБКА ЦЕЛОСТНОСТИ", "", "", str(ve), None)
                except Exception as e:
                    print(f"Ошибка обработки записи: {e}")
                    traceback.print_exc()

            self.statusBar().showMessage(f"Загружено записей: {len(records)}", 5000)

        except Exception as e:
            print(f"Критическая ошибка при загрузке данных: {e}")
            traceback.print_exc()
            self.statusBar().showMessage("Ошибка загрузки данных из БД")

    def load_data(self):
        #Запуск процесса загрузки в фоновом потоке
        self.statusBar().showMessage("Загрузка данных...")

        # создание поток
        self.loading_thread = QThread()
        self.worker = LoadDataWorker(self.db_helper) 
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
                    category = row.get('category', 'Uncategorized') if isinstance(row, dict) else "Uncategorized"
                    password = row.get('encrypted_password', row.get('password', ''))
                    notes = row.get('notes', '')
                else:
                    service = row[1]
                    login = row[2]
                    password = row[3]
                    notes = row[4] if len(row) > 4 else ""

                self.table.add_record(service, login, category, password, notes, self.copy_to_clipboard)

            except Exception as e:
                print(f"Ошибка при чтении строки: {e}")

        self.statusBar().showMessage(f"Загружено записей: {len(records)}", 5000)

    def on_load_error(self, error_message):
        self.statusBar().showMessage(f"Ошибка: {error_message}")

    def open_password_change_dialog(self):
        from src.gui.password_change_dialog import PasswordChangeDialog

        dialog = PasswordChangeDialog(self.key_manager, self.db_helper, self)

        if dialog.exec():
            # Если диалог прошел валидацию -> начинаем процесс
            old_pwd = dialog.current_pwd_input.text()
            new_pwd = dialog.new_pwd_input.text()

            # Создаем прогресс бар
            progress = QProgressDialog("Перешифрование хранилища...", None, 0, 100, self)
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.setWindowTitle("Смена пароля")
            progress.show()

            def update_progress(val):
                progress.setValue(val)
                QApplication.processEvents()  # Чтобы окно не зависало

            # Запуск процесса
            success = self.key_manager.rotate_keys(
                old_pwd,
                new_pwd,
                progress_callback=update_progress
            )

            progress.close()

            if success:
                QMessageBox.information(self, "Успех", "Пароль успешно изменен! Данные обновлены.")
                self.load_data_from_db()
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось сменить пароль. Проверьте консоль.")

    def start_rotation_process(self, old_password, new_password):
        # сохранение старого ключа для перешифровки
        old_enc_key = self.key_manager.get_encryption_key()

        # создание прогресс бар
        self.progress_dialog = QProgressDialog("Перешифрование данных...", "Отмена", 0, 100, self)
        self.progress_dialog.setWindowTitle("Смена пароля")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.setAutoClose(False)
        self.progress_dialog.setAutoReset(False)

        #  запуск потока
        self.thread = QThread()
        self.worker = ReencryptWorker(self.db_helper, self.key_manager, old_enc_key)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.progress_dialog.setValue)

        # Логика завершения
        self.worker.finished.connect(self.on_rotation_finished)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        # Обработка отмены
        self.progress_dialog.canceled.connect(self.worker.cancel)

        # изменение пароля в системе key manager
        if not self.key_manager.rotate_keys(old_password, new_password):
            QMessageBox.critical(self, "Ошибка", "Не удалось обновить ключи безопасности.")
            return

        self.thread.start()
        self.progress_dialog.show()

    def on_rotation_finished(self, success):
        self.progress_dialog.close()
        if success:
            QMessageBox.information(self, "Успех", "Мастер-пароль успешно изменен. Все данные перешифрованы.")
        else:
            QMessageBox.critical(self, "Ошибка",
                                 "Процесс был прерван или произошла ошибка. Данные могут быть повреждены.")

    def on_setup_complete(self, password):
        #Вызывается после успешной регистрации
        try:
            # сохранение нового мастер пароля и ключа в бд
            self.key_manager.setup_new_user(password)

            # вход
            if self.auth_service.login(password):
                self.load_data_from_db()
                self.show()
                QMessageBox.information(self, "Успех", "Аккаунт создан! Вы вошли в систему.")
        except Exception as e:
            print(f"Ошибка при завершении настройки: {e}")
            traceback.print_exc()
            QMessageBox.critical(self, "Ошибка", f"Не удалось завершить настройку: {e}")


