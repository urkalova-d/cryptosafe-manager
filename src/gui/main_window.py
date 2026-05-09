import sys
import time
import traceback
import platform
from PyQt6.QtGui import QAction
from PyQt6.QtCore import QSettings, QStringListModel
from src.gui.settings_dialog import SettingsDialog

from src.database.db import DatabaseHelper
from src.gui.setup_wizard import SetupWizard
from src.gui.add_record_window import AddRecordWindow
from src.gui.widgets.secure_table import SecureTable
from PyQt6.QtCore import Qt, QTimer, QEvent, QObject, pyqtSignal, QThread
from PyQt6.QtWidgets import QPushButton
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QMessageBox,
                             QTableWidget, QApplication, QTableWidgetItem, QHeaderView,
                             QMenuBar, QMenu, QStatusBar, QToolBar, QLabel,
                             QProgressDialog, QLineEdit, QCompleter, QPushButton,
                             QSizePolicy)
from PyQt6.QtWidgets import QMessageBox, QApplication, QLabel, QWidget, QHBoxLayout, QPushButton
from PyQt6.QtCore import Qt, QTimer
from src.core.crypto.key_manager import KeyManager
from src.core.crypto.authentication import AuthenticationService
from src.core.vault.encryption_service import EncryptionService
from src.core.clipboard import ClipboardService, PlatformAdapter, ClipboardMonitor
from src.core.audit import AuditLogger, AuditLogSigner
from src.core.audit.log_verifier import LogVerifier
from src.gui.audit_viewer import AuditViewer
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
        # Кэш и настройки
        self.settings = QSettings("CryptoSafe", "PasswordManager")
        # инициализация бд
        from src.database.db import db_manager
        self.db_helper = db_manager
        self.current_master_password = None

        # кр
        self.key_manager = KeyManager(self.db_helper)

        # Инициализация менеджера записей
        from src.core.vault.entry_manager import EntryManager
        self.entry_manager = EntryManager(self.db_helper, self.key_manager)
        #  Инициализация аудита
        self.audit_logger = None
        # Подключаем сигналы менеджера записей
        self.entry_manager.EntryCreated.connect(self.on_entry_created)
        self.entry_manager.EntryUpdated.connect(self.on_entry_updated)
        self.entry_manager.EntryDeleted.connect(self.on_entry_deleted)

        self.auth_service = AuthenticationService(self.key_manager, self.db_helper, timeout_seconds=3600)
        self.encryption_service = EncryptionService(self.key_manager)

        self.all_records_cache = []
        #  Создание UI
        self.init_ui()

        #  Инициализация буфера обмена
        from src.core.clipboard import ClipboardService, PlatformAdapter, ClipboardMonitor

        self.platform_adapter = PlatformAdapter()
        self.clipboard_monitor =  ClipboardMonitor()
        self.clipboard_service = ClipboardService(self.platform_adapter, self.clipboard_monitor, self.db_helper)

        # Передаем ссылку на хранилище ключей для проверки блокировки
        self.clipboard_service.set_key_storage(self.key_manager.storage)

        self.clipboard_service.load_settings()

        # 4. Подключение сигналов
        self.clipboard_service.timer_updated.connect(self.update_timer_label_service)
        self.clipboard_service.clipboard_cleared.connect(self.on_clipboard_cleared)
        self.clipboard_service.clipboard_copied.connect(self.on_clipboard_copied)
        self.clipboard_service.warning_5_seconds.connect(self.show_clear_warning)

        self.clipboard_service.ephemeral_mode_changed.connect(self._on_ephemeral_mode_changed)
        # антискриншот
        self._anti_screenshot_enabled = False
        self.clipboard_service.protection_enabled.connect(self.enable_anti_screenshot)
        self.clipboard_service.protection_disabled.connect(self.disable_anti_screenshot)
        # Подключение новых сигналов таблицы
        self.table.copy_password_requested.connect(self.copy_password_to_clipboard)
        self.table.copy_username_requested.connect(self.copy_username_to_clipboard)
        self.table.copy_all_requested.connect(self.copy_all_to_clipboard)

        # Запуск мониторинга
        self.clipboard_monitor.start_monitoring()

        # Подключение сигналов аутентификации
        self.auth_service.UserLoggedIn.connect(self.on_user_logged_in)
        self.auth_service.UserLoggedOut.connect(self.on_user_logged_out)

        # Таймер сессии
        self.session_timer = QTimer(self)
        self.session_timer.timeout.connect(self.check_user_session)
        self.session_timer.start(5000)

        # Фильтр событий
        QApplication.instance().installEventFilter(self)



        self.hide()
        QTimer.singleShot(100, self.check_first_run)


    def init_ui(self):

        # центральный виджет
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # создание компонентов по порядку
        self.create_app_menu()
        self.create_toolbar()
        self.create_table_area()
        self.create_status_bar()

    def eventFilter(self, obj, event):
        # проверка активности
        if event.type() in [QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress]:
            if hasattr(self, 'auth_service') and self.auth_service.is_authenticated():
                self.auth_service.update_activity()

        # Ctrl+V для эфемерного буфера
        if event.type() == QEvent.Type.KeyPress:
            if event.modifiers() == Qt.KeyboardModifier.ControlModifier and event.key() == Qt.Key.Key_V:
                # проверка состояния режима
                if hasattr(self, 'clipboard_service') and self.clipboard_service.is_ephemeral_mode():
                    # получениепароля из эфемерного буфера
                    password = self.clipboard_service.get_ephemeral_password()
                    if password:
                        focus_widget = QApplication.focusWidget()
                        if isinstance(focus_widget, QLineEdit):
                            focus_widget.setText(password)
                            self.statusBar().showMessage("🔒 Пароль вставлен из эфемерного буфера", 3000)
                            return True

        return super().eventFilter(obj, event)

    def closeEvent(self, event):
        print("Закрытие приложения -> Очистка памяти")
        self.disable_anti_screenshot()
        if hasattr(self, 'clipboard_service'):
            self.clipboard_service.clear_now()
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

        try:
            print("[MainWindow] Initializing Audit Logger...")
            signer = AuditLogSigner(self.key_manager)
            self.audit_logger = AuditLogger(self.db_helper, signer)
            self.audit_logger.start()

            # Startup Verification
            print("[MainWindow] Verifying audit log integrity...")
            verifier = LogVerifier(self.db_helper, signer)
            verification_result = verifier.verify_all()

            if verification_result['verified']:
                print(f"[MainWindow] Audit Log Integrity: OK ({verification_result['total_checked']} entries)")
            else:
                # Формируем детальное сообщение
                msg = f"Audit Log Integrity FAILED!\n" \
                      f"Invalid Hashes: {len(verification_result.get('invalid_hashes', []))}\n" \
                      f"Chain breaks: {len(verification_result.get('chain_breaks', []))}"
                print(f"[MainWindow] {msg}")
                QMessageBox.critical(self, "Security Alert",
                                     "CRITICAL: Audit log tampering detected! The database may be compromised.")

            #  Periodic Verification
            self.periodic_verify_timer = QTimer(self)
            self.periodic_verify_timer.timeout.connect(self.periodic_audit_check)
            # Запуск раз в 24 часа
            self.periodic_verify_timer.start(24 * 60 * 60 * 1000)

            sample_entry = {
                'timestamp': '2026-05-07T12:00:00Z',
                'event_type': 'VAULT_READ',
                'severity': 'INFO',
                'source': 'vault_manager',
                'user_id': 'admin',
                'details': {'entry_id': 1}
            }
            cef_log = AuditLogger.format_as_cef(sample_entry)
            print(f"[CEF FORMAT]: {cef_log}")

        except Exception as e:
            print(f"[MainWindow] CRITICAL: Failed to start Audit Logger: {e}")
            QMessageBox.warning(self, "Ошибка Аудита", f"Не удалось запустить систему аудита: {e}")

        self.load_data_from_db()
        self.enable_anti_screenshot()
        # показ главного окна
        self.show()

        self.statusBar().showMessage("Вы успешно вошли в систему")

    def on_user_logged_out(self):
        # для события выхода
        print("Событие: UserLoggedOut")
        self.disable_anti_screenshot()
        if hasattr(self, 'clipboard_service'):
            self.clipboard_service.on_vault_lock()
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
        backup_menu = file_menu.addMenu("Резервное копирование")

        export_action = backup_menu.addAction("Экспорт хранилища")
        export_action.triggered.connect(self.open_export_dialog)

        import_action = backup_menu.addAction("Импорт хранилища")
        import_action.triggered.connect(self.open_import_dialog)

        clear_clip_action = file_menu.addAction("Очистить буфер обмена")
        clear_clip_action.triggered.connect(self.manual_clear_clipboard)
        file_menu.addSeparator()
        exit_action = file_menu.addAction("Выход")
        exit_action.triggered.connect(self.close)

        # редактирование
        edit_menu = menubar.addMenu("Редактирование")

        add_action = edit_menu.addAction("Добавить")
        add_action.triggered.connect(self.open_add_window)

        edit_action = edit_menu.addAction("Редактировать")
        edit_action.triggered.connect(self.edit_selected_entry)

        delete_action = edit_menu.addAction("Удалить")
        delete_action.triggered.connect(self.delete_selected_entry)

        change_pwd_action = edit_menu.addAction("Сменить мастер-пароль")
        change_pwd_action.triggered.connect(self.open_password_change_dialog)

        # просмотр
        view_menu = menubar.addMenu("Просмотр")
        verify_action = view_menu.addAction("🛡️ Проверить целостность логов")
        verify_action.triggered.connect(self.manual_verify_audit_logs)
        logs_action = view_menu.addAction("📜 Журналы аудита")
        logs_action.triggered.connect(self.open_audit_viewer)
        settings_action = view_menu.addAction("⚙️ Настройки")
        settings_action.triggered.connect(self.open_settings_dialog)

        # справка
        help_menu = menubar.addMenu("Справка")
        help_menu.addAction("О программе")

    def create_toolbar(self):
        # создание панели инструментов
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)

        add_action = QAction("Добавить", self)
        add_action.triggered.connect(self.open_add_window)
        toolbar.addAction(add_action)

        # глобальный переключатель
        self.toggle_pass_action = QAction("Показать пароли", self)
        self.toggle_pass_action.setCheckable(True)
        self.toggle_pass_action.toggled.connect(self.toggle_password_visibility)
        toolbar.addAction(self.toggle_pass_action)

        # Добавляем спейсер или просто следующую кнопку
        toolbar.addSeparator()

        self.ephemeral_action = QAction("🔒 Эфемерный режим", self)
        self.ephemeral_action.setCheckable(True)
        self.ephemeral_action.setChecked(False)
        self.ephemeral_action.setToolTip(
            "Включить эфемерный режим\n"
            "В этом режиме пароли НЕ попадают в системный буфер обмена."

        )
        self.ephemeral_action.toggled.connect(self._on_ephemeral_action_toggled)
        toolbar.addAction(self.ephemeral_action)

        # Растягивающийся спейсер
        toolbar.addSeparator()
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        # Поиск
        toolbar.addWidget(QLabel("  Поиск: "))
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Поиск...")
        self.search_bar.setFixedWidth(200)
        self.search_bar.textChanged.connect(self.run_search)
        toolbar.addWidget(self.search_bar)

    def _on_ephemeral_action_toggled(self, checked):
         #Обработчик кнопки эфемерного режима в тулбаре.
        print(f"[MainWindow] Ephemeral action toggled: {checked}")
        if hasattr(self, 'clipboard_service'):
            self.clipboard_service.set_ephemeral_mode(checked)
            if checked:
                QMessageBox.information(self, "Эфемерный режим",
                                        "Пароли больше не попадают в историю буфера обмена.\n"
                                        "Для вставки используйте Ctrl+V внутри приложения.")

    def toggle_password_visibility(self, checked):
        #показ паролей
        self.table.toggle_all_passwords(checked)
        self.toggle_pass_action.setText("Скрыть пароли" if checked else "Показать пароли")

    def keyPressEvent(self, event):
        #показ парлей через горяие клавиши
        if event.modifiers() == (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier):
            if event.key() == Qt.Key.Key_P:
                current_state = self.toggle_pass_action.isChecked()
                self.toggle_pass_action.setChecked(not current_state)
                return
        super().keyPressEvent(event)

    def create_table_area(self):
        # создание таблицы
        self.table = SecureTable()
        self.main_layout.addWidget(self.table)

        # сигналы контекстного меню
        self.table.edit_requested.connect(self.edit_entry_by_id)
        self.table.delete_requested.connect(self.delete_entry_by_id)
        #self.table.copy_requested.connect(self.copy_to_clipboard)

    def create_status_bar(self):
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Система готова")

        # таймер очистки
        self.timer_label = QLabel("")
        self.status_bar.addPermanentWidget(self.timer_label)

        # превью буфера
        self.clipboard_preview = QLabel("Буфер: пусто")
        self.clipboard_preview.setStyleSheet("color: #888; padding: 0 10px;")
        self.status_bar.addPermanentWidget(self.clipboard_preview)

        # индикатор эфемерного режима
        self._ephemeral_status_indicator = QLabel("🔒 EPHEMERAL MODE")
        self._ephemeral_status_indicator.setStyleSheet(
            "color: #27ae60; font-weight: bold; padding: 2px 8px; background-color: #2c3e50; border-radius: 3px; margin: 2px;"
        )
        self._ephemeral_status_indicator.setVisible(False)
        self.status_bar.addPermanentWidget(self._ephemeral_status_indicator)

        print("[MainWindow] Status bar created")
    """
    def copy_to_clipboard(self, entry_id):
        #Получает пароль по ID только в момент копирования.
        if not entry_id:
            return
        try:
            #  Расшифровка происходит только сейчас, данные не висят в памяти
            entry_data = self.entry_manager.get_entry(entry_id)
            password = entry_data.get('password', '')

            if not password:
                self.statusBar().showMessage("Пароль пуст", 3000)
                return

            self.clipboard_service.copy_password(entry_id, password)
            self.statusBar().showMessage("Пароль скопирован в буфер!", 5000)

            # Публикация события
            self.entry_manager.copy_to_clipboard_secure(entry_id)

            if hasattr(self, 'start_clipboard_timer'):
                self.start_clipboard_timer(30)

        except Exception as e:
            print(f"Ошибка при копировании: {e}")
            QMessageBox.critical(self, "Ошибка", "Не удалось скопировать пароль")
    """


    def update_timer_label_service(self, seconds: int):
         #обновление таймера
        if seconds > 0:
            self.timer_label.setText(f"Буфер очистится через: {seconds}с  ")
        else:
            self.timer_label.setText("")

    def copy_password(self, password):  # функция копирования запускающая процесс
        QApplication.clipboard().setText(password)
        self.statusBar().showMessage("Пароль скопирован в буфер", 5000)
        self.start_clipboard_timer(30)

    def check_first_run(self):
        # переключение setup login
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
            sys.exit()  # закрытиче крестиком

    def show_login_dialog(self):
        from src.gui.login_window import LoginWindow
        self.hide()

        self.login_win = LoginWindow(self)
        self.login_win.login_attempt.connect(self.verify_login)

        if not self.login_win.exec():
            sys.exit(0)  # закрытие через крестик

    def _run_logic(self):
        if not self.db_helper.get_setting("master_hash"):
            self.show_setup_wizard()
        else:
            self.show_login_dialog()

    def verify_login(self, password):
        # Вызывается при попытке входа
        self.hide()

        print(" ДИАГНОСТИКА ВХОДА")
        print(f"Пароль получен, длина: {len(password)}")

        # Проверка наличие хеша
        stored_hash = self.db_helper.get_setting("master_hash")
        print(f"Хеш в БД: {stored_hash is not None}")
        if stored_hash:
            print(f"Хеш (первые 50 символов): {stored_hash[:50]}...")

        success = self.auth_service.login(password)

        if success:
            from src.core.events import event_bus, EventType
            event_bus.publish(EventType.AUTH_LOGIN_SUCCESS, {'user_id': 'default'})
            print("Вход успешен!")
            self.login_win.accept()
        else:
            from src.core.events import event_bus, EventType
            event_bus.publish(EventType.AUTH_LOGIN_FAILURE, {
                'reason': 'Invalid password',
                'attempts': self.auth_service._failed_attempts
            })
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
            self.add_win = AddRecordWindow(self.db_helper, self)

            self.add_win.record_saved.connect(
                lambda s, l, p, u, c, n: self.handle_save(s, l, p, u, c, n)
            )

            self.add_win.exec()
        except Exception as e:
            print(f"Критическая ошибка при открытии окна: {e}")
            traceback.print_exc()

    def handle_save(self, service, login, password, url, category, notes):
        #вызывается при сохранении из диалога
        try:
            entry_data = {
                'service': service,
                'username': login,
                'category': category,
                'password': password,
                'url': url,
                'notes': notes
            }
            # Использование EntryManager вместо прямого шифрования
            self.entry_manager.create_entry(entry_data)
            self.statusBar().showMessage(f"Запись {service} добавлена", 5000)

        except Exception as e:
            print(f"Ошибка при сохранении: {e}")
            traceback.print_exc()
            QMessageBox.critical(self, "Ошибка БД", f"Не удалось сохранить: {e}")

    def get_password_for_entry(self, entry_id: int) -> str:
        #геттер пароля для виджета таблицы

        if not entry_id:
            return ""
        try:
            # Расшифровка происходит только здесь
            entry_data = self.entry_manager.get_entry(entry_id)
            return entry_data.get('password', '')
        except Exception as e:
            print(f"Secure getter error: {e}")
            return "ERROR"

    def load_data_from_db(self):
        try:
            self.table.setRowCount(0)
            records = self.db_helper.get_all_entries()
            if not records:
                self.statusBar().showMessage("База данных пуста", 5000)
                self.all_records_cache = []
                return

            if not self.key_manager.get_encryption_key():
                return

            cache_list = []

            for rec in records:
                enc_blob = rec.get('encrypted_data')
                try:
                    data = self.encryption_service.decrypt_entry(enc_blob)

                    service_name = data.get('title', 'Unknown')
                    username = data.get('username', '')
                    category = data.get('category', 'Uncategorized')
                    notes = data.get('notes', '')
                    url = data.get('url', '')
                    rec_id = rec.get('id')
                    modified = rec.get('updated_at', '')

                    cache_entry = {
                        'id': rec_id,
                        'service': service_name,
                        'title': service_name,
                        'username': username,
                        'url': url,
                        'category': category,
                        'notes': notes,
                        'created_at': rec.get('created_at'),
                        'updated_at': modified,
                    }
                    cache_list.append(cache_entry)


                    self.table.add_record(
                        service_name,
                        username,
                        category,
                        "••••••••",
                        notes,
                        None,
                        record_id=rec_id,
                        modified_date=modified,
                        url=url,
                        password_getter=self.get_password_for_entry
                    )
                except ValueError as ve:
                    self.table.add_record("ОШИБКА", "", "", "", str(ve), None)
                except Exception as e:
                    print(f"Ошибка обработки записи: {e}")

            self.all_records_cache = cache_list
            self.statusBar().showMessage(f"Загружено записей: {len(records)}", 5000)

        except Exception as e:
            print(f"Критическая ошибка при загрузке данных: {e}")
            traceback.print_exc()
            self.statusBar().showMessage("Ошибка загрузки данных из БД")

    def on_entry_created(self, entry_id):
        print(f"Событие: EntryCreated (ID: {entry_id})")
        # перезагрузка таблицы
        self.load_data_from_db()

    def on_entry_updated(self, entry_id):
        print(f"Событие: EntryUpdated (ID: {entry_id})")
        self.load_data_from_db()

    def on_entry_deleted(self, entry_id):
        print(f"Событие: EntryDeleted (ID: {entry_id})")
        self.load_data_from_db()

    def load_data(self):
        # Запуск процесса загрузки в фоновом потоке
        self.statusBar().showMessage("Загрузка данных...")

        # создание потока
        self.loading_thread = QThread()
        self.worker = LoadDataWorker(self.db_helper)
        self.worker.moveToThread(self.loading_thread)

        # соединение сигналов
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
            # если диалог прошел валидацию  начинаем процесс
            old_pwd = dialog.current_pwd_input.text()
            new_pwd = dialog.new_pwd_input.text()

            # Создаем прогресс бар
            progress = QProgressDialog("Перешифрование хранилища...", None, 0, 100, self)
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.setWindowTitle("Смена пароля")
            progress.show()

            def update_progress(val):
                progress.setValue(val)
                QApplication.processEvents()
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
        # Вызывается после успешной регистрации
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

    def delete_selected_entry(self):
        #удаление выбранной записи
        selected_row = self.table.currentRow()# получение айди из скрытой колонки таблицы
        if selected_row < 0:
            QMessageBox.warning(self, "Внимание", "Выберите запись для удаления")
            return

        item = self.table.item(selected_row, 0)
        entry_id = item.data(Qt.ItemDataRole.UserRole)

        reply = QMessageBox.question(self, "Подтверждение",
                                     "Вы уверены, что хотите переместить запись в корзину?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.entry_manager.delete_entry(entry_id, soft_delete=True)
                self.statusBar().showMessage("Запись перемещена в корзину", 5000)
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось удалить: {e}")

    def edit_selected_entry(self):
        #редактирование выбранной записи
        selected_row = self.table.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "Внимание", "Выберите запись для редактирования")
            return

        item = self.table.item(selected_row, 0)
        entry_id = item.data(Qt.ItemDataRole.UserRole)

        # загрузка данных  из менеджера
        entry_data = self.entry_manager.get_entry(entry_id)
        from src.core.events import event_bus, EventType
        event_bus.publish(EventType.VAULT_ENTRY_READ, {
            'action': 'read',
            'entry_id': entry_id
        })

        # открытие окна добавления в режиме редактирования
        from src.gui.add_record_window import AddRecordWindow
        edit_win = AddRecordWindow(self)
        edit_win.setWindowTitle("Редактировать запись")

        # Заполнение поля старыми данными
        service_name = entry_data.get('title', entry_data.get('service', ''))
        edit_win.service.setText(service_name)
        edit_win.login.setText(entry_data.get('username', ''))
        edit_win.password.setText(entry_data.get('password', ''))
        edit_win.notes.setText(entry_data.get('notes', ''))
        edit_win.url.setText(entry_data.get('url', ''))

        # Устанавливаем категорию
        idx = edit_win.category.findText(entry_data.get('category', ''))
        if idx >= 0:
            edit_win.category.setCurrentIndex(idx)

        # Переподключение сигнала сохранения на handle_update
        try:
            edit_win.record_saved.disconnect()  # попытка отключить старое
        except TypeError:
            pass  # если не было подключений

        # Подключаем к обработчику ОБНОВЛЕНИЯ, а не создания
        edit_win.record_saved.connect(
            lambda s, l, p, u, c, n: self.handle_update(entry_id, s, l, p, u, c, n)
        )

        edit_win.exec()

    def edit_entry_by_id(self, entry_id):
        #Слот для сигнала edit_requested из таблицы
        entry_data = self.entry_manager.get_entry(entry_id)
        from src.core.events import event_bus, EventType
        event_bus.publish(EventType.VAULT_ENTRY_READ, {
            'action': 'read',
            'entry_id': entry_id
        })

        from src.gui.add_record_window import AddRecordWindow
        edit_win = AddRecordWindow(self.db_helper, self)
        edit_win.setWindowTitle("Редактировать запись")

        service_name = entry_data.get('title', entry_data.get('service', ''))
        edit_win.service.setText(service_name)
        edit_win.login.setText(entry_data.get('username', ''))
        edit_win.password.setText(entry_data.get('password', ''))
        edit_win.notes.setText(entry_data.get('notes', ''))
        edit_win.url.setText(entry_data.get('url', ''))

        idx = edit_win.category.findText(entry_data.get('category', ''))
        if idx >= 0: edit_win.category.setCurrentIndex(idx)

        try:
            edit_win.record_saved.disconnect()
        except TypeError:
            pass

        edit_win.record_saved.connect(
            lambda s, l, p, u, c, n: self.handle_update(entry_id, s, l, p, u, c, n)
        )
        edit_win.exec()

    def delete_entry_by_id(self, entry_id):
        #Слот для сигнала delete_requested из таблицы
        reply = QMessageBox.question(self, "Подтверждение",
                                     "Вы уверены, что хотите переместить запись в корзину?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.entry_manager.delete_entry(entry_id, soft_delete=True)
                self.statusBar().showMessage("Запись перемещена в корзину", 5000)
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось удалить: {e}")

    def handle_update(self, entry_id, service, login, password, url, category, notes):
        try:
            data = {
                'service': service, 'username': login, 'password': password,
                'url': url, 'category': category, 'notes': notes
            }
            self.entry_manager.update_entry(entry_id, data)
            self.statusBar().showMessage("Запись обновлена", 5000)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось обновить: {e}")

    #  поиск и фильтрация
    def run_search(self):
        query = self.search_bar.text()
        if not self.all_records_cache:
            return

        filtered = self.entry_manager.filter_entries(self.all_records_cache, query)
        self.table.display_data(filtered, None, self.get_password_for_entry)

        if query:
            self.statusBar().showMessage(f"Найдено результатов: {len(filtered)}", 3000)

    def save_search_history(self):
        # Сохранение в БД для аудита
        query = self.search_bar.text().strip()
        if not query:
            return

        # Сохраняем в БД для интеграции с Audit Log на 5 спринт
        try:
            self.db_helper.save_search_query(query)
        except Exception as e:
            print(f"Ошибка сохранения истории поиска в БД: {e}")
        history = self.settings.value("search_history", [], type=list)
        if query in history:
            history.remove(query)
        history.insert(0, query)
        history = history[:10]
        self.settings.setValue("search_history", history)

        # Обновляем модель комплетера
        self.completer.setModel(QStringListModel(history, self))

    def manual_clear_clipboard(self):
         #ручная очистка
        self.clipboard_service.clear_now()
        self.statusBar().showMessage("Буфер обмена очищен вручную", 3000)

    def _on_ephemeral_mode_changed(self, enabled):
         #эфемерный режим
        print(f"[MainWindow] Ephemeral mode changed: {enabled}")

        if enabled:
            # показ сообщения в статус-баре
            self.statusBar().showMessage(
                "🔒 Эфемерный режим ВКЛЮЧЕН - пароли не попадают в системный буфер. Используйте Ctrl+V для вставки",
                5000
            )

            # Добавляем постоянный индикатор в статус-бар (слева)
            if not hasattr(self, '_ephemeral_status_indicator'):
                self._ephemeral_status_indicator = QLabel("🔒 EPHEMERAL MODE ACTIVE")
                self._ephemeral_status_indicator.setStyleSheet(
                    "color: #27ae60; font-weight: bold; padding: 2px 10px; background-color: #2c3e50; border-radius: 3px; margin: 2px;"
                )
                # Добавляем в начало статус-бара
                self.status_bar.insertWidget(0, self._ephemeral_status_indicator)
            else:
                self._ephemeral_status_indicator.setVisible(True)

            # Синхронизация кнопки
            if hasattr(self, 'ephemeral_action') and not self.ephemeral_action.isChecked():
                self.ephemeral_action.setChecked(True)

        else:
            # Скрытие индикатора
            if hasattr(self, '_ephemeral_status_indicator'):
                self._ephemeral_status_indicator.setVisible(False)

            self.statusBar().showMessage("Эфемерный режим ВЫКЛЮЧЕН", 3000)

            # синхронизация кнопки
            if hasattr(self, 'ephemeral_action') and self.ephemeral_action.isChecked():
                self.ephemeral_action.setChecked(False)

    def _create_ephemeral_indicator(self):
        #индикатор эфемерного режима
        toolbar = None
        for tb in self.findChildren(QToolBar):
            if tb.windowTitle() == "Main Toolbar":
                toolbar = tb
                break

        if not toolbar:
            print("[MainWindow] Toolbar not found!")
            return

        self._ephemeral_indicator = QLabel("🔒 EPHEMERAL")
        self._ephemeral_indicator.setStyleSheet(
            "color: #27ae60; font-weight: bold; padding: 0 10px; background-color: #2c3e50; border-radius: 3px;"
        )
        self._ephemeral_indicator.setVisible(False)
        toolbar.addWidget(self._ephemeral_indicator)
        print("[MainWindow] Ephemeral indicator created in _create_ephemeral_indicator")

    def integrate_ephemeral_paste_for_widget(self, line_edit: QLineEdit):
        #вставка в эфемерном режиме
        if not hasattr(self, 'clipboard_service'):
            return

        from PyQt6.QtGui import QAction

        def custom_context_menu(pos):
            menu = QMenu(line_edit)

            # стандартные действия
            copy_action = menu.addAction("📋 Копировать")
            copy_action.triggered.connect(line_edit.copy)

            cut_action = menu.addAction("✂️ Вырезать")
            cut_action.triggered.connect(line_edit.cut)

            menu.addSeparator()

            # Эфемерная вставка
            ephemeral_action = QAction("🔒 Вставить из эфемерного буфера (безопасно)", line_edit)
            has_ephemeral = (self.clipboard_service.defender.has_ephemeral_data()
                             if hasattr(self.clipboard_service, 'defender') else False)
            ephemeral_action.setEnabled(has_ephemeral)
            ephemeral_action.triggered.connect(lambda: self._ephemeral_paste_to_field(line_edit))
            menu.addAction(ephemeral_action)

            # Стандартная вставка
            paste_action = menu.addAction("📋 Вставить (стандартно)")
            paste_action.triggered.connect(line_edit.paste)

            menu.exec(line_edit.mapToGlobal(pos))

        line_edit.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        line_edit.customContextMenuRequested.connect(custom_context_menu)

    def _ephemeral_paste_to_field(self, line_edit: QLineEdit):
        # Вставка пароля из эфемерного буфера в поле
        password = self.clipboard_service.get_ephemeral_password()
        if password:
            line_edit.setText(password)
            self.statusBar().showMessage(
                "🔒 Пароль вставлен из эфемерного буфера (безопасно, без системного буфера)",
                3000
            )
            # Опционально: очищаем эфемерный буфер после вставки
            # self.clipboard_service.defender._clear_ephemeral()
        else:
            self.statusBar().showMessage("Нет данных в эфемерном буфере", 2000)

    def copy_password_to_clipboard(self, entry_id):
        #print(f"[MainWindow] copy_password_to_clipboard slot hit! ID: {entry_id}")
        #копирование пароля
        if not entry_id: return
        try:
            entry_data = self.entry_manager.get_entry(entry_id)
            password = entry_data.get('password', '')
            if password:
                self.clipboard_service.copy_password(entry_id, password)
                # показ уведомлений только если включено
                if self.clipboard_service.are_notifications_enabled():
                    self.show_toast("🔑 Пароль скопирован")
            else:
                self.statusBar().showMessage("Пароль пуст", 3000)
        except Exception as e:
            print(f"Error copying password: {e}")

    def copy_username_to_clipboard(self, entry_id):
        if not entry_id: return
        try:
            entry_data = self.entry_manager.get_entry(entry_id)
            username = entry_data.get('username', '')
            if username:
                self.clipboard_service.copy_username(entry_id, username)
                if self.clipboard_service.are_notifications_enabled():
                    self.show_toast("👤 Логин скопирован")
            else:
                self.statusBar().showMessage("Логин пуст", 3000)
        except Exception as e:
            print(f"Error copying username: {e}")

    def copy_all_to_clipboard(self, entry_id):
        if not entry_id: return
        try:
            entry_data = self.entry_manager.get_entry(entry_id)
            username = entry_data.get('username', '')
            password = entry_data.get('password', '')
            data_str = f"{username}\t{password}"
            self.clipboard_service.copy_all(entry_id, data_str)
            if self.clipboard_service.are_notifications_enabled():
                self.show_toast("📋 Данные скопированы")
        except Exception as e:
            print(f"Error copying all: {e}")

    def on_clipboard_copied(self, entry_id):
        #Обновление UI после копирования
        # Подсвечиваем строку в таблице
        self.table.highlight_row(entry_id)
        # Обновляем превью в статус-баре
        self.update_clipboard_preview()

    def on_clipboard_cleared(self):
        #Обновление UI после очистки
        self.table.remove_highlight()
        self.statusBar().showMessage("Буфер очищен", 3000)
        self.clear_clipboard_preview()
        if self.clipboard_service.are_notifications_enabled():
            self.show_toast("🧹 Буфер очищен")

    def show_clear_warning(self):
        #Предупреждение за 5 секунд до очистки
        if self.clipboard_service.are_notifications_enabled():
            self.show_toast("⚠️ Буфер очистится через 5 секунд!")
        self.statusBar().showMessage("⚠️ Внимание! Буфер очистится через 5 секунд", 5000)

    def show_toast(self, message: str):
        #всплывающие уведомления
        if not hasattr(self, '_toast_label'):
            self._toast_label = QLabel(self)
            self._toast_label.setStyleSheet("""
                QLabel {
                    background-color: #333;
                    color: white;
                    padding: 10px;
                    border-radius: 5px;
                    font-weight: bold;
                }
            """)
            self._toast_label.setWindowFlags(Qt.WindowType.ToolTip)

        self._toast_label.setText(message)
        self._toast_label.adjustSize()

        # Позиционирование внизу справа
        x = self.width() - self._toast_label.width() - 20
        y = self.height() - self._toast_label.height() - 50
        self._toast_label.move(x, y)
        self._toast_label.show()

        # Таймер скрытия
        QTimer.singleShot(2000, self._toast_label.hide)

    def update_clipboard_preview(self):
        # обновление превью буфера в статус-баре
        if not hasattr(self, 'clipboard_preview'):
            return

        entry_id = self.clipboard_service.get_current_entry_id()
        data_type = self.clipboard_service.get_current_data_type()

        if entry_id:
            try:
                # Ищем данные в кэше
                entry_info = next((r for r in self.all_records_cache if r['id'] == entry_id), None)
                if entry_info:
                    source = entry_info.get('service', 'Unknown')

                    # Маскировака контента
                    preview_text = "••••••••"
                    if data_type == 'username':
                        preview_text = entry_info.get('username', '')
                    elif data_type == 'all':
                        preview_text = f"{entry_info.get('username', '')}:••••••••"

                    self.clipboard_preview.setText(f"📋 [{source}] {preview_text}")
                    self.clipboard_preview.setStyleSheet("color: #27ae60; font-weight: bold; padding: 0 10px;")
            except Exception as e:
                print(f"Preview error: {e}")
        else:
            self.clear_clipboard_preview()

    def clear_clipboard_preview(self):
        if hasattr(self, 'clipboard_preview'):
            self.clipboard_preview.setText("Буфер: пусто")
            self.clipboard_preview.setStyleSheet("color: #888; padding: 0 10px;")

    def enable_anti_screenshot(self):
        # антискриншот
        # print("[MainWindow] Enabling Anti-Screenshot protection...")

        if self._anti_screenshot_enabled:
            return
        if platform.system() == "Windows":
            try:
                import ctypes
                # Получаем дескриптор окна (HWND)
                hwnd = int(self.winId())

                user32 = ctypes.windll.user32
                WDA_EXCLUDEFROMCAPTURE = 0x00000011

                result = user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)

                if result:
                    self._anti_screenshot_enabled =True
                    print("[MainWindow] SUCCESS: Window protected from capture (WDA_EXCLUDEFROMCAPTURE).")
                else:
                    error = ctypes.get_last_error()
                    print(f"[MainWindow] FAILED: SetWindowDisplayAffinity returned 0. Error: {error}")

            except Exception as e:
                print(f"[MainWindow] Error enabling Anti-Screenshot: {e}")
        else:
            pass

    def disable_anti_screenshot(self):
        # Выключает защиту окна от скриншотов.
        # print("[MainWindow] Disabling Anti-Screenshot protection...")

        if not self._anti_screenshot_enabled:
            return
        if platform.system() == "Windows":
            try:
                import ctypes
                hwnd = int(self.winId())
                user32 = ctypes.windll.user32
                WDA_NONE = 0x00000000  # Снимаем все ограничения

                result = user32.SetWindowDisplayAffinity(hwnd, WDA_NONE)

                if result:
                    self._anti_screenshot_enabled = False
                    print("[MainWindow] SUCCESS: Window capture restored.")
                else:
                    print("[MainWindow] FAILED to restore window capture.")

            except Exception as e:
                print(f"[MainWindow] Error disabling Anti-Screenshot: {e}")

    def open_settings_dialog(self):
        # открытие окна настроек
        if not self.auth_service.is_authenticated():
            QMessageBox.warning(self, "Ошибка", "Сначала войдите в систему.")
            return

        dialog = SettingsDialog(self.clipboard_service, self.db_helper, self)

        # Подключаем сигнал пересоздания иконок/индикаторов если нужно
        dialog.settings_updated.connect(self._on_settings_updated)

        if dialog.exec():
            print("[MainWindow] Settings updated successfully.")

    def _on_settings_updated(self):
        # вызов после сохранения настроек
        pass

    #  Ручная проверка
    def manual_verify_audit_logs(self):
        if not hasattr(self, 'audit_logger') or not self.audit_logger:
            QMessageBox.warning(self, "Ошибка", "Система аудита не запущена.")
            return

        from src.core.audit.log_verifier import LogVerifier

        verifier = LogVerifier(self.db_helper, self.audit_logger.signer)
        results = verifier.verify_all()

        # Формируем отчет
        report = f"Проверено записей: {results['total_checked']}\n\n"

        if results['verified']:
            report += "✅ Статус: Целостность ПОДТВЕРЖДЕНА.\nВсе записи валидны."
            QMessageBox.information(self, "Проверка Аудита", report)
        else:
            report += "❌ Статус: ОБНАРУЖЕНО ВМЕШАТЕЛЬСТВО!\n\n"
            if results['invalid_hashes']:
                report += f"Измененные данные: {len(results['invalid_hashes'])}\n"
            if results['chain_breaks']:
                report += f"Разрывы цепочки: {len(results['chain_breaks'])}\n"

            #  Уведомление и реакция
            QMessageBox.critical(self, "Security Alert!", report)

            #  Блокировка хранилища
            # self.auth_service.logout()

    def open_audit_viewer(self):
        #Открытие окна просмотра журнала аудита
        if not self.auth_service.is_authenticated():
            QMessageBox.warning(self, "Ошибка", "Сначала войдите в систему.")
            return

        from src.gui.audit_viewer import AuditViewer
        viewer = AuditViewer(self.db_helper, self)
        viewer.exec()

    def periodic_audit_check(self):
        print("[Security] Running periodic audit check...")
        # Просто вызываем метод ручной проверки, но без диалога, если все ОК
        if not hasattr(self, 'audit_logger'): return

        from src.core.audit.log_verifier import LogVerifier
        verifier = LogVerifier(self.db_helper, self.audit_logger.signer)
        results = verifier.verify_all(limit=1000)  # Проверяем последние 1000

        if not results['verified']:
            QMessageBox.critical(self, "Security Alert", "Tampering detected during periodic check!")
            self.auth_service.logout()


    def open_export_dialog(self):
        """Открывает диалог экспорта (UI-1)."""
        from src.gui.export_dialog import ExportDialog

        # Проверка аудита (он нужен для логирования экспорта)
        if not self.audit_logger:
            QMessageBox.warning(self, "Ошибка", "Система аудита не инициализирована.")
            return

        dialog = ExportDialog(self.entry_manager, self.audit_logger, self)
        dialog.exec()


    def open_import_dialog(self):
        """Заглушка для импорта."""
        QMessageBox.information(self, "В разработке", "Импорт будет реализован в следующем модуле.")