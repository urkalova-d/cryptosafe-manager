import re  # Добавлен импорт для регулярных выражений
from PyQt6.QtWidgets import (QDialog, QFormLayout, QLineEdit, QPushButton,
                             QVBoxLayout, QHBoxLayout, QMessageBox, QComboBox,
                             QLabel, QMenu, QCheckBox, QSpinBox, QWidget)
from PyQt6.QtCore import pyqtSignal, QUrl, Qt, QThread
from PyQt6.QtGui import QIcon, QPixmap

from urllib.parse import urlparse
from src.core.vault.password_generator import PasswordGenerator
from PyQt6.QtGui import QAction

import requests


class FaviconWorker(QThread):
    # поток для загрузки
    finished = pyqtSignal(QPixmap)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        try:
            resp = requests.get(self.url, timeout=3)
            if resp.status_code == 200:
                from PyQt6.QtGui import QImage
                img = QImage()
                if img.loadFromData(resp.content):
                    pixmap = QPixmap.fromImage(img)
                    self.finished.emit(pixmap)
        except Exception:
            pass


class AddRecordWindow(QDialog):
    record_saved = pyqtSignal(str, str, str, str, str, str)

    def __init__(self, db_helper, parent=None):
        super().__init__(parent)
        self.db_helper = db_helper
        self.setWindowTitle("Добавить запись")
        self.setMinimumWidth(500)

        self._is_updating_url = False

        # Получаем clipboard_service от parent (MainWindow)
        if parent and hasattr(parent, 'clipboard_service'):
            self.clipboard_service = parent.clipboard_service
        else:
            self.clipboard_service = None

        layout = QVBoxLayout()
        form = QFormLayout()

        # поля ввода

        # Сервис с местом под иконку
        service_layout = QHBoxLayout()
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(24, 24)
        self.icon_label.setStyleSheet("border: 1px solid #ccc; border-radius: 2px;")
        self.service = QLineEdit()
        service_layout.addWidget(self.icon_label)
        service_layout.addWidget(self.service)
        form.addRow("Сервис:", service_layout)

        # URL с валидацией
        self.url = QLineEdit()
        self.url.textChanged.connect(self.on_url_changed)
        form.addRow("URL:", self.url)

        # ногин с автозаполнением
        self.login = QLineEdit()
        form.addRow("Логин:", self.login)

        # категории
        self.category = QComboBox()
        self.category.addItems(["Uncategorized", "Work", "Personal", "Finance", "Social", "Development"])
        self.category.setEditable(True)
        form.addRow("Категория:", self.category)

        # пароль
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.textChanged.connect(self.update_strength_indicator)

        self.password.keyPressEvent = self._create_keypress_handler(self.password)

        # метка силы
        self.strength_label = QLabel("")
        self.strength_label.setStyleSheet("font-size: 10px;")

        pass_layout = QVBoxLayout()
        pass_layout.addWidget(self.password)
        pass_layout.addWidget(self.strength_label)
        form.addRow("Пароль:", pass_layout)

        # заметки
        self.notes = QLineEdit()
        form.addRow("Заметки:", self.notes)


        layout.addLayout(form)
        if self.clipboard_service:
            self.integrate_ephemeral_paste(self.password)

        # кнопки

        btn_layout = QHBoxLayout()

        self.btn_gen = QPushButton("Сгенерировать")
        self.gen_menu = QMenu(self)
        self.gen_menu.addAction("По умолчанию (16 символов)", lambda: self.generate_password())
        custom_action = self.gen_menu.addAction("Настроить...")
        custom_action.triggered.connect(self.show_config_popup)

        self.btn_gen.setMenu(self.gen_menu)
        btn_layout.addWidget(self.btn_gen)

        btn_layout.addStretch()

        btn_save = QPushButton("Сохранить")
        btn_save.clicked.connect(self.save)
        btn_layout.addWidget(btn_save)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def on_url_changed(self, text):
        # защита от рекурсии
        if self._is_updating_url:
            return

        domain = self._extract_domain(text)

        # автозаполнение логина, только если он пуст
        if domain and not self.login.text():
            default_login = f"user@{domain}"
            self.login.setText(default_login)

        # Загрузка фавиконки
        self.load_favicon(text)

    def load_favicon(self, url):
        # fсинхронная загрузка
        domain = self._extract_domain(url)
        if domain:
            favicon_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=32"
            if hasattr(self, 'worker') and self.worker.isRunning():
                self.worker.terminate()  # остановка предыдущего запроса

            self.worker = FaviconWorker(favicon_url)
            self.worker.finished.connect(self.set_icon)
            self.worker.start()

    def set_icon(self, pixmap):
        if not pixmap.isNull():
            self.icon_label.setPixmap(
                pixmap.scaled(24, 24, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
            self.icon_label.setStyleSheet("border: none;")

    def _extract_domain(self, url):
        try:
            #  добавление http для парсинга
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return ""

    def show_config_popup(self):
        #
        dialog = QDialog(self)
        dialog.setWindowTitle("Настройки генерации")
        layout = QVBoxLayout(dialog)

        length_spin = QSpinBox()
        length_spin.setRange(8, 64)
        length_spin.setValue(16)
        layout.addWidget(QLabel("Длина:"))
        layout.addWidget(length_spin)

        chk_upper = QCheckBox("Заглавные (A-Z)");
        chk_upper.setChecked(True)
        chk_lower = QCheckBox("Строчные (a-z)");
        chk_lower.setChecked(True)
        chk_digits = QCheckBox("Цифры (0-9)");
        chk_digits.setChecked(True)
        chk_symbols = QCheckBox("Символы (!@#$)");
        chk_symbols.setChecked(True)
        chk_amb = QCheckBox("Исключить похожие (l, I, 1)");
        chk_amb.setChecked(True)

        layout.addWidget(chk_upper)
        layout.addWidget(chk_lower)
        layout.addWidget(chk_digits)
        layout.addWidget(chk_symbols)
        layout.addWidget(chk_amb)

        btn_gen = QPushButton("Сгенерировать")

        def do_gen():
            pwd, _ = PasswordGenerator.generate_custom(
                length=length_spin.value(),
                use_upper=chk_upper.isChecked(),
                use_lower=chk_lower.isChecked(),
                use_digits=chk_digits.isChecked(),
                use_symbols=chk_symbols.isChecked(),
                exclude_ambiguous=chk_amb.isChecked(),
                db_helper=self.db_helper
            )
            self.password.setText(pwd)
            self.password.setEchoMode(QLineEdit.EchoMode.Normal)
            dialog.accept()

        btn_gen.clicked.connect(do_gen)
        layout.addWidget(btn_gen)

        dialog.exec()

    def generate_password(self):
        try:
            pwd, score = PasswordGenerator.generate(db_helper=self.db_helper)
            self.password.setText(pwd)
            self.password.setEchoMode(QLineEdit.EchoMode.Normal)
            self.update_strength_indicator()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def update_strength_indicator(self):
        text = self.password.text()
        if not text:
            self.strength_label.setText("")
            return

        score = 0
        try:
            # Проверка доступности через модуль, а не атрибут класса
            try:
                from zxcvbn import zxcvbn
                res = zxcvbn(text)
                score = res['score']
            except ImportError:
                # если библиотеки нет, простая оценка по длине
                score = 4 if len(text) >= 16 else 2
        except:
            score = 0

        color = "green" if score >= 3 else "orange" if score == 2 else "red"
        self.strength_label.setText(f"Сила: {score}/4")
        self.strength_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def save(self):
        # реализация строгой валидации формы

        service = self.service.text().strip()
        pwd = self.password.text()
        url = self.url.text().strip()

        #обязательные поля
        if not service:
            QMessageBox.warning(self, "Ошибка валидации", "Поле 'Сервис' обязательно для заполнения.")
            return

        if not pwd:
            QMessageBox.warning(self, "Ошибка валидации", "Поле 'Пароль' обязательно для заполнения.")
            return

        # URL
        if url:
            check_url = url
            if not url.startswith(('http://', 'https://')):
                check_url = 'https://' + url

            domain_regex = re.compile(
                r'^(https?://)?'  
                r'((([a-z\d]([a-z\d-]*[a-z\d])*)\.)+[a-z]{2,}|'  
                r'((\d{1,3}\.){3}\d{1,3})|'  
                r'localhost)'  
                r'(:\d+)?'  
                r'(/.*)?$', re.IGNORECASE)

            if not domain_regex.match(check_url):
                QMessageBox.warning(self, "Ошибка валидации",
                                    "Некорректный формат URL.\nПример: https://example.com")
                return
            url = check_url

        #  сила пароля
        is_valid_strength, msg = PasswordGenerator.validate_password_strength(pwd)

        if not is_valid_strength:
            # Если пароль слабый, показываем ошибку и не даем сохранить
            QMessageBox.critical(self, "Слабый пароль",
                                 f"Пароль не соответствует требованиям безопасности:\n{msg}\n\n"
                                 "Пожалуйста, используйте генератор или придумайте надежный пароль.")
            return

        # Если все проверки пройдены
        self.record_saved.emit(
            service,
            self.login.text(),
            pwd,
            url,
            self.category.currentText(),
            self.notes.text()
        )
        self.accept()

    def integrate_ephemeral_paste(self, line_edit: QLineEdit):
        """
        Интеграция эфемерной вставки в поле ввода.
        Позволяет вставлять пароль через стандартное Ctrl+V когда эфемерный режим включен.
        """
        if not self.clipboard_service:
            return

        # Сохраняем оригинальный метод paste
        original_paste = line_edit.paste

        def custom_paste():
            """Переопределенная вставка для эфемерного режима"""
            if self.clipboard_service and self.clipboard_service.is_ephemeral_mode():
                # В эфемерном режиме - берем пароль из эфемерного буфера
                password = self.clipboard_service.get_ephemeral_password()
                if password:
                    line_edit.setText(password)
                    if self.parent() and hasattr(self.parent(), 'statusBar'):
                        self.parent().statusBar().showMessage("🔒 Пароль вставлен из эфемерного буфера", 3000)
                    return
            # Иначе - стандартная вставка
            original_paste()

        # Переопределяем paste
        line_edit.paste = custom_paste

    def _ephemeral_paste_to_field(self, line_edit: QLineEdit):
        """Вставка из эфемерного буфера в поле"""
        if not self.clipboard_service:
            return
        password = self.clipboard_service.get_ephemeral_password()
        if password:
            line_edit.setText(password)
            # Уведомление (если есть statusBar через parent)
            if self.parent() and hasattr(self.parent(), 'statusBar'):
                self.parent().statusBar().showMessage("Пароль вставлен из эфемерного буфера (безопасно)", 3000)

    def _paste_from_ephemeral(self):
        """Вставка из эфемерного буфера по кнопке"""
        if not self.clipboard_service:
            return
        password = self.clipboard_service.get_ephemeral_password()
        if password:
            self.password.setText(password)
            self.password.setEchoMode(QLineEdit.EchoMode.Normal)
            if self.parent() and hasattr(self.parent(), 'statusBar'):
                self.parent().statusBar().showMessage("🔒 Пароль вставлен из эфемерного буфера", 3000)
        else:
            QMessageBox.information(self, "Нет данных", "В эфемерном буфере нет пароля")

    def _update_ephemeral_button(self):
        """Обновление состояния кнопки эфемерной вставки"""
        if not self.clipboard_service:
            return
        is_ephemeral = self.clipboard_service.is_ephemeral_mode()
        has_data = False
        if hasattr(self.clipboard_service, 'defender') and self.clipboard_service.defender:
            has_data = self.clipboard_service.defender.has_ephemeral_data()
        self.ephemeral_paste_btn.setVisible(is_ephemeral and has_data)

    def _create_keypress_handler(self, line_edit):
        """Создает обработчик клавиш для поля ввода"""
        original_keypress = line_edit.keyPressEvent

        def custom_keypress(event):
            # Проверяем Ctrl+V
            if event.modifiers() == Qt.KeyboardModifier.ControlModifier and event.key() == Qt.Key.Key_V:
                if self.clipboard_service and self.clipboard_service.is_ephemeral_mode():
                    password = self.clipboard_service.get_ephemeral_password()
                    if password:
                        line_edit.setText(password)
                        line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
                        if self.parent() and hasattr(self.parent(), 'statusBar'):
                            self.parent().statusBar().showMessage("🔒 Пароль вставлен из эфемерного буфера", 3000)
                        return
            # Для всех остальных клавиш - стандартная обработка
            original_keypress(event)

        return custom_keypress

