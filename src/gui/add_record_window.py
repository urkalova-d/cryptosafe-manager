from PyQt6.QtWidgets import (QDialog, QFormLayout, QLineEdit, QPushButton,
                             QVBoxLayout, QHBoxLayout, QMessageBox, QComboBox,
                             QLabel, QMenu, QCheckBox, QSpinBox, QWidget)
from PyQt6.QtCore import pyqtSignal, QUrl, Qt, QThread
from PyQt6.QtGui import QIcon, QPixmap

from urllib.parse import urlparse
from src.core.vault.password_generator import PasswordGenerator

# Импорт для загрузки через requests
import requests


class FaviconWorker(QThread):
    """Поток для загрузки фавиконки"""
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

        # Флаг для предотвращения рекурсии
        self._is_updating_url = False

        layout = QVBoxLayout()
        form = QFormLayout()

        # --- Поля ввода ---

        # Сервис (с местом под иконку)
        service_layout = QHBoxLayout()
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(24, 24)
        self.icon_label.setStyleSheet("border: 1px solid #ccc; border-radius: 2px;")
        self.service = QLineEdit()
        service_layout.addWidget(self.icon_label)
        service_layout.addWidget(self.service)
        form.addRow("Сервис:", service_layout)

        # URL (с валидацией)
        self.url = QLineEdit()
        self.url.textChanged.connect(self.on_url_changed)
        form.addRow("URL:", self.url)

        # Логин (с автозаполнением)
        self.login = QLineEdit()
        form.addRow("Логин:", self.login)

        # Категория
        self.category = QComboBox()
        self.category.addItems(["Uncategorized", "Work", "Personal", "Finance", "Social", "Development"])
        self.category.setEditable(True)
        form.addRow("Категория:", self.category)

        # Пароль
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.textChanged.connect(self.update_strength_indicator)

        # Метка силы
        self.strength_label = QLabel("")
        self.strength_label.setStyleSheet("font-size: 10px;")

        pass_layout = QVBoxLayout()
        pass_layout.addWidget(self.password)
        pass_layout.addWidget(self.strength_label)
        form.addRow("Пароль:", pass_layout)

        # Заметки
        self.notes = QLineEdit()
        form.addRow("Заметки:", self.notes)

        layout.addLayout(form)

        # --- Кнопки ---

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
        """Req 3: Auto-fill username based on domain patterns"""

        # ЗАЩИТА ОТ РЕКУРСИИ: Если мы сейчас сами меняем текст, выходим
        if self._is_updating_url:
            return

        domain = self._extract_domain(text)

        # Автозаполнение логина, только если он пуст
        if domain and not self.login.text():
            default_login = f"user@{domain}"
            self.login.setText(default_login)
            # УБРАНО: self.login.setFocus() - это вызывало перескок фокуса

        # Загрузка фавиконки
        self.load_favicon(text)

    def load_favicon(self, url):
        """Асинхронная загрузка фавиконки"""
        domain = self._extract_domain(url)
        if domain:
            favicon_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=32"
            if hasattr(self, 'worker') and self.worker.isRunning():
                self.worker.terminate()  # Останавливаем предыдущий запрос

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
            # Если протокол не указан, добавляем http для парсинга
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return ""

    def show_config_popup(self):
        """Req 1: Configuration popup"""
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
            from src.core.vault.password_generator import ZXCVBN_AVAILABLE
            if ZXCVBN_AVAILABLE:
                from zxcvbn import zxcvbn
                res = zxcvbn(text)
                score = res['score']
            else:
                score = 4 if len(text) >= 16 else 2
        except:
            score = 0

        color = "green" if score >= 3 else "orange" if score == 2 else "red"
        self.strength_label.setText(f"Сила: {score}/4")
        self.strength_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def save(self):
        """Req 2: Form validation"""
        service = self.service.text().strip()
        pwd = self.password.text()
        url = self.url.text().strip()

        if not service:
            QMessageBox.warning(self, "Ошибка", "Название сервиса обязательно!")
            return

        # Проверка URL
        if url:
            # Авто-исправление: добавляем https если нет протокола
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            qurl = QUrl(url)
            if not qurl.isValid():
                QMessageBox.warning(self, "Ошибка", "Некорректный формат URL.")
                return

        # Проверка силы пароля
        valid, msg = PasswordGenerator.validate_password_strength(pwd)
        if not valid:
            reply = QMessageBox.question(self, "Слабый пароль",
                                         f"{msg}\n\nВсе равно сохранить?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                return

        self.record_saved.emit(
            service,
            self.login.text(),
            pwd,
            url,  # Отправляем исправленный URL
            self.category.currentText(),
            self.notes.text()
        )
        self.accept()