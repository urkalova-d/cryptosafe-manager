from PyQt6.QtWidgets import (QDialog, QFormLayout, QLineEdit, QPushButton,
                             QVBoxLayout, QHBoxLayout, QMessageBox, QComboBox,QLabel)
from PyQt6.QtCore import pyqtSignal

from src.core.vault.password_generator import PasswordGenerator


class AddRecordWindow(QDialog):
    record_saved = pyqtSignal(str, str, str, str, str, str)

    def __init__(self,db_helper, parent=None):
        super().__init__(parent)
        self.db_helper = db_helper  # Сохраняем ссылку на БД
        self.setWindowTitle("Добавить запись")
        self.setMinimumWidth(450)

        layout = QVBoxLayout()
        form = QFormLayout()

        # Поля ввода
        self.service = QLineEdit()
        self.login = QLineEdit()
        self.url = QLineEdit()  # Поле URL
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        # Подключаем сигнал изменения текста к функции обновления силы
        self.password.textChanged.connect(self.update_strength_indicator)

        self.notes = QLineEdit()

        self.strength_label = QLabel("")
        self.strength_label.setStyleSheet("font-size: 10px;")

        # Выбор категории
        self.category = QComboBox()
        self.category.addItems(["Uncategorized", "Work", "Personal", "Finance", "Social", "Development"])
        self.category.setEditable(True)  # Разрешаем ввод своей категории

        form.addRow("Сервис:", self.service)
        form.addRow("Логин:", self.login)
        form.addRow("URL:", self.url)
        form.addRow("Категория:", self.category)
        form.addRow("Пароль:", self.password)
        form.addRow("", self.strength_label)  # Добавили метку силы
        form.addRow("Заметки:", self.notes)

        layout.addLayout(form)

        # Кнопки
        btn_layout = QHBoxLayout()

        btn_gen = QPushButton("Сгенерировать")
        btn_gen.clicked.connect(self.generate_password)
        btn_layout.addWidget(btn_gen)

        btn_save = QPushButton("Сохранить")
        btn_save.clicked.connect(self.save)
        btn_layout.addWidget(btn_save)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def generate_password(self):
        try:
            pwd, score = PasswordGenerator.generate(
                length=16,
                exclude_ambiguous=True,
                db_helper=self.db_helper
            )
            # Устанавливаем пароль в поле ввода
            self.password.setText(pwd)
            # Показываем пароль (снимаем маску)
            self.password.setEchoMode(QLineEdit.EchoMode.Normal)

            # Ручное обновление метки силы (т.к. setText может не вызвать update_strength_indicator мгновенно)
            self.update_strength_indicator()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сгенерировать: {e}")

    def update_strength_indicator(self):
        """Проверяет текущий пароль и обновляет метку силы."""
        text = self.password.text()

        if not text:
            self.strength_label.setText("")
            return

        # Проверяем через zxcvbn, если доступен
        score = 0
        try:
            # Используем тот же механизм, что и в генераторе
            from src.core.vault.password_generator import ZXCVBN_AVAILABLE
            if ZXCVBN_AVAILABLE:
                from zxcvbn import zxcvbn
                results = zxcvbn(text)
                score = results['score']
            else:
                # Fallback: простая проверка длины, если zxcvbn нет
                score = 4 if len(text) >= 16 else 2
        except Exception:
            score = 0

        # Формируем текст и цвет
        strength_text = f"Сила пароля: {score}/4"
        if score >= 3:
            color = "green"
        elif score == 2:
            color = "orange"
        else:
            color = "red"

        self.strength_label.setText(strength_text)
        self.strength_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def save(self):
        if not self.service.text() or not self.password.text():
            QMessageBox.warning(self, "Внимание", "Сервис и Пароль обязательны!")
            return

        self.record_saved.emit(
            self.service.text(),
            self.login.text(),
            self.password.text(),
            self.url.text(),
            self.category.currentText(),
            self.notes.text()
        )
        self.accept()