from PyQt6.QtWidgets import (QDialog, QFormLayout, QLineEdit, QPushButton,
                             QVBoxLayout, QHBoxLayout, QMessageBox, QComboBox)
from PyQt6.QtCore import pyqtSignal

from src.core.vault.password_generator import PasswordGenerator


class AddRecordWindow(QDialog):
    record_saved = pyqtSignal(str, str, str, str, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Добавить запись")
        self.setMinimumWidth(400)

        layout = QVBoxLayout()
        form = QFormLayout()

        # Поля ввода
        self.service = QLineEdit()
        self.login = QLineEdit()
        self.url = QLineEdit()  # Поле URL
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.notes = QLineEdit()

        # Выбор категории (Requirement 3.2)
        self.category = QComboBox()
        self.category.addItems(["Uncategorized", "Work", "Personal", "Finance", "Social", "Development"])
        self.category.setEditable(True)  # Разрешаем ввод своей категории

        form.addRow("Сервис:", self.service)
        form.addRow("Логин:", self.login)
        form.addRow("URL:", self.url)
        form.addRow("Категория:", self.category)
        form.addRow("Пароль:", self.password)
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
            pwd = PasswordGenerator.generate(length=20)
            self.password.setText(pwd)
            self.password.setEchoMode(QLineEdit.EchoMode.Normal)
            QMessageBox.information(self, "Успех", "Надежный пароль сгенерирован!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сгенерировать: {e}")

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