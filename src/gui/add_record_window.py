from PyQt6.QtWidgets import QDialog, QFormLayout, QLineEdit, QPushButton, QVBoxLayout
from PyQt6.QtCore import pyqtSignal

class AddRecordWindow(QDialog):
    record_saved = pyqtSignal(str, str, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Добавить запись")
        self.setMinimumWidth(350)

        layout = QVBoxLayout()
        form = QFormLayout()

        self.service = QLineEdit()
        self.login = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.notes = QLineEdit()

        form.addRow("Сервис:", self.service)
        form.addRow("Логин:", self.login)
        form.addRow("Пароль:", self.password)
        form.addRow("Заметки:", self.notes)

        layout.addLayout(form)

        btn_save = QPushButton("Сохранить")
        btn_save.clicked.connect(self.save)
        layout.addWidget(btn_save)

        self.setLayout(layout)

    def save(self):
        self.record_saved.emit(
            self.service.text(),
            self.login.text(),
            self.password.text(),
            self.notes.text()
        )
        self.accept()