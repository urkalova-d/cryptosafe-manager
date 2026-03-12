from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt6.QtCore import pyqtSignal

class LoginWindow(QDialog):
    login_attempt = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Вход в систему")
        self.setFixedSize(300, 150)
        self.setModal(True)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Введите мастер-пароль:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        self.btn_login = QPushButton("Войти")
        self.btn_login.clicked.connect(self.handle_login)
        layout.addWidget(self.btn_login)

        self.setLayout(layout)

    def handle_login(self):
        password = self.password_input.text()
        if password:
            self.login_attempt.emit(password)
            self.accept()