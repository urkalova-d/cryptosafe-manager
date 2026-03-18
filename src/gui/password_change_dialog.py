from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QLabel, QLineEdit,
                             QPushButton, QMessageBox, QProgressDialog, QStatusBar)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from src.core.crypto.key_derivation import KeyDerivationService


class PasswordChangeDialog(QDialog):
    def __init__(self, key_manager, db_helper, parent=None):
        super().__init__(parent)
        self.key_manager = key_manager
        self.db_helper = db_helper
        self.kdf = KeyDerivationService()

        self.setWindowTitle("Смена мастер-пароля")
        self.setFixedSize(400, 250)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)

        layout = QVBoxLayout()

        # текущий пароль
        layout.addWidget(QLabel("Текущий мастер-пароль:"))
        self.current_pwd_input = QLineEdit()
        self.current_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.current_pwd_input)

        # новый пароль
        layout.addWidget(QLabel("Новый мастер-пароль:"))
        self.new_pwd_input = QLineEdit()
        self.new_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.new_pwd_input)

        # подтверждение нового пароля
        layout.addWidget(QLabel("Подтвердите новый пароль:"))
        self.confirm_pwd_input = QLineEdit()
        self.confirm_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm_pwd_input)

        self.btn_change = QPushButton("Сменить пароль")
        self.btn_change.clicked.connect(self.validate_and_accept)
        layout.addWidget(self.btn_change)

        self.setLayout(layout)

    def validate_and_accept(self):
        current_pwd = self.current_pwd_input.text()
        new_pwd = self.new_pwd_input.text()
        confirm_pwd = self.confirm_pwd_input.text()

        # проверка текущего пароля
        stored_hash = self.db_helper.get_setting("master_hash")
        if not self.kdf.verify_password(current_pwd, stored_hash):
            QMessageBox.critical(self, "Ошибка", "Неверный текущий пароль!")
            return # Окно не закрывается

        # проверка совпадения
        if new_pwd != confirm_pwd:
            QMessageBox.critical(self, "Ошибка", "Новые пароли не совпадают!")
            return

        #  надежность
        is_strong, msg = self.kdf.validate_password_strength(new_pwd)
        if not is_strong:
            QMessageBox.warning(self, "Слабый пароль", msg)
            return

        #  передача данных родителю и закрытие
        self.new_password = new_pwd
        self.old_password = current_pwd
        self.accept()