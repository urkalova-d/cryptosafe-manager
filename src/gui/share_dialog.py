from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QComboBox,
                             QRadioButton, QButtonGroup, QSpinBox,
                             QFileDialog, QMessageBox, QGroupBox, QTextEdit)
import json
import os


class ShareDialog(QDialog):
    """
    UI для процесса шаринга (SHR-3).
    """

    def __init__(self, entry_manager, entry_id, parent=None):
        super().__init__(parent)
        self.entry_manager = entry_manager
        self.entry_id = entry_id
        self.setWindowTitle("Безопасный обмен записью")
        self.setMinimumWidth(450)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # --- Выбор метода (SHR-1) ---
        method_group = QGroupBox("Метод шифрования")
        method_layout = QVBoxLayout()

        self.radio_password = QRadioButton("Пароль (Простой)")
        self.radio_rsa = QRadioButton("Публичный ключ (RSA)")
        self.radio_password.setChecked(True)

        method_layout.addWidget(self.radio_password)
        method_layout.addWidget(self.radio_rsa)
        method_group.setLayout(method_layout)
        layout.addWidget(method_group)

        # --- Параметры ---
        params_group = QGroupBox("Параметры")
        params_layout = QVBoxLayout()

        # Поле для пароля или ключа
        self.stacked_input_label = QLabel("Пароль для файла:")
        self.stacked_input = QLineEdit()
        self.stacked_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.stacked_input_confirm = QLineEdit()
        self.stacked_input_confirm.setPlaceholderText("Повторите пароль")
        self.stacked_input_confirm.setEchoMode(QLineEdit.EchoMode.Password)

        # Поле для публичного ключа (скрыто по умолчанию)
        self.pub_key_label = QLabel("Публичный ключ получателя (PEM):")
        self.pub_key_input = QTextEdit()
        self.pub_key_input.setPlaceholderText("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----")
        self.pub_key_input.setVisible(False)
        self.pub_key_label.setVisible(False)

        # Переключение режимов
        self.radio_password.toggled.connect(self.toggle_input_mode)

        params_layout.addWidget(self.stacked_input_label)
        params_layout.addWidget(self.stacked_input)
        params_layout.addWidget(self.stacked_input_confirm)
        params_layout.addWidget(self.pub_key_label)
        params_layout.addWidget(self.pub_key_input)

        # Срок действия
        exp_layout = QHBoxLayout()
        exp_layout.addWidget(QLabel("Срок действия (дней):"))
        self.exp_spin = QSpinBox()
        self.exp_spin.setRange(1, 30)
        self.exp_spin.setValue(7)
        exp_layout.addStretch()
        exp_layout.addWidget(self.exp_spin)
        params_layout.addLayout(exp_layout)

        params_group.setLayout(params_layout)
        layout.addWidget(params_group)

        # --- Кнопки ---
        btn_layout = QHBoxLayout()
        self.share_btn = QPushButton("Создать файл обмена")
        self.share_btn.clicked.connect(self.perform_share)
        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.clicked.connect(self.reject)

        btn_layout.addStretch()
        btn_layout.addWidget(self.share_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

    def toggle_input_mode(self, is_password):
        is_rsa = not is_password

        self.stacked_input_label.setText("Пароль для файла:" if is_password else "Ваш секрет:")
        self.stacked_input.setVisible(is_password)
        self.stacked_input_confirm.setVisible(is_password)

        self.pub_key_label.setVisible(is_rsa)
        self.pub_key_input.setVisible(is_rsa)

    def perform_share(self):
        # Валидация
        days = self.exp_spin.value()

        try:
            from src.core.import_export.sharing_service import SharingService
            service = SharingService(self.entry_manager)

            if self.radio_password.isChecked():
                pwd = self.stacked_input.text()
                pwd_conf = self.stacked_input_confirm.text()

                if len(pwd) < 6:
                    QMessageBox.warning(self, "Ошибка", "Пароль слишком короткий (мин. 6 символов).")
                    return
                if pwd != pwd_conf:
                    QMessageBox.warning(self, "Ошибка", "Пароли не совпадают.")
                    return

                package = service.share_via_password(self.entry_id, pwd, days)

            else:
                pub_key = self.pub_key_input.toPlainText().strip()
                if not pub_key.startswith("-----BEGIN PUBLIC KEY-----"):
                    QMessageBox.warning(self, "Ошибка", "Неверный формат публичного ключа.")
                    return

                package = service.share_via_public_key(self.entry_id, pub_key, days)

            # Сохранение файла
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Сохранить запись", "shared_entry.csshare", "CryptoSafe Share (*.csshare)"
            )

            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(package, f, indent=4)

                QMessageBox.information(self, "Успех", f"Запись успешно зашифрована и сохранена!\nФайл: {file_path}")
                self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать файл обмена:\n{str(e)}")