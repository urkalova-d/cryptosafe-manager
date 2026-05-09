# src/gui/export_dialog.py
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QComboBox, QCheckBox,
                             QFileDialog, QMessageBox, QGroupBox, QWidget)
from PyQt6.QtCore import Qt
import os


class ExportDialog(QDialog):
    def __init__(self, entry_manager, audit_logger, parent=None):
        # === ЭТА СТРОКА ВАЖНА ===
        # Мы передаем только 'parent' в QDialog.
        # 'entry_manager' и 'audit_logger' мы сохраняем в self.
        super().__init__(parent)

        self.entry_manager = entry_manager
        self.audit_logger = audit_logger
        self.selected_file_path = ""

        self.setWindowTitle("Экспорт хранилища")
        self.setMinimumWidth(500)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # --- Выбор формата ---
        format_group = QGroupBox("Формат экспорта")
        format_layout = QVBoxLayout()

        self.format_combo = QComboBox()
        self.format_combo.addItem("Encrypted JSON (Рекомендуется)", "encrypted_json")
        self.format_combo.addItem("CSV (Открытый текст)", "csv")
        self.format_combo.currentIndexChanged.connect(self.on_format_changed)

        format_layout.addWidget(QLabel("Формат файла:"))
        format_layout.addWidget(self.format_combo)
        format_group.setLayout(format_layout)
        layout.addWidget(format_group)

        # --- Настройки безопасности ---
        self.security_group = QGroupBox("Безопасность")
        security_layout = QVBoxLayout()

        security_layout.addWidget(QLabel("Пароль для файла экспорта:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Введите пароль для шифрования файла")
        security_layout.addWidget(self.password_input)

        self.password_confirm = QLineEdit()
        self.password_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_confirm.setPlaceholderText("Повторите пароль")
        security_layout.addWidget(self.password_confirm)

        self.compress_check = QCheckBox("Сжатие (GZIP)")
        self.compress_check.setChecked(True)
        security_layout.addWidget(self.compress_check)

        self.exclude_notes_check = QCheckBox("Исключить заметки (Notes)")
        security_layout.addWidget(self.exclude_notes_check)

        self.security_group.setLayout(security_layout)
        layout.addWidget(self.security_group)

        # --- Выбор файла ---
        file_layout = QHBoxLayout()
        self.file_path_label = QLabel("Файл не выбран")
        self.browse_btn = QPushButton("Выбрать файл...")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_path_label, 1)
        file_layout.addWidget(self.browse_btn)
        layout.addLayout(file_layout)

        # --- Кнопки ---
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.export_btn = QPushButton("Экспорт")
        self.export_btn.clicked.connect(self.perform_export)

        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

        self.on_format_changed(0)

    def on_format_changed(self, index):
        is_encrypted = self.format_combo.currentData() == "encrypted_json"
        self.security_group.setEnabled(is_encrypted)

    def browse_file(self):
        fmt = self.format_combo.currentData()
        ext = ".csjson" if fmt == "encrypted_json" else ".csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить как", f"vault_backup{ext}", f"Files (*{ext})"
        )
        if path:
            self.selected_file_path = path
            self.file_path_label.setText(os.path.basename(path))

    def perform_export(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "Ошибка", "Выберите файл для сохранения.")
            return

        fmt = self.format_combo.currentData()
        password = None

        if fmt == "encrypted_json":
            pwd = self.password_input.text()
            pwd_conf = self.password_confirm.text()
            if len(pwd) < 8:
                QMessageBox.warning(self, "Слабый пароль", "Пароль должен быть не менее 8 символов.")
                return
            if pwd != pwd_conf:
                QMessageBox.warning(self, "Ошибка", "Пароли не совпадают.")
                return
            password = pwd

        try:
            from src.core.import_export.exporter import VaultExporter
            exporter = VaultExporter(self.entry_manager, self.audit_logger)

            options = {
                'compression': self.compress_check.isChecked(),
                'exclude_fields': ['notes'] if self.exclude_notes_check.isChecked() else []
            }

            success = exporter.export_vault(
                file_path=self.selected_file_path,
                password=password,
                entry_ids=None,
                format_type=fmt,
                options=options
            )

            if success:
                QMessageBox.information(self, "Успех", f"Экспорт завершен!\nФайл: {self.selected_file_path}")
                self.accept()
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось выполнить экспорт.")

        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Ошибка", f"Ошибка при экспорте:\n{str(e)}")