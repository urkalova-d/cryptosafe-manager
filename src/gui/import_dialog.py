# src/gui/import_dialog.py
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QComboBox,
                             QRadioButton, QButtonGroup, QSpinBox,
                             QFileDialog, QMessageBox, QListWidget, QGroupBox,
                             QSplitter, QTextEdit, QProgressDialog)
from PyQt6.QtCore import Qt
import os


class ImportDialog(QDialog):
    def __init__(self, entry_manager, audit_logger, parent=None):
        super().__init__(parent)
        self.entry_manager = entry_manager
        self.audit_logger = audit_logger
        self.selected_file_path = ""

        self.setWindowTitle("Импорт данных")
        self.resize(700, 500)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # --- File Selection ---
        src_group = QGroupBox("Источник")
        src_layout = QHBoxLayout()
        self.file_label = QLabel("Файл не выбран")
        btn_browse = QPushButton("Обзор...")
        btn_browse.clicked.connect(self.browse_file)
        src_layout.addWidget(self.file_label, 1)
        src_layout.addWidget(btn_browse)
        src_group.setLayout(src_layout)
        layout.addWidget(src_group)

        # --- Settings ---
        sett_group = QGroupBox("Настройки")
        sett_layout = QVBoxLayout()

        # Format
        h_fmt = QHBoxLayout()
        h_fmt.addWidget(QLabel("Формат:"))
        self.format_combo = QComboBox()
        self.format_combo.addItem("Автоопределение", "auto")
        self.format_combo.addItem("CryptoSafe (.csjson)", "csjson")
        self.format_combo.addItem("CSV", "csv")
        self.format_combo.addItem("Bitwarden JSON", "bitwarden_json")
        h_fmt.addWidget(self.format_combo)
        sett_layout.addLayout(h_fmt)

        # Password
        h_pwd = QHBoxLayout()
        h_pwd.addWidget(QLabel("Пароль:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Для .csjson")
        # --- ДОБАВЛЕНО: Обновление предпросмотра при вводе пароля ---
        self.password_input.textChanged.connect(self.run_dry_run)
        h_pwd.addWidget(self.password_input)
        sett_layout.addLayout(h_pwd)

        # Mode (IMP-3)
        self.radio_merge = QRadioButton("Слияние (Добавить новые)")
        self.radio_replace = QRadioButton("Замена (Удалить текущие)")
        self.radio_preview = QRadioButton("Предпросмотр (Только чтение)")
        self.radio_merge.setChecked(True)

        sett_layout.addWidget(self.radio_merge)
        sett_layout.addWidget(self.radio_replace)
        sett_layout.addWidget(self.radio_preview)

        sett_group.setLayout(sett_layout)
        layout.addWidget(sett_group)

        # --- Preview Area (UI-2) ---
        splitter = QSplitter(Qt.Orientation.Vertical)

        # List of entries
        self.preview_list = QListWidget()
        self.preview_list.setAlternatingRowColors(True)
        splitter.addWidget(self.preview_list)

        # Summary
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMaximumHeight(100)
        splitter.addWidget(self.summary_text)

        layout.addWidget(splitter)

        # --- Buttons ---
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.import_btn = QPushButton("Импорт")
        self.import_btn.clicked.connect(self.perform_import)
        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.import_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Файл", "", "All Supported (*.csjson *.csv *.json *.csshare)")
        if path:
            self.selected_file_path = path
            self.file_label.setText(os.path.basename(path))
            self.run_dry_run()  # Auto-preview (UI-2)

    def run_dry_run(self):
        """UI-2: Автоматический предпросмотр."""
        if not self.selected_file_path:
            return

        try:
            from src.core.import_export.importer import VaultImporter
            importer = VaultImporter(self.entry_manager, self.audit_logger)

            pwd = self.password_input.text() or None
            fmt = self.format_combo.currentData()

            stats = importer.import_vault(
                self.selected_file_path, pwd, mode='dry-run',
                format_type=fmt if fmt != 'auto' else None
            )

            # Update UI
            self.preview_list.clear()
            for item in stats.get('preview', []):
                svc = item.get('service', item.get('title', 'Unknown'))
                usr = item.get('username', '')
                self.preview_list.addItem(f"{svc} ({usr})")

            # Summary
            summary = f"Найдено записей: {stats['imported']}\n"
            summary += f"Ошибок валидации: {stats['skipped']}"
            self.summary_text.setText(summary)

        except Exception as e:
            self.preview_list.clear()
            self.summary_text.setText(f"Ошибка чтения: {e}")

    def perform_import(self):
        if not self.selected_file_path:
            return

        try:
            from src.core.import_export.importer import VaultImporter
            importer = VaultImporter(self.entry_manager, self.audit_logger)

            mode = 'merge'
            if self.radio_replace.isChecked(): mode = 'replace'

            pwd = self.password_input.text() or None
            fmt = self.format_combo.currentData()

            stats = importer.import_vault(
                self.selected_file_path, pwd, mode=mode,
                format_type=fmt if fmt != 'auto' else None
            )

            QMessageBox.information(self, "Готово",
                                    f"Импорт завершен.\nДобавлено: {stats['imported']}\nДубликатов: {stats['duplicates']}")
            self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))