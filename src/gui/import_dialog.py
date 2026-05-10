from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QComboBox,
                             QFileDialog, QMessageBox, QListWidget, QGroupBox,
                             QRadioButton, QButtonGroup, QProgressDialog)
from PyQt6.QtCore import Qt
import os


class ImportDialog(QDialog):
    def __init__(self, entry_manager, audit_logger, parent=None):
        super().__init__(parent)
        self.entry_manager = entry_manager
        self.audit_logger = audit_logger
        self.selected_file_path = ""

        self.setWindowTitle("Импорт данных")
        self.setMinimumWidth(600)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # --- Выбор файла ---
        file_group = QGroupBox("Источник")
        file_layout = QHBoxLayout()
        self.file_label = QLabel("Файл не выбран")
        self.browse_btn = QPushButton("Обзор...")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_label, 1)
        file_layout.addWidget(self.browse_btn)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # --- Настройки ---
        settings_group = QGroupBox("Настройки")
        settings_layout = QVBoxLayout()

        # Формат
        fmt_layout = QHBoxLayout()
        fmt_layout.addWidget(QLabel("Формат:"))
        self.format_combo = QComboBox()
        self.format_combo.addItem("Автоопределение", "auto")
        self.format_combo.addItem("CryptoSafe (.csjson)", "csjson")
        self.format_combo.addItem("CSV (General)", "csv")
        self.format_combo.addItem("Bitwarden (JSON)", "bitwarden_json")
        fmt_layout.addWidget(self.format_combo)
        settings_layout.addLayout(fmt_layout)

        # Пароль (если нужно)
        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(QLabel("Пароль (для .csjson):"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Оставьте пустым для CSV/Bitwarden")
        pwd_layout.addWidget(self.password_input)
        settings_layout.addLayout(pwd_layout)

        # Режим (IMP-3)
        mode_layout = QVBoxLayout()
        self.mode_group = QButtonGroup(self)

        self.radio_merge = QRadioButton("Слияние (Добавить новые, пропустить дубли)")
        self.radio_replace = QRadioButton("Замена (Удалить текущие и загрузить новые)")
        self.radio_preview = QRadioButton("Предпросмотр (Ничего не сохранять)")

        self.radio_merge.setChecked(True)  # По умолчанию безопасный режим

        self.mode_group.addButton(self.radio_merge, 0)
        self.mode_group.addButton(self.radio_replace, 1)
        self.mode_group.addButton(self.radio_preview, 2)

        mode_layout.addWidget(self.radio_merge)
        mode_layout.addWidget(self.radio_replace)
        mode_layout.addWidget(self.radio_preview)

        settings_layout.addLayout(mode_layout)
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # --- Превью ---
        self.preview_list = QListWidget()
        self.preview_list.setVisible(False)
        layout.addWidget(self.preview_list)

        # --- Кнопки ---
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
        path, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл", "",
            "All Supported (*.csjson *.csv *.json *.csshare);;"
            "CryptoSafe Backup (*.csjson);;"
            "CryptoSafe Share (*.csshare);;"
            "CSV (*.csv);;"
            "JSON (*.json);;"
            "All Files (*.*)")
        if path:
            self.selected_file_path = path
            self.file_label.setText(os.path.basename(path))

    def perform_import(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "Ошибка", "Выберите файл.")
            return

        fmt = self.format_combo.currentData()
        pwd = self.password_input.text() if self.password_input.text() else None

        # Определяем режим
        if self.radio_merge.isChecked():
            mode = 'merge'
        elif self.radio_replace.isChecked():
            mode = 'replace'
        else:
            mode = 'dry-run'

        try:
            from src.core.import_export.importer import VaultImporter

            # Импортер
            importer = VaultImporter(self.entry_manager, self.audit_logger)

            # Запуск
            stats = importer.import_vault(
                file_path=self.selected_file_path,
                password=pwd,
                mode=mode,
                format_type=fmt if fmt != 'auto' else None
            )

            # Обработка результата
            if mode == 'dry-run':
                QMessageBox.information(self, "Предпросмотр",
                                        f"Найдено записей: {stats['imported']}\n"
                                        f"Пропущено (ошибки): {stats['skipped']}")
                # Можно показать список в self.preview_list
            else:
                QMessageBox.information(self, "Успех",
                                        f"Импорт завершен!\n"
                                        f"Добавлено: {stats['imported']}\n"
                                        f"Дубликатов пропущено: {stats['duplicates']}")
                self.accept()

        except ValueError as ve:
            QMessageBox.warning(self, "Ошибка данных", str(ve))
        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Ошибка", f"Не удалось импортировать:\n{str(e)}")