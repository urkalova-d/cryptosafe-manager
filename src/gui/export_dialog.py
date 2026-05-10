from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QComboBox, QCheckBox,
                             QFileDialog, QMessageBox, QGroupBox, QWidget,
                             QTreeWidget, QTreeWidgetItem, QSplitter, QTextEdit)
from PyQt6.QtCore import Qt
import os
import json


class ExportDialog(QDialog):
    def __init__(self, entry_manager, audit_logger, parent=None):
        super().__init__(parent)
        self.entry_manager = entry_manager
        self.audit_logger = audit_logger
        self.selected_file_path = ""
        self.all_entries = []

        self.setWindowTitle("Экспорт хранилища")
        self.resize(700, 500)  # Увеличили размер
        self.setup_ui()
        self.load_entries()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # --- Main Splitter (Tree | Preview) ---
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Entry Selection (UI-1)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Выберите записи")
        self.tree.setColumnCount(1)
        left_layout.addWidget(self.tree)

        # Buttons for selection
        sel_layout = QHBoxLayout()
        btn_all = QPushButton("Выбрать все")
        btn_all.clicked.connect(self.select_all)
        btn_none = QPushButton("Снять выбор")
        btn_none.clicked.connect(self.deselect_all)
        sel_layout.addWidget(btn_all)
        sel_layout.addWidget(btn_none)
        left_layout.addLayout(sel_layout)

        splitter.addWidget(left_widget)

        # Right: Preview (UI-1)
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        right_layout.addWidget(QLabel("Предпросмотр (первые 5 записей):"))
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        right_layout.addWidget(self.preview_text)

        splitter.addWidget(right_widget)

        layout.addWidget(splitter)

        # --- Format Settings ---
        settings_group = QGroupBox("Настройки")
        settings_layout = QVBoxLayout()

        # Format
        fmt_row = QHBoxLayout()
        fmt_row.addWidget(QLabel("Формат:"))
        self.format_combo = QComboBox()
        self.format_combo.addItem("Encrypted JSON (Рекомендуется)", "encrypted_json")
        self.format_combo.addItem("CSV (Открытый текст)", "csv")
        self.format_combo.currentIndexChanged.connect(self.on_format_changed)
        fmt_row.addWidget(self.format_combo)
        settings_layout.addLayout(fmt_row)

        # Security
        self.security_group = QGroupBox("Шифрование")
        sec_layout = QVBoxLayout()

        sec_layout.addWidget(QLabel("Пароль для файла:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        sec_layout.addWidget(self.password_input)

        self.password_confirm = QLineEdit()
        self.password_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_confirm.setPlaceholderText("Повторите пароль")
        sec_layout.addWidget(self.password_confirm)

        self.compress_check = QCheckBox("Сжатие (GZIP)")
        self.compress_check.setChecked(True)
        sec_layout.addWidget(self.compress_check)

        self.exclude_notes_check = QCheckBox("Исключить заметки")
        sec_layout.addWidget(self.exclude_notes_check)

        self.security_group.setLayout(sec_layout)
        settings_layout.addWidget(self.security_group)

        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # --- File & Buttons ---
        file_layout = QHBoxLayout()
        self.file_label = QLabel("Файл не выбран")
        btn_browse = QPushButton("Обзор...")
        btn_browse.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_label, 1)
        file_layout.addWidget(btn_browse)
        layout.addLayout(file_layout)

        # Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch()
        self.export_btn = QPushButton("Экспорт")
        self.export_btn.clicked.connect(self.perform_export)
        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.clicked.connect(self.reject)
        btn_box.addWidget(self.export_btn)
        btn_box.addWidget(self.cancel_btn)
        layout.addLayout(btn_box)

    def load_entries(self):
        """UI-1: Загрузка записей в дерево."""
        self.all_entries = self.entry_manager.get_all_entries()
        self.tree.clear()
        self.tree.blockSignals(True)
        for entry in self.all_entries:
            name = entry.get('title', entry.get('service', 'Unknown'))
            item = QTreeWidgetItem([name])
            item.setData(0, Qt.ItemDataRole.UserRole, entry.get('id'))
            item.setCheckState(0, Qt.CheckState.Checked)  # По умолчанию все выбраны
            self.tree.addTopLevelItem(item)

        self.tree.blockSignals(False)

        # Подключаем сигнал изменения элемента к обновлению предпросмотра
        try:
            self.tree.itemChanged.disconnect()
        except:
            pass
        self.tree.itemChanged.connect(self.update_preview)

        self.update_preview()

    def select_all(self):
        self._set_all_checked(Qt.CheckState.Checked)

    def deselect_all(self):
        self._set_all_checked(Qt.CheckState.Unchecked)

    def _set_all_checked(self, state):
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setCheckState(0, state)
        self.update_preview()

    def update_preview(self):
        """UI-1: Обновление предпросмотра."""
        selected = self.get_selected_entries()
        preview_data = selected[:5]  # Берем первые 5

        text = f"Выбрано записей: {len(selected)}\n\n"
        for e in preview_data:
            text += f"Service: {e.get('service')}\nUser: {e.get('username')}\n---\n"

        self.preview_text.setText(text)

    def get_selected_entries(self):
        ids = []
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            if item.checkState(0) == Qt.CheckState.Checked:
                ids.append(item.data(0, Qt.ItemDataRole.UserRole))
        return [e for e in self.all_entries if e['id'] in ids]

    def on_format_changed(self, index):
        is_enc = self.format_combo.currentData() == "encrypted_json"
        self.security_group.setEnabled(is_enc)

    def browse_file(self):
        fmt = self.format_combo.currentData()
        ext = ".csjson" if fmt == "encrypted_json" else ".csv"
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить", f"backup{ext}", f"*{ext}")
        if path:
            self.selected_file_path = path
            self.file_label.setText(os.path.basename(path))

    def perform_export(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "Ошибка", "Выберите файл.")
            return

        selected_entries = self.get_selected_entries()
        if not selected_entries:
            QMessageBox.warning(self, "Ошибка", "Ничего не выбрано.")
            return

        fmt = self.format_combo.currentData()
        pwd = None

        if fmt == "encrypted_json":
            p1 = self.password_input.text()
            p2 = self.password_confirm.text()
            if len(p1) < 8:
                QMessageBox.warning(self, "Ошибка", "Пароль минимум 8 символов.")
                return
            if p1 != p2:
                QMessageBox.warning(self, "Ошибка", "Пароли не совпадают.")
                return
            pwd = p1

        try:
            from src.core.import_export.exporter import VaultExporter
            exporter = VaultExporter(self.entry_manager, self.audit_logger)

            options = {
                'compression': self.compress_check.isChecked(),
                'exclude_fields': ['notes'] if self.exclude_notes_check.isChecked() else []
            }

            # Экспортируем только выбранные
            success = exporter.export_vault(
                file_path=self.selected_file_path,
                password=pwd,
                entry_ids=[e['id'] for e in selected_entries],  # UI-1: Entry Selection
                format_type=fmt,
                options=options
            )

            if success:
                QMessageBox.information(self, "Успех", f"Экспортировано {len(selected_entries)} записей.")
                self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))





