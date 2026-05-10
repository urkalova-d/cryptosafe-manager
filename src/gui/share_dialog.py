from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QComboBox,
                             QRadioButton, QButtonGroup, QSpinBox,
                             QFileDialog, QMessageBox, QGroupBox, QTextEdit,
                             QListWidget, QTabWidget, QWidget)
import json
import os


class ShareDialog(QDialog):
    """
    UI для процесса шаринга (SHR-3).
    """

    def __init__(self, entry_manager, db_helper, entry_id, parent=None):
        super().__init__(parent)
        self.entry_manager = entry_manager
        self.db = db_helper
        self.entry_id = entry_id
        self.setWindowTitle("Безопасный обмен")
        self.setMinimumWidth(500)
        self.setup_ui()
        self.load_contacts()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # --- Выбор метода (SHR-1) ---
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # -- Tab 1: Share --
        share_tab = QWidget()
        t_layout = QVBoxLayout(share_tab)

        # Method
        grp_method = QGroupBox("Метод")
        m_layout = QVBoxLayout(grp_method)
        self.radio_pwd = QRadioButton("Пароль")
        self.radio_key = QRadioButton("Публичный ключ (из контактов)")
        self.radio_key_custom = QRadioButton("Свой публичный ключ")

        self.radio_pwd.setChecked(True)
        m_layout.addWidget(self.radio_pwd)
        m_layout.addWidget(self.radio_key)
        m_layout.addWidget(self.radio_key_custom)
        t_layout.addWidget(grp_method)

        # Parameters
        grp_params = QGroupBox("Параметры")
        p_layout = QVBoxLayout(grp_params)

        # Password Input
        self.pwd_label = QLabel("Пароль:")
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        p_layout.addWidget(self.pwd_label)
        p_layout.addWidget(self.pwd_input)

        # Contact List (for Key method)
        self.contact_label = QLabel("Выберите контакт:")
        self.contact_combo = QComboBox()
        p_layout.addWidget(self.contact_label)
        p_layout.addWidget(self.contact_combo)

        # Custom Key Input
        self.key_label = QLabel("Вставьте публичный ключ:")
        self.key_input = QTextEdit()
        self.key_input.setVisible(False)
        self.key_label.setVisible(False)
        p_layout.addWidget(self.key_label)
        p_layout.addWidget(self.key_input)

        # Expiration
        h_exp = QHBoxLayout()
        h_exp.addWidget(QLabel("Срок действия (дней):"))
        self.spin_days = QSpinBox()
        self.spin_days.setRange(1, 30)
        self.spin_days.setValue(7)
        h_exp.addWidget(self.spin_days)
        p_layout.addLayout(h_exp)

        t_layout.addWidget(grp_params)

        # Buttons
        btn_box = QHBoxLayout()
        self.btn_share = QPushButton("Создать файл")
        self.btn_share.clicked.connect(self.do_share)
        btn_box.addStretch()
        btn_box.addWidget(self.btn_share)
        t_layout.addLayout(btn_box)

        tabs.addTab(share_tab, "📤 Отправить")

        # -- Tab 2: History (UI-3) --
        history_tab = QWidget()
        h_layout = QVBoxLayout(history_tab)
        self.history_list = QListWidget()
        h_layout.addWidget(self.history_list)
        tabs.addTab(history_tab, "📜 История")

        # Connections
        self.radio_pwd.toggled.connect(self.update_ui_state)
        self.radio_key.toggled.connect(self.update_ui_state)
        self.radio_key_custom.toggled.connect(self.update_ui_state)

        self.update_ui_state()
        self.load_history()

    def load_contacts(self):
        # Загружаем контакты из БД
        cursor = self.db.conn.execute("SELECT id, name FROM contacts")
        rows = cursor.fetchall()
        for r in rows:
            self.contact_combo.addItem(r['name'], r['id'])

    def update_ui_state(self):
        is_pwd = self.radio_pwd.isChecked()
        is_contact = self.radio_key.isChecked()
        is_custom = self.radio_key_custom.isChecked()

        self.pwd_label.setVisible(is_pwd)
        self.pwd_input.setVisible(is_pwd)

        self.contact_label.setVisible(is_contact)
        self.contact_combo.setVisible(is_contact)

        self.key_label.setVisible(self.radio_key_custom.isChecked())
        self.key_input.setVisible(self.radio_key_custom.isChecked())

    def do_share(self):
        try:
            from src.core.import_export.sharing_service import SharingService
            service = SharingService(self.entry_manager, self.db)

            method = "password"
            recipient = "Unknown"

            if self.radio_pwd.isChecked():
                pwd = self.pwd_input.text()
                if len(pwd) < 6:
                    raise ValueError("Пароль слишком короткий.")
                recipient = "Password Protected"
                # Вызываем метод шаринга паролем
                package = service.share_via_password(self.entry_id, pwd, self.spin_days.value())

            elif self.radio_key.isChecked():
                # Берем ключ выбранного контакта
                contact_id = self.contact_combo.currentData()
                if not contact_id:
                    raise ValueError("Контакт не выбран.")

                cursor = self.db.conn.execute("SELECT name, public_key_pem FROM contacts WHERE id=?", (contact_id,))
                row = cursor.fetchone()
                if not row: raise ValueError("Ошибка БД.")

                recipient = row['name']
                pub_key = row['public_key_pem']
                # Используем RSA метод
                package = service.share_via_public_key(self.entry_id, pub_key, self.spin_days.value())

            else:
                # Свой ключ
                pub_key = self.key_input.toPlainText()
                recipient = "Custom Key"
                package = service.share_via_public_key(self.entry_id, pub_key, self.spin_days.value())

            # Save File
            path, _ = QFileDialog.getSaveFileName(self, "Сохранить", "share.csshare", "*.csshare")
            if path:
                with open(path, 'w') as f:
                    json.dump(package, f, indent=4)

                # Save History (UI-3)
                self._log_share(recipient, method)
                self.load_history()

                QMessageBox.information(self, "Успех", "Запись успешно зашифрована!")
                self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def _log_share(self, recipient, method):
        entry_name = self.entry_manager.get_entry(self.entry_id).get('service', 'Unknown')
        self.db.conn.execute("""
            INSERT INTO sharing_history (entry_id, entry_name, recipient, method, expires_at, status)
            VALUES (?, ?, ?, ?, datetime('now', '+' || ? || ' days'), 'active')
        """, (self.entry_id, entry_name, recipient, method, self.spin_days.value()))
        self.db.conn.commit()

    def load_history(self):
        """UI-3: Загрузка истории шаринга."""
        self.history_list.clear()
        try:
            cursor = self.db.conn.execute("""
                SELECT entry_name, recipient, method, created_at, status 
                FROM sharing_history 
                ORDER BY created_at DESC
            """)
            rows = cursor.fetchall()

            for r in rows:
                # Форматируем строку для отображения
                # r['created_at'] может быть длинным, обрежем до даты
                date_str = str(r['created_at'])[:10]
                item_text = f"[{date_str}] {r['entry_name']} -> {r['recipient']} ({r['method']})"
                self.history_list.addItem(item_text)
        except Exception as e:
            print(f"Error loading history: {e}")