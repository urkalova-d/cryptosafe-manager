from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QCheckBox, QSpinBox, QLabel, QPushButton,
                             QComboBox, QMessageBox, QGridLayout, QTabWidget,
                             QWidget, QListWidget, QLineEdit, QFileDialog)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QPixmap
import io


class SettingsDialog(QDialog):
    settings_updated = pyqtSignal()

    def __init__(self, clipboard_service, db_helper, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки CryptoSafe")
        self.setMinimumSize(550, 500)  # Увеличили размер под вкладки
        self.setWindowModality(Qt.WindowModality.ApplicationModal)

        self.clipboard_service = clipboard_service
        self.db_helper = db_helper

        self._init_ui()
        self._load_settings()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Создаем вкладки
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # --- Вкладка 1: Безопасность ---
        security_tab = QWidget()
        tabs.addTab(security_tab, "Безопасность")
        self._setup_security_tab(security_tab)

        # --- Вкладка 2: Ключи и Контакты (NEW) ---
        keys_tab = QWidget()
        tabs.addTab(keys_tab, "🔑 Ключи и Контакты")
        self._setup_keys_tab(keys_tab)

        # Кнопки ОК/Отмена
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        save_btn = QPushButton("💾 Сохранить")
        save_btn.setDefault(True)
        save_btn.clicked.connect(self._save_settings)
        btn_layout.addWidget(save_btn)

        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        layout.addLayout(btn_layout)

    def _setup_security_tab(self, parent_widget):
        layout = QVBoxLayout(parent_widget)
        layout.setSpacing(15)

        # Профиль безопасности
        profile_group = QGroupBox("Профиль безопасности (Буфер обмена)")
        profile_layout = QGridLayout(profile_group)

        profile_layout.addWidget(QLabel("Выберите профиль:"), 0, 0)
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("Standard (30 сек)", "standard")
        self.profile_combo.addItem("Secure (15 сек)", "secure")
        self.profile_combo.addItem("Public Computer (5 сек)", "public")
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        profile_layout.addWidget(self.profile_combo, 0, 1, 1, 2)

        self.profile_desc = QLabel("")
        self.profile_desc.setStyleSheet("color: #666; font-style: italic; font-size: 11px;")
        self.profile_desc.setWordWrap(True)
        profile_layout.addWidget(self.profile_desc, 1, 0, 1, 3)

        profile_layout.addWidget(QLabel("Авто-очистка через:"), 2, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setSuffix(" сек")
        profile_layout.addWidget(self.timeout_spin, 2, 1)

        self.notif_enabled = QCheckBox("Показывать уведомления")
        profile_layout.addWidget(self.notif_enabled, 3, 0, 1, 3)

        layout.addWidget(profile_group)

        # Политика хранения
        retention_group = QGroupBox("Политика хранения журнала аудита")
        retention_layout = QGridLayout(retention_group)

        retention_layout.addWidget(QLabel("Хранить логи:"), 0, 0)
        self.retention_spin = QSpinBox()
        self.retention_spin.setRange(30, 3650)
        self.retention_spin.setSuffix(" дней")
        retention_layout.addWidget(self.retention_spin, 0, 1)

        retention_layout.addWidget(QLabel("Макс. количество записей:"), 1, 0)
        self.max_entries_spin = QSpinBox()
        self.max_entries_spin.setRange(10, 1000000)
        self.max_entries_spin.setSingleStep(1000)
        retention_layout.addWidget(self.max_entries_spin, 1, 1)

        self.cleanup_btn = QPushButton("🧹 Очистить старые логи сейчас")
        self.cleanup_btn.clicked.connect(self._cleanup_logs)
        retention_layout.addWidget(self.cleanup_btn, 2, 0, 1, 2)

        layout.addWidget(retention_group)

        # Доп защита
        adv_group = QGroupBox("Дополнительная защита")
        adv_layout = QVBoxLayout(adv_group)
        self.anti_screenshot_check = QCheckBox("Защита от скриншотов (Windows)")
        adv_layout.addWidget(self.anti_screenshot_check)
        layout.addWidget(adv_group)

    def _setup_keys_tab(self, parent_widget):
        """QR-1, QR-3: Интерфейс для ключей."""
        layout = QVBoxLayout(parent_widget)

        # -- Мои ключи --
        my_keys_group = QGroupBox("Мой публичный ключ")
        mk_layout = QVBoxLayout(my_keys_group)

        self.gen_key_btn = QPushButton("🔄 Сгенерировать новую пару ключей")
        self.gen_key_btn.clicked.connect(self._generate_keys)
        mk_layout.addWidget(self.gen_key_btn)

        self.show_qr_btn = QPushButton("📱 Показать мой QR-код")
        self.show_qr_btn.clicked.connect(self._show_my_qr)
        self.show_qr_btn.setEnabled(False)  # Пока ключей нет
        mk_layout.addWidget(self.show_qr_btn)

        layout.addWidget(my_keys_group)

        # -- Контакты --
        contacts_group = QGroupBox("Контакты (Публичные ключи друзей)")
        c_layout = QVBoxLayout(contacts_group)

        self.contacts_list = QListWidget()
        self.contacts_list.setAlternatingRowColors(True)
        c_layout.addWidget(self.contacts_list)

        btn_row = QHBoxLayout()
        self.scan_qr_btn = QPushButton("📷 Сканировать QR (из файла)")
        self.scan_qr_btn.clicked.connect(self._scan_qr_file)
        btn_row.addWidget(self.scan_qr_btn)

        self.del_contact_btn = QPushButton("🗑️ Удалить контакт")
        self.del_contact_btn.clicked.connect(self._delete_contact)
        btn_row.addWidget(self.del_contact_btn)

        c_layout.addLayout(btn_row)
        layout.addWidget(contacts_group)

        self._load_keys_status()

    def _load_keys_status(self):
        """Проверяет, есть ли сохраненные ключи."""
        # Мы будем хранить приватный ключ в key_store с типом 'sharing_private_key'
        priv_key, _ = self.db_helper.get_key_store('sharing_private_key')
        if priv_key:
            self.show_qr_btn.setEnabled(True)
            self.gen_key_btn.setText("🔄 Перегенерировать ключи (старые станут недействительными)")

        # Загрузка контактов
        self._load_contacts()

    def _load_contacts(self):
        self.contacts_list.clear()
        from src.core.import_export.key_exchange import KeyExchangeService
        service = KeyExchangeService(self.db_helper)
        contacts = service.get_all_contacts()
        for c in contacts:
            self.contacts_list.addItem(f"{c['name']} (ID: {c['fingerprint']})")

    def _generate_keys(self):
        """QR-3: Генерация RSA пары."""
        reply = QMessageBox.question(self, "Подтверждение",
                                     "Это аннулирует ваши старые ключи. Продолжить?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.No:
            return

        try:
            from src.core.import_export.key_exchange import KeyExchangeService
            service = KeyExchangeService(self.db_helper)
            priv_pem, pub_pem = service.generate_key_pair()

            # Сохраняем приватный ключ в защищенное хранилище
            self.db_helper.save_key_store('sharing_private_key', priv_pem.encode())
            # Публичный ключ можно не сохранять отдельно, он генерируется из приватного при показе

            QMessageBox.information(self, "Успех", "Пара ключей успешно создана!")
            self._load_keys_status()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать ключи: {e}")

    def _show_my_qr(self):
        """QR-1: Показ QR кода."""
        try:
            priv_key_bytes, _ = self.db_helper.get_key_store('sharing_private_key')
            if not priv_key_bytes:
                QMessageBox.warning(self, "Ошибка", "Сначала сгенерируйте ключи.")
                return

            from src.core.import_export.key_exchange import KeyExchangeService
            from cryptography.hazmat.primitives import serialization

            # Загружаем приватный ключ чтобы получить публичный
            private_key = serialization.load_pem_private_key(priv_key_bytes, password=None)
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            service = KeyExchangeService(self.db_helper)
            payload = service.create_share_payload(public_pem, "MyCryptoSafeUser")

            # Генерируем картинку
            qr_bytes = service.generate_qr_code(payload)

            # Показываем в диалоге
            self._show_qr_dialog(qr_bytes, "Ваш публичный ключ")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка генерации QR: {e}")

    def _scan_qr_file(self):
        """QR-2: Сканирование QR из файла."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите изображение QR", "", "Images (*.png *.jpg)")
        if not file_path:
            return

        try:
            from PIL import Image
            from pyzbar.pyzbar import decode

            img = Image.open(file_path)
            decoded_objects = decode(img)

            if not decoded_objects:
                QMessageBox.warning(self, "Ошибка", "QR код не найден на изображении.")
                return

            payload_str = decoded_objects[0].data.decode('utf-8')

            from src.core.import_export.key_exchange import KeyExchangeService
            service = KeyExchangeService(self.db_helper)
            data = service.parse_qr_payload(payload_str)

            # Сохраняем контакт
            service.save_contact(data['user'], data['public_key'])
            QMessageBox.information(self, "Успех", f"Контакт '{data['user']}' добавлен!")
            self._load_contacts()

        except ImportError:
            QMessageBox.critical(self, "Ошибка",
                                 "Библиотеки Pillow и pyzbar не установлены.\npip install Pillow pyzbar")
        except ValueError as ve:
            QMessageBox.warning(self, "Ошибка безопасности", str(ve))
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать QR: {e}")

    def _delete_contact(self):
        current_item = self.contacts_list.currentItem()
        if not current_item:
            return
        # Простое удаление по имени (в реальности лучше по ID)
        # Здесь опущено для краткости, можно реализовать через парсинг строки
        QMessageBox.information(self, "Инфо", "Функция удаления контакта в разработке.")

    def _show_qr_dialog(self, img_bytes, title):
        """Вспомогательный диалог для показа картинки."""
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        layout = QVBoxLayout(dialog)

        lbl = QLabel()
        pixmap = QPixmap()
        pixmap.loadFromData(img_bytes.getvalue())
        lbl.setPixmap(pixmap)
        lbl.setScaledContents(True)
        layout.addWidget(lbl)

        btn = QPushButton("Закрыть")
        btn.clicked.connect(dialog.accept)
        layout.addWidget(btn)
        dialog.exec()

    # --- Методы сохранения настроек (без изменений) ---

    def _on_profile_changed(self, index):
        profile_key = self.profile_combo.currentData()
        desc = ""

        if profile_key == "standard":
            desc = "Стандартный режим."
        elif profile_key == "secure":
            desc = "Усиленный режим."
        elif profile_key == "public":
            desc = "Режим для публичных ПК."
            self.anti_screenshot_check.setChecked(True)

        self.profile_desc.setText(desc)
        profiles = {"standard": 30, "secure": 15, "public": 5}
        if profile_key in profiles:
            self.timeout_spin.setValue(profiles[profile_key])

    def _load_settings(self):
        current_profile = self.clipboard_service.get_current_profile()
        index = self.profile_combo.findData(current_profile)
        if index >= 0:
            self.profile_combo.setCurrentIndex(index)

        self.timeout_spin.setValue(self.clipboard_service.get_timeout())
        self.notif_enabled.setChecked(self.clipboard_service.are_notifications_enabled())
        self.anti_screenshot_check.setChecked(self.clipboard_service._anti_screenshot_enabled)

        retention_days = int(self.db_helper.get_setting("audit_retention_days") or 365)
        max_entries = int(self.db_helper.get_setting("audit_max_entries") or 10000)
        self.retention_spin.setValue(retention_days)
        self.max_entries_spin.setValue(max_entries)

    def _save_settings(self):
        try:
            profile_key = self.profile_combo.currentData()
            self.clipboard_service.set_security_profile(profile_key)
            self.clipboard_service.set_timeout(self.timeout_spin.value())
            self.clipboard_service.set_notifications_enabled(self.notif_enabled.isChecked())
            self.clipboard_service._anti_screenshot_enabled = self.anti_screenshot_check.isChecked()

            self.db_helper.save_setting("anti_screenshot_enabled",
                                        "1" if self.anti_screenshot_check.isChecked() else "0")
            self.db_helper.save_setting("audit_retention_days", str(self.retention_spin.value()))
            self.db_helper.save_setting("audit_max_entries", str(self.max_entries_spin.value()))

            QMessageBox.information(self, "Успех", "Настройки успешно сохранены.")
            self.settings_updated.emit()
            self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить настройки: {e}")

    def _cleanup_logs(self):
        try:
            self.db_helper.save_setting("audit_retention_days", str(self.retention_spin.value()))
            self.db_helper.save_setting("audit_max_entries", str(self.max_entries_spin.value()))
            self.db_helper.cleanup_old_audit_logs()
            QMessageBox.information(self, "Готово", "Очистка завершена.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка очистки: {e}")