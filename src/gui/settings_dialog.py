from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QCheckBox, QSpinBox, QLabel, QPushButton,
                             QComboBox, QMessageBox, QGridLayout, QFrame)
from PyQt6.QtCore import Qt, pyqtSignal


class SettingsDialog(QDialog):
    settings_updated = pyqtSignal()

    def __init__(self, clipboard_service, db_helper, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки буфера обмена")
        self.setMinimumWidth(450)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)

        self.clipboard_service = clipboard_service
        self.db_helper = db_helper

        self._init_ui()
        self._load_settings()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        profile_group = QGroupBox("Профиль безопасности")
        profile_layout = QGridLayout(profile_group)

        profile_layout.addWidget(QLabel("Выберите профиль:"), 0, 0)
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("Standard (30 сек, уведомления вкл)", "standard")
        self.profile_combo.addItem("Secure (15 сек, мониторинг)", "secure")
        self.profile_combo.addItem("Public Computer (5 сек)", "public")
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        profile_layout.addWidget(self.profile_combo, 0, 1, 1, 2)

        # описание
        self.profile_desc = QLabel("")
        self.profile_desc.setStyleSheet("color: #666; font-style: italic; font-size: 11px;")
        self.profile_desc.setWordWrap(True)
        profile_layout.addWidget(self.profile_desc, 1, 0, 1, 3)

        layout.addWidget(profile_group)

        # настройки
        custom_group = QGroupBox("Ручные настройки")
        custom_layout = QGridLayout(custom_group)

        # автоочистка
        custom_layout.addWidget(QLabel("Авто-очистка через:"), 0, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setSuffix(" сек")
        custom_layout.addWidget(self.timeout_spin, 0, 1)

        #уведомления настройка
        self.notif_enabled = QCheckBox("Показывать уведомления (Toast)")
        custom_layout.addWidget(self.notif_enabled, 1, 0, 1, 3)

        self.warn_5_sec = QCheckBox("Предупреждать за 5 секунд до очистки")
        self.warn_5_sec.setChecked(True)
        custom_layout.addWidget(self.warn_5_sec, 2, 0, 1, 3)

        layout.addWidget(custom_group)

        # повышенная защита
        adv_group = QGroupBox("Дополнительная защита")
        adv_layout = QVBoxLayout(adv_group)

        self.anti_screenshot_check = QCheckBox("Защита от скриншотов (Windows)")
        self.anti_screenshot_check.setToolTip(
            "Включает защиту окна от захвата экрана при копировании паролей.\n"
            "Автоматически активируется в режиме 'Public Computer'."
        )
        adv_layout.addWidget(self.anti_screenshot_check)


        layout.addWidget(adv_group)

        # кнопочки
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

    def _on_profile_changed(self, index):
        #описание и подсказки
        profile_key = self.profile_combo.currentData()
        desc = ""

        if profile_key == "standard":
            desc = "Стандартный режим для домашнего использования. Сбалансированная безопасность."
        elif profile_key == "secure":
            desc = "Усиленный режим для работы с конфиденциальными данными. Быстрая очистка."
        elif profile_key == "public":
            desc = "Режим для публичных компьютеров. Максимальная защита: быстрая очистка и блокировка скриншотов."
            self.anti_screenshot_check.setChecked(True)

        self.profile_desc.setText(desc)

        profiles = {
            "standard": 30,
            "secure": 15,
            "public": 5
        }
        if profile_key in profiles:
            self.timeout_spin.setValue(profiles[profile_key])

    def _load_settings(self):
        #текущие настройки
        # загрузка
        current_profile = self.clipboard_service.get_current_profile()
        index = self.profile_combo.findData(current_profile)
        if index >= 0:
            self.profile_combo.setCurrentIndex(index)

        # таймаут
        self.timeout_spin.setValue(self.clipboard_service.get_timeout())

        #уведомления
        self.notif_enabled.setChecked(self.clipboard_service.are_notifications_enabled())

        # антискриншонт
        self.anti_screenshot_check.setChecked(self.clipboard_service._anti_screenshot_enabled)

    def _save_settings(self):
        #сохранение настроек
        try:
            # применение профиля
            profile_key = self.profile_combo.currentData()
            self.clipboard_service.set_security_profile(profile_key)

            # таймаут
            custom_timeout = self.timeout_spin.value()
            self.clipboard_service.set_timeout(custom_timeout)

            # уведомления
            self.clipboard_service.set_notifications_enabled(self.notif_enabled.isChecked())

            #антискриншот
            self.clipboard_service._anti_screenshot_enabled = self.anti_screenshot_check.isChecked()
            # сохранение флага в бд
            self.db_helper.save_setting("anti_screenshot_enabled",
                                        "1" if self.anti_screenshot_check.isChecked() else "0")

            QMessageBox.information(self, "Успех", "Настройки успешно сохранены.")
            self.settings_updated.emit()
            self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить настройки: {e}")