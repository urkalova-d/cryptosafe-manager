# src/gui/clipboard_security_dialog.py
"""
Диалог настройки защиты буфера обмена (MON-2, MON-4)
"""
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QCheckBox, QSpinBox, QLabel, QPushButton,
                             QMessageBox, QComboBox, QSlider)
from PyQt6.QtCore import Qt, pyqtSignal

from src.core.clipboard.clipboard_defender import ThreatLevel


class ClipboardSecurityDialog(QDialog):
    """
    Диалог настройки и отображения статуса защиты буфера.
    """

    # Сигналы изменения настроек
    ephemeral_mode_toggled = pyqtSignal(bool)
    block_copies_toggled = pyqtSignal(bool)
    settings_changed = pyqtSignal(dict)

    def __init__(self, clipboard_service, parent=None):
        super().__init__(parent)
        self.service = clipboard_service
        self.setWindowTitle("Безопасность буфера обмена")
        self.setMinimumWidth(500)
        self.setMinimumHeight(400)

        self._init_ui()
        self._load_settings()
        self._connect_signals()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # ===== Группа: Текущий статус =====
        status_group = QGroupBox("Текущий статус защиты")
        status_layout = QVBoxLayout(status_group)

        self.threat_label = QLabel("Уровень угрозы: Нет")
        self.threat_label.setStyleSheet("font-weight: bold;")
        status_layout.addWidget(self.threat_label)

        self.copy_blocked_label = QLabel("Копирование: Разрешено")
        status_layout.addWidget(self.copy_blocked_label)

        self.ephemeral_label = QLabel("Эфемерный режим: Выключен")
        status_layout.addWidget(self.ephemeral_label)

        layout.addWidget(status_group)

        # ===== MON-4: Эфемерный буфер =====
        ephemeral_group = QGroupBox("MON-4: Эфемерный буфер (in-memory only)")
        ephemeral_layout = QVBoxLayout(ephemeral_group)

        self.ephemeral_check = QCheckBox("Использовать эфемерный буфер обмена")
        self.ephemeral_check.setToolTip(
            "В этом режиме пароли НЕ попадают в системный буфер.\n"
            "Другие приложения не смогут их перехватить.\n"
            "Требуется ручная вставка через кнопку 'Вставить из эфемерного буфера'."
        )
        ephemeral_layout.addWidget(self.ephemeral_check)

        info_label = QLabel(
            "ℹ️ Эфемерный режим обеспечивает максимальную защиту от снупинга,\n"
            "но требует дополнительного действия для вставки пароля."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #666; font-size: 11px;")
        ephemeral_layout.addWidget(info_label)

        layout.addWidget(ephemeral_group)

        # ===== MON-2: Настройки автоочистки =====
        clear_group = QGroupBox("MON-2: Автоочистка при угрозах")
        clear_layout = QVBoxLayout(clear_group)

        self.accelerated_clear_check = QCheckBox("Ускорять очистку при обнаружении внешней активности")
        self.accelerated_clear_check.setChecked(True)
        clear_layout.addWidget(self.accelerated_clear_check)

        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Ускоренная очистка через (сек):"))
        self.accelerated_delay_spin = QSpinBox()
        self.accelerated_delay_spin.setRange(1, 10)
        self.accelerated_delay_spin.setValue(2)
        delay_layout.addWidget(self.accelerated_delay_spin)
        delay_layout.addStretch()
        clear_layout.addLayout(delay_layout)

        layout.addWidget(clear_group)

        # ===== MON-2: Автоблокировка =====
        block_group = QGroupBox("MON-2: Автоматическая блокировка")
        block_layout = QVBoxLayout(block_group)

        self.auto_block_check = QCheckBox("Автоматически блокировать копирование при высоком уровне угрозы")
        self.auto_block_check.setChecked(True)
        block_layout.addWidget(self.auto_block_check)

        # Ручная блокировка
        manual_layout = QHBoxLayout()
        self.block_copies_check = QCheckBox("Заблокировать копирование (ручной режим)")
        manual_layout.addWidget(self.block_copies_check)
        manual_layout.addStretch()
        block_layout.addLayout(manual_layout)

        layout.addWidget(block_group)

        # ===== MON-2: Уведомления =====
        notify_group = QGroupBox("Уведомления")
        notify_layout = QVBoxLayout(notify_group)

        self.show_notifications_check = QCheckBox("Показывать уведомления о подозрительной активности")
        self.show_notifications_check.setChecked(True)
        notify_layout.addWidget(self.show_notifications_check)

        layout.addWidget(notify_group)

        # ===== Кнопки =====
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Сохранить")
        save_btn.clicked.connect(self._save_settings)
        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(self.reject)
        apply_btn = QPushButton("Применить")
        apply_btn.clicked.connect(self._apply_settings)

        button_layout.addWidget(save_btn)
        button_layout.addWidget(apply_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

    def _load_settings(self):
        """Загрузка текущих настроек из сервиса"""
        if not self.service:
            return

        # Ephemeral mode
        self.ephemeral_check.setChecked(self.service.defender.is_ephemeral_mode())

        # Block copies
        self.block_copies_check.setChecked(not self.service.defender.can_copy())

        # Auto clear settings
        self.accelerated_clear_check.setChecked(
            self.service.defender._auto_clear_on_read
        )
        self.accelerated_delay_spin.setValue(
            self.service.defender._auto_clear_on_read_delay
        )

        # Update status labels
        self._update_status_labels()

    def _update_status_labels(self):
        """Обновление меток статуса"""
        if not self.service:
            return

        threat = self.service.defender._current_threat
        threat_texts = {
            ThreatLevel.NONE: "✅ Нет",
            ThreatLevel.LOW: "⚠️ Низкий",
            ThreatLevel.MEDIUM: "⚠️⚠️ Средний",
            ThreatLevel.HIGH: "🔴 Высокий",
            ThreatLevel.CRITICAL: "💀 КРИТИЧЕСКИЙ"
        }
        self.threat_label.setText(f"Уровень угрозы: {threat_texts.get(threat, 'Неизвестно')}")

        if threat in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            self.threat_label.setStyleSheet("font-weight: bold; color: red;")
        elif threat == ThreatLevel.MEDIUM:
            self.threat_label.setStyleSheet("font-weight: bold; color: orange;")
        else:
            self.threat_label.setStyleSheet("font-weight: bold; color: green;")

        can_copy = self.service.defender.can_copy()
        self.copy_blocked_label.setText(f"Копирование: {'❌ ЗАБЛОКИРОВАНО' if not can_copy else '✅ Разрешено'}")

        is_ephemeral = self.service.defender.is_ephemeral_mode()
        self.ephemeral_label.setText(f"Эфемерный режим: {'✅ Включен' if is_ephemeral else '❌ Выключен'}")

    def _connect_signals(self):
        """Подключение сигналов UI"""
        self.ephemeral_check.stateChanged.connect(self._on_ephemeral_toggle)
        self.block_copies_check.stateChanged.connect(self._on_block_toggle)

        # Подключаем сигналы от сервиса для обновления UI
        if self.service:
            self.service.threat_detected.connect(self._on_threat_detected)
            self.service.block_state_changed.connect(self._on_block_state_changed)
            self.service.ephemeral_mode_changed.connect(self._on_ephemeral_state_changed)

    def _on_ephemeral_toggle(self, state):
        """Включение/выключение эфемерного режима"""
        enabled = state == Qt