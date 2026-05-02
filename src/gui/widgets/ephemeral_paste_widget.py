# src/gui/widgets/ephemeral_paste_widget.py
"""
Виджет для работы с эфемерным буфером (MON-4)
Позволяет вставлять пароли без системного буфера
"""
from PyQt6.QtWidgets import (QWidget, QHBoxLayout, QPushButton, QLineEdit,
                             QLabel, QFrame, QVBoxLayout, QApplication)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QFont, QAction


class EphemeralPasteWidget(QWidget):
    """
    Виджет для вставки паролей из эфемерного буфера.
    Заменяет стандартное Ctrl+V для защищенных полей.
    """

    password_pasted = pyqtSignal(str)  # Сигнал при вставке пароля

    def __init__(self, clipboard_service, parent=None):
        super().__init__(parent)
        self.service = clipboard_service
        self._setup_ui()
        self._setup_timer()

        # Подключаемся к сервису для обновления статуса
        if self.service:
            self.service.ephemeral_mode_changed.connect(self._on_ephemeral_mode_changed)
            self.service.threat_detected.connect(self._on_threat_detected)

    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        # Индикатор эфемерного буфера
        self.indicator = QLabel("🔒")
        self.indicator.setToolTip("Эфемерный буфер активен - пароли не попадают в систему")
        self.indicator.setVisible(False)
        layout.addWidget(self.indicator)

        # Кнопка "Вставить из эфемерного буфера"
        self.paste_btn = QPushButton("📋 Вставить из эфемерного буфера")
        self.paste_btn.setToolTip(
            "Вставить пароль из защищенного эфемерного буфера.\n"
            "Пароль не сохраняется в истории Windows."
        )
        self.paste_btn.clicked.connect(self.paste_from_ephemeral)
        self.paste_btn.setVisible(False)
        layout.addWidget(self.paste_btn)

        # Статус таймера
        self.timer_label = QLabel("")
        self.timer_label.setStyleSheet("color: #666; font-size: 10px;")
        layout.addWidget(self.timer_label)

        layout.addStretch()

        # Стилизация
        self.setStyleSheet("""
            QPushButton {
                background-color: #2c3e50;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #34495e;
            }
            QPushButton:pressed {
                background-color: #1a252f;
            }
        """)

    def _setup_timer(self):
        self._update_timer = QTimer(self)
        self._update_timer.timeout.connect(self._update_status)
        self._update_timer.start(500)

    def _update_status(self):
        """Обновление статуса эфемерного буфера"""
        if not self.service:
            return

        has_data = self.service.defender.has_ephemeral_data()
        is_ephemeral = self.service.defender.is_ephemeral_mode()

        self.indicator.setVisible(is_ephemeral)
        self.paste_btn.setVisible(is_ephemeral and has_data)

        if is_ephemeral and has_data:
            remaining = self.service.defender._ephemeral_remaining
            if remaining > 0:
                self.timer_label.setText(f"⏱ {remaining}с")
            else:
                self.timer_label.setText("")

    def paste_from_ephemeral(self):
        """Вставка пароля из эфемерного буфера"""
        if not self.service:
            return

        password = self.service.get_ephemeral_password()
        if password:
            self.password_pasted.emit(password)
            print("[EphemeralPasteWidget] Password pasted from ephemeral buffer")

    def _on_ephemeral_mode_changed(self, enabled):
        """Реакция на изменение режима"""
        if not enabled:
            self.paste_btn.setVisible(False)
            self.indicator.setVisible(False)

    def _on_threat_detected(self, level, message):
        """При угрозе - показываем предупреждение"""
        if level.value >= 3:  # HIGH или CRITICAL
            self.paste_btn.setStyleSheet("""
                QPushButton {
                    background-color: #c0392b;
                    color: white;
                }
            """)
            QTimer.singleShot(3000, lambda: self.paste_btn.setStyleSheet(""))