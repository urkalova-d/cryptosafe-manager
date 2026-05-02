from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout
from PyQt6.QtCore import Qt, pyqtSignal


class ThreatWarningDialog(QDialog):
    """Безопасный диалог предупреждения об угрозе"""

    ephemeral_mode_requested = pyqtSignal()

    def __init__(self, threat_level, message, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚠️ Обнаружена угроза")
        self.setModal(True)
        self.setMinimumWidth(400)

        # Устанавливаем флаги окна для стабильности
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowStaysOnTopHint
        )

        layout = QVBoxLayout(self)

        # Иконка и заголовок
        icon_label = QLabel("⚠️" if threat_level < 3 else "🔴")
        icon_label.setStyleSheet("font-size: 48px;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)

        # Сообщение
        msg_label = QLabel(message)
        msg_label.setWordWrap(True)
        msg_label.setStyleSheet("font-size: 14px; margin: 10px;")
        msg_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(msg_label)

        # Рекомендации
        if threat_level >= 3:
            rec_label = QLabel(
                "Рекомендации:\n"
                "• Проверьте запущенные программы\n"
                "• Включите эфемерный режим\n"
                "• Смените мастер-пароль"
            )
            rec_label.setWordWrap(True)
            rec_label.setStyleSheet("color: #666; font-size: 11px; margin: 10px;")
            layout.addWidget(rec_label)

        # Кнопки
        btn_layout = QHBoxLayout()

        ok_btn = QPushButton("Понятно")
        ok_btn.clicked.connect(self.accept)
        btn_layout.addWidget(ok_btn)

        if threat_level >= 3:
            ephemeral_btn = QPushButton("🔒 Включить эфемерный режим")
            ephemeral_btn.clicked.connect(self._on_ephemeral_requested)
            btn_layout.addWidget(ephemeral_btn)

        layout.addLayout(btn_layout)

    def _on_ephemeral_requested(self):
        self.ephemeral_mode_requested.emit()
        self.accept()