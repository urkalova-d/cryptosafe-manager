# src/core/clipboard/clipboard_defender.py

import time
from enum import Enum
from PyQt6.QtCore import QObject, pyqtSignal, QTimer


class ThreatLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ClipboardDefender(QObject):
    """
    Модуль защиты буфера обмена.
    Реализует MON-1 (детекция), MON-2 (реакция), MON-4 (эфемерный режим)
    """

    threat_detected = pyqtSignal(ThreatLevel, str)
    auto_clear_requested = pyqtSignal(int)
    block_state_changed = pyqtSignal(bool)
    ephemeral_mode_changed = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)

        # Состояние
        self._monitoring = False
        self._copies_blocked = False
        self._ephemeral_mode = False
        self._ephemeral_password = None
        self._ephemeral_entry_id = None
        self._ephemeral_remaining = 0

        # Для детекции
        self._last_content = ""
        self._access_count = 0
        self._change_count = 0

        # Таймеры
        self._check_timer = QTimer(self)
        self._check_timer.timeout.connect(self._check)

        self._ephemeral_timer = QTimer(self)
        self._ephemeral_timer.timeout.connect(self._clear_ephemeral)

        # Настройки
        self._access_threshold = 4
        self._clear_on_threshold = True

    def start_monitoring(self):
        """MON-1: Запуск мониторинга"""
        self._monitoring = True
        self._check_timer.start(800)
        print("[ClipboardDefender] Monitoring started")

    def stop_monitoring(self):
        self._monitoring = False
        self._check_timer.stop()

    def _check(self):
        """MON-1: Проверка активности с буфером"""
        if not self._monitoring:
            return

        try:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            current = clipboard.text()

            if current and current != self._last_content:
                if self._last_content != "":
                    self._change_count += 1
                    self.threat_detected.emit(
                        ThreatLevel.MEDIUM,
                        "Обнаружено внешнее изменение буфера обмена"
                    )

                    if self._clear_on_threshold:
                        self.auto_clear_requested.emit(2)

                self._access_count += 1

                if self._access_count >= self._access_threshold:
                    self.threat_detected.emit(
                        ThreatLevel.HIGH,
                        "⚠️ Обнаружена подозрительная активность с буфером обмена (возможно Win+V)"
                    )
                    self.auto_clear_requested.emit(0)
                    self._access_count = 0

            else:
                self._access_count = max(0, self._access_count - 1)
                self._change_count = max(0, self._change_count - 1)

            self._last_content = current

        except Exception:
            pass

    # ==================== MON-2: Блокировка ====================

    def set_block_copies(self, blocked: bool):
        self._copies_blocked = blocked
        self.block_state_changed.emit(blocked)

    def can_copy(self) -> bool:
        return not self._copies_blocked

    # ==================== MON-4: Эфемерный буфер ====================

    def set_ephemeral_mode(self, enabled: bool):
        """Включение/выключение эфемерного режима"""
        self._ephemeral_mode = enabled
        self.ephemeral_mode_changed.emit(enabled)

        if enabled:
            # Очищаем системный буфер
            try:
                from PyQt6.QtWidgets import QApplication
                QApplication.clipboard().clear()
            except:
                pass
            print("[ClipboardDefender] Ephemeral mode ENABLED")
        else:
            self._clear_ephemeral()
            print("[ClipboardDefender] Ephemeral mode DISABLED")

    def is_ephemeral_mode(self) -> bool:
        return self._ephemeral_mode

    def copy_ephemeral(self, entry_id: int, password: str, timeout: int = 30) -> bool:
        """Копирование в эфемерный буфер"""
        if not self._ephemeral_mode:
            return False

        self._clear_ephemeral()
        self._ephemeral_password = password
        self._ephemeral_entry_id = entry_id
        self._ephemeral_remaining = timeout

        if timeout > 0:
            self._ephemeral_timer.start(1000)

        print(f"[ClipboardDefender] Password stored in EPHEMERAL buffer")
        return True

    def get_ephemeral_password(self) -> str:
        return self._ephemeral_password

    def get_ephemeral_entry_id(self) -> int:
        return self._ephemeral_entry_id

    def has_ephemeral_data(self) -> bool:
        return self._ephemeral_mode and self._ephemeral_password is not None

    def _clear_ephemeral(self):
        self._ephemeral_password = None
        self._ephemeral_entry_id = None
        self._ephemeral_remaining = 0
        self._ephemeral_timer.stop()