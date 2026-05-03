import secrets
import ctypes
from typing import Optional
from PyQt6.QtCore import QObject, pyqtSignal, QTimer

from .platform_adapter import PlatformAdapter
from .clipboard_monitor import ClipboardMonitor


# Простая реализация уровня угрозы для совместимости
class ThreatLevel:
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ClipboardService(QObject):
    """
    Централизованный интерфейс для работы с буфером обмена.
    Объединяет сервис и защиту (Defender) в одном классе для надежности.
    """

    # --- Observer Signals ---
    clipboard_copied = pyqtSignal(int)
    clipboard_cleared = pyqtSignal()
    timer_updated = pyqtSignal(int)

    copy_username_requested = pyqtSignal(int)
    copy_all_requested = pyqtSignal(int)
    warning_5_seconds = pyqtSignal()  # Сигнал за 5 секунд до очистки

    # --- Defense Signals ---
    threat_detected = pyqtSignal(int, str)  # (ThreatLevel, message)
    block_state_changed = pyqtSignal(bool)
    ephemeral_mode_changed = pyqtSignal(bool)

    _instance = None

    def __init__(self, platform_adapter: PlatformAdapter, monitor: ClipboardMonitor, db_helper=None):
        super().__init__()
        self.adapter = platform_adapter
        self.monitor = monitor
        self.db_helper = db_helper

        # --- Ephemeral Mode State (MON-4) ---
        self._ephemeral_mode = False
        self._ephemeral_password: Optional[str] = None
        self._ephemeral_entry_id: Optional[int] = None
        self._ephemeral_timer = QTimer(self)
        self._ephemeral_timer.timeout.connect(self._clear_ephemeral)

        # Secure Memory Storage
        self._secure_data: Optional[bytearray] = None
        self._current_entry_id: Optional[int] = None

        # NEW: Храним тип скопированных данных ('password', 'username', 'all')
        self._current_data_type: Optional[str] = None

        # Timer Logic
        self._clear_timer = QTimer(self)
        self._clear_timer.timeout.connect(self._tick)
        self._remaining_seconds = 0
        self._timeout_duration = self._load_timeout()

        # Флаг для отслеживания предупреждения
        self._warning_shown = False

        # Monitor Integration
        self.monitor.content_changed.connect(self._on_external_clipboard_change)

    # --- Singleton ---
    @classmethod
    def get_instance(cls, adapter=None, monitor=None, db_helper=None):
        if cls._instance is None:
            if adapter and monitor:
                cls._instance = cls(adapter, monitor, db_helper)
        return cls._instance

    # --- Settings ---
    def set_db_helper(self, db_helper):
        self.db_helper = db_helper
        self._timeout_duration = self._load_timeout()

    def _load_timeout(self) -> int:
        if not self.db_helper: return 30
        val = self.db_helper.get_setting("clipboard_timeout")
        try:
            return int(val) if val else 30
        except ValueError:
            return 30

    def set_timeout(self, seconds: int):
        if seconds < 5: seconds = 5
        if seconds > 300: seconds = 300
        self._timeout_duration = seconds
        if self.db_helper:
            self.db_helper.save_setting("clipboard_timeout", seconds)

    def get_timeout(self) -> int:
        return self._timeout_duration

    # --- MON-4: Ephemeral Mode ---

    def set_ephemeral_mode(self, enabled: bool):
        """Включение/выключение эфемерного режима."""
        self._ephemeral_mode = enabled


        if enabled:
            # При включении очищаем системный буфер для безопасности
            self.adapter.clear_clipboard()
            self._cleanup_memory()
            print("[ClipboardService] Ephemeral mode ENABLED")
        else:
            self._clear_ephemeral()
            print("[ClipboardService] Ephemeral mode DISABLED")
        self.ephemeral_mode_changed.emit(enabled)

    def is_ephemeral_mode(self) -> bool:
        return self._ephemeral_mode

    def get_ephemeral_password(self) -> Optional[str]:
        """Метод для получения пароля из эфемерного буфера (используется в UI)."""
        if self._ephemeral_mode:
            return self._ephemeral_password
        return None

    def has_ephemeral_data(self) -> bool:
        return self._ephemeral_mode and self._ephemeral_password is not None

    def _clear_ephemeral(self):
        """Очистка эфемерного буфера."""
        self._ephemeral_password = None
        self._ephemeral_entry_id = None
        self._ephemeral_timer.stop()

    # --- Main Copy Logic ---

        # --- Main Copy Logic ---

    def copy_password(self, entry_id: int, password: str):
        """Копирование пароля."""
        self._copy_data(entry_id, password, 'password')

    def copy_username(self, entry_id: int, username: str):
        """Копирование имени пользователя (Sprint 5)."""
        self._copy_data(entry_id, username, 'username')

    def copy_all(self, entry_id: int, data_str: str):
        """Копирование всех данных (Sprint 5). data_str = 'username:password'."""
        self._copy_data(entry_id, data_str, 'all')

    def _copy_data(self, entry_id: int, data: str, data_type: str):
        """Внутренняя логика копирования."""
        if self._ephemeral_mode:
            # В эфемерном режиме сохраняем только пароль, остальные типы игнорируем или обрабатываем иначе
            if data_type == 'password':
                self._clear_ephemeral()
                self._ephemeral_password = data
                self._ephemeral_entry_id = entry_id
                if self._timeout_duration > 0:
                    self._ephemeral_timer.start(self._timeout_duration * 1000)
                self.clipboard_copied.emit(entry_id)
            return

        # Обычный режим
        self._cleanup_memory()
        self._secure_data = bytearray(data.encode('utf-8'))
        self._current_entry_id = entry_id
        self._current_data_type = data_type
        self._warning_shown = False  # Сброс флага предупреждения

        success = self.adapter.copy_to_clipboard(data)

        if success:
            self.monitor.update_internal_state(data)
            if self._timeout_duration > 0:
                self._remaining_seconds = self._timeout_duration
                self._clear_timer.start(1000)
            self.clipboard_copied.emit(entry_id)
        else:
            self._cleanup_memory()
            raise RuntimeError("Failed to copy to clipboard")

    def clear_now(self):
        """Принудительная очистка обоих буферов."""
        self._perform_clear()
        self._clear_ephemeral()

    # --- Internal Logic ---

    def _tick(self):
        self._remaining_seconds -= 1
        self.timer_updated.emit(self._remaining_seconds)

        # Sprint 5: Предупреждение за 5 секунд
        if self._remaining_seconds == 5 and not self._warning_shown:
            self.warning_5_seconds.emit()
            self._warning_shown = True

        if self._remaining_seconds <= 0:
            self._perform_clear()

    def _perform_clear(self):
        self._clear_timer.stop()
        self.adapter.clear_clipboard()
        self._cleanup_memory()
        self.clipboard_cleared.emit()
        print("[ClipboardService] Clipboard cleared.")

    def _cleanup_memory(self):
        if self._secure_data:
            for i in range(len(self._secure_data)):
                self._secure_data[i] = 0
            self._secure_data = None
        self._current_entry_id = None
        self._current_data_type = None
        self._warning_shown = False
        self.timer_updated.emit(0)

    def _on_external_clipboard_change(self, new_content: str):
        if self._secure_data:
            try:
                if new_content != self._secure_data.decode('utf-8'):
                    print("[ClipboardService] External change detected.")
                    self._clear_timer.stop()
                    self._cleanup_memory()
            except Exception:
                pass

    # API для UI индикации
    def get_current_entry_id(self) -> Optional[int]:
        return self._current_entry_id

    def get_current_data_type(self) -> Optional[str]:
        return self._current_data_type

