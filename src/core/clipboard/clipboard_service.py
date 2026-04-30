import secrets
from typing import Optional
from PyQt6.QtCore import QObject, pyqtSignal, QTimer

from .platform_adapter import PlatformAdapter
from .clipboard_monitor import ClipboardMonitor


class ClipboardService(QObject):
    """
    Централизованный интерфейс для работы с буфером обмена.
    Реализует Observer pattern через PyQt сигналы.
    Интегрируется с KeyStorage для безопасного хранения.
    """

    # --- Observer Signals ---
    clipboard_copied = pyqtSignal(int)  # ID записи, чей пароль скопирован
    clipboard_cleared = pyqtSignal()  # Буфер очищен
    timer_updated = pyqtSignal(int)  # Оставшееся время в секундах

    # --- Internal State ---
    _instance = None

    def __init__(self, platform_adapter: PlatformAdapter, monitor: ClipboardMonitor,db_helper=None):
        super().__init__()
        self.adapter = platform_adapter
        self.monitor = monitor
        self.db_helper = db_helper

        # Secure Memory Storage
        self._secure_data: Optional[bytearray] = None
        self._current_entry_id: Optional[int] = None

        # Timer Logic
        self._clear_timer = QTimer(self)
        self._clear_timer.timeout.connect(self._tick)
        self._remaining_seconds = 0
        # Load settings
        self._timeout_duration = self._load_timeout()

        # Monitor Integration
        self.monitor.content_changed.connect(self._on_external_clipboard_change)

    @classmethod
    def get_instance(cls, adapter=None, monitor=None):
        if cls._instance is None:
            if adapter and monitor:
                cls._instance = cls(adapter, monitor)
        return cls._instance

    def set_db_helper(self, db_helper):
        """Устанавливает хелпер БД после инициализации."""
        self.db_helper = db_helper
        self._timeout_duration = self._load_timeout()

    def _load_timeout(self) -> int:
        """Загружает таймаут из БД. Default: 30 сек."""
        if not self.db_helper:
            return 30
        val = self.db_helper.get_setting("clipboard_timeout")
        try:
            return int(val) if val else 30
        except ValueError:
            return 30

    def set_timeout(self, seconds: int):
        """Устанавливает и сохраняет новый таймаут."""
        if seconds < 5: seconds = 5  # Min limit (Req 2)
        if seconds > 300: seconds = 300  # Max limit 5 min (Req 2)
        if seconds == 0:
            # 0 means "Never" (Req 2)
            pass

        self._timeout_duration = seconds

        if self.db_helper:
            self.db_helper.save_setting("clipboard_timeout", seconds)
            print(f"[ClipboardService] Timeout set to {seconds}s and saved.")

    def get_timeout(self) -> int:
        return self._timeout_duration

    def copy_password(self, entry_id: int, password: str, timeout: int = 30):
        """
        Безопасно копирует пароль в буфер.
        1. Сохраняет пароль в защищенной памяти (bytearray).
        2. Кладет в системный буфер.
        3. Запускает таймер очистки.
        """
        self._cleanup_memory()

        # 1. Store in "secure" memory (bytearray allows zeroing out)
        self._secure_data = bytearray(password.encode('utf-8'))
        self._current_entry_id = entry_id

        # 2. Copy to system clipboard
        success = self.adapter.copy_to_clipboard(password)

        if success:
            # Update monitor to ignore this specific change if needed
            self.monitor.update_internal_state(password)

            # 3. Start Timer
            if self._timeout_duration > 0:
                self._remaining_seconds = self._timeout_duration
                self._clear_timer.start(1000)
                print(f"[ClipboardService] Password copied. Auto-clear in {self._timeout_duration}s.")
            else:
                print("[ClipboardService] Password copied. Auto-clear DISABLED (Never).")

            self.clipboard_copied.emit(entry_id)
        else:
            self._cleanup_memory()
            raise RuntimeError("Failed to copy password to clipboard")

    def clear_now(self):
        """Принудительная очистка буфера."""
        self._perform_clear()


    def _tick(self):
        """Тик таймера."""
        self._remaining_seconds -= 1
        self.timer_updated.emit(self._remaining_seconds)

        if self._remaining_seconds <= 0:
            self._perform_clear()

    def _perform_clear(self):
        """Выполняет очистку памяти и буфера."""
        self._clear_timer.stop()

        # 1. Clear system clipboard
        self.adapter.clear_clipboard()

        # 2. Clear internal memory
        self._cleanup_memory()

        # 3. Emit Event
        self.clipboard_cleared.emit()
        print("[ClipboardService] Clipboard cleared and memory zeroed.")

    def _cleanup_memory(self):
        """Безопасная очистка внутренней памяти."""
        if self._secure_data:
            for i in range(len(self._secure_data)):
                self._secure_data[i] = 0  # Zero out memory
            self._secure_data = None
        self._current_entry_id = None
        self.timer_updated.emit(0)

    def _on_external_clipboard_change(self, new_content: str):
        """
        Реакция на изменение буфера извне.
        Если пользователь скопировал что-то другое, мы сбрасываем таймер.
        """
        if self._secure_data:
            # Если у нас есть данные в памяти, значит мы ожидали очистки.
            # Если контент изменился на другой, сбрасываем нашу защиту.
            try:
                current_pwd = self._secure_data.decode('utf-8')
                if new_content != current_pwd:
                    print("[ClipboardService] External clipboard change detected. Canceling auto-clear.")
                    self._clear_timer.stop()
                    self._cleanup_memory()

            except Exception:
                pass