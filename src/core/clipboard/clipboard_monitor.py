# src/core/clipboard/clipboard_monitor.py
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from .platform_adapter import PlatformAdapter


class ClipboardMonitor(QObject):
    """
    Мониторинг системного буфера обмена.
    Детектирует внешние изменения (защита от перезаписи).
    """

    # Сигналы
    content_changed = pyqtSignal(str)  # Уведомляет, что содержимое изменилось извне

    def __init__(self, platform_adapter: PlatformAdapter, check_interval_ms=1000):
        super().__init__()
        self.adapter = platform_adapter
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._check_clipboard)
        self._last_content_hash = None
        self._check_interval = check_interval_ms
        self._is_monitoring = False

    def start_monitoring(self):
        """Запуск мониторинга."""
        if not self._is_monitoring:
            self._last_content_hash = self._hash_content(self.adapter.get_clipboard_content())
            self._timer.start(self._check_interval)
            self._is_monitoring = True
            print("[ClipboardMonitor] Started monitoring")

    def stop_monitoring(self):
        """Остановка мониторинга."""
        self._timer.stop()
        self._is_monitoring = False
        print("[ClipboardMonitor] Stopped monitoring")

    def _check_clipboard(self):
        """Периодическая проверка буфера."""
        current_content = self.adapter.get_clipboard_content()
        current_hash = self._hash_content(current_content)

        if current_hash != self._last_content_hash:
            # Содержимое изменилось извне или нами
            self._last_content_hash = current_hash
            self.content_changed.emit(current_content if current_content else "")

    def update_internal_state(self, content: str):
        """Обновляет внутреннее состояние после легального копирования сервисом."""
        self._last_content_hash = self._hash_content(content)

    def _hash_content(self, content: str) -> str:
        # Простой хеш для сравнения, чтобы не хранить строки в памяти лишний раз
        if not content:
            return ""
        return str(hash(content))