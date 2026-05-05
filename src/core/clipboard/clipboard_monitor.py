from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication
from typing import Optional


class ClipboardMonitor(QObject):
    #Мониторинг системного буфера обмена

    content_changed = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._last_content_hash: Optional[int] = None
        self._is_monitoring = False
        # Инициализируем доступ к буферу обмена Qt
        self._clipboard = None

        try:
            self._clipboard = QApplication.clipboard()
            if not self._clipboard:
                print("[ClipboardMonitor] WARNING: QApplication.clipboard() returned None. Monitoring disabled.")
        except Exception as e:
            print(f"[ClipboardMonitor] CRITICAL: Failed to access clipboard API: {e}")

    def start_monitoring(self):
        #Запуск мониторинга
        if self._is_monitoring:
            return

        if not self._clipboard:
            print("[ClipboardMonitor] Cannot start monitoring: Clipboard API unavailable.")
            return

        try:
            # Сохраняем текущее состояние
            self._last_content_hash = self._hash_content(self._clipboard.text())
            # Подключаемся к сигналу
            self._clipboard.dataChanged.connect(self._on_clipboard_change)
            self._is_monitoring = True
            print("[ClipboardMonitor] Started (Event-driven mode)")
        except Exception as e:
            print(f"[ClipboardMonitor] Error starting monitoring: {e}. Running in degraded mode.")
            self._is_monitoring = False

    def stop_monitoring(self):
        #Остановка мониторинга
        if self._is_monitoring and self._clipboard:
            try:
                self._clipboard.dataChanged.disconnect(self._on_clipboard_change)
            except TypeError:
                pass
            self._is_monitoring = False
            print("[ClipboardMonitor] Stopped")

    def _on_clipboard_change(self):
        if not self._is_monitoring or not self._clipboard:
            return

        try:
            # чтение содержимого
            current_content = self._clipboard.text()
            current_hash = self._hash_content(current_content)

            if current_hash != self._last_content_hash:
                self._last_content_hash = current_hash
                # Emit signal only if content actually changed
                self.content_changed.emit(current_content if current_content else "")
        except Exception as e:
            print(f"[ClipboardMonitor] Error handling change: {e}")

    def update_internal_state(self, content: str):
        if self._clipboard:
            self._last_content_hash = self._hash_content(content)

    def _hash_content(self, content: str) -> int:
        #Быстрый хеш для сравнения
        if not content:
            return 0
        # Используем встроенный хеш Python
        return hash(content)