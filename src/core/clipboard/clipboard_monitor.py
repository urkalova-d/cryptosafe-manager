from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication
from typing import Optional


class ClipboardMonitor(QObject):
    """
    Мониторинг системного буфера обмена.
    Req 10.2: Использует событийную модель Qt вместо опроса (polling).
    Это гарантирует 0% CPU usage в простое.
    """

    content_changed = pyqtSignal(str)

    def __init__(self):
        """
        Конструктор без аргументов.
        Использует QApplication.clipboard() напрямую.
        """
        super().__init__()
        self._last_content_hash: Optional[int] = None
        self._is_monitoring = False
        # Инициализируем доступ к буферу обмена Qt
        self._clipboard = QApplication.clipboard()

    def start_monitoring(self):
        """Запуск мониторинга. Подключаемся к сигналу Qt."""
        if not self._is_monitoring:
            # Сохраняем текущее состояние, чтобы не детектировать его как изменение сразу же
            if self._clipboard:
                self._last_content_hash = self._hash_content(self._clipboard.text())
                # Подключаем слот к системному сигналу изменения буфера
                self._clipboard.dataChanged.connect(self._on_clipboard_change)

            self._is_monitoring = True
            print("[ClipboardMonitor] Started (Event-driven mode)")

    def stop_monitoring(self):
        """Остановка мониторинга."""
        if self._is_monitoring and self._clipboard:
            try:
                self._clipboard.dataChanged.disconnect(self._on_clipboard_change)
            except TypeError:
                pass  # Уже отключен
            self._is_monitoring = False
            print("[ClipboardMonitor] Stopped")

    def _on_clipboard_change(self):
        """
        Слот, вызываемый Qt при изменении буфера обмена ОС.
        Работает мгновенно и не потребляет ресурсы в простое.
        """
        if not self._is_monitoring or not self._clipboard:
            return

        try:
            # Читаем содержимое. Использование text() быстрее, чем mimeData()
            current_content = self._clipboard.text()
            current_hash = self._hash_content(current_content)

            if current_hash != self._last_content_hash:
                self._last_content_hash = current_hash
                # Emit signal only if content actually changed
                self.content_changed.emit(current_content if current_content else "")
        except Exception as e:
            print(f"[ClipboardMonitor] Error handling change: {e}")

    def update_internal_state(self, content: str):
        """
        Обновляет внутренний хеш после легального копирования нашим сервисом.
        Это предотвращает ложное срабатывание защиты.
        """
        self._last_content_hash = self._hash_content(content)

    def _hash_content(self, content: str) -> int:
        """Быстрый хеш для сравнения."""
        if not content:
            return 0
        # Используем встроенный хеш Python
        return hash(content)