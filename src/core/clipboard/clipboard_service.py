import secrets
import ctypes
from typing import Optional
from PyQt6.QtCore import QObject, pyqtSignal, QTimer

from .platform_adapter import PlatformAdapter
from .clipboard_monitor import ClipboardMonitor
from src.core.crypto.key_storage import KeyStorage


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

        self._key_storage_ref = None

        # --- Ephemeral Mode State (MON-4) ---
        self._ephemeral_mode = False
        self._ephemeral_password: Optional[str] = None
        self._ephemeral_entry_id: Optional[int] = None
        self._ephemeral_timer = QTimer(self)
        self._ephemeral_timer.timeout.connect(self._clear_ephemeral)

        # Secure Memory Storage
        self._secure_data: Optional[bytearray] = None
        self._xor_mask: Optional[bytearray] = None
        self._current_entry_id: Optional[int] = None
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

    def set_key_storage(self, key_storage):
        """Передача ссылки на KeyStorage для проверки блокировки."""
        self._key_storage_ref = key_storage

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

    def _check_vault_unlocked(self) -> bool:
        """Req 6.3: Проверка, что хранилище разблокировано перед операцией."""
        if self._key_storage_ref and self._key_storage_ref.is_locked():
            print("[ClipboardService] BLOCKED: Vault is locked.")
            return False
        return True

    # --- Main Copy Logic ---
    def copy_password(self, entry_id: int, password: str):
        """Копирование пароля."""
        print(f"[ClipboardService] copy_password called with ID: {entry_id}")
        self._copy_data(entry_id, password, 'password')

    def copy_username(self, entry_id: int, username: str):
        """Копирование имени пользователя (Sprint 5)."""
        print(f"[ClipboardService] copy_username called with ID: {entry_id}")
        self._copy_data(entry_id, username, 'username')

    def copy_all(self, entry_id: int, data_str: str):
        """Копирование всех данных (Sprint 5). data_str = 'username:password'."""
        print(f"[ClipboardService] copy_all called with ID: {entry_id}")
        self._copy_data(entry_id, data_str, 'all')


    def _copy_data(self, entry_id: int, data: str, data_type: str):
        print(f"[ClipboardService] _copy_data START. ID: {entry_id}, Type: {data_type}")
        """Внутренняя логика копирования."""
        if not self._check_vault_unlocked():
            raise PermissionError("Vault is locked. Cannot copy to clipboard.")

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

        # --- Обычный режим с защитой памяти ---

        # 1. Очистка старых данных
        self._cleanup_memory()

        # 2. Подготовка данных
        plain_bytes = data.encode('utf-8')

        # 3. XOR Obfuscation (Req 6.2)
        # Генерируем случайную маску той же длины
        if len(plain_bytes) > 0:
            self._xor_mask = bytearray(secrets.token_bytes(len(plain_bytes)))

            # Применяем XOR: result = data ^ mask
            obfuscated_bytes = bytearray()
            for i in range(len(plain_bytes)):
                obfuscated_bytes.append(plain_bytes[i] ^ self._xor_mask[i])
        else:
            self._xor_mask = bytearray()
            obfuscated_bytes = bytearray()

        # 4. Secure Memory Storage (Req 6.1)
        # Мы используем упрощенный вариант защиты через KeyStorage если он есть
        # или просто храним bytearray. KeyStorage.protect_data требует экземпляр.
        if self._key_storage_ref:
            self._secure_data = self._key_storage_ref.protect_data(bytes(obfuscated_bytes))
        else:
            # Fallback если key_storage не передан (не должно быть)
            self._secure_data = obfuscated_bytes

        self._current_entry_id = entry_id
        self._current_data_type = data_type
        self._warning_shown = False

        # 5. Копирование в системный буфер
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
        """Req 6.1: Zero memory immediately after clearing."""
        if self._secure_data:
            # ИСПРАВЛЕНО: используем self._key_storage_ref
            if self._key_storage_ref:
                self._key_storage_ref.zero_buffer(self._secure_data)
            else:
                # Fallback zeroing
                for i in range(len(self._secure_data)):
                    self._secure_data[i] = 0
            self._secure_data = None

        if self._xor_mask:
            for i in range(len(self._xor_mask)):
                self._xor_mask[i] = 0
            self._xor_mask = None

        self._current_entry_id = None
        self._current_data_type = None
        self._warning_shown = False
        self.timer_updated.emit(0)

    def _on_external_clipboard_change(self, new_content: str):
        # Если у нас есть защищенные данные, мы не можем просто сравнить строки.
        # Нужно расшифровать, сравнить, и сразу забыть.
        if self._secure_data and self._xor_mask:
            try:
                # Расшифровка для сравнения
                unmasked = bytearray()
                # Снимаем защиту памяти (если нужно, зависит от реализации protect_data)
                # Обычно protect_data возвращает bytearray, который защищен в памяти

                # Если KeyStorage использовал CryptProtectMemory, он мог оставить данные в том же буфере
                # Для простоты считаем, что _secure_data сейчас содержит обфусцированные данные

                # Восстанавливаем оригинал для сравнения
                original_bytes = self._decrypt_memory_data()

                if new_content != original_bytes.decode('utf-8'):
                    print("[ClipboardService] External change detected.")
                    self._clear_timer.stop()
                    self._cleanup_memory()
            except Exception:
                pass

    def _decrypt_memory_data(self) -> bytes:
        """Вспомогательный метод для безопасного чтения данных."""
        if not self._secure_data or not self._xor_mask:
            return b""

        # Получаем сырые данные (снимаем защиту ОС)
        raw_data = None
        if self._key_storage_ref:
            raw_data = self._key_storage_ref.unprotect_data(self._secure_data)
        else:
            raw_data = bytes(self._secure_data)

        if not raw_data: return b""

        # Снимаем XOR
        decrypted = bytearray()
        for i in range(len(raw_data)):
            decrypted.append(raw_data[i] ^ self._xor_mask[i])

        return bytes(decrypted)

    # API для UI индикации
    def get_current_entry_id(self) -> Optional[int]:
        return self._current_entry_id

    def get_current_data_type(self) -> Optional[str]:
        return self._current_data_type

