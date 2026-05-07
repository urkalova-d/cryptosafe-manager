import secrets
import ctypes
from typing import Optional
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from src.core.events import event_bus, EventType

from .platform_adapter import PlatformAdapter
from .clipboard_monitor import ClipboardMonitor
from src.core.crypto.key_storage import KeyStorage

class ThreatLevel:
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

SECURITY_PROFILES = {
    "standard": {
        "name": "Standard",
        "timeout": 30,
        "monitor_level": 1, # Basic
        "anti_screenshot": False
    },
    "secure": {
        "name": "Secure",
        "timeout": 15,
        "monitor_level": 2, # Enhanced
        "anti_screenshot": False
    },
    "public": {
        "name": "Public Computer",
        "timeout": 5,
        "monitor_level": 3, # Paranoid
        "anti_screenshot": True
    }
}


class ClipboardService(QObject):
    # интерфейс для работы с буфером обмена
    clipboard_copied = pyqtSignal(int)
    clipboard_cleared = pyqtSignal()
    timer_updated = pyqtSignal(int)

    copy_username_requested = pyqtSignal(int)
    copy_all_requested = pyqtSignal(int)
    warning_5_seconds = pyqtSignal()  #  5 секунд до очистки

    threat_detected = pyqtSignal(int, str)
    block_state_changed = pyqtSignal(bool)
    ephemeral_mode_changed = pyqtSignal(bool)

    protection_enabled = pyqtSignal()  # включить защиту окна
    protection_disabled = pyqtSignal()  #  выключить защиту окна
    error_occurred = pyqtSignal(str)
    _instance = None

    def __init__(self, platform_adapter: PlatformAdapter, monitor: ClipboardMonitor, db_helper=None):
        super().__init__()
        self.adapter = platform_adapter
        self.monitor = monitor
        self.db_helper = db_helper

        self._entry_manager = None
        self._key_storage_ref = None

        self._security_profile = "standard"
        self._anti_screenshot_enabled = False
        self._notifications_enabled = True

        self._ephemeral_mode = False
        self._ephemeral_password: Optional[str] = None
        self._ephemeral_entry_id: Optional[int] = None
        self._ephemeral_timer = QTimer(self)
        self._ephemeral_timer.timeout.connect(self._clear_ephemeral)

        self._secure_data: Optional[bytearray] = None
        self._xor_mask: Optional[bytearray] = None
        self._current_entry_id: Optional[int] = None
        self._current_data_type: Optional[str] = None

        self._clear_timer = QTimer(self)
        self._clear_timer.timeout.connect(self._tick)
        self._remaining_seconds = 0

        self._timeout_duration = self._load_timeout()

        # Флаг для отслеживания предупреждения
        self._warning_shown = False

        self.monitor.content_changed.connect(self._on_external_clipboard_change)

    @classmethod
    def get_instance(cls, adapter=None, monitor=None, db_helper=None):
        if cls._instance is None:
            if adapter and monitor:
                cls._instance = cls(adapter, monitor, db_helper)
        return cls._instance

    def set_key_storage(self, key_storage):
        #Передача ссылки на KeyStorage для проверки блокировки
        self._key_storage_ref = key_storage

    def set_db_helper(self, db_helper):
        self.db_helper = db_helper
        self._timeout_duration = self._load_timeout()

    def set_entry_manager(self, entry_manager):
        # Передача ссылки на EntryManager
        self._entry_manager = entry_manager

    def _load_timeout(self) -> int:
        #Загружает таймаут из бд
        if not self.db_helper: return 30
        val = self.db_helper.get_setting("clipboard_timeout")
        try:
            return int(val) if val else 30
        except ValueError:
            return 30

    def load_settings(self):
        #загрузка настроек из бд
        if not self.db_helper: return

        profile = self.db_helper.get_setting("security_profile")
        if profile and profile in SECURITY_PROFILES:
            self.set_security_profile(profile, save=False)
        else:
            self.set_security_profile("standard", save=False)

        notif = self.db_helper.get_setting("notifications_enabled")
        self._notifications_enabled = (notif is None or notif == "1")

    def set_security_profile(self, profile_key: str, save: bool = True):
        #применение пофиля защиты
        if profile_key not in SECURITY_PROFILES:
            print(f"[ClipboardService] Invalid profile: {profile_key}")
            return

        self._security_profile = profile_key
        config = SECURITY_PROFILES[profile_key]

        self._timeout_duration = config["timeout"]
        self._anti_screenshot_enabled = config["anti_screenshot"]

        print(f"[ClipboardService] Profile set to: {config['name']} (Timeout: {self._timeout_duration}s)")

        if save and self.db_helper:
            self.db_helper.save_setting("security_profile", profile_key)

        #self.config_changed.emit(config)

    def get_current_profile(self) -> str:
        return self._security_profile

    def set_timeout(self, seconds: int):
        if seconds < 5: seconds = 5
        if seconds > 300: seconds = 300
        self._timeout_duration = seconds
        if self.db_helper:
            self.db_helper.save_setting("clipboard_timeout", seconds)

    def get_timeout(self) -> int:
        return self._timeout_duration

    def are_notifications_enabled(self) -> bool:
        # проверка включены ли уведомления
        return self._notifications_enabled

    def set_notifications_enabled(self, enabled: bool):
        #Включение/выключение уведомлений
        self._notifications_enabled = enabled
        if self.db_helper:
            self.db_helper.save_setting("notifications_enabled", "1" if enabled else "0")

    def set_ephemeral_mode(self, enabled: bool):
        #Включение/выключение эфемерного режима
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
        # получениепароля из эфемерного буфера
        if self._ephemeral_mode:
            return self._ephemeral_password
        return None

    def has_ephemeral_data(self) -> bool:
        return self._ephemeral_mode and self._ephemeral_password is not None

    def _clear_ephemeral(self):
        #Очистка эфемерного буфера
        self._ephemeral_password = None
        self._ephemeral_entry_id = None
        self._ephemeral_timer.stop()

    def _check_vault_unlocked(self) -> bool:
        #Проверка что хранилище разблокировано перед операцией
        if self._key_storage_ref and self._key_storage_ref.is_locked():
            print("[ClipboardService] BLOCKED: Vault is locked.")
            return False
        return True

    def on_vault_lock(self):
        #Мгновенно очищает все буферы
        print("[ClipboardService] Vault lock detected. Clearing clipboard immediately.")
        self.clear_now()
        # Дополнительно логируем событие безопасности
        self._log_security_event("VAULT_LOCK_CLEAR", None, "Clipboard cleared due to vault lock")

    def copy_password(self, entry_id: int, password: str):
        # для совместимости
        self._copy_data(entry_id, password, 'password')
        event_bus.publish(EventType.CLIPBOARD_COPY, {
            'action': 'copy',
            'entry_id': entry_id,
            'data_type': 'password'
        })

    def copy_username(self, entry_id: int, username: str):
        #Копирование имени пользователя
        print(f"[ClipboardService] copy_username called with ID: {entry_id}")
        self._copy_data(entry_id, username, 'username')
        event_bus.publish(EventType.CLIPBOARD_COPY, {
            'action': 'copy',
            'entry_id': entry_id,
            'data_type': 'username'
        })

    def copy_all(self, entry_id: int, data_str: str):
        #Копирование всех данных
        print(f"[ClipboardService] copy_all called with ID: {entry_id}")
        self._copy_data(entry_id, data_str, 'all')
        event_bus.publish(EventType.CLIPBOARD_COPY, {
            'action': 'copy',
            'entry_id': entry_id,
            'data_type': 'all'
        })

    def copy_from_entry(self, entry_id: int, field: str = 'password'):
        if not self._entry_manager:
            raise RuntimeError("EntryManager not linked to ClipboardService")

        # Получение записи
        entry = self._entry_manager.get_entry(entry_id)

        #  Проверка флага запрета копирования
        if entry.get('never_copy', False):
            msg = f"Copy blocked by policy for entry {entry_id}"
            print(f"[ClipboardService] {msg}")
            # Логируем попытку нарушения политики
            self._log_security_event("COPY_BLOCKED_POLICY", entry_id, "Attempted to copy 'never_copy' entry")
            raise PermissionError("This entry is marked as 'Never copy to clipboard'")

        #  Извлекаем данные
        data_to_copy = ""
        if field == 'password':
            data_to_copy = entry.get('password', '')
        elif field == 'username':
            data_to_copy = entry.get('username', '')
        elif field == 'totp':
            # Future integration: TOTP
            # data_to_copy = self._entry_manager.generate_totp(entry.get('totp_secret'))
            pass

        if not data_to_copy:
            return

        #  Выполняем низкоуровневое копирование
        self._copy_data(entry_id, data_to_copy, field)

        # Логируем успешное действие
        self._log_clipboard_action("COPY", entry_id, field)



    def _copy_data(self, entry_id: int, data: str, data_type: str):
        if not isinstance(entry_id, int) or entry_id < 0:
            raise ValueError("Invalid Entry ID")

        if not isinstance(data, str):
            # Защита от передачи None или объектов
            data = str(data) if data is not None else ""

        # Защита от переполнения
        MAX_CLIPBOARD_SIZE = 1024 * 1024  # 1мб
        if len(data) > MAX_CLIPBOARD_SIZE:
            raise ValueError("Data exceeds maximum safe clipboard size")
        if not self._check_vault_unlocked():
            raise PermissionError("Vault is locked. Cannot copy to clipboard.")

        if self._ephemeral_mode:
            if data_type == 'password':
                self._clear_ephemeral()
                self._ephemeral_password = data
                self._ephemeral_entry_id = entry_id
                if self._timeout_duration > 0:
                    self._ephemeral_timer.start(self._timeout_duration * 1000)
                self.clipboard_copied.emit(entry_id)
            return

        #Обычный режим с защитой памяти
        try:
            # Очистка старых данных
            self._cleanup_memory()

            # Подготовка данных
            plain_bytes = data.encode('utf-8')
            data_len = len(plain_bytes)

            #  XOR
            if data_len > 0:
                self._xor_mask = secrets.token_bytes(data_len)
                # Генерация XOR маски и применение в одну строку
                obfuscated_bytes = bytes(p ^ m for p, m in zip(plain_bytes, self._xor_mask))
            else:
                self._xor_mask = bytearray()
                obfuscated_bytes = bytearray()

            # безопасное хранение в памяти
            if self._key_storage_ref:
                self._secure_data = self._key_storage_ref.protect_data(bytes(obfuscated_bytes))
            else:
                self._secure_data = obfuscated_bytes

            self._current_entry_id = entry_id
            self._current_data_type = data_type
            self._warning_shown = False

            # Копирование в системный буфер
            success = self.adapter.copy_to_clipboard(data)

            if success:
                self.monitor.update_internal_state(data)
                if self._timeout_duration > 0:
                    self._remaining_seconds = self._timeout_duration
                    self._clear_timer.start(1000)

                # антискриншот
                if self._anti_screenshot_enabled:
                    self.protection_enabled.emit()

                self.clipboard_copied.emit(entry_id)
                print("[ClipboardService] Copy SUCCESS.")
            else:
                self._log_security_event("COPY_FAILED", entry_id, "Platform adapter returned False")
                self._cleanup_memory()
                raise RuntimeError("Failed to copy to clipboard")

        except MemoryError:
            self._log_security_event("MEMORY_ERROR", entry_id, "Out of memory during XOR obfuscation")
            self._cleanup_memory()
            raise RuntimeError("System out of memory. Data too large.")

        except Exception as e:
            self._log_security_event("UNEXPECTED_ERROR", entry_id, f"Exception: {str(e)}")
            self._cleanup_memory()
            # Перебрасываем исключение, чтобы UI мог его обработать
            raise e

    def clear_now(self):
        #Принудительная очистка обоих буферов
        self._perform_clear()
        self._clear_ephemeral()


    def _tick(self):
        self._remaining_seconds -= 1
        self.timer_updated.emit(self._remaining_seconds)

        #  Предупреждение за 5 секунд
        if self._remaining_seconds == 5 and not self._warning_shown:
            self.warning_5_seconds.emit()
            self._warning_shown = True

        if self._remaining_seconds <= 0:
            self._perform_clear()

    def _perform_clear(self):
        #востановлние
        self._clear_timer.stop()

        # Попытка очистки
        clear_success = self.adapter.clear_clipboard()

        self.protection_disabled.emit()

        if self._current_entry_id:
            event_bus.publish(EventType.CLIPBOARD_CLEARED, {
                'action': 'clear',
                'entry_id': self._current_entry_id,
                'trigger': 'manual'
            })
        self._cleanup_memory()
        self.clipboard_cleared.emit()

        if not clear_success:
            msg = "CRITICAL: Failed to clear system clipboard! Please clear it manually (Ctrl+V in a text editor)."
            print(f"[ClipboardService] {msg}")
            # Логируем инцидент
            self._log_security_event("CLEAR_FAILED", self._current_entry_id, "Adapter failed to clear clipboard")
            # Предупреждаем UI
            self.threat_detected.emit(ThreatLevel.HIGH, "Failed to clear clipboard. Manual clearing required.")
            self.error_occurred.emit(msg)
        else:
            print("[ClipboardService] Clipboard cleared.")

    def _cleanup_memory(self):
        #зануленик памяти
        # Быстрая очистка
        if self._secure_data:
            if self._key_storage_ref:
                self._key_storage_ref.zero_buffer(self._secure_data)
            elif isinstance(self._secure_data, bytearray):
                # Быстрая очистка bytearra
                for i in range(len(self._secure_data)):
                    self._secure_data[i] = 0
            self._secure_data = None

        if self._xor_mask:
            # _xor_mask может быть bytes (immutable) или bytearray
            if isinstance(self._xor_mask, bytearray):
                for i in range(len(self._xor_mask)):
                    self._xor_mask[i] = 0
            self._xor_mask = None

        self._current_entry_id = None
        self._current_data_type = None
        self._warning_shown = False
        self.timer_updated.emit(0)

    def _on_external_clipboard_change(self, new_content: str):
        if self._secure_data and self._xor_mask:
            try:
                # Расшифровываем то что хранится у нас
                original_bytes = self._decrypt_memory_data()
                if original_bytes and new_content == original_bytes.decode('utf-8'):
                    return

                # Если содержимое НЕ совпадает -> кто-то извне перезаписал буфер
                print("[ClipboardService] External change detected! Forcing cleanup.")
                event_bus.publish(EventType.CLIPBOARD_EXTERNAL_CHANGE, {
                    'action': 'external_tamper',
                    'entry_id': self._current_entry_id,
                    'reason': 'External overwrite detected'
                })
                self._clear_timer.stop()
                self._cleanup_memory()
            except Exception:
                pass

    def _decrypt_memory_data(self) -> bytes:
        #Вспомогательный метод для безопасного чтения данных
        if not self._secure_data or not self._xor_mask:
            return b""

        # Получаем сырые данные
        raw_data = None
        if self._key_storage_ref:
            raw_data = self._key_storage_ref.unprotect_data(self._secure_data)
        else:
            raw_data = bytes(self._secure_data)

        if not raw_data: return b""

        return bytes(r ^ m for r, m in zip(raw_data, self._xor_mask))

    # API для UI индикации
    def get_current_entry_id(self) -> Optional[int]:
        return self._current_entry_id

    def get_current_data_type(self) -> Optional[str]:
        return self._current_data_type

    """
    def _log_clipboard_action(self, action: str, entry_id: int, field: str):
        if self.db_helper:
            details = f"Field: {field}"
            self.db_helper.add_audit_log(f"CLIPBOARD_{action}", entry_id, details)

    def _log_security_event(self, event_type: str, entry_id: int, details: str):
        if self.db_helper:
            self.db_helper.add_audit_log(event_type, entry_id, details)
    """