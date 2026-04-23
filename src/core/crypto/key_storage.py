import sys
import ctypes
import platform
import ctypes.util
import time
from typing import Optional, Tuple
from enum import Enum, auto
ENABLE_MEMORY_PROTECTION = True

class LockReason(Enum):
    MANUAL = auto()
    INACTIVITY = auto()
    APP_BACKGROUND = auto()
    APP_CLOSE = auto()


class KeyStorage:
    INACTIVITY_TIMEOUT = 3600

    def __init__(self):
        # ИНИЦИАЛИЗИРУЕМ АТРИБУТЫ ВСЕГДА, независимо от защиты
        self._auth_key: Optional[bytearray] = None
        self._encryption_key: Optional[bytearray] = None
        self._last_activity_time: float = 0
        self._is_locked: bool = True
        self._is_active: bool = True
        self._memory_protection_available = False
        self._protection_method = None
        self._os_type = platform.system()

        # Инициализация защиты памяти (только если включена)
        if ENABLE_MEMORY_PROTECTION:
            self._init_secure_memory()
            if self._memory_protection_available:
                print(f"[KeyStorage] Memory protection ENABLED using: {self._protection_method}")
            else:
                print("[KeyStorage] Memory protection FAILED to initialize, running without protection")
        else:
            print("[KeyStorage] Memory protection DISABLED")

        print("[KeyStorage] Initialized")

    def _init_secure_memory(self):
        """Инициализация защищенных областей памяти"""
        if self._os_type == "Windows":
            self._init_windows_protection()
        elif self._os_type in ["Linux", "Darwin"]:
            self._init_unix_protection()
        else:
            print(f"Memory protection not available for {self._os_type}")
            self._memory_protection_available = False

    def _init_windows_protection(self):
        try:
            crypt32 = ctypes.windll.crypt32

            if hasattr(crypt32, 'CryptProtectMemory'):
                self._cryptprotect_memory = crypt32.CryptProtectMemory
                self._cryptprotect_memory.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
                self._cryptprotect_memory.restype = ctypes.c_bool

                self._cryptunprotect_memory = crypt32.CryptUnprotectMemory
                self._cryptunprotect_memory.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
                self._cryptunprotect_memory.restype = ctypes.c_bool

                self._memory_protection_available = True
                self._protection_method = "CryptProtectMemory"
                print("Windows CryptProtectMemory initialized successfully")
            else:
                print("CryptProtectMemory not available")
                self._memory_protection_available = False

        except Exception as e:
            print(f"Windows memory protection initialization failed: {e}")
            self._memory_protection_available = False

    def _init_unix_protection(self):
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"))

            if hasattr(libc, 'mlock'):
                self._mlock = libc.mlock
                self._mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self._mlock.restype = ctypes.c_int

                self._munlock = libc.munlock
                self._munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self._munlock.restype = ctypes.c_int

                self._memory_protection_available = True
                self._protection_method = "mlock"
                print("Unix mlock initialized successfully")
            else:
                print("mlock not available")
                self._memory_protection_available = False

        except Exception as e:
            print(f"Unix memory protection initialization failed: {e}")
            self._memory_protection_available = False

    def _lock_memory(self, buffer: bytearray) -> bool:
        if not self._memory_protection_available or not buffer:
            return False

        try:
            buffer_ptr = (ctypes.c_char * len(buffer)).from_buffer(buffer)
            addr = ctypes.addressof(buffer_ptr)
            size = len(buffer)

            if self._protection_method == "CryptProtectMemory":
                result = self._cryptprotect_memory(addr, size, 0)
                if not result:
                    error = ctypes.GetLastError()
                    print(f"CryptProtectMemory failed with error: {error}")
                    return False
                return True
            elif self._protection_method == "mlock":
                result = self._mlock(addr, size)
                if result != 0:
                    error = ctypes.get_errno()
                    print(f"mlock failed with error: {error}")
                    return False
                return True

        except Exception as e:
            print(f"Memory lock failed: {e}")
            return False
        return False

    def _unlock_memory(self, buffer: bytearray) -> bool:
        if not self._memory_protection_available or not buffer:
            return False

        try:
            buffer_ptr = (ctypes.c_char * len(buffer)).from_buffer(buffer)
            addr = ctypes.addressof(buffer_ptr)
            size = len(buffer)

            if self._protection_method == "CryptProtectMemory":
                result = self._cryptunprotect_memory(addr, size, 0)
                if not result:
                    error = ctypes.GetLastError()
                    print(f"CryptUnprotectMemory failed with error: {error}")
                    return False
                return True
            elif self._protection_method == "mlock":
                result = self._munlock(addr, size)
                return result == 0

        except Exception as e:
            print(f"Memory unlock failed: {e}")
            return False
        return False

    def set_keys(self, auth_key: Optional[bytes], enc_key: Optional[bytes]):
        """Установка ключей с защитой памяти"""
        print(f"[KeyStorage] set_keys called - enc_key length: {len(enc_key) if enc_key else 0}")

        # Очищаем старые ключи
        self.clear()

        # Устанавливаем новые ключи
        if auth_key is not None:
            self._auth_key = bytearray(auth_key)
            if self._memory_protection_available:
                self._lock_memory(self._auth_key)

        if enc_key is not None:
            self._encryption_key = bytearray(enc_key)
            print(
                f"[KeyStorage] Before protection: {self._encryption_key.hex()[:32] if self._encryption_key else 'None'}")
            if self._memory_protection_available:
                self._lock_memory(self._encryption_key)
            print(
                f"[KeyStorage] After protection: {self._encryption_key.hex()[:32] if self._encryption_key else 'None'}")

        self._is_locked = False
        self._update_activity()

    def get_enc_key(self) -> Optional[bytes]:
        """Получение ключа шифрования"""
        print(f"[KeyStorage] get_enc_key called")

        if self._is_locked or not self._is_active:
            print(f"[KeyStorage] Locked or inactive")
            return None

        if not self._check_activity_timeout():
            print(f"[KeyStorage] Activity timeout")
            return None

        self._update_activity()

        if self._encryption_key is not None:
            # Если защита включена - расшифровываем перед чтением
            if self._memory_protection_available:
                self._unlock_memory(self._encryption_key)
                result = bytes(self._encryption_key)
                self._lock_memory(self._encryption_key)
                print(f"[KeyStorage] Returning enc_key (protected): {result.hex()[:32]}")
                return result
            else:
                result = bytes(self._encryption_key)
                print(f"[KeyStorage] Returning enc_key (unprotected): {result.hex()[:32]}")
                return result
        else:
            print(f"[KeyStorage] No enc_key stored")
            return None

    def get_auth_key(self) -> Optional[bytes]:
        """Получение ключа аутентификации"""
        print(f"[KeyStorage] get_auth_key called")

        if self._is_locked or not self._is_active:
            return None

        if not self._check_activity_timeout():
            return None

        self._update_activity()

        if self._auth_key is not None:
            if self._memory_protection_available:
                self._unlock_memory(self._auth_key)
                result = bytes(self._auth_key)
                self._lock_memory(self._auth_key)
                return result
            else:
                return bytes(self._auth_key)
        return None

    def _update_activity(self):
        self._last_activity_time = time.time()

    def _check_activity_timeout(self) -> bool:
        if self._last_activity_time == 0:
            return True

        inactive_time = time.time() - self._last_activity_time
        if inactive_time > self.INACTIVITY_TIMEOUT:
            self.lock(LockReason.INACTIVITY)
            return False
        return True

    def set_active(self, active: bool):
        was_active = self._is_active
        self._is_active = active
        if was_active and not active:
            self.lock(LockReason.APP_BACKGROUND)

    def lock(self, reason: LockReason = LockReason.MANUAL):
        if self._is_locked:
            return
        self._is_locked = True
        self._zero_out_keys()
        print(f"Хранилище заблокировано. Причина: {reason.name}")

    def unlock(self) -> bool:
        if not self._is_locked:
            return True
        if not self._is_active:
            print("Нельзя разблокировать: приложение неактивно")
            return False
        self._zero_out_keys()
        self._auth_key = None
        self._encryption_key = None
        self._is_locked = False
        self._update_activity()
        return True

    def _zero_out_keys(self):
        def zero_out(buffer):
            if buffer:
                try:
                    if self._memory_protection_available:
                        self._unlock_memory(buffer)
                    for i in range(len(buffer)):
                        buffer[i] = 0
                except Exception as e:
                    print(f"Error zeroing memory: {e}")

        zero_out(self._auth_key)
        zero_out(self._encryption_key)

    def clear(self):
        self._zero_out_keys()
        self._auth_key = None
        self._encryption_key = None
        self._is_locked = True
        self._last_activity_time = 0

    def is_locked(self) -> bool:
        return self._is_locked or not self._is_active or not self._check_activity_timeout()

    def is_active(self) -> bool:
        return self._is_active and not self._is_locked

    def get_lock_reason(self) -> Optional[str]:
        if not self._is_active:
            return "Приложение неактивно (свернуто)"
        if self._is_locked:
            return "Хранилище заблокировано"
        if not self._check_activity_timeout():
            return "Превышен таймаут бездействия"
        return None

    def get_protection_status(self) -> dict:
        return {
            "protection_available": self._memory_protection_available,
            "protection_method": self._protection_method,
            "os_type": self._os_type,
            "is_locked": self._is_locked,
            "is_active": self._is_active
        }

    def __del__(self):
        self.clear()

class ActivityManager:
    def __init__(self, key_storage: KeyStorage):
        self.key_storage = key_storage
        self._last_activity = time.time()
        self._is_focused = True

    def on_activity(self):
        self._last_activity = time.time()
        if not self.key_storage.is_locked():
            self.key_storage._update_activity()

    def on_focus_lost(self):
        self._is_focused = False
        self.key_storage.set_active(False)

    def on_focus_gained(self):
        self._is_focused = True
        self.key_storage.set_active(True)

    def check_auto_lock(self) -> bool:
        if not self._is_focused:
            return True

        if not self.key_storage.is_active():
            return True

        return False