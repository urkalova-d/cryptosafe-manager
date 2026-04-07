import sys
import ctypes
import platform
import ctypes.util
import time
from typing import Optional, Tuple
from enum import Enum, auto


class LockReason(Enum):
    #Причины блокировки хранилища
    MANUAL = auto()  # ручной выход
    INACTIVITY = auto()  #бездействие
    APP_BACKGROUND = auto()  #приложение свернуто
    APP_CLOSE = auto()  # закрытие приложения


class KeyStorage:
    INACTIVITY_TIMEOUT = 3600  #1час бездействия

    def __init__(self):
        self._auth_key: Optional[bytearray] = None
        self._encryption_key: Optional[bytearray] = None
        self._last_activity_time: float = 0
        self._is_locked: bool = True
        self._is_active: bool = True

        self._memory_protection_available = False
        self._protection_method = None

        # попытка инициализации защищенной памяти
        self._init_secure_memory()

    def _init_secure_memory(self):
        #Инициализация защищенных областей памяти. использование доступных механизмов защиты

        self._os_type = platform.system()

        if self._os_type == "Windows":
            self._init_windows_protection()
        elif self._os_type in ["Linux", "Darwin"]:  #Darwin=macOS
            self._init_unix_protection()
        else:
            print(f"Memory protection not available for {self._os_type}")
            self._memory_protection_available = False

    def _init_windows_protection(self):
        #инициализация защиты памяти для windows
        try:
            # разные варианты загрузки функции
            crypt32 = ctypes.windll.crypt32

            #проверка существования функции
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
                print("CryptProtectMemory not available, using fallback method")
                self._memory_protection_available = False

        except Exception as e:
            print(f"Windows memory protection initialization failed: {e}")
            self._memory_protection_available = False

    def _init_unix_protection(self):
        #инициализация защиты памяти для unix
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"))

            # Проверяем наличие mlock
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
                print("mlock not available, using fallback method")
                self._memory_protection_available = False

        except Exception as e:
            print(f"Unix memory protection initialization failed: {e}")
            self._memory_protection_available = False

    def _lock_memory(self, buffer: bytearray) -> bool:
        #блокировка памяти для предотвращения выгрузки в swap
        if not self._memory_protection_available or not buffer:
            return False

        try:
            #получение адреса буфера
            buffer_ptr = (ctypes.c_char * len(buffer)).from_buffer(buffer)
            addr = ctypes.addressof(buffer_ptr)
            size = len(buffer)

            if self._protection_method == "CryptProtectMemory":
                # Windows: CryptProtectMemory
                # CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
                result = self._cryptprotect_memory(addr, size, 0)
                if not result:
                    error = ctypes.GetLastError()
                    print(f"CryptProtectMemory failed with error: {error}")
                    return False
                return True

            elif self._protection_method == "mlock":
                # Unix: mlock
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
        #снятие блокировки памяти
        if not self._memory_protection_available or not buffer:
            return False

        try:
            buffer_ptr = (ctypes.c_char * len(buffer)).from_buffer(buffer)
            addr = ctypes.addressof(buffer_ptr)
            size = len(buffer)

            if self._protection_method == "CryptProtectMemory":
                # Windows: CryptUnprotectMemory
                result = self._cryptunprotect_memory(addr, size, 0)
                return bool(result)

            elif self._protection_method == "mlock":
                # Unix: munlock
                result = self._munlock(addr, size)
                return result == 0

        except Exception as e:
            print(f"Memory unlock failed: {e}")
            return False

        return False

    def set_keys(self, auth_key: Optional[bytes], enc_key: Optional[bytes]):
        #Установка ключей с защитой памяти

        self.clear()

        if auth_key is not None:
            self._auth_key = bytearray(auth_key)
            if self._memory_protection_available:
                self._lock_memory(self._auth_key)

        if enc_key is not None:
            self._encryption_key = bytearray(enc_key)
            if self._memory_protection_available:
                self._lock_memory(self._encryption_key)

        self._is_locked = False
        self._update_activity()

    def get_auth_key(self) -> Optional[bytes]:
        #Получение ключа аутентификации: ключ аутентификации или none если хранилище заблокировано
        if self._is_locked or not self._is_active:
            return None

        # Проверка таймаута бездействия
        if not self._check_activity_timeout():
            return None

        self._update_activity()
        return bytes(self._auth_key) if self._auth_key is not None else None

    def get_enc_key(self) -> Optional[bytes]:
        #Получение ключа шифрования.Ключ шифрования или None, если хранилище заблокировано
        if self._is_locked or not self._is_active:
            return None

        # Проверка таймаута бездействия
        if not self._check_activity_timeout():
            return None

        self._update_activity()
        return bytes(self._encryption_key) if self._encryption_key is not None else None

    def _update_activity(self):
        #Обновление времени последней активности
        self._last_activity_time = time.time()

    def _check_activity_timeout(self) -> bool:
        #Проверка таймаута бездействия
        if self._last_activity_time == 0:
            return True

        inactive_time = time.time() - self._last_activity_time
        if inactive_time > self.INACTIVITY_TIMEOUT:
            self.lock(LockReason.INACTIVITY)
            return False

        return True

    def set_active(self, active: bool):
        #Установка состояния активности приложения
        was_active = self._is_active
        self._is_active = active

        # При переходе в неактивное состояние блокировка хранилища
        if was_active and not active:
            self.lock(LockReason.APP_BACKGROUND)

    def lock(self, reason: LockReason = LockReason.MANUAL):
        #блокировка хранилища с очисткой ключей
        if self._is_locked:
            return

        self._is_locked = True
        self._zero_out_keys()
        print(f"Хранилище заблокировано. Причина: {reason.name}")

    def unlock(self) -> bool:
        # разблокировка хранилища
        if not self._is_locked:
            return True

        if not self._is_active:
            print("Нельзя разблокировать: приложение неактивно")
            return False

        #очистка старых ключей
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
                    # сняте защиты памяти перед обнулением
                    if self._memory_protection_available:
                        self._unlock_memory(buffer)

                    #обнуление
                    for i in range(len(buffer)):
                        buffer[i] = 0

                    # заполнение случайными данными
                    import secrets
                    random_data = secrets.token_bytes(len(buffer))
                    for i in range(len(buffer)):
                        buffer[i] = random_data[i]

                    # повторное обнуление
                    for i in range(len(buffer)):
                        buffer[i] = 0

                    # синхронизация памяти
                    if hasattr(buffer, 'flush'):
                        buffer.flush()

                except Exception as e:
                    print(f"Error zeroing memory: {e}")

        zero_out(self._auth_key)
        zero_out(self._encryption_key)

    def clear(self):
        #Полная очистка хранилища.
        self._zero_out_keys()
        self._auth_key = None
        self._encryption_key = None
        self._is_locked = True
        self._last_activity_time = 0

    def is_locked(self) -> bool:
        #Проверка состояния хранилища
        return self._is_locked or not self._is_active or not self._check_activity_timeout()

    def is_active(self) -> bool:
        #Проверка активности хранилища
        return self._is_active and not self._is_locked

    def get_lock_reason(self) -> Optional[str]:
        #Получение причины блокировки
        if not self._is_active:
            return "Приложение неактивно (свернуто)"
        if self._is_locked:
            return "Хранилище заблокировано"
        if not self._check_activity_timeout():
            return "Превышен таймаут бездействия"
        return None

    def get_protection_status(self) -> dict:
        #Получение статуса защиты памяти
        return {
            "protection_available": self._memory_protection_available,
            "protection_method": self._protection_method,
            "os_type": self._os_type,
            "is_locked": self._is_locked,
            "is_active": self._is_active
        }

    def __del__(self):
        #Деструктор: гарантированная очистка памяти
        self.clear()



class ActivityManager:#  класс для автоматического управления активностью
    #менеджер активности приложения

    def __init__(self, key_storage: KeyStorage):
        self.key_storage = key_storage
        self._last_activity = time.time()
        self._is_focused = True

    def on_activity(self):
        #Вызывается при любой активности пользователя
        self._last_activity = time.time()
        if not self.key_storage.is_locked():
            self.key_storage._update_activity()

    def on_focus_lost(self):
        #вызывается при потере фокуса приложения
        self._is_focused = False
        self.key_storage.set_active(False)

    def on_focus_gained(self):
        # вызывается при получении фокуса приложения
        self._is_focused = True
        self.key_storage.set_active(True)

    def check_auto_lock(self) -> bool:
        #проверка автоматической блокировки
        if not self._is_focused:
            return True

        if not self.key_storage.is_active():
            return True

        return False