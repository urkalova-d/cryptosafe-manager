import sys
import ctypes
import platform
import ctypes.util

class KeyStorage:

    def __init__(self):
        self._auth_key = None
        self._encryption_key = None

    def set_keys(self, auth_key: bytes, enc_key: bytes):
        # Сначала очищаем старые ключи, если они были
        self.clear()

        self._auth_key = bytearray(auth_key)
        self._encryption_key = bytearray(enc_key)

        print("Ключи загружены в защищенное хранилище.")

    def get_auth_key(self) -> bytes:
        if self._auth_key is None: return None
        return bytes(self._auth_key)

    def get_enc_key(self) -> bytes:
        if self._encryption_key is None: return None
        return bytes(self._encryption_key)


    def clear(self):
         #Безопасная очистка ключей из памяти
        if self._auth_key is None and self._encryption_key is None:
            return

        #зануление байтов
        def _zero_out(buffer):
            if buffer:
                for i in range(len(buffer)):
                    buffer[i] = 0

        # Зануление памяти
        _zero_out(self._auth_key)
        _zero_out(self._encryption_key)

        # Удаление ссылки
        self._auth_key = None
        self._encryption_key = None

        print("Память очищена (zeroed).")

    def _protect_windows(self, lock: bool):
        #шифровка области памяти, чтобы она была нечитаема в дампах памяти
        # Константы Windows API
        CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00

        # Загрузка DLL
        try:
            crypt32 = ctypes.windll.crypt32
        except Exception:
            return

        buffers = [self._auth_key, self._encryption_key]

        for buf in buffers:
            if not buf:
                continue

            # Получение указателя на буфер
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)

            if lock:
                # шифрование памяти
                if not crypt32.CryptProtectMemory(ctypes.byref(ptr), len(buf), CRYPTPROTECTMEMORY_SAME_PROCESS):
                    # print("Debug: CryptProtectMemory failed")
                    pass
            else:
                # расшифровывка памяти перед удалением
                if not crypt32.CryptUnprotectMemory(ctypes.byref(ptr), len(buf), CRYPTPROTECTMEMORY_SAME_PROCESS):
                    # print("Debug: CryptUnprotectMemory failed")
                    pass

    def _protect_unix(self, lock: bool):
         # предотвращает  запись на диск области памяти.
        try:
            libc_name = ctypes.util.find_library("c")
            if not libc_name:
                return
            libc = ctypes.CDLL(libc_name)
        except Exception:
            return

        libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.mlock.restype = ctypes.c_int

        libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.munlock.restype = ctypes.c_int

        buffers = [self._auth_key, self._encryption_key]

        for buf in buffers:
            if not buf:
                continue

            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)

            if lock:
                libc.mlock(ctypes.byref(ptr), len(buf))
            else:
                libc.munlock(ctypes.byref(ptr), len(buf))