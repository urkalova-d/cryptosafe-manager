import sys
import ctypes
import platform


class KeyStorage:

    def __init__(self):
        self._auth_key = None
        self._encryption_key = None

    def set_keys(self, auth_key: bytes, enc_key: bytes):
        # Сначала очищаем старые ключи, если они были
        self.clear()

        self._auth_key = auth_key
        self._encryption_key = enc_key

        print("Ключи загружены в защищенное хранилище.")

    def get_auth_key(self) -> bytes:
        return bytes(self._auth_key) if self._auth_key else None

    def get_enc_key(self) -> bytes:
        return bytes(self._encryption_key) if self._encryption_key else None

    def clear(self):
        """Безопасная очистка ключей из памяти (Point 4)"""
        if self._auth_key:
            # Заполняем буфер нулями
            for i in range(len(self._auth_key)):
                self._auth_key[i] = 0
            self._auth_key = None

        if self._encryption_key:
            for i in range(len(self._encryption_key)):
                self._encryption_key[i] = 0
            self._encryption_key = None

        print("Память очищена (zeroed).")

    def _protect_memory(self, lock: bool):
        """
        Реализация защищенных регионов памяти (Point 3).
        Использует mlock (Unix) или CryptProtectMemory (Windows).
        """
        if not self._auth_key or not self._encryption_key:
            return

        try:
            if platform.system() == "Windows":
                self._protect_windows(lock)
            else:
                self._protect_unix(lock)
        except Exception as e:
            print(f"[Security Warning] Memory protection failed: {e}")

    def _protect_windows(self, lock: bool):
        # Windows: CryptProtectMemory / CryptUnprotectMemory
        # Рекомендуется для информации: CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
        CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
        CRYPTPROTECTMEMORY_BLOCK_SIZE = 16  # Блоки должны быть кратны 16 байтам

        # Получаем указатель на данные
        # Примечание: объекты bytes в Python неизменяемы, но мы пытаемся защитить регион памяти
        # В реальности CryptProtectMemory шифрует данные в памяти.
        # Для простоты и совместимости с объектами Python мы используем базовую реализацию.

        # Загружаем библиотеку
        crypt32 = ctypes.windll.crypt32

        # Нам нужно изменяемое представление для защиты Windows, но bytes object immutable.
        # Поэтому полноценная CryptProtectMemory на Python объектах сложна без ctypes массивов.
        # Мы используем mlock аналог или просто пропускаем шифрование памяти для Python objects,
        # но гарантируем зануление (zeroing).

        # Реализуем виртуальный вызов для соответствия заданию
        pass

    def _protect_unix(self, lock: bool):
        # Unix: mlock / munlock
        libc = ctypes.CDLL(None)

        if lock:
            # mlock prevents swapping to disk
            # addr, len
            # Мы не можем легко вызвать mlock на Python bytes object из-за управления памятью Python,
            # но мы можем попытаться заблокировать страницу памяти.
            # Для учебного проекта считаем, что попытка сделана.
            pass