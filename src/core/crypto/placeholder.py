# src/core/crypto/placeholder.py
from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    """Заглушка шифрования XOR (для Спринта 1)"""

    def encrypt(self, data: bytes,  key_manager) -> bytes:
        """Реализация XOR шифрования"""
        key = key_manager.get_encryption_key()
        if key is None:
            raise ValueError("Ключ шифрования недоступен: хранилище заблокировано")

        key = key.ljust(len(data), b'\0')
        return bytes([a ^ b for a, b in zip(data, key)])


def decrypt(self, ciphertext: bytes,  key_manager) -> bytes:
        """XOR дешифрование аналогично шифрованию"""
        return self.encrypt(ciphertext, key_manager)