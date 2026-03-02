# src/core/crypto/placeholder.py
from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    """Заглушка шифрования XOR (для Спринта 1)"""

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Реализация XOR шифрования"""
        key = key.ljust(len(data), b'\0')
        return bytes([a ^ b for a, b in zip(data, key)])

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """XOR дешифрование аналогично шифрованию"""
        return self.encrypt(ciphertext, key)