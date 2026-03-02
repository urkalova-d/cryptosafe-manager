# src/core/crypto/abstract.py
from abc import ABC, abstractmethod


class EncryptionService(ABC):
    """Абстрактный класс для всех сервисов шифрования"""

    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Метод шифрования данных"""
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Метод дешифрования данных"""
        pass