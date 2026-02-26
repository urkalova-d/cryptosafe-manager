import base64
from .abstract import EncryptionService

class AES256Placeholder(EncryptionService):
    """Временная реализация XOR для Спринта 1"""
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        # Простой XOR для теста
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        return self.encrypt(ciphertext, key) # XOR обратим тем же действием