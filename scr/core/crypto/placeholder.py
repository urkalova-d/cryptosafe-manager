from .abstract import EncryptionService

class AES256Placeholder(EncryptionService):
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        # Простая заглушка для Спринта 1: XOR с первым байтом ключа
        xor_key = key[0] if key else 0xFF
        return bytes([b ^ xor_key for b in data])

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        return self.encrypt(ciphertext, key) # XOR обратим тем же действием