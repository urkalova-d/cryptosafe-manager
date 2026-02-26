import ctypes

class EncryptionService:
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        raise NotImplementedError

    @staticmethod
    def wipe_memory(variable):
        """Затирает данные в памяти (best effort для Python)"""
        if isinstance(variable, bytearray):
            for i in range(len(variable)):
                variable[i] = 0