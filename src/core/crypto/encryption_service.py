
import base64
from cryptography.fernet import Fernet


class EncryptionService:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def _get_fernet(self):
        #создание объекта шифрования на основе текущего ключа в памяти
        key = self.key_manager.get_encryption_key()

        if not key:
            raise ValueError("Ключ шифрования не найден в памяти. Сначала разблокируйте хранилище.")

        # Fernet требует 32 байта в формате base64
        return Fernet(base64.urlsafe_b64encode(key))

    def encrypt(self, data: str) -> str:
        #шифрование текста
        if not data: return ""
        f = self._get_fernet()
        if not f: return data  # если  нет ключа возвращает как есть или ошибку

        return f.encrypt(data.encode('utf-8')).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        #расшифровка текста
        if not data:
            return ""
        f = self._get_fernet()
        return f.decrypt(data.encode('utf-8')).decode('utf-8')