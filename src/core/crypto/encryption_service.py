
import base64
from cryptography.fernet import Fernet


class EncryptionService:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def _get_fernet(self):
        #создание объекта шифрования на основе текущего ключа в памяти
        derived_key = self.key_manager.storage.get_key()

        if not derived_key:
            # если пользователь не вошел шифрование невозможно
            return None

        # Fernet требует 32 байта в формате base64
        fernet_key = base64.urlsafe_b64encode(derived_key)
        return Fernet(fernet_key)

    def encrypt(self, data: str) -> str:
        #шифрование текста"
        if not data: return ""
        f = self._get_fernet()
        if not f: return data  # если  нет ключа возвращает как есть или ошибку

        return f.encrypt(data.encode()).decode()

    def decrypt(self, encrypted_data: str) -> str:
        #расшифровка текста
        if not encrypted_data: return ""
        try:
            f = self._get_fernet()
            if not f: return "[Сейф заблокирован]"
            return f.decrypt(encrypted_data.encode()).decode()
        except Exception:
            return "[Ошибка расшифровки]"