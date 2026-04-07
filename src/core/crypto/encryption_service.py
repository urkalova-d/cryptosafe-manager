"""import base64
import traceback
from cryptography.fernet import Fernet, InvalidToken


class EncryptionService:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def _get_fernet(self):
        #Создание объекта шифрования на основе текущего ключа в памяти
        key = self.key_manager.get_encryption_key()

        if not key:
            raise ValueError("Ключ шифрования не найден в памяти. Сначала разблокируйте хранилище.")

        # Fernet требует 32 байта в формате base64
        return Fernet(base64.urlsafe_b64encode(key))

    def encrypt(self, data: str) -> str:
        #Шифрование строки
        if not data:
            return ""
        try:
            f = self._get_fernet()
            encrypted = f.encrypt(data.encode('utf-8'))
            return encrypted.decode('utf-8')
        except Exception as e:
            print(f"Ошибка шифрования: {e}")
            print(traceback.format_exc())
            raise ValueError(f"Не удалось зашифровать данные: {e}")

    def decrypt(self, encrypted_data: str) -> str:
        #асшифровка строки
        if not encrypted_data:
            return ""
        try:
            f = self._get_fernet()
            decrypted = f.decrypt(encrypted_data.encode('utf-8'))
            return decrypted.decode('utf-8')
        except InvalidToken as e:
            print(f"Ошибка расшифровки: Неверный токен/ключ")
            print(traceback.format_exc())
            return "[Ошибка: Неверный ключ шифрования]"
        except Exception as e:
            print(f"Ошибка расшифровки: {e}")
            print(traceback.format_exc())
            return f"[Ошибка расшифровки: {str(e)}]"
"""