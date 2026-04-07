import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class EncryptionService:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def _get_aes_key(self):
        """
        Получает сырой ключ из KeyManager.
        Примечание: KeyManager хранит ключ, полученный через PBKDF2.
        Для AES-GCM ключ должен быть 32 байтами (256 бит).
        """
        key = self.key_manager.get_encryption_key()
        if not key:
            raise PermissionError("Хранилище заблокировано. Ключ недоступен.")

        # Если ключ уже 32 байта, используем как есть.
        # Если ключ был получен через Fernet (urlsafe_b64decode), он может быть длиннее,
        # но в нашей текущей реализации KeyManager.derive_encryption_key возвращает ровно 32 байта.
        if len(key) == 32:
            return key
        else:
            # Если длина отличается (маловероятно при текущем KDF), деривируем через HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,  # Salt можно не использовать, так как ключ уже выведен из соленого пароля
                info=b'aes-gcm-key-derivation',
                backend=default_backend()
            )
            return hkdf.derive(key)

    def encrypt(self, plaintext: str) -> str:
        """
        Шифрует строку с использованием AES-256-GCM.
        Генерирует уникальный Nonce (IV) для каждого шифрования.
        Формат возвращаемой строки: base64(nonce || ciphertext)
        """
        if not plaintext:
            return ""

        key = self._get_aes_key()
        aesgcm = AESGCM(key)

        # Генерация случайного Nonce (12 байт - стандарт для GCM)
        nonce = os.urandom(12)

        # Шифрование (plaintext в байты)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

        # Объединяем nonce и ciphertext и кодируем в base64 для хранения в БД
        combined = nonce + ciphertext
        return base64.urlsafe_b64encode(combined).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        """
        Расшифровывает строку, зашифрованную методом encrypt.
        """
        if not encrypted_data:
            return ""

        try:
            key = self._get_aes_key()
            aesgcm = AESGCM(key)

            # Декодируем base64
            combined = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))

            # Извлекаем nonce (первые 12 байт) и ciphertext (остальное)
            nonce = combined[:12]
            ciphertext = combined[12:]

            # Расшифровка
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')

        except Exception as e:
            print(f"Ошибка расшифровки AES-GCM: {e}")
            return "[ОШИБКА ДЕКОДИРОВАНИЯ]"