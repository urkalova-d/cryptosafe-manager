# src/core/key_manager.py
import os
import secrets
from dotenv import load_dotenv
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Загружаем переменные из .env файла (СЕК-1)
load_dotenv()


class KeyManager:
    def __init__(self):
        self.backend = default_backend()
        self.salt = None
        # Получаем соль из окружения или генерируем новую, если ее нет
        salt_str = os.getenv("MASTER_KEY_SALT")
        if salt_str:
            self.salt = salt_str.encode()
        else:
            self.salt = secrets.token_bytes(16)
            # В реальном проекте здесь стоило бы сохранить новую соль в .env

    def derive_key(self, password: str, salt: bytes = None) -> bytes:
        """
        Преобразует мастер-пароль в криптографический ключ (PBKDF2) (КРИК-3).
        Используется 100 000 итераций для защиты от перебора.
        """
        if salt is None:
            salt = self.salt
        else:
            self.salt = salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Длина ключа для AES-256
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def store_key(self):
        """Заглушка для сохранения ключа (заполнитель для Спринта 2)"""
        pass

    def load_key(self):
        """Заглушка для загрузки ключа (заполнитель для Спринта 2)"""
        pass