import os
import json
import secrets
from argon2 import PasswordHasher, Type
# Импортируем низкоуровневые функции Argon2 для генерации ключей
from argon2.low_level import hash_secret_raw, Type as LowLevelType

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class KeyDerivationService:
    def __init__(self, config=None):
        if config is None:
            config = {}

        # Параметры Argon2
        self.time_cost = config.get('argon2_time', 3)
        self.memory_cost = config.get('argon2_memory', 65536)  # 64 MiB
        self.parallelism = config.get('argon2_parallelism', 4)

        # Хешер для хранения пароля (проверка входа)
        self.argon2_hasher = PasswordHasher(
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )

        # Параметры PBKDF2
        self.pbkdf2_iterations = config.get('pbkdf2_iterations', 100000)

    def create_auth_hash(self, password: str) -> str:
        """Создание хеша для хранения в БД (для проверки входа)"""
        return self.argon2_hasher.hash(password)

    def generate_encryption_key(self, password: str, salt: bytes) -> bytes:
        """
        Генерация Ключа Шифрования через PBKDF2-HMAC-SHA256.
        Используется для шифрования данных.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def generate_auth_key(self, password: str, salt: bytes) -> bytes:
        """
        Генерация Ключа Аутентификации через Argon2id (RAW mode).
        Используется для производных целей.
        """
        return hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=32,
            type=LowLevelType.ID
        )

    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Проверка пароля по хешу argon2"""
        try:
            self.argon2_hasher.verify(stored_hash, password)
            return True
        except Exception:
            # Защита от timing attack
            secrets.compare_digest(b"dummy", b"value")
            return False

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        import re
        if len(password) < 12:
            return False, "Пароль должен быть не менее 12 символов."
        if not re.search(r"[a-z]", password):
            return False, "Добавьте строчные буквы."
        if not re.search(r"[A-Z]", password):
            return False, "Добавьте заглавные буквы."
        if not re.search(r"\d", password):
            return False, "Добавьте цифры."
        if not re.search(r"[^a-zA-Z0-9]", password):
            return False, "Добавьте спецсимволы (например: ! @ # $ % ^ & *)"
        common_patterns = ["password", "qwerty", "123456", "admin"]
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Пароль слишком простой."
        return True, "Пароль надежен."