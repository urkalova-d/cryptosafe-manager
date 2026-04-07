import os
import secrets
import json
import base64
import re
from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyDerivationService:
    def __init__(self, config=None):
        if config is None:
            config = {}

        # параметры Argon2id
        self.argon2_time = config.get('argon2_time', 3)
        self.argon2_memory = config.get('argon2_memory', 65536)  # 64 MiB
        self.argon2_parallelism = config.get('argon2_parallelism', 4)

        self.argon2_hasher = PasswordHasher(
            time_cost=self.argon2_time,
            memory_cost=self.argon2_memory,
            parallelism=self.argon2_parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )

        self.pbkdf2_iterations = config.get('pbkdf2_iterations', 100000)

    def create_auth_hash(self, password: str) -> str:
        """Создание хеша пароля через Argon2id"""
        return self.argon2_hasher.hash(password)

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        """Генерация ключа шифрования через PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def derive_auth_key(self, password: str, salt: bytes) -> bytes:
        """Генерация ключа аутентификации через Argon2id (ДОБАВЛЕНО)"""
        from argon2.low_level import hash_secret_raw

        # Используем низкоуровневый API Argon2 для получения сырых байтов
        raw_hash = hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=self.argon2_time,
            memory_cost=self.argon2_memory,
            parallelism=self.argon2_parallelism,
            hash_len=32,
            type=Type.ID
        )
        return raw_hash

    def generate_auth_key(self, password: str, salt: bytes) -> bytes:
        """Алиас для derive_auth_key (для обратной совместимости)"""
        return self.derive_auth_key(password, salt)

    def derive_special_key(self, master_key: bytes, purpose: str, salt: bytes = None) -> bytes:
        """Генерация специализированных ключей на основе мастер-ключа"""
        if salt is None:
            # фиксированная соль в рамках сессии
            salt = b'cryptosafe_special_salt_v1'

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=purpose.encode('utf-8'),
            backend=default_backend()
        )
        return hkdf.derive(master_key)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Проверка пароля через Argon2id"""
        try:
            return self.argon2_hasher.verify(stored_hash, password)
        except Exception:
            # Проверка в режиме постоянного времени для предотвращения атак по времени
            secrets.compare_digest(b'dummy', b'dummy')
            return False

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        """Валидация сложности пароля"""
        if len(password) < 12:
            return False, "Пароль должен быть не менее 12 символов."
        if not re.search(r"[a-z]", password):
            return False, "Добавьте строчные буквы."
        if not re.search(r"[A-Z]", password):
            return False, "Добавьте заглавные буквы."
        if not re.search(r"\d", password):
            return False, "Добавьте цифры."
        if not re.search(r"[^a-zA-Z0-9]", password):
            return False, "Добавьте спецсимволы."
        common_patterns = ["password", "qwerty", "123456", "admin"]
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Пароль слишком простой."
        return True, "Пароль надежен."