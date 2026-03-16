import os
from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import argon2
import secrets
from argon2.low_level import hash_secret_raw


class KeyDerivationService:
    def __init__(self, config=None):
        # настройка параметров
        if config is None:
            config = {}

        self.argon2_hasher = PasswordHasher(
            time_cost=config.get('argon2_time', 3),
            memory_cost=config.get('argon2_memory', 65536),  # 64 MiB
            parallelism=config.get('argon2_parallelism', 4),
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )
        self.pbkdf2_iterations = config.get('pbkdf2_iterations', 100000)

    def create_auth_hash(self, password: str) -> str:
        # создание argon2 хеша для проверки пароля
        return self.argon2_hasher.hash(password)

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        #Вывод ключа AES 256 из пароля через PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def verify_password(self, password: str, stored_hash: str) -> bool:
        #проверка пароля по хешу argon2
        try:
            return self.argon2_hasher.verify(stored_hash, password)
        except Exception:
            secrets.compare_digest(b"dummy_value_for_timing_attack", b"dummy_value_for_timing_attack")
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

        # проверка спецсимволов
        if not re.search(r"[^a-zA-Z0-9]", password):
            return False, "Добавьте спецсимволы (например: ! @ # $ % ^ & *)"

        common_patterns = ["password", "qwerty", "123456", "admin"]
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Пароль слишком простой."

        return True, "Пароль надежен."