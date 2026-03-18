import os
import secrets
import base64
from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class KeyDerivationService:
    def __init__(self, config=None):
        if config is None:
            config = {}

        self.argon2_hasher = PasswordHasher(
            time_cost=config.get('argon2_time', 3),
            memory_cost=config.get('argon2_memory', 65536),
            parallelism=config.get('argon2_parallelism', 4),
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )
        self.pbkdf2_iterations = config.get('pbkdf2_iterations', 100000)

    def create_auth_hash(self, password: str) -> str:#argon2
        # Возвращаем строку хеша
        return self.argon2_hasher.hash(password)

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:#PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def generate_auth_key(self, password: str, salt: bytes) -> bytes:
        #Генерация ключа аутентификации через Argon2.
        # пароль+соль
        combined_secret = password + salt.hex()
        dummy_hash = self.argon2_hasher.hash(combined_secret)

        # Извлекаем байты хеша
        parts = dummy_hash.split('$')
        key_b64 = parts[-1]

        # Декодируем Base64
        padding = len(key_b64) % 4
        if padding:
            key_b64 += '=' * (4 - padding)

        return base64.urlsafe_b64decode(key_b64)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        try:
            return self.argon2_hasher.verify(stored_hash, password)
        except Exception:
            # Constant-time dummy verification to prevent timing attacks
            secrets.compare_digest(b'dummy', b'dummy')
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
            return False, "Добавьте спецсимволы."
        common_patterns = ["password", "qwerty", "123456", "admin"]
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Пароль слишком простой."
        return True, "Пароль надежен."