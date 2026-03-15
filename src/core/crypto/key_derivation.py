import os
from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class KeyDerivationService:
    @staticmethod
    def derive_key_argon2(password: str, salt: bytes, length: int = 32) -> bytes:
        #генерация ключа с argon2
        ph = PasswordHasher(
            time_cost=3,      # Количество итераций
            memory_cost=65536, # Использование ОЗУ (64 МБ)
            parallelism=4,     # Количество потоков
            hash_len=length,
            type=Type.ID
        )

        from argon2.low_level import hash_secret_raw
        return hash_secret_raw(
            password.encode(),
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=length,
            type=Type.ID
        )

    @staticmethod
    def derive_key_pbkdf2(password: str, salt: bytes, length: int = 32) -> bytes:
        #генерация ключа PBKDF2 (резервный вариант)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())