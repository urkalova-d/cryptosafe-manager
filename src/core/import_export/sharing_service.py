import os
import json
import base64
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class SharingService:
    """
    SHR-1: Методы шаринга (Пароль, RSA).
    SHR-2: Формат пакета.
    """

    def __init__(self, entry_manager, db_helper=None):
        self.entry_manager = entry_manager
        self.db = db_helper

    def share_via_password(self, entry_id: int, password: str, expiration_days: int) -> dict:
        """SHR-1: Шаринг через пароль (AES-256-GCM)."""
        entry = self.entry_manager.get_entry(entry_id)
        if not entry:
            raise ValueError("Entry not found")

        # Удаляем системные поля перед отправкой
        clean_entry = self._clean_entry_for_sharing(entry)

        # Генерация ключа
        salt = os.urandom(16)
        nonce = os.urandom(12)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))

        # Шифрование
        aesgcm = AESGCM(key)
        plaintext = json.dumps(clean_entry).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Формирование пакета
        package = {
            "version": "1.0",
            "type": "cryptosafe_share",
            "method": "password",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=expiration_days)).isoformat(),
            "encryption": {
                "algorithm": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256",
                "iterations": 100000,
                "salt": base64.b64encode(salt).decode('ascii'),
                "nonce": base64.b64encode(nonce).decode('ascii')
            },
            "data": base64.b64encode(ciphertext).decode('ascii')
        }

        return package

    def share_via_public_key(self, entry_id: int, public_key_pem: str, expiration_days: int) -> dict:
        """SHR-1: Шаринг через публичный ключ (Hybrid RSA + AES)."""
        entry = self.entry_manager.get_entry(entry_id)
        if not entry:
            raise ValueError("Entry not found")

        clean_entry = self._clean_entry_for_sharing(entry)

        # 1. Генерируем сессионный ключ AES
        session_key = os.urandom(32)
        nonce = os.urandom(12)

        # 2. Шифруем данные сессионным ключом
        aesgcm = AESGCM(session_key)
        plaintext = json.dumps(clean_entry).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # 3. Шифруем сессионный ключ публичным ключом получателя
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )

            # Проверка типа ключа (ожидаем RSA)
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("Нужен RSA публичный ключ.")

            encrypted_session_key = public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise ValueError(f"Ошибка обработки публичного ключа: {e}")

        package = {
            "version": "1.0",
            "type": "cryptosafe_share",
            "method": "rsa_public_key",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=expiration_days)).isoformat(),
            "encryption": {
                "algorithm": "RSA-OAEP-AES-256-GCM",
                "nonce": base64.b64encode(nonce).decode('ascii')
            },
            "encrypted_key": base64.b64encode(encrypted_session_key).decode('ascii'),
            "data": base64.b64encode(ciphertext).decode('ascii')
        }

        return package

    def _clean_entry_for_sharing(self, entry: dict) -> dict:
        """SHR-2: Очистка записи от лишних полей."""
        return {
            "service": entry.get('service', ''),
            "username": entry.get('username', ''),
            "password": entry.get('password', ''),
            "url": entry.get('url', ''),
            "notes": entry.get('notes', ''),
            "category": entry.get('category', 'Shared')
        }