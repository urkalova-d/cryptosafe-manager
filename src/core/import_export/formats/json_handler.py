# src/core/import_export/formats/json_handler.py
import json
import base64
import os
import gzip
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class JsonFormatHandler:
    """
    Обработчик родного формата CryptoSafe (Encrypted JSON).
    EXP-1, EXP-2.
    """

    def __init__(self):
        self.extension = ".csjson"

    def export_data(self, entries: list, password: str, options: dict) -> bytes:
        """
        Формирует и шифрует JSON пакет.
        """
        # 1. Подготовка payload
        export_payload = {
            "version": "1.0",
            "app": "CryptoSafe",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "count": len(entries),
            "entries": entries
        }

        # 2. Опции
        use_compression = options.get('compression', False)

        # 3. Сериализация
        json_str = json.dumps(export_payload, ensure_ascii=False)
        plaintext = json_str.encode('utf-8')

        # 4. Сжатие (EXP-3)
        if use_compression:
            plaintext = gzip.compress(plaintext)

        # 5. Шифрование (EXP-2)
        encrypted_package = self._encrypt_payload(plaintext, password)

        # 6. Integrity Hash (EXP-2)
        # Хеш считается по исходным данным (для проверки при импорте)
        integrity_hash = hashlib.sha256(json_str.encode('utf-8')).hexdigest()
        encrypted_package['integrity'] = {
            "hash": integrity_hash,
            "algorithm": "SHA256"
        }

        # Возвращаем байты для записи в файл
        return json.dumps(encrypted_package).encode('utf-8')

    def _encrypt_payload(self, plaintext: bytes, password: str) -> dict:
        salt = os.urandom(16)
        nonce = os.urandom(12)

        # Key Derivation (PBKDF2)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode('utf-8'))

        # AES-256-GCM
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return {
            "encryption": {
                "algorithm": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256",
                "iterations": 100000,
                "salt": base64.b64encode(salt).decode('ascii'),
                "nonce": base64.b64encode(nonce).decode('ascii')
            },
            "data": base64.b64encode(ciphertext).decode('ascii')
        }