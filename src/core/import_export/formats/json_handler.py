
import json
import base64
import os
import gzip
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag


class JsonFormatHandler:
    """Обработчик родного формата CryptoSafe (Encrypted JSON)."""

    def __init__(self):
        self.extension = ".csjson"

    def export_data(self, entries: list, password: str, options: dict) -> bytes:
        """Экспорт (из предыдущего шага)."""
        export_payload = {
            "version": "1.0",
            "app": "CryptoSafe",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "count": len(entries),
            "entries": entries
        }

        json_str = json.dumps(export_payload, ensure_ascii=False)
        plaintext = json_str.encode('utf-8')

        # Сжатие
        use_compression = options.get('compression', False)
        if use_compression:
            plaintext = gzip.compress(plaintext)

        encrypted_package = self._encrypt_payload(plaintext, password)

        # Integrity Hash
        integrity_hash = hashlib.sha256(json_str.encode('utf-8')).hexdigest()
        encrypted_package['integrity'] = {
            "hash": integrity_hash,
            "algorithm": "SHA256"
        }

        return json.dumps(encrypted_package).encode('utf-8')

    def _encrypt_payload(self, plaintext: bytes, password: str) -> dict:
        salt = os.urandom(16)
        nonce = os.urandom(12)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode('utf-8'))

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

    def import_data(self, file_path: str, password: str) -> list:
        """Импорт (новый функционал)."""
        if not password:
            raise ValueError("Для импорта .csjson файлов требуется пароль.")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                package = json.load(f)
            if package.get('type') == 'cryptosafe_share':
                return self._import_shared_package(package, password)

            if not all(k in package for k in ['encryption', 'data']):
                raise ValueError("Invalid CryptoSafe file structure.")

            enc_info = package['encryption']
            salt = base64.b64decode(enc_info['salt'])
            nonce = base64.b64decode(enc_info['nonce'])
            ciphertext = base64.b64decode(package['data'])

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=enc_info.get('iterations', 100000),
            )
            key = kdf.derive(password.encode('utf-8'))

            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            # Распаковка (проверяем магические байты GZIP)
            if plaintext[:2] == b'\x1f\x8b':
                plaintext = gzip.decompress(plaintext)

            data = json.loads(plaintext.decode('utf-8'))
            return data.get('entries', [])

        except InvalidTag:
            raise ValueError("Неверный пароль или файл поврежден.")
        except Exception as e:
            raise ValueError(f"Ошибка чтения JSON: {e}")

    def _import_shared_package(self, package: dict, password: str) -> list:
        """SHR-4: Расшифровка записи из режима Sharing."""
        try:
            method = package['method']
            enc_info = package['encryption']

            if method == 'password':
                # Логика аналогична обычному экспорту
                salt = base64.b64decode(enc_info['salt'])
                nonce = base64.b64decode(enc_info['nonce'])
                ciphertext = base64.b64decode(package['data'])

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=enc_info.get('iterations', 100000),
                )
                key = kdf.derive(password.encode('utf-8'))

                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)

                entry_data = json.loads(plaintext.decode('utf-8'))
                return [entry_data]  # Возвращаем список из одной записи

            elif method == 'rsa_public_key':
                # Для RSA требуется приватный ключ, это сложнее реализовать в GUI сразу
                # Обычно это делается через отдельный диалог
                raise ValueError("Импорт RSA-зашифрованных записей требует приватного ключа.")

        except Exception as e:
            raise ValueError(f"Ошибка расшифровки Shared Entry: {e}")