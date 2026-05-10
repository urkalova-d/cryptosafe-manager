import os
import json
import base64
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature



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

        hmac_obj = hmac.new(key, nonce + ciphertext, hashlib.sha256)
        hmac_digest = hmac_obj.hexdigest()
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
            "integrity": {
                "type": "HMAC-SHA256",
                "hash": hmac_digest},
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
            recipient_pub_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )

            # Поддержка RSA (для совместимости)
            if isinstance(recipient_pub_key, rsa.RSAPublicKey):
                encrypted_session_key = recipient_pub_key.encrypt(
                    session_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                key_enc_algo = "RSA-OAEP"
            else:
                raise ValueError("Тип ключа не поддерживается для этого метода. Используйте ECDH для ECC ключей.")
        except Exception as e:
            raise ValueError(f"Ошибка обработки публичного ключа: {e}")

            # Формирование пакета
        package = {
            "version": "1.0",
            "type": "cryptosafe_share",
            "method": "rsa_hybrid",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=expiration_days)).isoformat(),
            "encryption": {
                "algorithm": "RSA-OAEP-AES-256-GCM",
                "nonce": base64.b64encode(nonce).decode('ascii')
            },
            "encrypted_key": base64.b64encode(encrypted_session_key).decode('ascii'),
            "data": base64.b64encode(ciphertext).decode('ascii')
        }

        # CRY-4: Подпись отправителя
        return self._sign_package(package)

    def share_via_ecdh(self, entry_id: int, recipient_pub_key_pem: str, expiration_days: int) -> dict:
        """
        CRY-3: Perfect Forward Secrecy (PFS) через ECDH.
        Генерирует эфемерную пару ключей для каждого шаринга.
        """
        entry = self.entry_manager.get_entry(entry_id)
        if not entry:
            raise ValueError("Entry not found")
        clean_entry = self._clean_entry_for_sharing(entry)

        # 1. Загружаем публичный ключ получателя (ожидаем ECC)
        try:
            recipient_pub_key = serialization.load_pem_public_key(
                recipient_pub_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            if not isinstance(recipient_pub_key, ec.EllipticCurvePublicKey):
                raise ValueError("Для ECDH нужен ECC публичный ключ.")
        except Exception as e:
            raise ValueError(f"Неверный ECC ключ получателя: {e}")

        # 2. Генерируем эфемерную пару ключей отправителя (CRY-3)
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()

        # 3. Выполняем Key Exchange (ECDH)
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_pub_key)

        # 4. Выводим симметричный ключ из секрета через HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'cryptosafe sharing session',
            backend=default_backend()
        ).derive(shared_secret)

        # 5. Шифруем данные
        nonce = os.urandom(12)
        aesgcm = AESGCM(derived_key)
        plaintext = json.dumps(clean_entry).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # 6. Сериализуем эфемерный публичный ключ для включения в пакет
        ephemeral_pub_pem = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        package = {
            "version": "1.0",
            "type": "cryptosafe_share",
            "method": "ecdh_pfs",  # Perfect Forward Secrecy
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=expiration_days)).isoformat(),
            "encryption": {
                "algorithm": "ECDH-ES-AES-256-GCM",
                "nonce": base64.b64encode(nonce).decode('ascii'),
                "ephemeral_public_key": ephemeral_pub_pem
            },
            "data": base64.b64encode(ciphertext).decode('ascii')
        }

        # CRY-4: Подпись
        return self._sign_package(package)

    def _sign_package(self, package: dict) -> dict:
        """
        CRY-4: Подписывает пакет приватным ключом отправителя.
        Добавляет sender_public_key в пакет.
        """
        if not self.db:
            return package  # Невозможно подписать без доступа к БД

        try:
            # Загружаем приватный ключ отправителя
            priv_key_bytes, _ = self.db.get_key_store('sharing_private_key')
            if not priv_key_bytes:
                return package  # Ключ не сгенерирован

            private_key = serialization.load_pem_private_key(
                priv_key_bytes, password=None, backend=default_backend()
            )

            # Добавляем публичный ключ отправителя (CRY-2)
            sender_pub_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            package['sender_public_key'] = sender_pub_pem

            # Вычисляем хеш данных для подписи
            data_to_sign = json.dumps(package, sort_keys=True).encode('utf-8')

            # Подписываем (ECDSA или PSS)
            if isinstance(private_key, ec.EllipticCurvePrivateKey):
                signature = private_key.sign(
                    data_to_sign,
                    ec.ECDSA(hashes.SHA256())
                )
                sig_algo = "ECDSA-SHA256"
            elif isinstance(private_key, rsa.RSAPrivateKey):
                signature = private_key.sign(
                    data_to_sign,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                sig_algo = "RSA-PSS-SHA256"
            else:
                return package

            package['signature'] = {
                "algorithm": sig_algo,
                "value": base64.b64encode(signature).decode('ascii')
            }

            return package

        except Exception as e:
            print(f"[SharingService] Warning: Signing failed: {e}")
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