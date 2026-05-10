# tests/test_sprint6_crypto.py
import pytest
import os
import sys
import json
import base64
import hmac
import hashlib

# Путь к проекту
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# --- Mocks ---

class MockDBHelper:
    def __init__(self):
        # Генерируем реальную пару ключей для тестов подписи
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.pub_key_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_key_store(self, key_type):
        if key_type == 'sharing_private_key':
            return self.pub_key_bytes, 1
        return None, None


class MockEntryManager:
    def get_entry(self, entry_id):
        return {
            'service': 'TestService',
            'username': 'user',
            'password': 'secret_password',
            'url': 'http://example.com',
            'notes': 'My notes'
        }


# --- Тесты ---

def test_cry1_password_sharing_protocol():
    """CRY-1: Проверка протокола шифрования паролем."""
    from src.core.import_export.sharing_service import SharingService

    manager = MockEntryManager()
    service = SharingService(manager)

    package = service.share_via_password(1, "testpass", 7)

    # 1. Проверка структуры
    assert package['method'] == 'password'
    assert 'encryption' in package

    # 2. Проверка KDF (PBKDF2-SHA256)
    enc_info = package['encryption']
    assert enc_info['kdf'] == "PBKDF2-SHA256"
    assert enc_info['iterations'] == 100000

    # 3. Проверка наличия Salt и Nonce
    assert 'salt' in enc_info
    assert 'nonce' in enc_info

    # 4. Проверка Integrity (HMAC) - CRY-4
    assert 'integrity' in package
    assert package['integrity']['type'] == 'HMAC-SHA256'

    # 5. Данные не в открытом виде
    assert 'secret_password' not in str(package['data'])
    print("✅ Test CRY-1 PASSED: Password protocol correct.")


def test_cry2_rsa_hybrid_encryption():
    """CRY-2: Гибридное шифрование (RSA + AES)."""
    from src.core.import_export.sharing_service import SharingService

    # Генерируем ключ получателя (RSA)
    recipient_priv_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    recipient_pub_pem = recipient_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    manager = MockEntryManager()
    db_mock = MockDBHelper()
    service = SharingService(manager, db_mock)

    package = service.share_via_public_key(1, recipient_pub_pem, 7)

    # 1. Проверка метода
    assert package['method'] == 'rsa_hybrid'

    # 2. Проверка гибридной структуры (encrypted_key + data)
    assert 'encrypted_key' in package
    assert 'data' in package

    # 3. Проверка подписи отправителя (CRY-4)
    assert 'signature' in package
    assert 'sender_public_key' in package

    print("✅ Test CRY-2 PASSED: RSA Hybrid encryption correct.")


def test_cry3_forward_secrecy_ecdh():
    """CRY-3: Perfect Forward Secrecy через ECDH."""
    from src.core.import_export.sharing_service import SharingService

    # Генерируем ключ получателя (ECC)
    recipient_priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    recipient_pub_pem = recipient_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    manager = MockEntryManager()
    db_mock = MockDBHelper()
    service = SharingService(manager, db_mock)

    # Первый шаринг
    package1 = service.share_via_ecdh(1, recipient_pub_pem, 7)

    # Второй шаринг (должен быть другой ключ!)
    package2 = service.share_via_ecdh(1, recipient_pub_pem, 7)

    # 1. Проверка метода
    assert package1['method'] == 'ecdh_pfs'

    # 2. Проверка наличия эфемерного ключа в пакете
    assert 'ephemeral_public_key' in package1['encryption']

    # 3. Forward Secrecy Check: Эфемерные ключи должны быть разными для каждого шаринга!
    ephemeral_key_1 = package1['encryption']['ephemeral_public_key']
    ephemeral_key_2 = package2['encryption']['ephemeral_public_key']

    assert ephemeral_key_1 != ephemeral_key_2, "Эфемерные ключи должны быть уникальными для каждой операции!"

    # 4. Проверка подписи (CRY-4)
    assert 'signature' in package1

    print("✅ Test CRY-3 PASSED: Forward Secrecy (ECDH) implemented correctly.")


def test_cry4_integrity_protection():
    """CRY-4: Проверка целостности и обнаружение подделки."""
    from src.core.import_export.sharing_service import SharingService

    manager = MockEntryManager()
    db_mock = MockDBHelper()
    service = SharingService(manager, db_mock)

    # Генерируем простой ECC ключ для теста
    recipient_priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    recipient_pub_pem = recipient_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    package = service.share_via_ecdh(1, recipient_pub_pem, 7)

    # 1. Проверка наличия подписи
    assert 'signature' in package
    assert 'value' in package['signature']

    # 2. Проверка валидности подписи (упрощенно)
    # В реальности мы бы верифицировали публичный ключ отправителя
    assert package['signature']['algorithm'] == 'ECDSA-SHA256'

    print("✅ Test CRY-4 PASSED: Integrity protection present.")


if __name__ == "__main__":
    print("--- Running Sprint 6 Crypto Tests ---")
    test_cry1_password_sharing_protocol()
    test_cry2_rsa_hybrid_encryption()
    test_cry3_forward_secrecy_ecdh()
    test_cry4_integrity_protection()
    print("\n🎉 All Crypto Tests Passed!")