import pytest
import sqlite3
import os
import sys
from unittest.mock import MagicMock
import hashlib


# Моки для отсутствующих модулей криптографии

class MockKeyStorage:
    def __init__(self):
        self._enc_key = None

    def set_keys(self, auth_key, enc_key):
        self._enc_key = enc_key

    def get_enc_key(self):
        return self._enc_key


class MockKeyDerivationService:
    def derive_key(self, purpose, length):
        return b's' * length

    def verify_password(self, password, stored_hash):
        return password == "test_master_password"

    def create_auth_hash(self, password):
        return "hash_of_" + password

    def derive_encryption_key(self, password, salt):
        return b'e' * 32

    def derive_special_key(self, master_key, purpose):
        return hashlib.sha256(master_key + purpose.encode()).digest()


# установка модулей перед импортом
sys.modules['src.core.crypto.key_derivation'] = MagicMock()
sys.modules['src.core.crypto.key_storage'] = MagicMock()
sys.modules['src.core.crypto.key_derivation'].KeyDerivationService = MockKeyDerivationService
sys.modules['src.core.crypto.key_storage'].KeyStorage = MockKeyStorage

# Импорты проекта
from src.database.db import DatabaseHelper
from src.core.crypto.key_manager import KeyManager
from src.core.audit.audit_logger import AuditLogger
from src.core.audit.log_signer import AuditLogSigner
from src.core.audit.log_verifier import LogVerifier
from src.core.audit.log_exporter import LogExporter


@pytest.fixture(scope="function")
def db():
    #Создает временную БД для каждого теста
    db_path = "test_vault_temp.db"
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except PermissionError:
            pass

    db_helper = DatabaseHelper(db_path=db_path)
    yield db_helper

    db_helper.close()
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except:
            pass


@pytest.fixture
def key_manager(db):
    km = KeyManager(db)
    km.storage.set_keys(b"", b"master_encryption_key_32_bytes_long!!")
    return km


@pytest.fixture
def signer(key_manager):
    s = AuditLogSigner(key_manager)
    assert s.initialize(), "Signer failed to initialize"
    return s


@pytest.fixture
def audit_logger(db, signer):
    #Запускает логгер. При старте создается Genesis запись
    logger = AuditLogger(db, signer)
    logger.start()
    yield logger
    logger.stop()