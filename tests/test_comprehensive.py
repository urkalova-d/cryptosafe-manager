import pytest
import os
import sys
import threading
import time
import json
from concurrent.futures import ThreadPoolExecutor

# Настройка путей для импорта
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Импорты модулей проекта
from src.core.vault.encryption_service import EncryptionService
from src.core.vault.password_generator import PasswordGenerator
from src.core.crypto.key_derivation import KeyDerivationService
from src.database.db import DatabaseHelper
from src.core.vault.entry_manager import EntryManager
from src.core.crypto.key_manager import KeyManager


@pytest.fixture(scope="module")
def test_db():
    #Создает временную БД для тестов
    db_path = "test_vault.db"
    # удвление старого файла
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except PermissionError:
            pass

    db = DatabaseHelper(db_path=db_path)
    yield db

    # Очистка после тестов
    db.close()
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
    except Exception:
        pass


@pytest.fixture(scope="module")
def key_manager(test_db):
    #Создает KeyManager с тестовым паролем
    km = KeyManager(test_db)
    secure_test_password = "S0meR@nd0mStr0ngP@ss!2024"

    km.setup_new_user(secure_test_password)
    assert km.verify_and_unlock(secure_test_password)
    return km


@pytest.fixture(scope="module")
def encryption_service(key_manager):
    return EncryptionService(key_manager)


@pytest.fixture(scope="module")
def entry_manager(test_db, key_manager):
    return EntryManager(test_db, key_manager)


def test_encryption_round_trip(encryption_service):
    # Проверка цикла шифрования.

    known_data = {
        "service": "TestService",
        "username": "user1",
        "password": "MySecretPassword123!",
        "url": "http://example.com",
        "notes": "Some notes here"
    }

    # 1шиифрование
    encrypted_blob = encryption_service.encrypt_entry(known_data)

    # 2Проверка, что это не plaintext
    assert isinstance(encrypted_blob, bytes)
    assert b"MySecretPassword123!" not in encrypted_blob
    assert b"TestService" not in encrypted_blob
    assert len(encrypted_blob) > 50

    # 3расшифровка
    decrypted_data = encryption_service.decrypt_entry(encrypted_blob)

    # 4верификация целостности
    assert decrypted_data.get('title') == known_data['service']
    assert decrypted_data.get('username') == known_data['username']
    assert decrypted_data.get('password') == known_data['password']
    assert decrypted_data.get('url') == known_data['url']
    assert decrypted_data.get('notes') == known_data['notes']


def test_crud_integration(entry_manager):
    # CRUD тест
    
    initial_count = len(entry_manager.get_all_entries())
    created_ids = []

    # создание 100 записей
    for i in range(100):
        data = {
            'service': f'Service_{i}',
            'username': f'user_{i}',
            'password': f'pass_{i}',
            'category': 'Test'
        }
        entry_id = entry_manager.create_entry(data)
        assert entry_id is not None
        created_ids.append(entry_id)

    # Проверка количества
    current_entries = entry_manager.get_all_entries()
    assert len(current_entries) == initial_count + 100

    # 2. Update (первые 10 записей)
    for i, entry_id in enumerate(created_ids[:10]):
        update_data = {
            'service': f'Updated_Service_{i}',
            'username': 'updated_user',
            'password': 'new_pass',
            'category': 'Updated'
        }
        entry_manager.update_entry(entry_id, update_data)

    # проверка обновления
    check_entry = entry_manager.get_entry(created_ids[0])

    assert check_entry.get('title') == 'Updated_Service_0'
    assert check_entry.get('password') == 'new_pass'

    # удаление
    for entry_id in created_ids[-10:]:
        entry_manager.delete_entry(entry_id, soft_delete=True)

    #проверка колва после удаления
    final_entries = entry_manager.get_all_entries()
    assert len(final_entries) == initial_count + 90


def test_concurrency(entry_manager):
    # Тест конкурентности

    errors = []

    def worker_task(action, index):
        try:
            if action == 'create':
                data = {'service': f'Concurrent_{index}', 'password': 'pass'}
                entry_manager.create_entry(data)
            elif action == 'read':
                entry_manager.get_all_entries()
            elif action == 'update':
                entries = entry_manager.get_all_entries()
                if entries:
                    last_id = entries[-1]['id']
                    entry_manager.update_entry(last_id, {'service': 'ConcurrentUpd', 'password': 'p'})
        except Exception as e:
            errors.append(e)

    with ThreadPoolExecutor(max_workers=10) as executor:
        for i in range(20):
            executor.submit(worker_task, 'create', i)
        for i in range(20):
            executor.submit(worker_task, 'read', i)
        for i in range(20):
            executor.submit(worker_task, 'update', i)

    assert len(errors) == 0, f"Concurrency errors occurred: {errors}"


def test_password_generator():
    # Тест генератора паролей.

    passwords = set()
    count = 10000

    try:
        from zxcvbn import zxcvbn
        zxcvbn_available = True
    except ImportError:
        zxcvbn_available = False

    for _ in range(count):
        pwd, score = PasswordGenerator.generate_custom(
            length=16,
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_symbols=True,
            exclude_ambiguous=True
        )

        assert pwd not in passwords, "Duplicate password found!"
        passwords.add(pwd)

        assert len(pwd) == 16
        assert any(c.islower() for c in pwd), "Missing lowercase"
        assert any(c.isupper() for c in pwd), "Missing uppercase"
        assert any(c.isdigit() for c in pwd), "Missing digits"
        assert any(c in "!@#$%^&*" for c in pwd), "Missing symbols"

        if zxcvbn_available:
            assert score >= 3, f"Password too weak: {pwd}, score: {score}"

    print(f"\n[TEST-4] Generated {count} unique passwords successfully.")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])