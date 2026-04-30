import pytest
import os
import sys
import threading
import time
import hashlib
import string
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

# для импортов
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.vault.encryption_service import EncryptionService
from src.core.vault.entry_manager import EntryManager
from src.core.vault.password_generator import PasswordGenerator


# ==================== ПРАВИЛЬНЫЕ МОКИ ====================

class MockKeyManager:
    """Имитация KeyManager для тестов"""

    def __init__(self):
        self.test_key = b'testkey_32bytes_for_validation_!!'  # 32 байта
        self._encryption_key = self.test_key
        self._is_locked = False

    def get_encryption_key(self):
        return self._encryption_key if not self._is_locked else None

    def get_auth_key(self):
        return self.test_key

    def lock(self):
        self._is_locked = True

    def unlock(self, password):
        self._is_locked = False
        return True


class MockDbHelper:
    """Правильная имитация БД"""

    def __init__(self):
        self.entries = {}  # id -> record
        self.deleted_entries = {}
        self.history = set()
        self._lock = threading.RLock()
        self._id_counter = 1

    def add_entry(self, encrypted_data, tags=""):
        with self._lock:
            entry_id = self._id_counter
            self.entries[entry_id] = {
                'id': entry_id,
                'encrypted_data': encrypted_data,
                'tags': tags,
                'created_at': '2024-01-01 10:00:00',
                'updated_at': '2024-01-01 10:00:00'
            }
            self._id_counter += 1
            return entry_id

    def get_entry(self, entry_id):
        with self._lock:
            entry = self.entries.get(entry_id)
            if entry:
                return {
                    'id': entry['id'],
                    'encrypted_data': entry['encrypted_data'],
                    'tags': entry['tags'],
                    'created_at': entry['created_at'],
                    'updated_at': entry['updated_at']
                }
            return None

    def get_all_entries(self):
        with self._lock:
            return [
                {
                    'id': e['id'],
                    'encrypted_data': e['encrypted_data'],
                    'tags': e['tags'],
                    'created_at': e['created_at'],
                    'updated_at': e['updated_at']
                }
                for e in self.entries.values()
            ]

    def update_entry(self, entry_id, encrypted_data, tags=None):
        with self._lock:
            if entry_id in self.entries:
                self.entries[entry_id]['encrypted_data'] = encrypted_data
                if tags is not None:
                    self.entries[entry_id]['tags'] = tags
                self.entries[entry_id]['updated_at'] = '2024-01-02 10:00:00'
                return True
            return False

    def soft_delete_entry(self, entry_id, expiration_days=30):
        with self._lock:
            if entry_id in self.entries:
                self.deleted_entries[entry_id] = self.entries[entry_id].copy()
                del self.entries[entry_id]
                return True
            return False

    def hard_delete_entry(self, entry_id):
        with self._lock:
            if entry_id in self.deleted_entries:
                del self.deleted_entries[entry_id]
                return True
            return False

    def add_password_to_history(self, password_hash):
        with self._lock:
            self.history.add(password_hash)
            if len(self.history) > 20:
                self.history = set(list(self.history)[-20:])

    def is_password_in_history(self, password_hash):
        return password_hash in self.history

    def save_setting(self, key, value):
        pass

    def get_setting(self, key):
        return None

    def save_key_store(self, key_type, key_data, version=1):
        pass

    def get_key_store(self, key_type):
        return None, None

    def rotate_vault_keys(self, new_master_hash, new_auth_salt, new_enc_salt, re_encrypted_data):
        pass

    def clear(self):
        with self._lock:
            self.entries.clear()
            self.deleted_entries.clear()
            self.history.clear()
            self._id_counter = 1

    def get_count(self):
        return len(self.entries)


# ==================== FIXTURES ====================

@pytest.fixture
def key_manager():
    return MockKeyManager()


@pytest.fixture
def encryption_service(key_manager):
    return EncryptionService(key_manager)


@pytest.fixture
def db_helper():
    return MockDbHelper()


@pytest.fixture
def entry_manager(db_helper, key_manager):
    """Создает EntryManager с моками"""
    manager = EntryManager(db_helper, key_manager)
    db_helper.clear()
    yield manager
    db_helper.clear()


# ==================== ТЕСТ 1: ШИФРОВАНИЕ ====================

def test_encryption_round_trip(encryption_service):
    """TEST-1: Encryption Round-Trip Test"""
    known_data = {
        'service': 'TestService',
        'username': 'user123',
        'password': 'SuperSecretPassword!',
        'url': 'https://test.com',
        'notes': 'Some notes here',
        'category': 'Test'
    }

    encrypted_blob = encryption_service.encrypt_entry(known_data)

    assert isinstance(encrypted_blob, bytes), "Encrypted data must be bytes"
    assert len(encrypted_blob) > 12, "Blob too short (must contain nonce + tag)"
    assert b'SuperSecretPassword!' not in encrypted_blob, "Password found in plaintext!"
    assert b'TestService' not in encrypted_blob, "Service name found in plaintext!"

    decrypted_data = encryption_service.decrypt_entry(encrypted_blob)

    assert decrypted_data['title'] == known_data['service']
    assert decrypted_data['username'] == known_data['username']
    assert decrypted_data['password'] == known_data['password']
    assert decrypted_data['url'] == known_data['url']
    assert decrypted_data['notes'] == known_data['notes']
    assert decrypted_data['version'] == 1


# ==================== ТЕСТ 2: CRUD ИНТЕГРАЦИЯ ====================

def test_crud_integration(entry_manager):
    """TEST-2: CRUD Integration Test - Create 100 entries"""
    created_ids = []

    for i in range(100):
        data = {
            'service': f'Service_{i}',
            'username': f'user_{i}',
            'password': f'pass_{i}',
            'category': 'Work' if i % 2 == 0 else 'Personal'
        }
        entry_id = entry_manager.create_entry(data)
        created_ids.append(entry_id)

    assert len(created_ids) == 100

    all_entries = entry_manager.get_all_entries()
    assert len(all_entries) == 100

    for i in range(10):
        new_data = {
            'service': f'Updated_Service_{i}',
            'username': f'updated_user_{i}',
            'password': 'new_secure_pass',
            'category': 'Updated'
        }
        entry_manager.update_entry(created_ids[i], new_data)

    updated_entry = entry_manager.get_entry(created_ids[0])
    assert updated_entry['title'] == 'Updated_Service_0'
    assert updated_entry['username'] == 'updated_user_0'
    assert updated_entry['password'] == 'new_secure_pass'

    for i in range(90, 100):
        entry_manager.delete_entry(created_ids[i], soft_delete=True)

    remaining_entries = entry_manager.get_all_entries()
    assert len(remaining_entries) == 90


# ==================== ТЕСТ 3: КОНКУРЕНТНОСТЬ ====================

def test_concurrency():
    """TEST-3: Concurrency Test"""
    db = MockDbHelper()
    km = MockKeyManager()
    manager = EntryManager(db, km)

    errors = []
    lock = threading.Lock()

    def worker_task(worker_id):
        try:
            for i in range(20):
                data = {
                    'service': f'Worker{worker_id}_Item{i}',
                    'username': 'test',
                    'password': 'test',
                }
                e_id = manager.create_entry(data)
                entry = manager.get_entry(e_id)
                assert entry is not None
                manager.update_entry(e_id, {'service': 'Updated', 'username': 'u', 'password': 'p'})
                manager.delete_entry(e_id, soft_delete=True)
        except Exception as e:
            with lock:
                errors.append(f"Worker {worker_id}: {str(e)}")

    threads = []
    for i in range(10):
        t = threading.Thread(target=worker_task, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0, f"Errors: {errors}"
    final_entries = manager.get_all_entries()
    assert len(final_entries) == 0


# ==================== ТЕСТ 4: ГЕНЕРАТОР ПАРОЛЕЙ ====================

def test_password_generator_quality():
    """TEST-4: Password Generator Test"""
    count = 500
    mock_db = MockDbHelper()
    generated_list = []

    for _ in range(count):
        pwd, score = PasswordGenerator.generate_custom(
            length=16,
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_symbols=True,
            exclude_ambiguous=True,
            db_helper=mock_db
        )
        generated_list.append(pwd)

    unique_count = len(set(generated_list))
    assert unique_count == count, f"Found {count - unique_count} duplicates"

    valid_chars = set(string.ascii_letters + string.digits + PasswordGenerator.SYMBOLS)
    valid_chars.difference_update(set(PasswordGenerator.AMBIGUOUS))

    weak_count = 0
    for pwd in generated_list:
        assert len(pwd) == 16
        assert all(c in valid_chars for c in pwd)

        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_symbol = any(c in PasswordGenerator.SYMBOLS for c in pwd)

        if not (has_upper and has_lower and has_digit and has_symbol):
            weak_count += 1

    assert weak_count == 0, f"Found {weak_count} weak passwords"


# ==================== ТЕСТ 5-7: ПРОИЗВОДИТЕЛЬНОСТЬ ====================

def create_test_data(manager, count=1000):
    """Helper to create test data"""
    for i in range(count):
        data = {
            'service': f'PerfService_{i}',
            'username': f'user_{i}',
            'password': f'password_{i}',
            'url': f'https://example-{i}.com',
            'notes': 'Some notes text ' + str(i),
            'category': 'Test'
        }
        manager.create_entry(data)


def test_performance_loading():
    """PERF-1: Loading 1000 entries < 2 seconds"""
    db = MockDbHelper()
    km = MockKeyManager()
    manager = EntryManager(db, km)

    create_test_data(manager, 1000)

    start_time = time.perf_counter()
    entries = manager.get_all_entries()
    end_time = time.perf_counter()
    duration = end_time - start_time

    print(f"\n[Perf] Loading: {duration:.3f}s, entries: {len(entries)}")
    assert len(entries) == 1000
    assert duration < 2.0


def test_performance_search():
    """PERF-2: Search across 1000 entries < 200ms"""
    db = MockDbHelper()
    km = MockKeyManager()
    manager = EntryManager(db, km)

    create_test_data(manager, 1000)

    all_entries = manager.get_all_entries()
    assert len(all_entries) == 1000

    query = "PerfService_500"
    start_time = time.perf_counter()
    results = manager.filter_entries(all_entries, query)
    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000

    print(f"[Perf] Search: {duration_ms:.2f}ms, found: {len(results)}")
    assert len(results) > 0
    assert duration_ms < 200


def test_performance_memory():
    """PERF-3: Memory usage < 50MB for 1000 entries"""
    tracemalloc.start()

    db = MockDbHelper()
    km = MockKeyManager()
    manager = EntryManager(db, km)

    for i in range(1000):
        data = {
            'service': f'MemService_{i}',
            'username': f'user_{i}',
            'password': 'x' * 32,
            'notes': 'y' * 100,
            'category': 'Test'
        }
        manager.create_entry(data)

    all_entries = manager.get_all_entries()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / (1024 * 1024)
    print(f"\n[Memory] Peak: {peak_mb:.2f}MB, entries: {len(all_entries)}")

    assert len(all_entries) == 1000
    assert peak_mb < 50.0


# ==================== ТЕСТ 8: МЯГКОЕ УДАЛЕНИЕ ====================

def test_soft_delete_functionality(entry_manager):
    """Test soft delete functionality"""
    data = {
        'service': 'SoftDeleteTest',
        'username': 'testuser',
        'password': 'testpass123!',
        'category': 'Test'
    }
    entry_id = entry_manager.create_entry(data)

    entry = entry_manager.get_entry(entry_id)
    assert entry is not None
    assert entry['title'] == 'SoftDeleteTest'

    entry_manager.delete_entry(entry_id, soft_delete=True)

    # EntryManager.get_entry выбрасывает ValueError при отсутствии записи
    with pytest.raises(ValueError, match="Entry not found"):
        entry_manager.get_entry(entry_id)


# ==================== ТЕСТ 9: ПОИСК И ФИЛЬТРАЦИЯ ====================

def test_search_and_filter(entry_manager):
    """Test search and filter functionality"""
    test_data = [
        {'service': 'Gmail', 'username': 'user@gmail.com', 'notes': 'Work email'},
        {'service': 'GitHub', 'username': 'dev@github.com', 'notes': 'Code repository'},
        {'service': 'Google Drive', 'username': 'user@gmail.com', 'notes': 'Cloud storage'},
    ]

    for data in test_data:
        entry_manager.create_entry(data)

    all_entries = entry_manager.get_all_entries()
    assert len(all_entries) == 3

    results = entry_manager.filter_entries(all_entries, "Gmail")
    assert len(results) == 1
    assert results[0]['title'] == 'Gmail'

    results = entry_manager.filter_entries(all_entries, "user@gmail.com")
    assert len(results) == 2


# ==================== ТЕСТ 10: ВАЛИДАЦИЯ ПАРОЛЕЙ ====================

def test_password_validation():
    """Test password strength validation"""
    strong_passwords = [
        "MyStr0ngP@ssw0rd!",
        "C0mpl3x#P@ssw0rd99",
    ]
    weak_passwords = ["weak", "password123", "onlylowercase"]

    for pwd in strong_passwords:
        is_valid, _ = PasswordGenerator.validate_password_strength(pwd)
        assert is_valid, f"Password '{pwd}' should be valid"

    for pwd in weak_passwords:
        is_valid, _ = PasswordGenerator.validate_password_strength(pwd)
        assert not is_valid, f"Password '{pwd}' should be weak"


# ==================== ДОПОЛНИТЕЛЬНЫЙ ТЕСТ: ОБНОВЛЕНИЕ ====================

def test_update_nonexistent_entry(entry_manager):
    """Test updating non-existent entry"""
    with pytest.raises(Exception):
        entry_manager.update_entry(99999, {'service': 'Test'})


def test_delete_nonexistent_entry(entry_manager):
    """Test deleting non-existent entry"""
    with pytest.raises(Exception):
        entry_manager.delete_entry(99999)


# ==================== ЗАПУСК ====================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "--no-cov", "-s"])