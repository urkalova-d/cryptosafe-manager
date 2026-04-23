import pytest
import os
import sys
import threading
import time
import hashlib
import string
from concurrent.futures import ThreadPoolExecutor

# Добавляем корень проекта в путь для импортов
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Импорт тестируемых компонентов
from src.core.vault.encryption_service import EncryptionService
from src.core.vault.entry_manager import EntryManager
from src.core.vault.password_generator import PasswordGenerator


# --- MOCKS (Имитация среды) ---

class MockKeyManager:
    """Имитация KeyManager для тестов. Всегда возвращает один и тот же ключ."""

    def __init__(self):
        # Фиксированный ключ для детерминированных тестов
        self.test_key = b'testkey_32bytes_for_validation_!!'

    def get_encryption_key(self):
        return self.test_key

    def get_auth_key(self):
        return self.test_key


class MockDbHelper:
    """Имитация БД в памяти для изолированных тестов."""

    def __init__(self):
        self.store = {}  # ID -> record
        self.history = set()
        self._lock = threading.Lock()
        self._id_counter = 1

    def add_entry(self, encrypted_data, tags=""):
        with self._lock:
            entry_id = self._id_counter
            self._id_counter += 1
            self.store[entry_id] = {
                'id': entry_id,
                'encrypted_data': encrypted_data,
                'tags': tags,
                'created_at': '2023-01-01',
                'updated_at': '2023-01-01'
            }
            return entry_id

    def get_entry(self, entry_id):
        return self.store.get(entry_id)

    def get_all_entries(self):
        return list(self.store.values())

    def update_entry(self, entry_id, encrypted_data, tags=None):
        if entry_id in self.store:
            self.store[entry_id]['encrypted_data'] = encrypted_data
            if tags: self.store[entry_id]['tags'] = tags
            return True
        return False

    def soft_delete_entry(self, entry_id):
        if entry_id in self.store:
            del self.store[entry_id]
            return True
        return False

    def hard_delete_entry(self, entry_id):
        pass  # Not needed for these tests

    def add_password_to_history(self, h):
        self.history.add(h)

    def is_password_in_history(self, h):
        return h in self.history


# --- FIXTURES ---

@pytest.fixture
def key_manager():
    return MockKeyManager()


@pytest.fixture
def db_helper():
    return MockDbHelper()


@pytest.fixture
def encryption_service(key_manager):
    return EncryptionService(key_manager)


@pytest.fixture
def entry_manager(db_helper, key_manager):
    return EntryManager(db_helper, key_manager)


# --- TEST 1: Encryption Round-Trip ---

def test_encryption_round_trip(encryption_service):
    """
    Req 1: Encryption Round-Trip Test
    1. Create entry with known data
    2. Verify encrypted BLOB is not plaintext
    3. Decrypt and verify data integrity
    """
    known_data = {
        'service': 'TestService',
        'username': 'user123',
        'password': 'SuperSecretPassword!',
        'url': 'https://test.com',
        'notes': 'Some notes here'
    }

    # 1. Encrypt
    encrypted_blob = encryption_service.encrypt_entry(known_data)

    # Checks
    assert isinstance(encrypted_blob, bytes), "Encrypted data must be bytes"
    assert len(encrypted_blob) > 12, "Blob too short (must contain nonce + tag)"

    # 2. Verify NOT plaintext
    # Проверяем, что ни одно из исходных значений не содержится в бинарном виде в blob
    plain_str = str(known_data).encode('utf-8')
    assert plain_str not in encrypted_blob, "Encrypted blob contains plaintext (INSECURE!)"

    # Проверяем конкретные поля
    assert b'SuperSecretPassword!' not in encrypted_blob
    assert b'TestService' not in encrypted_blob

    # 3. Decrypt
    decrypted_data = encryption_service.decrypt_entry(encrypted_blob)

    # Verify integrity
    assert decrypted_data['title'] == known_data['service']
    assert decrypted_data['username'] == known_data['username']
    assert decrypted_data['password'] == known_data['password']
    assert decrypted_data['url'] == known_data['url']
    assert decrypted_data['notes'] == known_data['notes']


# --- TEST 2: CRUD Integration ---

def test_crud_integration(entry_manager):
    """
    Req 2: CRUD Integration Test
    Create 100 entries, perform updates, deletions, verify counts and data consistency.
    """
    # 1. Create 100 entries
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

    assert len(created_ids) == 100, "Should create 100 entries"

    # 2. Verify counts
    all_entries = entry_manager.get_all_entries()
    assert len(all_entries) == 100, "DB should contain 100 entries"

    # 3. Perform updates on first 10
    for i in range(10):
        new_data = {
            'service': f'Updated_Service_{i}',
            'username': f'updated_user_{i}',
            'password': 'new_secure_pass',
            'category': 'Updated'
        }
        entry_manager.update_entry(created_ids[i], new_data)

    # Verify update consistency
    updated_entry = entry_manager.get_entry(created_ids[0])

    # ВАЖНО: EncryptionService сохраняет 'service' как 'title' в JSON
    assert updated_entry['title'] == 'Updated_Service_0', "Title should be updated"
    assert updated_entry['username'] == 'updated_user_0'
    assert updated_entry['password'] == 'new_secure_pass'

    # 4. Delete 10 entries
    for i in range(90, 100):
        entry_manager.delete_entry(created_ids[i], soft_delete=True)

    remaining_entries = entry_manager.get_all_entries()
    assert len(remaining_entries) == 90, "Should have 90 entries remaining after deletion"
# --- TEST 3: Concurrency Test ---

def test_concurrency(db_helper, key_manager):
    """
    Req 3: Concurrency Test
    Simulate multiple GUI operations simultaneously, verify no data corruption.
    """
    # Используем реальный EntryManager, который опирается на DB Helper с локами
    manager = EntryManager(db_helper, key_manager)

    errors = []

    def worker_task(worker_id):
        try:
            for i in range(20):
                data = {
                    'service': f'Worker{worker_id}_Item{i}',
                    'username': 'test',
                    'password': 'test',
                }
                # Create
                e_id = manager.create_entry(data)
                # Read
                entry = manager.get_entry(e_id)
                assert entry is not None
                # Update
                manager.update_entry(e_id, {'service': 'Updated', 'username': 'u', 'password': 'p'})
                # Delete (soft)
                manager.delete_entry(e_id)
        except Exception as e:
            errors.append(e)

    # Запускаем 10 потоков одновременно
    threads = []
    for i in range(10):
        t = threading.Thread(target=worker_task, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0, f"Concurrency errors occurred: {errors}"

    # Проверяем целостность БД (не должно быть "битых" записей, вызывающих падение при чтении)
    # В данном моке мы эмулируем "чистую" работу, в реальной БД это проверило бы lock-и
    final_entries = manager.get_all_entries()
    assert isinstance(final_entries, list)


# --- TEST 4: Password Generator Test ---

def test_password_generator_quality():
    """
    Req 4: Password Generator Test
    Generate 10,000 passwords, verify:
    - No duplicates
    - Character set compliance
    - Strength requirements met
    """
    count = 10000
    passwords = set()

    # Генерируем 10000 паролей
    # Используем mock db_helper чтобы избежать переполнения истории в реальной БД
    mock_db = MockDbHelper()

    generated_list = []
    for _ in range(count):
        pwd, score = PasswordGenerator.generate_custom(length=16, db_helper=mock_db)
        generated_list.append(pwd)

    # 1. No duplicates
    # Статистически при длине 16 и хорошем генераторе совпадений быть не должно
    unique_count = len(set(generated_list))
    print(f"\nGenerated: {count}, Unique: {unique_count}")
    assert unique_count == count, "Found duplicate passwords! RNG might be weak."

    # 2. Character set compliance (проверяем несколько случайных на соответствие набору)
    valid_chars = set(string.ascii_letters + string.digits + PasswordGenerator.SYMBOLS)
    # Убираем неоднозначные символы если они исключены по умолчанию
    valid_chars.difference_update(set(PasswordGenerator.AMBIGUOUS))

    for pwd in generated_list[:100]:  # Check first 100
        # Проверка длины
        assert len(pwd) == 16
        # Проверка что символы валидны
        assert all(c in valid_chars for c in pwd)
        # Проверка наличия разных типов (если включены)
        assert any(c.islower() for c in pwd)
        assert any(c.isupper() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        # Symbols might be optional or constrained, check generator logic implies strict compliance

    # 3. Strength requirements
    # Простейшая проверка: пароль должен содержать символы из 4 групп
    # (PasswordGenerator уже возвращает score, можно проверить его, если zxcvbn доступен)
    weak_count = 0
    for pwd in generated_list:
        # Если zxcvbn недоступен, класс возвращает 0.
        # Поэтому проверим базовую логику: наличие Upper, Lower, Digit
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_symbol = any(c in PasswordGenerator.SYMBOLS for c in pwd)

        if not (has_upper and has_lower and has_digit and has_symbol):
            weak_count += 1

    assert weak_count == 0, "Some passwords do not meet basic complexity requirements (missing char types)"
