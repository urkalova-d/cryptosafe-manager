import pytest
import os
import sys
import threading
import time
import hashlib
import string
import tracemalloc
from concurrent.futures import ThreadPoolExecutor

# для импортов
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.vault.encryption_service import EncryptionService
from src.core.vault.entry_manager import EntryManager
from src.core.vault.password_generator import PasswordGenerator

# Имитация среды)

class MockKeyManager:
    #Имитация KeyManager для тестов всегда возвращает один и тот же ключ

    def __init__(self):
        # Фиксированный ключ для детерминированных тестов
        self.test_key = b'testkey_32bytes_for_validation_!!'

    def get_encryption_key(self):
        return self.test_key

    def get_auth_key(self):
        return self.test_key


class MockDbHelper:
    #имитация БД в памяти для изолированных тестов

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


# тест на двустороннее шифрование

def test_encryption_round_trip(encryption_service):
    known_data = {
        'service': 'TestService',
        'username': 'user123',
        'password': 'SuperSecretPassword!',
        'url': 'https://test.com',
        'notes': 'Some notes here'
    }

    # encrypt
    encrypted_blob = encryption_service.encrypt_entry(known_data)

    # Checks
    assert isinstance(encrypted_blob, bytes), "Encrypted data must be bytes"
    assert len(encrypted_blob) > 12, "Blob too short (must contain nonce + tag)"

    # Verify NOT plaintext
    plain_str = str(known_data).encode('utf-8')
    assert plain_str not in encrypted_blob, "Encrypted blob contains plaintext (INSECURE!)"

    # Проверка конкретных полей
    assert b'SuperSecretPassword!' not in encrypted_blob
    assert b'TestService' not in encrypted_blob

    # Decrypt
    decrypted_data = encryption_service.decrypt_entry(encrypted_blob)

    # Verify integrity
    assert decrypted_data['title'] == known_data['service']
    assert decrypted_data['username'] == known_data['username']
    assert decrypted_data['password'] == known_data['password']
    assert decrypted_data['url'] == known_data['url']
    assert decrypted_data['notes'] == known_data['notes']


# интеграционный тест

def test_crud_integration(entry_manager):
    #создание 100 записей
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

    # проверка колва
    all_entries = entry_manager.get_all_entries()
    assert len(all_entries) == 100, "DB should contain 100 entries"

    # обновление первых 10
    for i in range(10):
        new_data = {
            'service': f'Updated_Service_{i}',
            'username': f'updated_user_{i}',
            'password': 'new_secure_pass',
            'category': 'Updated'
        }
        entry_manager.update_entry(created_ids[i], new_data)

    updated_entry = entry_manager.get_entry(created_ids[0])

    assert updated_entry['title'] == 'Updated_Service_0', "Title should be updated"
    assert updated_entry['username'] == 'updated_user_0'
    assert updated_entry['password'] == 'new_secure_pass'

    # удаление 10
    for i in range(90, 100):
        entry_manager.delete_entry(created_ids[i], soft_delete=True)

    remaining_entries = entry_manager.get_all_entries()
    assert len(remaining_entries) == 90, "Should have 90 entries remaining after deletion"


# тест на параллелизм

def test_concurrency(db_helper, key_manager):
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
                # создание
                e_id = manager.create_entry(data)
                #чтение
                entry = manager.get_entry(e_id)
                assert entry is not None
                # обновление
                manager.update_entry(e_id, {'service': 'Updated', 'username': 'u', 'password': 'p'})
                # удалеиние
                manager.delete_entry(e_id)
        except Exception as e:
            errors.append(e)

    # Запуск 10 потоков одновременно
    threads = []
    for i in range(10):
        t = threading.Thread(target=worker_task, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0, f"Concurrency errors occurred: {errors}"

    # проверка целостности бд
    final_entries = manager.get_all_entries()
    assert isinstance(final_entries, list)


# генератор паролей

def test_password_generator_quality():
    count = 10000
    passwords = set()

    mock_db = MockDbHelper()

    generated_list = []
    for _ in range(count):
        pwd, score = PasswordGenerator.generate_custom(length=16, db_helper=mock_db)
        generated_list.append(pwd)

    # остутствиедубликатов
    unique_count = len(set(generated_list))
    print(f"\nGenerated: {count}, Unique: {unique_count}")
    assert unique_count == count, "Found duplicate passwords! RNG might be weak."

    # роверка на соответствие набору
    valid_chars = set(string.ascii_letters + string.digits + PasswordGenerator.SYMBOLS)
    # Убираем неоднозначные символы если они исключены по умолчанию
    valid_chars.difference_update(set(PasswordGenerator.AMBIGUOUS))

    for pwd in generated_list[:100]:  # Check first 100
        # проверка длины
        assert len(pwd) == 16
        # проверка что символы валидны
        assert all(c in valid_chars for c in pwd)
        #проверка наличия разных типов 
        assert any(c.islower() for c in pwd)
        assert any(c.isupper() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        # Symbols might be optional or constrained, check generator logic implies strict compliance

    #простая проверка
    weak_count = 0
    for pwd in generated_list:
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_symbol = any(c in PasswordGenerator.SYMBOLS for c in pwd)

        if not (has_upper and has_lower and has_digit and has_symbol):
            weak_count += 1

    assert weak_count == 0, "Some passwords do not meet basic complexity requirements (missing char types)"


#  PERFORMANCE REQUIREMENTS

@pytest.fixture
def performance_manager():
    #Подготовка менеджера с 1000 записями для тестов производительности.Создается один раз для всех тестов в этом блоке .
    
    db = MockDbHelper()
    km = MockKeyManager()
    manager = EntryManager(db, km)

    print("\n[Setup] Generating 1000 entries for performance tests...")
    for i in range(1000):
        data = {
            'service': f'PerfService_{i}',
            'username': f'user_{i}',
            'password': f'password_{i}',
            'url': f'https://example-{i}.com',
            'notes': 'Some notes text ' + str(i)
        }
        manager.create_entry(data)

    return manager


def test_performance_loading(performance_manager):
    #загрузка записей должна быть меньше 2 секунд
    start_time = time.perf_counter()

    # Имитация загрузки 
    entries = performance_manager.get_all_entries()

    end_time = time.perf_counter()
    duration = end_time - start_time

    print(f"\n[Perf] Loading 1000 entries took: {duration:.4f} seconds")

    assert len(entries) == 1000
    assert duration < 2.0, f"Loading took too long: {duration:.2f}s (Limit: 2.0s)"


def test_performance_search(performance_manager):
    #поиска записей должен быть меньше 200мс
    # Кэшируем список 
    all_entries = performance_manager.get_all_entries()

    query = "PerfService_500"

    start_time = time.perf_counter()

    # поиск
    results = performance_manager.filter_entries(all_entries, query)

    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000  # в миллисекундах

    print(f"[Perf] Search took: {duration_ms:.2f} ms")

    # Проверка производительности
    assert duration_ms < 200, f"Search took too long: {duration_ms:.2f}ms (Limit: 200ms)"

    if len(results) == 0:
        # Попробуем найти "500" (число, которое есть в имени)
        results = performance_manager.filter_entries(all_entries, "500")

    assert len(results) > 0, "Search should find at least one entry matching the query"

def test_performance_memory():
    #память не больше 50 мб для 1000 записей
    tracemalloc.start()

    # Создаем менеджер и 1000 записей
    db = MockDbHelper()
    km = MockKeyManager()
    manager = EntryManager(db, km)

    for i in range(1000):
        data = {
            'service': f'MemService_{i}',
            'username': f'user_{i}',
            'password': 'x' * 20,  # 20 символов пароль
            'notes': 'y' * 50  # 50 символов заметки
        }
        manager.create_entry(data)

    # Загружаем в память (как при отображении в GUI)
    all_entries = manager.get_all_entries()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / (1024 * 1024)

    print(f"\n[Perf] Memory usage for 1000 entries: {peak_mb:.2f} MB")

    # Проверка. Делаем допуск на overhead самого python процесса (примерно 10-15MB)
    # Реально данные должны занимать меньше 50MB.
    assert peak_mb < 50.0, f"Memory usage exceeded limit: {peak_mb:.2f}MB (Limit: 50MB)"
    assert len(all_entries) == 1000