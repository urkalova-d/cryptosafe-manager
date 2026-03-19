import pytest
import time
import os
import sys
import json
import base64
import secrets
from cryptography.fernet import Fernet

# Добавляем путь к проекту для импорта модулей
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.crypto.key_derivation import KeyDerivationService
from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.key_manager import KeyManager


# --- Фикстуры (Настройка окружения для тестов) ---

@pytest.fixture
def kdf_service():
    """Создает сервис генерации ключей с параметрами по умолчанию"""
    return KeyDerivationService()


@pytest.fixture
def temp_db(tmp_path):
    """
    Создает временную базу данных в памяти (или временный файл) для интеграционных тестов.
    Это изолирует тесты от реальной базы данных пользователя.
    """

    # Создаем временную БД в памяти для скорости
    # Если нужна файловая БД: db_path = os.path.join(tmp_path, "test_vault.db")
    class MockDB:
        def __init__(self):
            self.data = {}  # Эмуляция хранилища key_store
            self.settings = {}  # Эмуляция settings
            self.entries = []  # Эмуляция записей
            self.id_counter = 1

        def save_key_store(self, key_type, key_data, version=1):
            # Эмуляция сохранения (упрощенная, без SQL)
            if isinstance(key_data, bytes):
                self.data[key_type] = (key_data.hex(), version)
            else:
                self.data[key_type] = (key_data, version)

        def get_key_store(self, key_type):
            val = self.data.get(key_type)
            if val:
                # Возвращаем bytes и version
                return bytes.fromhex(val[0]), val[1]
            return None, None

        def save_setting(self, key, value):
            self.settings[key] = value

        def get_setting(self, key):
            return self.settings.get(key)

        def add_entry(self, service, username, enc_pass, notes):
            self.entries.append({
                'id': self.id_counter,
                'service': service,
                'username': username,
                'encrypted_password': enc_pass,
                'notes': notes
            })
            self.id_counter += 1

        def get_all_entries(self):
            return self.entries

        # Методы, необходимые для KeyManager (заглушки)
        def rotate_vault_keys(self, mh, a_salt, e_salt, re_enc_data):
            self.save_setting("master_hash", mh)
            self.save_key_store("auth_salt", a_salt)
            self.save_key_store("encryption_salt", e_salt)
            # Обновляем записи
            for eid, enc_val in re_enc_data:
                for entry in self.entries:
                    if entry['id'] == eid:
                        entry['encrypted_password'] = enc_val

    return MockDB()


# --- Тесты ---

def test_1_argon2_parameter_validation(kdf_service):
    """
    Тест 1: Argon2 Parameter Validation Test.
    Проверяем, что разные параметры создают валидные хеши, и сервис работает без ошибок.
    """
    password = "TestPassword123!"

    # 1. Стандартные параметры
    hash1 = kdf_service.create_auth_hash(password)
    assert hash1 is not None
    assert hash1.startswith("$argon2id$")

    # 2. Измененные параметры (низкие значения для быстроты теста)
    custom_config = {
        'argon2_time': 1,
        'argon2_memory': 16384,  # 16MB
        'argon2_parallelism': 1
    }
    kdf_custom = KeyDerivationService(config=custom_config)
    hash2 = kdf_custom.create_auth_hash(password)
    assert hash2 is not None

    # Хеши должны отличаться из-за разной соли, но оба быть валидными
    assert hash1 != hash2

    # Проверяем верификацию для обоих
    assert kdf_service.verify_password(password, hash1)
    assert kdf_custom.verify_password(password, hash2)


def test_2_key_derivation_consistency(kdf_service):
    """
    Тест 2: Key Derivation Consistency Test.
    Генерируем ключ 100 раз с одинаковым вводом, проверяем идентичность выхода.
    """
    password = "ConsistentPassword!"
    salt = secrets.token_bytes(16)  # Фиксированная соль

    keys = set()
    iterations = 100

    for _ in range(iterations):
        # Генерируем ключ шифрования (PBKDF2 должен быть детерминированным)
        key = kdf_service.derive_encryption_key(password, salt)
        # Преобразуем в hex для хранения в set (или хешируем объект bytes)
        keys.add(key)

    # В наборе должен быть ровно 1 уникальный ключ
    assert len(keys) == 1, f"Ожидался 1 уникальный ключ, получено {len(keys)}"


def test_3_timing_attack_resistance(kdf_service):
    """
    Тест 3: Timing Attack Resistance Test.
    Проверяем, что сравнение паролей занимает примерно одинаковое время для правильных и неправильных паролей.
    """
    password = "CorrectPassword"
    wrong_password = "WrongPassword123"
    stored_hash = kdf_service.create_auth_hash(password)

    # Делаем несколько прогревочных запусков (не учитываем)
    for _ in range(5):
        kdf_service.verify_password(wrong_password, stored_hash)

    # Замер времени для неверного пароля
    start_wrong = time.perf_counter()
    for _ in range(100):
        kdf_service.verify_password(wrong_password, stored_hash)
    time_wrong = time.perf_counter() - start_wrong

    # Замер времени для верного пароля
    start_correct = time.perf_counter()
    for _ in range(100):
        kdf_service.verify_password(password, stored_hash)
    time_correct = time.perf_counter() - start_correct

    # Разница во времени не должна быть огромной (например, не в 10 раз)
    # Допускаем небольшую погрешность, но не порядковую разницу
    ratio = time_wrong / time_correct if time_correct > 0 else 0
    print(f"\nTiming Ratio (Wrong/Correct): {ratio:.2f}")

    # Обычно библиотека Argon2 делает сравнение за константное время
    # Проверяем, что время сравнения неверного пароля не равно 0 и соизмеримо
    assert time_wrong > 0
    # Разница не должна превышать 50% (эвристическая оценка для CI)
    assert abs(time_wrong - time_correct) < (time_correct * 0.5), "Замечена значительная разница во времени сравнения"


def test_4_memory_safety():
    """
    Тест 4: Memory Safety Test.
    Проверяем, что ключи очищаются из памяти (зануляются).
    """
    storage = KeyStorage()
    dummy_key = secrets.token_bytes(32)
    dummy_key_2 = secrets.token_bytes(32)

    storage.set_keys(dummy_key, dummy_key_2)

    # Проверяем, что ключи есть
    assert storage.get_auth_key() is not None
    assert storage.get_enc_key() is not None

    # Сохраняем ссылку на массив (необычная практика, но для теста нужно)
    # KeyStorage хранит bytearray
    auth_buf = storage._auth_key
    enc_buf = storage._encryption_key

    storage.clear()

    # Проверяем, что ссылки теперь указывают на None
    assert storage._auth_key is None
    assert storage._encryption_key is None

    # Проверяем, что память в объектах bytearray была очищена (занулена)
    # (если GC еще не переместил их, что вероятно в синхронном тесте)
    # Внимание: это работает только если KeyStorage.zero_out работает корректно
    # и мы сохранили ссылку на объект bytearray.

    # Читаем сырые байты из старого буфера (Python может уже очистить, но попробуем)
    # Если буфер обнулен, все байты будут \x00
    # Однако, после clear() storage._auth_key становится None, а мы держим ссылку на старый массив.

    is_zeroed = all(b == 0 for b in auth_buf)
    assert is_zeroed, "Память Auth Key не была очищена (занулена)"

    is_zeroed_enc = all(b == 0 for b in enc_buf)
    assert is_zeroed_enc, "Память Enc Key не была очищена (занулена)"


def test_5_password_change_integration(temp_db):
    """
    Тест 5: Password Change Integration Test.
    Полный сценарий:
    1. Create vault with "A"
    2. Add 10 entries
    3. Change password to "B"
    4. Verify all entries accessible with "B"
    """
    # 1. Инициализация и создание хранилища с паролем "A"
    km = KeyManager(temp_db)
    password_a = "PasswordA_Secure123"
    km.setup_new_user(password_a)

    # 2. Добавление 10 записей
    # Нам нужен сервис шифрования для ручного шифрования, так как мы тестируем KeyManager
    # Но KeyManager.rotate_keys использует Fernet внутри.
    # Для добавления записей нам тоже нужно зашифровать данные.

    # Получаем ключ шифрования для пароля A
    # (обычно это делается через verify_and_unlock, но мы можем сымитировать вход)
    assert km.verify_and_unlock(password_a), "Не удалось разблокировать с паролем A"
    key_a = km.get_encryption_key()
    fernet_a = Fernet(base64.urlsafe_b64encode(key_a))

    test_data = []
    for i in range(10):
        plain_pass = f"SecretData_{i}"
        enc_pass = fernet_a.encrypt(plain_pass.encode()).decode()
        temp_db.add_entry(f"Service_{i}", f"user_{i}", enc_pass, "notes")
        test_data.append(plain_pass)  # Сохраняем открытые пароли для сверки

    # 3. Смена пароля на "B"
    password_b = "PasswordB_NewSecure456"
    # Метод rotate_keys должен перешифровать все записи
    success = km.rotate_keys(password_a, password_b)
    assert success, "Смена пароля не удалась"

    # 4. Проверка доступа с новым паролем
    # Сначала "забываем" старый ключ (разблокируем заново)
    km.storage.clear()

    assert km.verify_and_unlock(password_b), "Не удалось разблокировать с новым паролем B"
    key_b = km.get_encryption_key()
    fernet_b = Fernet(base64.urlsafe_b64encode(key_b))

    # Проверяем все записи
    entries = temp_db.get_all_entries()
    assert len(entries) == 10, "Количество записей изменилось"

    for i, entry in enumerate(entries):
        enc_p = entry['encrypted_password']
        dec_p = fernet_b.decrypt(enc_p.encode()).decode()
        assert dec_p == test_data[i], f"Данные записи {i} повреждены или не расшифровываются"

    print("\nИнтеграционный тест смены пароля пройден успешно.")