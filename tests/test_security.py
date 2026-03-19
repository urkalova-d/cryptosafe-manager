import pytest
import time
import os
import sys
import json
import base64
import secrets
from cryptography.fernet import Fernet
from src.core.crypto.key_derivation import KeyDerivationService
from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.key_manager import KeyManager


#  путь к проекту
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture
def kdf_service():
    # Создает сервис генерации ключей с параметрами по умолчанию"""
    return KeyDerivationService()


@pytest.fixture
def temp_db(tmp_path):
    #временная база данных для теста
    class MockDB:
        def __init__(self):
            self.data = {}
            self.settings = {}
            self.entries = []
            self.id_counter = 1

        def save_key_store(self, key_type, key_data, version=1):
            if isinstance(key_data, bytes):
                self.data[key_type] = (key_data.hex(), version)
            else:
                self.data[key_type] = (key_data, version)

        def get_key_store(self, key_type):
            val = self.data.get(key_type)
            if val:
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

        # методы для заглушки
        def rotate_vault_keys(self, mh, a_salt, e_salt, re_enc_data):
            self.save_setting("master_hash", mh)
            self.save_key_store("auth_salt", a_salt)
            self.save_key_store("encryption_salt", e_salt)
            # обновление записей
            for eid, enc_val in re_enc_data:
                for entry in self.entries:
                    if entry['id'] == eid:
                        entry['encrypted_password'] = enc_val

    return MockDB()


def test_1_argon2_parameter_validation(kdf_service):
    #Argon2 Parameter Validation Test.
    password = "TestPassword123!"

    # параметры
    hash1 = kdf_service.create_auth_hash(password)
    assert hash1 is not None
    assert hash1.startswith("$argon2id$")

    # Измененные параметры для быстроты теста
    custom_config = {
        'argon2_time': 1,
        'argon2_memory': 16384,
        'argon2_parallelism': 1
    }
    kdf_custom = KeyDerivationService(config=custom_config)
    hash2 = kdf_custom.create_auth_hash(password)
    assert hash2 is not None

    assert hash1 != hash2

    assert kdf_service.verify_password(password, hash1)
    assert kdf_custom.verify_password(password, hash2)


def test_2_key_derivation_consistency(kdf_service):
    # Key Derivation Consistency Test:генерация ключа 100 раз с одинаковым вводом проверка идентичности выхода
    password = "ConsistentPassword!"
    salt = secrets.token_bytes(16)

    keys = set()
    iterations = 100

    for _ in range(iterations):
        # генерирация ключа шифрования (PBKDF2)
        key = kdf_service.derive_encryption_key(password, salt)
        keys.add(key)

    # должен быть  один уникальный ключ
    assert len(keys) == 1, f"Ожидался 1 уникальный ключ, получено {len(keys)}"


def test_3_timing_attack_resistance(kdf_service):
     # Timing Attack Resistance Test:проверка,что сравнение паролей занимает примерно одинаковое время для правильных и неправильных паролей

    password = "CorrectPassword"
    wrong_password = "WrongPassword123"
    stored_hash = kdf_service.create_auth_hash(password)

    # несколько запусков
    for _ in range(5):
        kdf_service.verify_password(wrong_password, stored_hash)

    # замер времени для неправильного пароля
    start_wrong = time.perf_counter()
    for _ in range(100):
        kdf_service.verify_password(wrong_password, stored_hash)
    time_wrong = time.perf_counter() - start_wrong

    # замер времени для правильного пароля
    start_correct = time.perf_counter()
    for _ in range(100):
        kdf_service.verify_password(password, stored_hash)
    time_correct = time.perf_counter() - start_correct
    #разница во времени
    ratio = time_wrong / time_correct if time_correct > 0 else 0
    print(f"\nTiming Ratio (Wrong/Correct): {ratio:.2f}")

    # проверка что время неправьного пароля не равна 0
    assert time_wrong > 0
    # разница не превышает 50 процентов
    assert abs(time_wrong - time_correct) < (time_correct * 0.5), "Замечена значительная разница во времени сравнения"


def test_4_memory_safety():
    # Memory Safety Test:проверка, что ключи очищаются из памяти
    storage = KeyStorage()
    dummy_key = secrets.token_bytes(32)
    dummy_key_2 = secrets.token_bytes(32)

    storage.set_keys(dummy_key, dummy_key_2)

    # проверка на наличие ключа
    assert storage.get_auth_key() is not None
    assert storage.get_enc_key() is not None

    auth_buf = storage._auth_key
    enc_buf = storage._encryption_key

    storage.clear()

    assert storage._auth_key is None
    assert storage._encryption_key is None

    is_zeroed = all(b == 0 for b in auth_buf)
    assert is_zeroed, "Память Auth Key не была очищена (занулена)"

    is_zeroed_enc = all(b == 0 for b in enc_buf)
    assert is_zeroed_enc, "Память Enc Key не была очищена (занулена)"


def test_5_password_change_integration(temp_db):
     # Password Change Integration Test
    #  Инициализация и создание хранилища с паролем "A"
    km = KeyManager(temp_db)
    password_a = "PasswordA_Secure123"
    km.setup_new_user(password_a)

    # Добавление 10 записей получаем ключ шифрования для пароля A

    assert km.verify_and_unlock(password_a), "Не удалось разблокировать с паролем A"
    key_a = km.get_encryption_key()
    fernet_a = Fernet(base64.urlsafe_b64encode(key_a))

    test_data = []
    for i in range(10):
        plain_pass = f"SecretData_{i}"
        enc_pass = fernet_a.encrypt(plain_pass.encode()).decode()
        temp_db.add_entry(f"Service_{i}", f"user_{i}", enc_pass, "notes")
        test_data.append(plain_pass)  # Сохраняем открытые пароли для сверки

    #  Смена пароля на "B"
    password_b = "PasswordB_NewSecure456"
    success = km.rotate_keys(password_a, password_b)
    assert success, "Смена пароля не удалась"

    #  проверка доступа с новым паролем
    km.storage.clear()

    assert km.verify_and_unlock(password_b), "Не удалось разблокировать с новым паролем B"
    key_b = km.get_encryption_key()
    fernet_b = Fernet(base64.urlsafe_b64encode(key_b))

    # проверка всех записей
    entries = temp_db.get_all_entries()
    assert len(entries) == 10, "Количество записей изменилось"

    for i, entry in enumerate(entries):
        enc_p = entry['encrypted_password']
        dec_p = fernet_b.decrypt(enc_p.encode()).decode()
        assert dec_p == test_data[i], f"Данные записи {i} повреждены или не расшифровываются"

    print("\nИнтеграционный тест смены пароля пройден успешно.")