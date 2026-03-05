import pytest
import os
from src.database.db import DatabaseHelper


@pytest.fixture
def temp_db():
    test_db_path = "test_vault.db"
    # Перед созданием убедимся, что старый файл удален
    if os.path.exists(test_db_path):
        try:
            os.remove(test_db_path)
        except:
            pass

    helper = DatabaseHelper(db_path=test_db_path)
    yield helper

    # Явно закрываем, если helper хранит соединение
    helper.close()

    # Даем системе небольшую паузу (иногда Windows не успевает)
    import time
    time.sleep(0.1)

    if os.path.exists(test_db_path):
        try:
            os.remove(test_db_path)
        except:
            pass


def test_init_db(temp_db):
    """Проверка создания таблиц"""
    conn = temp_db.get_connection()
    cursor = conn.cursor()

    # Проверяем наличие таблицы vault_entries
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vault_entries'")
    assert cursor.fetchone() is not None


def test_add_and_get_entry(temp_db):
    """Проверка записи и чтения (Пункт 2 ТЗ)"""
    temp_db.add_entry("Google", "user@gmail.com", "encrypted_blob_here")
    entries = temp_db.get_all_entries()

    assert len(entries) == 1
    assert entries[0]['title'] == "Google"
    # Проверяем, что пароль хранится в том виде, в котором пришел (уже зашифрованным)
    assert entries[0]['encrypted_password'] == "encrypted_blob_here"