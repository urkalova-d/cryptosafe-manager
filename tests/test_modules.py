import pytest
from src.database.db import DatabaseHelper
from src.core.crypto.placeholder import AES256Placeholder
from src.core.events import event_bus, EventType

def test_db_schema_actual(db_helper):
    #Проверка,что колонки в базе соответствуют коду
    conn = db_helper.get_connection()
    cursor = conn.cursor()

    # проверка структуры таблицы
    cursor.execute("PRAGMA table_info(vault_entries)")
    columns = [row[1] for row in cursor.fetchall()]

    assert "service" in columns
    assert "encrypted_password" in columns
    conn.close()

def test_encryption_decryption():
    #Проверка XOR
    crypto = AES256Placeholder()
    key = b"secret_key"
    data = b"my_password"

    encrypted = crypto.encrypt(data, key)
    decrypted = crypto.decrypt(encrypted, key)

    assert data == decrypted
    assert data != encrypted


def test_event_bus_publishing():
    #Проверка системы событий
    received_data = []

    def callback(data):
        received_data.append(data)

    event_bus.subscribe(EventType.ENTRY_ADDED, callback)
    event_bus.publish(EventType.ENTRY_ADDED, "Test Entry")

    assert len(received_data) == 1
    assert received_data[0] == "Test Entry"