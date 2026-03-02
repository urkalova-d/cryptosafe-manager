# tests/test_modules.py
import pytest
from src.database.db import DatabaseHelper
from src.core.crypto.placeholder import AES256Placeholder
from src.core.events import event_bus, EventType


def test_db_schema_creation(db_helper):
    """Проверка создания таблиц (ДБ-1)"""
    conn = db_helper.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    assert "vault_entries" in tables
    assert "audit_log" in tables
    conn.close()


def test_encryption_decryption():
    """Проверка XOR (КРИК-2)"""
    crypto = AES256Placeholder()
    key = b"secret_key"
    data = b"my_password"

    encrypted = crypto.encrypt(data, key)
    decrypted = crypto.decrypt(encrypted, key)

    assert data == decrypted
    assert data != encrypted


def test_event_bus_publishing():
    """Проверка системы событий (ЭВТ-1)"""
    received_data = []

    def callback(data):
        received_data.append(data)

    event_bus.subscribe(EventType.ENTRY_ADDED, callback)
    event_bus.publish(EventType.ENTRY_ADDED, "Test Entry")

    assert len(received_data) == 1
    assert received_data[0] == "Test Entry"