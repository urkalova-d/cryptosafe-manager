# tests/test_sprint6_arch.py
import pytest
import os
import sys
import json
import tempfile

# Добавляем путь к проекту
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Импортируем наши новые модули
from src.core.import_export.exporter import VaultExporter
from src.core.import_export.importer import VaultImporter
from src.core.import_export.key_exchange import KeyExchangeService


# --- Mocks (Имитация зависимостей) ---

class MockDBHelper:
    """Имитация базы данных."""
    pass


class MockKeyManager:
    """Имитация менеджера ключей (для EntryManager)."""

    def get_encryption_key(self):
        # В реальности это мастер-ключ, но для теста экспорта он не важен,
        # так как мы используем пароль экспорта.
        return b'master_key_32bytes_dummy_value_!!'


class MockEncryptionService:
    """Имитация сервиса шифрования."""

    def decrypt_entry(self, data):
        # Просто возвращаем данные как есть (имитируем расшифровку)
        return data


class MockEntryManager:
    """Имитация менеджера записей."""
    def __init__(self):
        self.entries = [
            {"id": 1, "service": "Google", "username": "user1", "password": "pass1", "url": "google.com"},
            {"id": 2, "service": "GitHub", "username": "dev1", "password": "secret", "url": "github.com"},
            {"id": 3, "service": "Bank", "username": "rich", "password": "money", "url": "bank.com"},
        ]

    def get_all_entries(self):
        return [dict(e) for e in self.entries]

    def get_entry(self, entry_id):
        for e in self.entries:
            if e['id'] == entry_id:
                return dict(e)
        return None

    def create_entry(self, data):
        # ИСПРАВЛЕНО: Теперь мок реально добавляет запись, чтобы тест проходил
        new_id = len(self.entries) + 1
        new_entry = dict(data)
        new_entry['id'] = new_id
        self.entries.append(new_entry)
        print(f"[Mock] Entry created with ID: {new_id}")
        return new_id


# --- Тесты ---

def test_module_imports():
    """Проверка ARC-1: Модули доступны для импорта."""
    assert VaultExporter is not None
    assert VaultImporter is not None
    assert KeyExchangeService is not None
    print("✅ Test 1 PASSED: Modules imported successfully.")


def test_export_encryption_key_separation():
    """Проверка ARC-2: Экспорт использует отдельный ключ."""
    exporter = VaultExporter(MockEntryManager())

    # Создаем временный файл
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp_path = tmp.name

    try:
        # Экспортируем с паролем "export_pass"
        exporter.export_vault(tmp_path, password="export_pass", entry_ids=None)

        # Читаем файл
        with open(tmp_path, 'r') as f:
            data = json.load(f)

        # Проверяем структуру
        assert "encryption" in data
        assert "data" in data
        assert data['encryption']['kdf'] == "PBKDF2-SHA256"

        # Проверяем, что данные не в открытом виде
        assert "Google" not in str(data['data'])
        print("✅ Test 2 PASSED: Export encryption (Key Separation) works.")

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_selective_export():
    """Проверка ARC-3: Выборочный экспорт записей."""
    mock_manager = MockEntryManager()
    exporter = VaultExporter(mock_manager)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp_path = tmp.name

    try:
        # Экспортируем ТОЛЬКО запись с ID 1 и 2 (Google и GitHub)
        target_ids = [1, 2]
        exporter.export_vault(tmp_path, password="pass", entry_ids=target_ids)

        # Расшифровываем и проверяем содержимое через Импортер (или просто смотрим метаданные)
        # Для чистоты теста, просто проверим, что файл создался и в нем есть метаданные count
        # Но лучше проверим через импортер в следующем тесте.

        # Здесь проверим, что count соответствует количеству выбранных
        # Для этого нам нужно расшифровать. Используем Importer.
        importer = VaultImporter(mock_manager)
        # Подменяем create_entry, чтобы просто посчитать
        imported_count = []
        original_create = mock_manager.create_entry
        mock_manager.create_entry = lambda x: imported_count.append(1)

        importer.import_vault(tmp_path, "pass")

        assert len(imported_count) == 2, "Should import only 2 selected entries"
        print("✅ Test 3 PASSED: Selective export works.")

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_round_trip_integrity():
    """Полный цикл: Экспорт -> Файл -> Импорт."""
    source_manager = MockEntryManager()

    # Создаем целевой менеджер и ЯВНО очищаем его список перед тестом
    target_manager = MockEntryManager()
    target_manager.entries = []

    exporter = VaultExporter(source_manager)
    importer = VaultImporter(target_manager)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp_path = tmp.name

    try:
        # 1. Экспорт
        exporter.export_vault(tmp_path, password="secure_pass")

        # 2. Импорт
        stats = importer.import_vault(tmp_path, "secure_pass")

        # Проверяем статистику
        assert stats['imported'] == 3, "Stats should report 3 imported entries"

        # Проверяем, что в целевом менеджере теперь 3 записи
        # (Спасибо исправленному моку, это теперь работает)
        assert len(target_manager.entries) == 3, "Target manager should have 3 entries"

        print(f"Stats: {stats}")
        print("✅ Test 4 PASSED: Round-trip integrity verified.")

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_key_exchange_qr():
    """Тест генерации QR кода."""
    service = KeyExchangeService()

    # Генерируем пару ключей (проверка CRY-2)
    private, public_pem = service.generate_key_pair()
    assert private is not None
    assert b"BEGIN PUBLIC KEY" in public_pem

    # Генерируем QR (проверка QR-1)
    qr_buffer = service.generate_qr_code(public_pem.decode('utf-8'))

    # Проверяем, что это PNG (первые байты PNG сигнатуры)
    qr_buffer.seek(0)
    header = qr_buffer.read(8)
    assert header[:4] == b'\x89PNG'

    print("✅ Test 5 PASSED: Key exchange and QR generation work.")


if __name__ == "__main__":
    print("--- Running Sprint 6 Architecture Tests ---")
    test_module_imports()
    test_export_encryption_key_separation()
    test_selective_export()
    test_round_trip_integrity()
    test_key_exchange_qr()
    print("\n🎉 All Architecture Tests Passed!")