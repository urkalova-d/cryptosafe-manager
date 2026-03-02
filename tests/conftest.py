# tests/conftest.py (файл настроек pytest)
import pytest
import os
from src.database.db import DatabaseHelper


@pytest.fixture
def db_helper():
    """Фикстура для создания тестовой БД перед каждым тестом"""
    test_db = "test_vault.db"
    if os.path.exists(test_db):
        os.remove(test_db)

    db = DatabaseHelper(test_db)
    yield db

    # Очистка после теста
    db.get_connection().close()
    if os.path.exists(test_db):
        os.remove(test_db)