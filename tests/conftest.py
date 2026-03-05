# tests/conftest.py (файл настроек pytest)
import pytest
import os
from src.database.db import DatabaseHelper


@pytest.fixture
def db_helper():
    test_db = "test_vault.db"
    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except:
            pass

    db = DatabaseHelper(test_db)
    yield db

    # Закрываем соединение внутри объекта, если оно там есть
    db.close()

    import time
    time.sleep(0.1)  # Пауза для Windows

    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except:
            pass