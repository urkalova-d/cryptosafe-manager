
import pytest
import os
from src.database.db import DatabaseHelper


@pytest.fixture
def db_helper():
    test_db = "test_vault.db"
    # очистка перед тестом
    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except:
            pass

    db = DatabaseHelper(test_db)
    yield db

    #безопасное закрытие
    if hasattr(db, 'close'):
        db.close()

    # Небольшая пауза, чтобы Windows успела "отпустить" файл
    import time
    time.sleep(0.1)

    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except:
            pass