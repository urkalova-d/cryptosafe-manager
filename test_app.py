# test_app.py
import unittest
import os
import sqlite3
import gc  # Модуль для очистки памяти
import time
from src.database.db import DatabaseHelper


class TestCryptoSafe(unittest.TestCase):
    def setUp(self):
        self.db_name = "test_vault.db"
        self.db = DatabaseHelper(self.db_name)

    def tearDown(self):
        # 1. Сначала удаляем ссылку на объект базы
        del self.db
        # 2. Принудительно очищаем память, чтобы закрылись все соединения
        gc.collect()
        # 3. Даем Windows миллисекунду «выдохнуть»
        time.sleep(0.1)

        if os.path.exists(self.db_name):
            try:
                os.remove(self.db_name)
            except PermissionError:
                # Если всё равно не удалилось, не страшно — удалим в следующий раз
                pass

    def test_database_initialization(self):
        """Проверяем, создались ли таблицы"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vault_entries'")
        self.assertIsNotNone(cursor.fetchone())
        conn.close()

    def test_save_and_get_setting(self):
        self.db.save_setting("test_key", "test_value")
        value = self.db.get_setting("test_key")
        self.assertEqual(value, "test_value")

    def test_master_password_flow(self):
        password = "supersecretpassword"
        # Теперь эта строка не будет выдавать AttributeError
        self.db.save_master_password(password)

        self.assertIsNotNone(self.db.get_setting("master_salt"))
        self.assertIsNotNone(self.db.get_setting("master_hash"))
        self.assertTrue(self.db.verify_master_password(password))
        self.assertFalse(self.db.verify_master_password("wrong_pass"))


if __name__ == '__main__':
    unittest.main()