import unittest
import os
from src.database.db import DatabaseHelper


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_vault.db"
        self.db = DatabaseHelper(self.db_path)

    def tearDown(self):
        import time
        self.db.close()
        time.sleep(0.2)  # Даем Windows время освободить дескриптор файла
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except PermissionError:
                pass

    def test_master_password_flow(self):
        #Проверка хеширования и соли
        password = "secure_master_123"
        self.db.save_master_password(password)

        # прроверка,что соль создана
        salt = self.db.get_setting("master_salt")
        self.assertIsNotNone(salt)

        #проверка верификации
        self.assertTrue(self.db.verify_master_password(password))
        self.assertFalse(self.db.verify_master_password("wrong_password"))

    def test_entry_persistence(self):
        # проверка сохранения и извлечения записей
        self.db.add_entry("Yandex", "daria_dev", "pass789", "Test note")

        records = self.db.get_all_entries()
        self.assertEqual(len(records), 1)
        # Проверка доступа через ключи
        self.assertEqual(records[0]['service'], "Yandex")
        self.assertEqual(records[0]['notes'], "Test note")