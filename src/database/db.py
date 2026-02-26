import sqlite3
import os

class DatabaseHelper:
    def __init__(self, db_path="vault.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Таблица записей
            cursor.execute('''CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY, title TEXT, username TEXT, 
                encrypted_password BLOB, url TEXT, notes TEXT, tags TEXT)''')
            # Таблица настроек
            cursor.execute('''CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY, setting_key TEXT UNIQUE, setting_value TEXT)''')
            # Таблица логов (Спринт 5)
            cursor.execute('''CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY, action TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            conn.commit()