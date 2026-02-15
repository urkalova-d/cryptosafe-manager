import sqlite3
import os


class DatabaseHelper:
    def __init__(self, db_path="vault.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Установка версии (Requirement DB-3)
            cursor.execute("PRAGMA user_version = 1")

            # Таблица записей (Requirement DB-1)
            cursor.execute('''CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT, username TEXT, encrypted_password BLOB,
                url TEXT, notes TEXT, tags TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

            # Таблица логов (Requirement DB-1)
            cursor.execute('''CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                entry_id INTEGER, details TEXT, signature TEXT)''')

            # Таблица настроек (Requirement DB-1)
            cursor.execute('''CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE, setting_value TEXT, encrypted BOOLEAN)''')

            conn.commit()