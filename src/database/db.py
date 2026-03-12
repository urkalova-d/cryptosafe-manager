import sqlite3
import hashlib
import os
from threading import Lock

class DatabaseHelper:
    def __init__(self, db_path="vault.db"):
        self.db_path = db_path
        self._lock = Lock()
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                # основная таблица записей
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS vault_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service TEXT NOT NULL,
                        username TEXT,
                        encrypted_password TEXT NOT NULL,
                        notes TEXT
                    )
                """)
                # таблица настроек
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        setting_key TEXT UNIQUE NOT NULL,
                        setting_value TEXT NOT NULL
                    )
                """)
                conn.commit()

    def save_setting(self, key, value):
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO settings (setting_key, setting_value)
                    VALUES (?, ?)
                """, (key, str(value)))
                conn.commit()

    def get_setting(self, key):
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT setting_value FROM settings WHERE setting_key = ?", (key,))
                result = cursor.fetchone()
                return result["setting_value"] if result else None

    def save_master_password(self, password):
        #  сохранение мастерпароля с хешированием и солью
        salt = os.urandom(16).hex()  # Генерация соли
        # хеширование
        payload = (password + salt).encode('utf-8')
        password_hash = hashlib.sha256(payload).hexdigest()

        #сохранение хеша и соли
        self.save_setting("master_hash", password_hash)
        self.save_setting("master_salt", salt)

    def verify_master_password(self, password):
        # проверка введенного пароля
        stored_hash = self.get_setting("master_hash")
        salt = self.get_setting("master_salt")

        if not stored_hash or not salt:
            return False

        #повторение процесса хеширования с введенным паролем
        payload = (password + salt).encode('utf-8')
        input_hash = hashlib.sha256(payload).hexdigest()

        return input_hash == stored_hash

    def add_entry(self, service, username, encrypted_password, notes=""):
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO vault_entries (service, username, encrypted_password, notes)
                    VALUES (?, ?, ?, ?)
                """, (service, username, encrypted_password, notes))
                conn.commit()
                return cursor.lastrowid

    def get_all_entries(self):
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM vault_entries")

                return [dict(row) for row in cursor.fetchall()]

    def close(self):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()

# создание глобального экземпляра
db_manager = DatabaseHelper(db_path="vault.db")