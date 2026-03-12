import sqlite3
from threading import Lock
from tkinter import messagebox
from src.core.events import event_bus, EventType
from src.core.key_manager import KeyManager

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
                        title TEXT NOT NULL,
                        username TEXT,
                        encrypted_password TEXT NOT NULL,
                        url TEXT,
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
                # таблица логов(для тестов модулей)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        action TEXT NOT NULL
                    )
                """)
                conn.commit()

    def close(self):
        # закрытие все соединения (нужно для тестов в windows)
        pass

    def add_entry(self, title, username, encrypted_password, url="", notes=""):
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO vault_entries (title, username, encrypted_password, url, notes)
                    VALUES (?, ?, ?, ?, ?)
                """, (title, username, encrypted_password, url, notes))
                conn.commit()
                return cursor.lastrowid

    def get_all_entries(self):
        with self._lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM vault_entries")
                return cursor.fetchall()

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
                return result[0] if result else None


    def save_master_password(self, password):
        # хеширует пароль и сохраняет соль и хеш в бд
        km = KeyManager()
        # генерация ключа(соль создается автоматически внутри km)
        derived_key = km.derive_key(password)

        self.save_setting("master_salt", km.salt.hex())
        self.save_setting("master_hash", derived_key.hex())
        event_bus.publish(EventType.SETTINGS_CHANGED, "Master password set")

    def verify_master_password(self, password):
        #проверка введеного пароля
        salt_str = self.get_setting("master_salt")
        stored_hash_str = self.get_setting("master_hash")

        if not salt_str or not stored_hash_str:
            return False

        km = KeyManager()
        salt = bytes.fromhex(salt_str)
        # генерирование ключа с той же солью
        derived_key = km.derive_key(password, salt)

        return derived_key.hex() == stored_hash_str

    def close(self):
        # Закрываем соединение для тестов
        if hasattr(self, 'conn') and self.conn:
                self.conn.close()
db_manager = DatabaseHelper(db_path="vault.db")