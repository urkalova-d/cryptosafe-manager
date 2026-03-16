import sqlite3
import hashlib
import os
from threading import Lock

class DatabaseHelper:
    def __init__(self, db_path="vault.db"):
        self.db_path = db_path
        self._lock = Lock()
        # Создаем постоянное соединение для всего жизненного цикла объекта
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.init_db()

    def get_connection(self):
        return self.conn

    def init_db(self):
        with self._lock:
            cursor = self.conn.cursor()
            # таблица для записей
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT,
                    encrypted_password TEXT NOT NULL,
                    notes TEXT
                )
            """)
            # таблица для настроек мастер пароля, соли и тд
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL
                )
            """)
            self.conn.execute("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)",
                              ("kdf_type", "argon2id"))
            self.conn.commit()

    def migrate_to_v2(self):
        #Простая система миграции
        # Проверка есть ли уже соль в настройках
        if not self.get_setting("kdf_salt"):
            print("Запуск миграции БД на новую систему ключей...")


    def save_setting(self, key, value):
        #сохранение или обновление настройки в базе
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO settings (setting_key, setting_value)
                VALUES (?, ?)
            """, (key, str(value)))
            self.conn.commit()

    def get_setting(self, key):
        #получение значения настройки по ключу
        with self._lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute("SELECT setting_value FROM settings WHERE setting_key = ?", (key,))
                result = cursor.fetchone()
                # Поскольку используем Row, извлекаем по имени колонки
                return result['setting_value'] if result else None
            except (sqlite3.OperationalError, TypeError, AttributeError):
                return None

    def save_master_password(self, password):
        #хеширует пароль через argon2 и сохраняет в настройки
        from src.core.crypto.key_derivation import KeyDerivationService

        kdf = KeyDerivationService()

        master_hash = kdf.create_auth_hash(password)

        # сохранение хеш строки
        self.save_setting("master_hash", master_hash)

    def verify_master_password(self, password):
        #проверка мастер пароля
        from src.core.crypto.key_derivation import KeyDerivationService
        import hashlib

        stored_hash = self.get_setting("master_hash")
        salt_hex = self.get_setting("kdf_salt")

        if not stored_hash or not salt_hex:
            return False

        salt = bytes.fromhex(salt_hex)
        kdf = KeyDerivationService()
        derived_key = kdf.derive_key_argon2(password, salt)

        input_hash = hashlib.sha256(derived_key).hexdigest()
        return input_hash == stored_hash

    def add_entry(self, service, username, encrypted_password, notes=""):
        #добавление новой записи
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO vault_entries (service, username, encrypted_password, notes)
                VALUES (?, ?, ?, ?)
            """, (service, username, encrypted_password, notes))
            self.conn.commit()
            return cursor.lastrowid

    def get_all_entries(self):
        #Возвращает все записи в виде списка
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM vault_entries")
            return [dict(row) for row in cursor.fetchall()]

    def close(self):
        #Закрывает соединение с базой
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()

# Глобальный экземпляр для приложения
db_manager = DatabaseHelper(db_path="vault.db")