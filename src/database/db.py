import sqlite3
import hashlib
import os
from threading import Lock
import json

class DatabaseHelper:
    def __init__(self, db_path="vault.db"):
        self.db_path = db_path
        self._lock = Lock()
        # Создаем постоянное соединение для всего жизненного цикла объекта
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False , timeout=20)
        self.conn.row_factory = sqlite3.Row
        self.init_db()

    def get_connection(self):
        return self.conn

    def init_db(self):
        with self._lock:
            cursor = self.conn.cursor()
            # таблица для записей (хранится только ID и зашифрованный BLOB)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    encrypted_data BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    tags TEXT
                )
            """)
            # таблица для настроек мастер пароля, соли и тд
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL
                )
            """)
            cursor.execute("""
                            CREATE TABLE IF NOT EXISTS key_store (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_type TEXT NOT NULL UNIQUE,
                    key_data TEXT NOT NULL,
                    version INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )
                        """)
            cursor.execute("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)",
                           ("auto_lock_timeout", "3600"))
            # Политика паролей: минимум 12 символов
            cursor.execute("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)",
                           ("policy_min_length", "12"))

            self.conn.commit()

    def save_key_store(self, key_type: str, key_data: bytes, version: int = 1):
        #сохранение соли и параметров

        with self._lock:
            cursor = self.conn.cursor()
            # Сохраняем hex-строку байтов
            cursor.execute("""
                INSERT OR REPLACE INTO key_store (key_type, key_data, version, created_at)
                VALUES (?, ?, ?, datetime('now'))
            """, (key_type, key_data.hex(), version))
            self.conn.commit()

    def get_key_store(self, key_type: str):
        #возвращает байты данных ключа
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT key_data, version FROM key_store WHERE key_type = ?", (key_type,))
            row = cursor.fetchone()
            if row:
                return bytes.fromhex(row['key_data']), row['version']
            return None, None

    def migrate_to_v2(self):
        #Простая система миграции
        # Проверка есть ли уже соль в настройках
        if not self.get_setting("kdf_salt"):
            print("Запуск миграции БД на новую систему ключей...")


    def save_setting(self, key, value):
        with self._lock:
            self.conn.execute("INSERT OR REPLACE INTO settings (setting_key, setting_value) VALUES (?, ?)",
                              (key, str(value)))
            self.conn.commit()

    def get_setting(self, key):
        #получение значения настройки по ключу
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT setting_value FROM settings WHERE setting_key = ?", (key,))
            row = cursor.fetchone()
            return row[0] if row else None

    def save_master_password(self, password):
        #хеширует пароль через argon2 и сохраняет в настройки
        #from src.core.crypto.key_derivation import KeyDerivationService
        #kdf = KeyDerivationService()
        #master_hash = kdf.create_auth_hash(password)
        # сохранение хеш строки
        #self.save_setting("master_hash", master_hash)
        pass
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

    def add_entry(self, encrypted_data: bytes, tags: str = ""):
        """Сохраняет зашифрованный JSON-блоб и метаданные."""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO vault_entries (encrypted_data, tags, created_at, updated_at)
                VALUES (?, ?, datetime('now'), datetime('now'))
            """, (encrypted_data, tags))
            self.conn.commit()
            return cursor.lastrowid

    def get_all_entries(self):
        """Возвращает список словарей с id, зашифрованными данными и метаданными."""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT id, encrypted_data, created_at, updated_at, tags FROM vault_entries")
            return [dict(row) for row in cursor.fetchall()]

    def update_entry(self, entry_id: int, encrypted_data: bytes, tags: str = None):
        """Обновление записи."""
        with self._lock:
            if tags is not None:
                self.conn.execute("UPDATE vault_entries SET encrypted_data = ?, tags = ?, updated_at = datetime('now') WHERE id = ?",
                                  (encrypted_data, tags, entry_id))
            else:
                self.conn.execute("UPDATE vault_entries SET encrypted_data = ?, updated_at = datetime('now') WHERE id = ?",
                                  (encrypted_data, entry_id))
            self.conn.commit()

    def delete_entry(self, entry_id: int):
        """Удаление записи."""
        with self._lock:
            self.conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
            self.conn.commit()

    def rotate_vault_keys(self, new_master_hash, new_auth_salt, new_enc_salt, re_encrypted_data):
        """Атомарное обновление при смене пароля."""
        with self._lock:
            try:
                self.conn.execute("BEGIN TRANSACTION")

                self.conn.execute("INSERT OR REPLACE INTO settings (setting_key, setting_value) VALUES (?, ?)",
                                      ("master_hash", new_master_hash))

                self.conn.execute("""
                        INSERT OR REPLACE INTO key_store (key_type, key_data, version, created_at)
                        VALUES (?, ?, 1, datetime('now'))
                    """, ("auth_salt", new_auth_salt.hex()))

                self.conn.execute("""
                        INSERT OR REPLACE INTO key_store (key_type, key_data, version, created_at)
                        VALUES (?, ?, 1, datetime('now'))
                    """, ("encryption_salt", new_enc_salt.hex()))

                # Обновляем BLOB-ы
                for entry_id, new_blob in re_encrypted_data:
                    self.conn.execute(
                            "UPDATE vault_entries SET encrypted_data = ? WHERE id = ?",
                            (new_blob, entry_id)
                        )

                self.conn.commit()
                return True
            except Exception as e:
                self.conn.rollback()
                print(f"Ошибка при ротации в БД: {e}")
                raise e

        def close(self):
            if hasattr(self, 'conn') and self.conn:
                self.conn.close()

db_manager = DatabaseHelper(db_path="vault.db")