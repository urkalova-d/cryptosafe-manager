import sqlite3
import hashlib
import os
from threading import Lock
import json

class DatabaseHelper:
    def __init__(self, db_path="vault.db"):
        self.db_path = db_path
        self._lock = Lock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=20)
        self.conn.row_factory = sqlite3.Row
        #  режим WAL для многопоточности и оптимизации
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
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
            # корзина
            cursor.execute("""
                            CREATE TABLE IF NOT EXISTS deleted_entries (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                encrypted_data BLOB NOT NULL,
                                original_created_at TIMESTAMP,
                                deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                expiration_timestamp TIMESTAMP
                            )
                        """)
            # история паролей
            cursor.execute("""
                           CREATE TABLE IF NOT EXISTS password_history (
                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                               password_hash TEXT NOT NULL,
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS search_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_created_at ON vault_entries(created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_updated_at ON vault_entries(updated_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_tags ON vault_entries(tags)")

            # Создаем виртуальную таблицу для поиска по тегам
            cursor.execute("""
                            CREATE VIRTUAL TABLE IF NOT EXISTS vault_entries_fts USING fts5(
                                tags, 
                                content=vault_entries, 
                                content_rowid=id
                            )
                        """)
            # Триггеры для автоматического обновления поискового индекса
            cursor.execute("""
                            CREATE TRIGGER IF NOT EXISTS vault_ai AFTER INSERT ON vault_entries BEGIN
                                INSERT INTO vault_entries_fts(rowid, tags) VALUES (new.id, new.tags);
                            END
                        """)
            cursor.execute("""
                            CREATE TRIGGER IF NOT EXISTS vault_ad AFTER DELETE ON vault_entries BEGIN
                                INSERT INTO vault_entries_fts(vault_entries_fts, rowid, tags) 
                                VALUES ('delete', old.id, old.tags);
                            END
                        """)
            cursor.execute("""
                            CREATE TRIGGER IF NOT EXISTS vault_au AFTER UPDATE ON vault_entries BEGIN
                                INSERT INTO vault_entries_fts(vault_entries_fts, rowid, tags) 
                                VALUES ('delete', old.id, old.tags);
                                INSERT INTO vault_entries_fts(rowid, tags) VALUES (new.id, new.tags);
                            END
                        """)

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
        #Сохраняет зашифрованный JSON-блоб и метаданные
        with self._lock:
            try:
                if not isinstance(encrypted_data, bytes):
                    encrypted_data = bytes(encrypted_data)

                print(f"[DB] Saving {len(encrypted_data)} bytes")

                self.conn.execute("BEGIN TRANSACTION")
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO vault_entries (encrypted_data, tags, created_at, updated_at)
                    VALUES (?, ?, datetime('now'), datetime('now'))
                """, (sqlite3.Binary(encrypted_data), tags))
                entry_id = cursor.lastrowid
                self.conn.commit()
                return entry_id
            except Exception as e:
                self.conn.rollback()
                print(f"[DB] Error in add_entry: {e}")
                raise e

    def get_entry(self, entry_id: int):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT id, encrypted_data, created_at, updated_at, tags FROM vault_entries WHERE id = ?",
                           (entry_id,))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                # Конвертируем encrypted_data
                if 'encrypted_data' in result and isinstance(result['encrypted_data'], memoryview):
                    result['encrypted_data'] = bytes(result['encrypted_data'])
                return result
            return None

    def get_all_entries(self):
        #Возвращает список словарей с id, зашифрованными данными и метаданными
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT id, encrypted_data, created_at, updated_at, tags FROM vault_entries")
            result = []
            for row in cursor.fetchall():
                row_dict = {}
                row_dict['id'] = row['id']
                # Принудительно конвертируем в bytes
                enc_data = row['encrypted_data']
                if isinstance(enc_data, memoryview):
                    enc_data = bytes(enc_data)
                row_dict['encrypted_data'] = enc_data
                row_dict['created_at'] = row['created_at']
                row_dict['updated_at'] = row['updated_at']
                row_dict['tags'] = row['tags']
                result.append(row_dict)
            return result


    def update_entry(self, entry_id: int, encrypted_data: bytes, tags: str = None):
        #Обновление записи
        with self._lock:
            try:
                if tags is not None:
                    self.conn.execute(
                        "UPDATE vault_entries SET encrypted_data = ?, tags = ?, updated_at = datetime('now') WHERE id = ?",
                        (sqlite3.Binary(encrypted_data), tags, entry_id)
                    )
                else:
                    self.conn.execute(
                        "UPDATE vault_entries SET encrypted_data = ?, updated_at = datetime('now') WHERE id = ?",
                        (sqlite3.Binary(encrypted_data), entry_id)
                    )
                self.conn.commit()
                return True
            except Exception as e:
                self.conn.rollback()
                print(f"Ошибка БД при обновлении: {e}")
                return False

    def delete_entry(self, entry_id: int):
        #Удаление записи
        with self._lock:
            self.conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
            self.conn.commit()

    def add_password_to_history(self, password_hash: str):
        #Добавляет хеш пароля в историю
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("INSERT INTO password_history (password_hash) VALUES (?)", (password_hash,))

            # Оставляем только последние 20 записей
            # Получаем ID 20-й с конца записи
            cursor.execute("""
                SELECT id FROM password_history ORDER BY id DESC LIMIT 1 OFFSET 20
            """)
            row = cursor.fetchone()
            if row:
                # Удаляем всё, что старше этого ID
                cursor.execute("DELETE FROM password_history WHERE id < ?", (row['id'],))

            self.conn.commit()

    def is_password_in_history(self, password_hash: str) -> bool:
        #Проверяет, был ли такой пароль недавно
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT id FROM password_history WHERE password_hash = ?", (password_hash,))
            return cursor.fetchone() is not None

    def rotate_vault_keys(self, new_master_hash, new_auth_salt, new_enc_salt, re_encrypted_data):
        #Атомарное обновление при смене пароля
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

    def soft_delete_entry(self, entry_id: int, expiration_days: int = 30):
        #Перемещает запись в таблицу deleted_entrie
        with self._lock:
            try:
                self.conn.execute("BEGIN TRANSACTION")

                # Получаем данные записи
                cursor = self.conn.cursor()
                cursor.execute("SELECT encrypted_data, created_at FROM vault_entries WHERE id = ?", (entry_id,))
                row = cursor.fetchone()
                if not row:
                    raise ValueError("Entry not found")

                enc_data = row['encrypted_data']
                orig_created = row['created_at']

                # Вставляем в deleted_entries
                # Вычисляем дату автоматического удаления
                self.conn.execute("""
                    INSERT INTO deleted_entries (id, encrypted_data, original_created_at, deleted_at, expiration_timestamp)
                    VALUES (?, ?, ?, datetime('now'), datetime('now', '+' || ? || ' days'))
                """, (entry_id, enc_data, orig_created, expiration_days))

                #  Удаляем из основной таблицы
                self.conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

                self.conn.commit()
                return True
            except Exception as e:
                self.conn.rollback()
                print(f"Error during soft delete: {e}")
                raise e

    def hard_delete_entry(self, entry_id: int):
        #Полное удаление из корзины
        with self._lock:
            self.conn.execute("DELETE FROM deleted_entries WHERE id = ?", (entry_id,))
            self.conn.commit()

    def close(self):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
            
    def save_search_query(self, query_text: str):
        with self._lock:
            # Удаляем дубликат, если есть
            self.conn.execute("DELETE FROM search_history WHERE query = ?", (query_text,))
            # Вставляем новый
            self.conn.execute("INSERT INTO search_history (query) VALUES (?)", (query_text,))
            # Ограничиваем историю 10 записями
            self.conn.execute("""
                DELETE FROM search_history WHERE id NOT IN 
                (SELECT id FROM search_history ORDER BY timestamp DESC LIMIT 10)
            """)
            self.conn.commit()

    def get_search_history(self):
        with self._lock:
            cursor = self.conn.execute("SELECT query FROM search_history ORDER BY timestamp DESC")
            return [row['query'] for row in cursor.fetchall()]

    def cleanup_expired_deleted(self):
        self.conn.execute("DELETE FROM deleted_entries WHERE expiration_timestamp <= datetime('now')")



db_manager = DatabaseHelper(db_path="vault.db")