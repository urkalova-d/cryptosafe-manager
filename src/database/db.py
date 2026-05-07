import sqlite3
import hashlib
import os
from threading import Lock
import json
from datetime import datetime

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


            # Новая таблица аудита
            cursor.execute("""
                            CREATE TABLE IF NOT EXISTS audit_log (
                                sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                                timestamp TEXT NOT NULL,
                                event_type TEXT NOT NULL,
                                severity TEXT NOT NULL,
                                source TEXT,
                                user_id TEXT,
                                details TEXT,
                                previous_hash TEXT NOT NULL,
                                entry_hash TEXT NOT NULL,
                                signature TEXT NOT NULL
                            )
                        """)

            # Таблица для хранения публичных ключей верификации
            cursor.execute("""
                            CREATE TABLE IF NOT EXISTS audit_public_keys (
                                key_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                public_key TEXT NOT NULL,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                is_active INTEGER DEFAULT 1
                            )
                        """)

            # === REQ DB-3: Индексы ===
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_sequence ON audit_log(sequence_number)")

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

            # настройки
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL
                )
            """)
            # Хранилище ключей
            cursor.execute("""
                            CREATE TABLE IF NOT EXISTS key_store (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_type TEXT NOT NULL UNIQUE,
                    key_data TEXT NOT NULL,
                    version INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )
                        """)

            # История поиска
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS search_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Дефолтные настройки
            cursor.execute("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)",
                           ("auto_lock_timeout", "3600"))
            cursor.execute("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)",
                           ("policy_min_length", "12"))

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
            cursor.execute("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)",
                           ("audit_retention_days", "365"))  # Хранить логи 1 год
            cursor.execute("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)",
                           ("audit_max_entries", "10000"))
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

            # Защита от изменения записей
            cursor.execute("""
                            CREATE TRIGGER IF NOT EXISTS prevent_audit_update
                            BEFORE UPDATE ON audit_log
                            FOR EACH ROW
                            BEGIN
                                SELECT RAISE(FAIL, 'SECURITY: Audit logs cannot be updated.');
                            END;
                        """)

            # Защита от удаления записей
            cursor.execute("""
                            CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
                            BEFORE DELETE ON audit_log
                            FOR EACH ROW
                            BEGIN
                                SELECT RAISE(FAIL, 'SECURITY: Audit logs cannot be deleted.');
                            END;
                        """)

            self.conn.commit()

    def add_audit_log(self, event_type: str, entry_id: int = None, details: str = None):
        # Запись события в журнал аудита.

        with self._lock:
            try:
                self.conn.execute("""
                    INSERT INTO audit_log (event_type, entry_id, details)
                    VALUES (?, ?, ?)
                """, (event_type, entry_id, details))
                self.conn.commit()
            except Exception as e:
                print(f"[DB] Error writing audit log: {e}")

    def get_audit_logs(self, limit=100):
        with self._lock:
            cursor = self.conn.execute("""
                SELECT timestamp, event_type, entry_id, details 
                FROM audit_log 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            return cursor.fetchall()

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

    def add_audit_entry(self, entry_data: dict, signature_hex: str, entry_hash: str, prev_hash: str):
        """Добавляет подписанную запись в журнал аудита."""
        with self._lock:
            self.conn.execute("""
                INSERT INTO audit_log 
                (timestamp, event_type, severity, source, user_id, details, previous_hash, entry_hash, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry_data['timestamp'],
                entry_data['event_type'],
                entry_data['severity'],
                entry_data.get('source'),
                entry_data.get('user_id'),
                json.dumps(entry_data.get('details', {})),
                prev_hash,
                entry_hash,
                signature_hex
            ))
            self.conn.commit()

    def get_last_audit_entry(self):
        """Получает последнюю запись для построения цепочки."""
        with self._lock:
            cursor = self.conn.execute("""
                SELECT sequence_number, entry_hash 
                FROM audit_log 
                ORDER BY sequence_number DESC LIMIT 1
            """)
            return cursor.fetchone()

    def get_audit_entries(self, limit=100, offset=0):
        """Получает список записей с пагинацией."""
        with self._lock:
            cursor = self.conn.execute("""
                SELECT sequence_number, timestamp, event_type, severity, source, user_id, details, signature
                FROM audit_log 
                ORDER BY sequence_number DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
            return cursor.fetchall()

    def get_filtered_audit_logs(self, limit: int, offset: int, filters: dict = None):
        """
        Получает отфильтрованные логи с пагинацией.
        Возвращает (список записей, общее количество записей).
        """
        with self._lock:
            base_query = "FROM audit_log WHERE 1=1"
            params = []

            if filters:
                # Фильтр по типу (начинается с...)
                if filters.get('event_type_like'):
                    base_query += " AND event_type LIKE ?"
                    params.append(filters['event_type_like'])

                # Фильтр по важности
                if filters.get('severity'):
                    base_query += " AND severity = ?"
                    params.append(filters['severity'])

                # Фильтр по дате (строго ISO формат)
                if filters.get('start_date'):
                    base_query += " AND timestamp >= ?"
                    params.append(filters['start_date'])
                if filters.get('end_date'):
                    base_query += " AND timestamp <= ?"
                    params.append(filters['end_date'])

                # Поиск по тексту (подстрока)
                if filters.get('search_text_like'):
                    base_query += " AND (event_type LIKE ? OR severity LIKE ? OR timestamp LIKE ? OR details LIKE ?)"
                    search_param = filters['search_text_like']
                    # Добавляем параметр 4 раза для каждого OR условия
                    params.extend([search_param, search_param, search_param, search_param])

            # Запрос общего количества
            count_query = f"SELECT COUNT(*) {base_query}"
            cursor = self.conn.execute(count_query, params)
            total_count = cursor.fetchone()[0]

            # Запрос данных с пагинацией
            data_query = f"SELECT * {base_query} ORDER BY sequence_number DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = self.conn.execute(data_query, params)
            rows = cursor.fetchall()

            return rows, total_count

    def save_audit_public_key(self, public_key_hex: str):
        """Сохраняет публичный ключ верификации."""
        with self._lock:
            # Деактивируем старые ключи
            self.conn.execute("UPDATE audit_public_keys SET is_active = 0")
            self.conn.execute("""
                INSERT INTO audit_public_keys (public_key, is_active)
                VALUES (?, 1)
            """, (public_key_hex,))
            self.conn.commit()

    def get_active_public_key(self):
        with self._lock:
            cursor = self.conn.execute("SELECT public_key FROM audit_public_keys WHERE is_active = 1 LIMIT 1")
            row = cursor.fetchone()
            return row[0] if row else None

    def cleanup_old_audit_logs(self):
        """Удаляет логи старше указанного количества дней или при превышении лимита."""
        retention_days = int(self.get_setting("audit_retention_days") or 365)
        max_entries = int(self.get_setting("audit_max_entries") or 10000)

        with self._lock:
            try:
                # Удаляем по дате
                self.conn.execute(f"""
                    DELETE FROM audit_log 
                    WHERE timestamp < datetime('now', '-{retention_days} days')
                """)

                # Если записей все еще слишком много, удаляем самые старые
                cursor = self.conn.execute("SELECT COUNT(*) FROM audit_log")
                count = cursor.fetchone()[0]

                if count > max_entries:
                    limit_to_delete = count - max_entries
                    print(f"[DB] Audit log cleanup: removing {limit_to_delete} oldest entries.")
                    # Находим ID записи, с которого нужно удалить
                    cursor = self.conn.execute(f"""
                        SELECT sequence_number FROM audit_log 
                        ORDER BY sequence_number ASC 
                        LIMIT 1 OFFSET {max_entries}
                    """)
                    row = cursor.fetchone()
                    if row:
                        threshold_id = row[0]
                        # Так как у нас триггер на DELETE, его нужно временно отключить или обойти
                        # Но так как триггер защищает от удаления, очистка должна быть привилегированной.
                        # Самый простой способ - удалить триггер, очистить, создать триггер.
                        # ИЛИ использовать флаг "hard_delete" в настройках (но это сложно).
                        # ДЛЯ COMP-3: Рекомендуется отключать защиту для операции очистки.

                        # Отключаем триггер
                        self.conn.execute("DROP TRIGGER IF EXISTS prevent_audit_delete")

                        self.conn.execute(f"DELETE FROM audit_log WHERE sequence_number < {threshold_id}")
                        self.conn.commit()

                        # Восстанавливаем триггер
                        self.conn.execute("""
                            CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
                            BEFORE DELETE ON audit_log
                            FOR EACH ROW
                            BEGIN
                                SELECT RAISE(FAIL, 'SECURITY: Audit logs cannot be deleted.');
                            END;
                        """)
                        self.conn.commit()

                print("[DB] Audit log retention cleanup complete.")
            except Exception as e:
                print(f"[DB] Error during audit cleanup: {e}")
                # Восстанавливаем триггер в случае ошибки
                try:
                    self.conn.execute("""
                        CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
                        BEFORE DELETE ON audit_log
                        FOR EACH ROW
                        BEGIN
                            SELECT RAISE(FAIL, 'SECURITY: Audit logs cannot be deleted.');
                        END;
                    """)
                    self.conn.commit()
                except:
                    pass




db_manager = DatabaseHelper(db_path="vault.db")