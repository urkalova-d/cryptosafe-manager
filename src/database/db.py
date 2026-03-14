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
            # Таблица для записей
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT,
                    encrypted_password TEXT NOT NULL,
                    notes TEXT
                )
            """)
            # Таблица для настроек (мастер-пароль, соль и т.д.)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL
                )
            """)
            self.conn.commit()

    def save_setting(self, key, value):
        """Сохраняет или обновляет настройку в базе"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO settings (setting_key, setting_value)
                VALUES (?, ?)
            """, (key, str(value)))
            self.conn.commit()

    def get_setting(self, key):
        """Получает значение настройки по ключу"""
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
        """Хеширует пароль с солью и сохраняет в настройки"""
        salt = os.urandom(16).hex()
        payload = (password + salt).encode('utf-8')
        password_hash = hashlib.sha256(payload).hexdigest()

        self.save_setting("master_hash", password_hash)
        self.save_setting("master_salt", salt)

    def verify_master_password(self, password):
        """Проверяет введенный пароль против сохраненного хеша"""
        stored_hash = self.get_setting("master_hash")
        salt = self.get_setting("master_salt")

        if not stored_hash or not salt:
            return False

        payload = (password + salt).encode('utf-8')
        input_hash = hashlib.sha256(payload).hexdigest()
        return input_hash == stored_hash

    def add_entry(self, service, username, encrypted_password, notes=""):
        """Добавляет новую запись в сейф"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO vault_entries (service, username, encrypted_password, notes)
                VALUES (?, ?, ?, ?)
            """, (service, username, encrypted_password, notes))
            self.conn.commit()
            return cursor.lastrowid

    def get_all_entries(self):
        """Возвращает все записи в виде списка словарей"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM vault_entries")
            return [dict(row) for row in cursor.fetchall()]

    def close(self):
        """Закрывает соединение с базой"""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()

# Глобальный экземпляр для приложения
db_manager = DatabaseHelper(db_path="vault.db")