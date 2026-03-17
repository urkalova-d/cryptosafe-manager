import os
from .key_derivation import KeyDerivationService
from .key_storage import KeyStorage
import secrets


class KeyManager:
    def __init__(self, db_helper):
        self.db = db_helper
        self.storage = KeyStorage()
        self.kdf = KeyDerivationService()

    def verify_password(self, password: str, stored_hash: str) -> bool:
        # проверка пароля через argon2
        return self.kdf.verify_password(password, stored_hash)

    def setup_new_user(self, password: str):
        """
        Первичная настройка: генерация солей, создание хеша и сохранение параметров.
        Вызывается при регистрации.
        """
        # 1. Генерация уникальных солей (16 байт)
        auth_salt = secrets.token_bytes(16)
        enc_salt = secrets.token_bytes(16)

        # 2. Создание хеша пароля для проверки (Argon2)
        # Используем встроенный генератор соли Argon2 для хеша проверки
        master_hash = self.kdf.create_auth_hash(password)

        # 3. Сохранение параметров в БД
        # Сохраняем хеш пароля
        self.db.save_setting("master_hash", master_hash)

        # Сохраняем соли и параметры в key_store
        auth_params = {
            "type": "argon2id",
            "time_cost": self.kdf.time_cost,
            "memory_cost": self.kdf.memory_cost,
            "parallelism": self.kdf.parallelism
        }
        self.db.save_key_store("auth_key", auth_salt, auth_params, version=1)

        enc_params = {
            "type": "pbkdf2-sha256",
            "iterations": self.kdf.pbkdf2_iterations
        }
        self.db.save_key_store("encryption_key", enc_salt, enc_params, version=1)

        print("Параметры ключей успешно сохранены.")

    def verify_and_unlock(self, password: str) -> bool:#проверка пароля и инициализация ключа в памяти
        """
                Проверка пароля и инициализация ключей в памяти.
                """
        # 1. Проверка пароля
        stored_hash = self.db.get_setting("master_hash")
        if not stored_hash:
            return False

        if not self.kdf.verify_password(password, stored_hash):
            return False

        # 2. Загрузка параметров ключей из БД
        auth_store = self.db.get_key_store("auth_key")
        enc_store = self.db.get_key_store("encryption_key")

        if not auth_store or not enc_store:
            print("Ошибка: параметры ключей не найдены в БД.")
            return False

        # 3. Генерация ключей на лету
        # Ключ аутентификации (Argon2)
        auth_key = self.kdf.generate_auth_key(password, auth_store['salt'])

        # Ключ шифрования (PBKDF2)
        enc_key = self.kdf.generate_encryption_key(password, enc_store['salt'])

        # 4. Сохранение в защищенное хранилище (в памяти)
        # Мы сохраняем оба ключа. Возможно, вам понадобится два слота в KeyStorage.
        # Для простоты изменим KeyStorage, чтобы он хранил словарь ключей.
        self.storage.set_keys(auth_key, enc_key)

        return True





    def get_encryption_key(self) -> bytes:
        return self.storage.get_enc_key()


    def get_auth_key(self) -> bytes:
        return self.storage.get_auth_key()