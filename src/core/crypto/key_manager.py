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
        # генерация соли
        auth_salt = secrets.token_bytes(16)
        enc_salt = secrets.token_bytes(16)

        #  создание хеша пароля
        master_hash = self.kdf.create_auth_hash(password)
        self.db.save_setting("master_hash", master_hash)

        auth_params = {
            "type": "argon2id",
            "time_cost": 3,
            "memory_cost": 65536,
            "parallelism": 4
        }
        self.db.save_key_store("auth_key", auth_salt, auth_params, version=1)

        enc_params = {
            "type": "pbkdf2-sha256",
            "iterations": self.kdf.pbkdf2_iterations
        }
        self.db.save_key_store("encryption_key", enc_salt, enc_params, version=1)
        print("Параметры ключей успешно сохранены.")

    def verify_and_unlock(self, password: str) -> bool:
        stored_hash = self.db.get_setting("master_hash")
        if not stored_hash:
            return False

        if not self.kdf.verify_password(password, stored_hash):
            return False

        auth_store = self.db.get_key_store("auth_key")
        enc_store = self.db.get_key_store("encryption_key")

        if not auth_store or not enc_store:
            print("Ошибка: параметры ключей не найдены.")
            return False

        # генерация ключей
        auth_key = self.kdf.generate_auth_key(password, auth_store['salt'])
        enc_key = self.kdf.derive_encryption_key(password, enc_store['salt'])

        self.storage.set_keys(auth_key, enc_key)
        return True





    def get_encryption_key(self) -> bytes:
        return self.storage.get_enc_key()


    def get_auth_key(self) -> bytes:
        return self.storage.get_auth_key()