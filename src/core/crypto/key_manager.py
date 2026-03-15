
import os
from .key_derivation import KeyDerivationService
from .key_storage import KeyStorage


class KeyManager:
    def __init__(self, db_helper):
        self.db = db_helper
        self.storage = KeyStorage()
        self.kdf = KeyDerivationService()

    def verify_and_unlock(self, password: str) -> bool:#проверка пароля и инициализация ключа в памяти
        # Получение соли и хеша из бд
        salt_hex = self.db.get_setting("kdf_salt")
        stored_hash = self.db.get_setting("master_hash")

        if not salt_hex or not stored_hash:
            return False

        salt = bytes.fromhex(salt_hex)

        # вывод ключа на argon2
        derived_key = self.kdf.derive_key_argon2(password, salt)

        # проверка соответсвия
        import hashlib
        current_hash = hashlib.sha256(derived_key).hexdigest()

        if current_hash == stored_hash:
            self.storage.set_key(derived_key)  # сохраниение ключа в защищенное хранилище
            return True
        return False

    def get_current_key(self) -> bytes:
        return self.storage.get_key()