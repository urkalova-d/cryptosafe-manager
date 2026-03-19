import os
import secrets
import base64
import json
from cryptography.fernet import Fernet
from .key_derivation import KeyDerivationService
from .key_storage import KeyStorage

class KeyManager:
    def __init__(self, db_helper):
        self.db = db_helper
        self.storage = KeyStorage()
        self.kdf = KeyDerivationService()

    def verify_password(self, password: str, stored_hash: str) -> bool:
        return self.kdf.verify_password(password, stored_hash)

    def setup_new_user(self, password: str):
        #  генерация соли
        auth_salt = secrets.token_bytes(16)
        enc_salt = secrets.token_bytes(16)

        # хеширование пароля
        master_hash = self.kdf.create_auth_hash(password)
        self.db.save_setting("master_hash", master_hash)

        # сохранение соли в бд
        self.db.save_key_store("auth_salt", auth_salt, version=1)
        self.db.save_key_store("encryption_salt", enc_salt, version=1)

        # Сохранение параметров KDF
        params = {
            "argon2_time": 3,
            "argon2_memory": 65536,
            "argon2_parallelism": 4,
            "pbkdf2_iterations": 100000
        }
        # Преобразуем словарь в байты для сохранения
        self.db.save_key_store("kdf_params", json.dumps(params).encode('utf-8'), version=1)

        print("Параметры ключей успешно сохранены (v2 schema).")

    def verify_and_unlock(self, password: str) -> bool:
        # загрузка соли и генерация ключей
        stored_hash = self.db.get_setting("master_hash")
        if not stored_hash:
            return False

        # проверка пароля
        if not self.kdf.verify_password(password, stored_hash):
            return False

        auth_salt_tuple = self.db.get_key_store("auth_salt")
        enc_salt_tuple = self.db.get_key_store("encryption_salt")

        # проверка на существование данных
        if not auth_salt_tuple or not auth_salt_tuple[0] or not enc_salt_tuple or not enc_salt_tuple[0]:
            print("Ошибка: соли не найдены в БД.")
            return False

        auth_salt = auth_salt_tuple[0]
        enc_salt = enc_salt_tuple[0]

        # генерация ключей
        enc_key = self.kdf.derive_encryption_key(password, enc_salt)
        auth_key = self.kdf.generate_auth_key(password, auth_salt)

        # сохранение в память
        self.storage.set_keys(auth_key, enc_key)
        return True

    def rotate_keys(self, old_password, new_password, progress_callback=None):
        #ротация ключей при смене пароля
        try:
            # проверка старого пароля
            stored_hash = self.db.get_setting("master_hash")
            if not self.kdf.verify_password(old_password, stored_hash):
                return False

            # получение старой соли и генерация староко ключа
            old_enc_salt, _ = self.db.get_key_store("encryption_salt")
            old_enc_key = self.kdf.derive_encryption_key(old_password, old_enc_salt)
            old_fernet = Fernet(base64.urlsafe_b64encode(old_enc_key))

            #  генерация новой соли и ключа
            new_auth_salt = secrets.token_bytes(16)
            new_enc_salt = secrets.token_bytes(16)
            new_enc_key = self.kdf.derive_encryption_key(new_password, new_enc_salt)
            new_fernet = Fernet(base64.urlsafe_b64encode(new_enc_key))
            new_master_hash = self.kdf.create_auth_hash(new_password)

            #  перешифровка данных
            records = self.db.get_all_entries()
            total = len(records)
            re_encrypted_list = []

            for i, rec in enumerate(records):
                try:
                    if rec['encrypted_password']:
                        # Расшифровываем старым ключом
                        raw_data = old_fernet.decrypt(rec['encrypted_password'].encode()).decode()
                        # Шифруем новым ключом
                        new_val = new_fernet.encrypt(raw_data.encode()).decode()
                        re_encrypted_list.append((rec['id'], new_val))
                except Exception as e:
                    print(f"Ошибка записи {rec['id']}: {e}")
                    # Если не удалось расшифровать, сохраняем как есть или пропускаем
                    continue

                if progress_callback:
                    progress_callback(int((i + 1) / total * 100))

            # атомарное сохранение в бд
            self.db.rotate_vault_keys(
                new_master_hash,
                new_auth_salt,
                new_enc_salt,
                re_encrypted_list
            )

            # обновление ключа в оперативной памяти
            self.storage.set_keys(b"", new_enc_key)
            return True

        except Exception as e:
            print(f"Критическая ошибка ротации: {e}")
            return False

    def get_encryption_key(self) -> bytes:
        return self.storage.get_enc_key()

import json