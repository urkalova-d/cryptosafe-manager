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
        """Настройка нового пользователя"""
        # ВАЛИДАЦИЯ ПАРОЛЯ
        is_valid, message = self.kdf.validate_password_strength(password)
        if not is_valid:
            raise ValueError(f"Ненадёжный пароль: {message}")

        # генерация соли (используем 32 байта для совместимости с Fernet)
        auth_salt = secrets.token_bytes(32)
        enc_salt = secrets.token_bytes(32)

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
        self.db.save_key_store("kdf_params", json.dumps(params).encode('utf-8'), version=1)

        print("Параметры ключей успешно сохранены.")

    def verify_and_unlock(self, password: str) -> bool:
        """Проверка пароля и разблокировка хранилища"""
        try:
            # загрузка хеша из БД
            stored_hash = self.db.get_setting("master_hash")
            if not stored_hash:
                print("Ошибка: мастер-хеш не найден")
                return False

            # проверка пароля
            if not self.kdf.verify_password(password, stored_hash):
                print("Неверный пароль")
                return False

            # получение солей
            auth_salt_tuple = self.db.get_key_store("auth_salt")
            enc_salt_tuple = self.db.get_key_store("encryption_salt")

            if not auth_salt_tuple or not auth_salt_tuple[0]:
                print("Ошибка: auth_salt не найден в БД")
                return False

            if not enc_salt_tuple or not enc_salt_tuple[0]:
                print("Ошибка: encryption_salt не найден в БД")
                return False

            auth_salt = auth_salt_tuple[0]
            enc_salt = enc_salt_tuple[0]

            print(f"Auth salt length: {len(auth_salt)}")
            print(f"Enc salt length: {len(enc_salt)}")

            # загрузка параметров KDF
            params_tuple = self.db.get_key_store("kdf_params")
            if params_tuple and params_tuple[0]:
                try:
                    params = json.loads(params_tuple[0].decode('utf-8'))
                    # Обновляем параметры KDF
                    self.kdf.pbkdf2_iterations = params.get('pbkdf2_iterations', 100000)
                    print(f"Загружены параметры KDF: {params}")
                except Exception as e:
                    print(f"Ошибка загрузки параметров KDF: {e}")

            # генерация ключей - ИСПРАВЛЕНО: используем derive_auth_key вместо generate_auth_key
            auth_key = self.kdf.derive_auth_key(password, auth_salt)
            enc_key = self.kdf.derive_encryption_key(password, enc_salt)

            print(f"Auth key generated: {len(auth_key)} bytes")
            print(f"Enc key generated: {len(enc_key)} bytes")

            # сохранение в память
            self.storage.set_keys(auth_key, enc_key)

            # проверка сохранения
            test_auth = self.storage.get_auth_key()
            test_enc = self.storage.get_enc_key()

            if test_enc is None:
                print("ОШИБКА: Ключ не сохранился в storage!")
                return False

            print("Ключи успешно сохранены в storage")
            return True

        except Exception as e:
            print(f"Ошибка в verify_and_unlock: {e}")
            import traceback
            traceback.print_exc()
            return False

    def get_special_key(self, purpose: str) -> bytes:
        """Возвращает специализированный ключ"""
        master_key = self.storage.get_enc_key()
        if not master_key:
            raise PermissionError("Хранилище заблокировано. Сначала выполните вход.")

        return self.kdf.derive_special_key(master_key, purpose)

    def get_audit_key(self) -> bytes:
        """Ключ для подписи записей в журнале аудита"""
        return self.get_special_key("audit_signing")

    def get_export_key(self) -> bytes:
        """Ключ для шифрования экспортируемых данных"""
        return self.get_special_key("export_encryption")

    def get_totp_key(self) -> bytes:
        """Ключ для защиты секретов TOTP"""
        return self.get_special_key("totp_derivation")

    def rotate_keys(self, old_password, new_password, progress_callback=None):
        """Ротация ключей при смене пароля"""
        try:
            # проверка старого пароля
            stored_hash = self.db.get_setting("master_hash")
            if not self.kdf.verify_password(old_password, stored_hash):
                return False

            # получение старой соли и генерация старого ключа
            old_enc_salt, _ = self.db.get_key_store("encryption_salt")
            if not old_enc_salt:
                print("Ошибка: encryption_salt не найден")
                return False

            old_enc_key = self.kdf.derive_encryption_key(old_password, old_enc_salt)
            old_fernet = Fernet(base64.urlsafe_b64encode(old_enc_key))

            # генерация новой соли и ключа
            new_auth_salt = secrets.token_bytes(32)
            new_enc_salt = secrets.token_bytes(32)
            new_enc_key = self.kdf.derive_encryption_key(new_password, new_enc_salt)
            new_fernet = Fernet(base64.urlsafe_b64encode(new_enc_key))
            new_master_hash = self.kdf.create_auth_hash(new_password)

            # перешифровка данных
            records = self.db.get_all_entries()
            total = len(records)
            re_encrypted_list = []

            for i, rec in enumerate(records):
                try:
                    if rec.get('encrypted_password'):
                        # Расшифровываем старым ключом
                        raw_data = old_fernet.decrypt(rec['encrypted_password'].encode()).decode()
                        # Шифруем новым ключом
                        new_val = new_fernet.encrypt(raw_data.encode()).decode()
                        re_encrypted_list.append((rec['id'], new_val))
                except Exception as e:
                    print(f"Ошибка обработки записи {rec.get('id')}: {e}")
                    continue

                if progress_callback:
                    progress_callback(int((i + 1) / total * 100) if total > 0 else 100)

            # атомарное сохранение в БД
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
            import traceback
            traceback.print_exc()
            return False

    def get_encryption_key(self) -> bytes:
        """Получение ключа шифрования из памяти"""
        key = self.storage.get_enc_key()
        if key is None:
            print("WARNING: Encryption key is None in storage")
        else:
            print(f"Encryption key retrieved, length: {len(key)}")
        return key

    def get_auth_key(self) -> bytes:
        """Получение ключа аутентификации из памяти"""
        key = self.storage.get_auth_key()
        if key is None:
            print("WARNING: Auth key is None in storage")
        else:
            print(f"Auth key retrieved, length: {len(key)}")
        return key

    def diagnose_login(self, password: str) -> dict:
        """Диагностика проблем с входом"""
        result = {
            "success": False,
            "steps": {}
        }

        try:
            # Шаг 1: Проверка хеша
            stored_hash = self.db.get_setting("master_hash")
            result["steps"]["hash_exists"] = stored_hash is not None
            if stored_hash:
                result["steps"]["hash_preview"] = stored_hash[:50]

            # Шаг 2: Проверка пароля
            if stored_hash:
                password_valid = self.kdf.verify_password(password, stored_hash)
                result["steps"]["password_verified"] = password_valid

                if not password_valid:
                    result["error"] = "Пароль не проходит проверку Argon2"
                    return result

            # Шаг 3: Проверка солей
            auth_salt_tuple = self.db.get_key_store("auth_salt")
            enc_salt_tuple = self.db.get_key_store("encryption_salt")

            result["steps"]["auth_salt_exists"] = auth_salt_tuple and auth_salt_tuple[0]
            result["steps"]["enc_salt_exists"] = enc_salt_tuple and enc_salt_tuple[0]

            if auth_salt_tuple and auth_salt_tuple[0]:
                result["steps"]["auth_salt_size"] = len(auth_salt_tuple[0])
            if enc_salt_tuple and enc_salt_tuple[0]:
                result["steps"]["enc_salt_size"] = len(enc_salt_tuple[0])

            # Шаг 4: Генерация ключей
            if auth_salt_tuple and auth_salt_tuple[0] and enc_salt_tuple and enc_salt_tuple[0]:
                auth_key = self.kdf.derive_auth_key(password, auth_salt_tuple[0])
                enc_key = self.kdf.derive_encryption_key(password, enc_salt_tuple[0])

                result["steps"]["auth_key_size"] = len(auth_key)
                result["steps"]["enc_key_size"] = len(enc_key)
                result["steps"]["keys_generated"] = True

                # Шаг 5: Тест шифрования
                from cryptography.fernet import Fernet
                test_str = "test_123"
                fernet = Fernet(base64.urlsafe_b64encode(enc_key))
                encrypted = fernet.encrypt(test_str.encode())
                decrypted = fernet.decrypt(encrypted).decode()
                result["steps"]["encryption_test"] = (decrypted == test_str)

            result["success"] = True

        except Exception as e:
            result["error"] = str(e)
            import traceback
            result["traceback"] = traceback.format_exc()

        return result