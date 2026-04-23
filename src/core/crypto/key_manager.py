import os
import secrets
import base64
import json
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
        is_valid, message = self.kdf.validate_password_strength(password)
        if not is_valid:
            raise ValueError(f"Ненадежный пароль: {message}")

        # Генерация солей
        auth_salt = secrets.token_bytes(16)
        enc_salt = secrets.token_bytes(16)

        print(f"[SETUP] Generated enc_salt: {enc_salt.hex()}")

        # Хеширование пароля
        master_hash = self.kdf.create_auth_hash(password)
        self.db.save_setting("master_hash", master_hash)

        # Сохранение солей в БД
        self.db.save_key_store("auth_salt", auth_salt, version=1)
        self.db.save_key_store("encryption_salt", enc_salt, version=1)

        # Проверка что соль сохранилась
        saved_salt, _ = self.db.get_key_store("encryption_salt")
        print(f"[SETUP] Saved enc_salt in DB: {saved_salt.hex() if saved_salt else 'None'}")
        print(f"[SETUP] Salt match: {saved_salt == enc_salt if saved_salt else False}")

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
        try:
            stored_hash = self.db.get_setting("master_hash")
            if not stored_hash:
                print("Ошибка: мастер-хеш не найден")
                return False

            if not self.kdf.verify_password(password, stored_hash):
                print("Неверный пароль")
                return False

            # Получение солей
            auth_salt_tuple = self.db.get_key_store("auth_salt")
            enc_salt_tuple = self.db.get_key_store("encryption_salt")

            print(
                f"[UNLOCK] enc_salt from DB (hex): {enc_salt_tuple[0].hex() if enc_salt_tuple and enc_salt_tuple[0] else 'None'}")

            if not enc_salt_tuple or not enc_salt_tuple[0]:
                print("Ошибка: encryption_salt не найден в БД")
                return False

            enc_salt = enc_salt_tuple[0]

            # Генерация ключа
            enc_key = self.kdf.derive_encryption_key(password, enc_salt)
            print(f"[UNLOCK] Derived enc_key (hex first 16): {enc_key.hex()[:32] if enc_key else 'None'}")

            self.storage.set_keys(b"", enc_key)

            return True
        except Exception as e:
            print(f"Ошибка в verify_and_unlock: {e}")
            return False

    def get_special_key(self, purpose: str) -> bytes:
        """Возвращает специализированный ключ"""
        master_key = self.storage.get_enc_key()
        if not master_key:
            raise PermissionError("Хранилище заблокировано.")
        return self.kdf.derive_special_key(master_key, purpose)

    def get_audit_key(self) -> bytes:
        return self.get_special_key("audit_signing")

    def get_export_key(self) -> bytes:
        return self.get_special_key("export_encryption")

    def get_totp_key(self) -> bytes:
        return self.get_special_key("totp_derivation")

    def rotate_keys(self, old_password, new_password, progress_callback=None):
        """
        Ротация ключей при смене пароля.
        ИСПРАВЛЕНО: Правильное перешифрование без потери данных.
        """
        try:
            # 1. Проверка старого пароля
            stored_hash = self.db.get_setting("master_hash")
            if not self.kdf.verify_password(old_password, stored_hash):
                return False

            # 2. Получаем старые соли и ключи
            old_enc_salt, _ = self.db.get_key_store("encryption_salt")
            if not old_enc_salt:
                print("Ошибка: encryption_salt не найден")
                return False

            # Деривируем старый ключ (НЕ сохраняем в storage!)
            old_enc_key = self.kdf.derive_encryption_key(old_password, old_enc_salt)

            # 3. Генерируем новые соли и ключи
            new_auth_salt = secrets.token_bytes(16)
            new_enc_salt = secrets.token_bytes(16)
            new_enc_key = self.kdf.derive_encryption_key(new_password, new_enc_salt)
            new_master_hash = self.kdf.create_auth_hash(new_password)

            # 4. Перешифрование данных
            # ВАЖНО: Используем старый ключ напрямую, а не через EncryptionService
            # который берет ключ из storage
            records = self.db.get_all_entries()
            total = len(records)
            re_encrypted_list = []

            # Создаем AESGCM объекты напрямую с ключами
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            old_aesgcm = AESGCM(old_enc_key)
            new_aesgcm = AESGCM(new_enc_key)

            for i, rec in enumerate(records):
                try:
                    enc_blob = rec.get('encrypted_data')
                    if enc_blob:
                        # Расшифровываем старым ключом
                        nonce = enc_blob[:12]
                        ciphertext = enc_blob[12:]
                        plaintext = old_aesgcm.decrypt(nonce, ciphertext, None)
                        data_dict = json.loads(plaintext.decode('utf-8'))

                        # Зашифровываем новым ключом
                        new_nonce = os.urandom(12)
                        new_plaintext = json.dumps(data_dict, ensure_ascii=False).encode('utf-8')
                        new_ciphertext = new_aesgcm.encrypt(new_nonce, new_plaintext, None)
                        new_blob = new_nonce + new_ciphertext

                        re_encrypted_list.append((rec['id'], new_blob))
                except Exception as e:
                    print(f"Ошибка записи {rec.get('id')}: {e}")
                    continue

                if progress_callback:
                    progress_callback(int((i + 1) / total * 100) if total > 0 else 100)

            # 5. Сохраняем в БД
            self.db.rotate_vault_keys(
                new_master_hash,
                new_auth_salt,
                new_enc_salt,
                re_encrypted_list
            )

            # 6. ОБНОВЛЯЕМ storage ТОЛЬКО после успешного сохранения
            self.storage.set_keys(b"", new_enc_key)

            return True

        except Exception as e:
            print(f"Критическая ошибка ротации: {e}")
            import traceback
            traceback.print_exc()
            return False

    def get_encryption_key(self) -> bytes:
        return self.storage.get_enc_key()

    def get_auth_key(self) -> bytes:
        return self.storage.get_auth_key()