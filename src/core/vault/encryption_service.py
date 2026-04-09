import os
import json
import base64
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

class EncryptionService:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def _get_aes_key(self):
        #Получает сырой ключ из KeyManager
        key = self.key_manager.get_encryption_key()
        if not key:
            raise PermissionError("Хранилище заблокировано. Ключ недоступен.")

        if len(key) == 32:
            return key
        else:
            # Если длина отличается , деривируем через HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'aes-gcm-vault-key',
                backend=default_backend()
            )
            return hkdf.derive(key)

    def encrypt_entry(self, entry_data: dict) -> bytes:
        #Упаковывает данные записи в JSON, добавляет метаданные и шифрует AES-256-GCM

        # 1. Подготовка JSON полезной нагрузки
        payload = {
            "version": 1,  # Версия формата
            "created_at": int(time.time()),  # Timestamp
            "title": entry_data.get('service', ''),
            "username": entry_data.get('username', ''),
            "password": entry_data.get('password', ''),
            "url": entry_data.get('url', ''),
            "category": entry_data.get('category', 'Uncategorized'),
            "notes": entry_data.get('notes', '')
        }

        json_str = json.dumps(payload, ensure_ascii=False)
        plaintext = json_str.encode('utf-8')

        # 2. Шифрование
        key = self._get_aes_key()
        aesgcm = AESGCM(key)

        nonce = os.urandom(12)  # Уникальный nonce для каждой записи

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Возвращаем raw bytes (nonce + ciphertext)
        return nonce + ciphertext

    def decrypt_entry(self, encrypted_data: bytes) -> dict:
        #Расшифровывает BLOB из БД и возвращает словарь
        if not encrypted_data:
            return {}

        try:
            key = self._get_aes_key()
            aesgcm = AESGCM(key)

            # Разбираем структуру
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            # Расшифровка
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            # Парсим JSON
            return json.loads(plaintext.decode('utf-8'))

        except InvalidTag:
            #  Обработка tampering
            print("КРИТИЧЕСКАЯ ОШИБКА: Данные были изменены или ключ неверен!")
            raise ValueError("Ошибка целостности данных: Invalid Authentication Tag")
        except Exception as e:
            print(f"Ошибка расшифровки: {e}")
            raise

    def encrypt(self, plaintext: str) -> str:
        #Шифрует строку с использованием AES-256-GCM
        if not plaintext:
            return ""

        key = self._get_aes_key()
        aesgcm = AESGCM(key)

        # Генерация случайного Nonce (12 байт - стандарт для GCM)
        nonce = os.urandom(12)

        # Шифрование (plaintext в байты)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

        # Объединяем nonce и ciphertext и кодируем в base64 для хранения в БД
        combined = nonce + ciphertext
        return base64.urlsafe_b64encode(combined).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        #Расшифровывает строку, зашифрованную методом encrypt

        if not encrypted_data:
            return ""

        try:
            key = self._get_aes_key()
            aesgcm = AESGCM(key)

            # Декодируем base64
            combined = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))

            # Извлекаем nonce (первые 12 байт) и ciphertext (остальное)
            nonce = combined[:12]
            ciphertext = combined[12:]

            # Расшифровка
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')

        except Exception as e:
            print(f"Ошибка расшифровки AES-GCM: {e}")
            return "[ОШИБКА ДЕКОДИРОВАНИЯ]"