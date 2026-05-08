import json
import base64
from typing import Dict, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class VaultImporter:
    """
    Отвечает за импорт данных из внешних файлов.
    IMP-2: Валидация и санитизация данных.
    """

    def __init__(self, entry_manager):
        self.entry_manager = entry_manager

    def import_vault(self, file_path: str, password: str, mode: str = "merge") -> Dict:
        """
        Импорт данных.

        Args:
            file_path: Путь к файлу.
            password: Пароль для расшифровки.
            mode: Режим импорта ('merge', 'replace').

        Returns:
            Dict: Статистика импорта (успех, ошибки, дубликаты).
        """
        stats = {"imported": 0, "skipped": 0, "errors": 0}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = json.load(f)

            # Проверка формата
            if not self._validate_format(file_content):
                raise ValueError("Неподдерживаемый формат файла")

            # Расшифровка
            decrypted_data = self._decrypt_data(file_content, password)

            # Обработка записей
            entries = decrypted_data.get('entries', [])

            for entry in entries:
                # Санитизация данных (IMP-2)
                clean_entry = self._sanitize_entry(entry)

                # TODO: Логика проверки дубликатов (IMP-2)

                # Создание записи
                self.entry_manager.create_entry(clean_entry)
                stats["imported"] += 1

            return stats

        except Exception as e:
            print(f"[Importer Error] {e}")
            raise e

    def _validate_format(self, data: Dict) -> bool:
        """Проверка структуры JSON."""
        # Простейшая проверка на наличие ключей шифрования и данных
        return "encryption" in data and "data" in data

    def _decrypt_data(self, package: Dict, password: str) -> Dict:
        """Расшифровка полезной нагрузки."""
        enc_info = package['encryption']
        salt = base64.b64decode(enc_info['salt'])
        nonce = base64.b64decode(enc_info['nonce'])
        ciphertext = base64.b64decode(package['data'])

        # Вывод ключа
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=enc_info.get('iterations', 100000),
        )
        key = kdf.derive(password.encode('utf-8'))

        # Расшифровка
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return json.loads(plaintext.decode('utf-8'))

    def _sanitize_entry(self, entry: Dict) -> Dict:
        """
        Очистка полей от потенциально опасного содержимого.
        IMP-2: Sanitize malicious content.
        """
        # Простая заглушка, в будущем можно добавить проверку на JS в notes и т.д.
        # Убираем лишние пробелы
        for key in ['service', 'username', 'url']:
            if key in entry and isinstance(entry[key], str):
                entry[key] = entry[key].strip()
        return entry