import os
import json
import base64
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class VaultExporter:
    """
    Отвечает за безопасный экспорт записей хранилища.
    ARC-2: Использует отдельные ключи для экспорта (не мастер-ключ).
    ARC-3: Поддерживает полный и выборочный экспорт.
    """

    def __init__(self, entry_manager):
        self.entry_manager = entry_manager

    def export_vault(self,
                     file_path: str,
                     password: str,
                     entry_ids: Optional[List[int]] = None) -> bool:
        """
        Основной метод экспорта.

        Args:
            file_path: Путь к файлу экспорта.
            password: Пароль для шифрования файла экспорта.
            entry_ids: Список ID записей (если None - экспорт всего хранилища).

        Returns:
            bool: Успешность операции.
        """
        try:
            # 1. Сбор данных (ARC-3)
            entries_data = self._collect_entries(entry_ids)

            # 2. Формирование метаданных
            export_payload = {
                "version": "1.0",
                "app": "CryptoSafe",
                "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "count": len(entries_data),
                "entries": entries_data
            }

            # 3. Шифрование (ARC-2 - генерируем отдельный ключ на базе пароля экспорта)
            encrypted_package = self._encrypt_data(export_payload, password)

            # 4. Запись в файл
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(encrypted_package, f, indent=4)

            return True

        except Exception as e:
            print(f"[Exporter Error] {e}")
            raise e

    def _collect_entries(self, entry_ids: Optional[List[int]]) -> List[Dict]:
        """Получает расшифрованные записи для экспорта."""
        # Если список пуст, берем все записи из кэша или БД
        if entry_ids is None:
            # Получаем все записи через менеджер (они будут расшифрованы)
            all_entries = self.entry_manager.get_all_entries()
            return all_entries
        else:
            # Выборочный экспорт
            selected = []
            for eid in entry_ids:
                entry = self.entry_manager.get_entry(eid)
                if entry:
                    selected.append(entry)
            return selected

    def _encrypt_data(self, data: Dict, password: str) -> Dict:
        """
        Шифрует данные паролем экспорта (AES-256-GCM).
        Ключ выводится через PBKDF2.
        """
        salt = os.urandom(16)
        nonce = os.urandom(12)

        # Вывод ключа (100 000 итераций)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode('utf-8'))

        # Шифрование
        aesgcm = AESGCM(key)
        plaintext = json.dumps(data).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return {
            "encryption": {
                "algorithm": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256",
                "iterations": 100000,
                "salt": base64.b64encode(salt).decode('ascii'),
                "nonce": base64.b64encode(nonce).decode('ascii')
            },
            "data": base64.b64encode(ciphertext).decode('ascii')
        }