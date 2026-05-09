import os
import json
import base64
import tempfile
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .formats import JsonFormatHandler, CsvFormatHandler


class VaultExporter:
    """
    Централизованный контроллер экспорта.
    ARC-2: Key Separation.
    EXP-4: Security & Audit.
    """

    def __init__(self, entry_manager, audit_logger=None):
        # ВАЖНО: добавили audit_logger=None
        self.entry_manager = entry_manager
        self.audit_logger = audit_logger  # Сохраняем ссылку на логгер

        # Инициализация хендлеров
        self.handlers = {
            'encrypted_json': JsonFormatHandler(),
            'csv': CsvFormatHandler()
        }
    def export_vault(self,
                     file_path: str,
                     password: str,
                     entry_ids: Optional[List[int]] = None,
                     format_type: str = 'encrypted_json',
                     options: Optional[Dict] = None) -> bool:
        """
        Основной метод экспорта.

        Args:
            file_path: Путь к файлу экспорта.
            password: Пароль для шифрования файла экспорта.
            entry_ids: Список ID записей (если None - экспорт всего хранилища).

        Returns:
            bool: Успешность операции.
        """
        options = options or {}
        try:
            # 1. Сбор данных (ARC-3)
            entries_data = self._collect_entries(entry_ids)

            # 2. Фильтрация полей (EXP-3)
            exclude_fields = options.get('exclude_fields', [])
            if exclude_fields:
                entries_data = self._filter_fields(entries_data, exclude_fields)

            # 3. Выбор хендлера
            handler = self.handlers.get(format_type)
            if not handler:
                raise ValueError(f"Unsupported format: {format_type}")

            # 4. Генерация данных
            # Используем временный файл для безопасности (EXP-4)
            raw_data = handler.export_data(entries_data, password, options)

            # 5. Запись в файл
            self._write_secure(file_path, raw_data)

            # 6. Логирование (EXP-4)
            if self.audit_logger:
                self.audit_logger.log_event(
                    event_type="VAULT_EXPORT",
                    severity="INFO",
                    source="exporter",
                    details={
                        "format": format_type,
                        "count": len(entries_data),
                        "destination": os.path.basename(file_path)
                    }
                )

            return True

        except Exception as e:
            print(f"[Exporter Error] {e}")
            # Логируем ошибку
            if self.audit_logger:
                self.audit_logger.log_event(
                    event_type="VAULT_EXPORT_FAILED",
                    severity="ERROR",
                    source="exporter",
                    details={"error": str(e)}
                )
            raise e

    def _collect_entries(self, entry_ids: Optional[List[int]]) -> List[Dict]:
        """Получает расшифрованные записи."""
        if entry_ids is None:
            return self.entry_manager.get_all_entries()
        else:
            selected = []
            for eid in entry_ids:
                entry = self.entry_manager.get_entry(eid)
                if entry:
                    selected.append(entry)
            return selected

    def _filter_fields(self, entries: List[Dict], exclude: List[str]) -> List[Dict]:
        """Удаляет указанные поля из записей (EXP-3)."""
        filtered = []
        for entry in entries:
            new_entry = {k: v for k, v in entry.items() if k not in exclude}
            filtered.append(new_entry)
        return filtered

    def _write_secure(self, file_path: str, data: bytes):
        """Безопасная запись в файл (EXP-4)."""
        # Пишем во временный файл, затем переименовываем (атомарная операция)
        temp_path = file_path + ".tmp"
        try:
            with open(temp_path, 'wb') as f:
                f.write(data)

            # Если файл существовал, удаляем его (или перезаписываем)
            if os.path.exists(file_path):
                os.remove(file_path)

            os.rename(temp_path, file_path)
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)  # Очистка временных файлов при ошибке
            raise e

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