import json
import os
import time
import html
import base64
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .formats import JsonFormatHandler, CsvFormatHandler, BitwardenHandler


class VaultImporter:
    """
    Отвечает за импорт данных из внешних файлов.
    IMP-2: Валидация и санитизация данных.
    """
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def __init__(self, entry_manager, audit_logger=None):
        self.entry_manager = entry_manager
        self.audit_logger = audit_logger

        # Регистрация хендлеров
        self.handlers = {
            'csjson': JsonFormatHandler(),
            'csv': CsvFormatHandler(),
            'bitwarden_json': BitwardenHandler()
        }

    def import_vault(self, file_path: str, password: str = None,
                     mode: str = "merge", format_type: str = None) -> Dict:
        """
        Импорт данных.

        Args:
            file_path: Путь к файлу.
            password: Пароль для расшифровки.
            mode: Режим импорта ('merge', 'replace').

        Returns:
            Dict: Статистика импорта (успех, ошибки, дубликаты).
        """
        start_time = time.time()
        stats = {"imported": 0, "skipped": 0, "errors": 0, "duplicates": 0, "preview": []}

        try:
            # IMP-4: Проверка размера файла
            if os.path.getsize(file_path) > self.MAX_FILE_SIZE:
                raise ValueError("Файл слишком большой (максимум 10MB).")

            # 1. Определение формата (IMP-1)
            if not format_type:
                format_type = self._detect_format(file_path)

            handler = self.handlers.get(format_type)
            if not handler:
                raise ValueError(f"Неподдерживаемый формат: {format_type}")

            # 2. Чтение данных
            entries = handler.import_data(file_path, password)

            # 3. Валидация и Санитизация (IMP-2)
            clean_entries = []
            for entry in entries:
                # IMP-4: Timeout check (simple iteration check)
                if time.time() - start_time > 30:
                    raise TimeoutError("Превышено время обработки файла (30 сек).")

                # Валидация
                if not self._validate_entry(entry):
                    stats['skipped'] += 1
                    continue

                # Санитизация
                safe_entry = self._sanitize_entry(entry)
                clean_entries.append(safe_entry)

            # 4. Обработка режима (IMP-3)
            if mode == 'dry-run':
                stats['preview'] = clean_entries[:50]  # Превью первых 50
                stats['imported'] = len(clean_entries)
                return stats

            elif mode == 'replace':
                self._clear_vault()

            # Merge mode (default)
            existing_entries = self.entry_manager.get_all_entries()
            # Создаем индекс существующих для проверки дублей
            # (простой пример: совпадение service + username)
            existing_keys = {
                (e.get('service', '').lower(), e.get('username', '').lower())
                for e in existing_entries
            }

            for entry in clean_entries:
                key = (entry.get('service', '').lower(), entry.get('username', '').lower())

                if key in existing_keys:
                    stats['duplicates'] += 1
                    # В режиме Merge пропускаем дубли
                    continue

                    # Создание записи
                self.entry_manager.create_entry(entry)
                stats['imported'] += 1

            # Логирование (IMP-4)
            if self.audit_logger:
                self.audit_logger.log_event(
                    event_type="VAULT_IMPORT",
                    severity="INFO",
                    source="importer",
                    details={"count": stats['imported'], "mode": mode}
                )

            return stats

        except Exception as e:
            print(f"[Importer Error] {e}")
            if self.audit_logger:
                self.audit_logger.log_event(
                    event_type="VAULT_IMPORT_FAILED",
                    severity="ERROR",
                    source="importer",
                    details={"error": str(e)}
                )
            raise e

    def _validate_format(self, data: Dict) -> bool:
        """Проверка структуры JSON."""
        # Простейшая проверка на наличие ключей шифрования и данных
        return "encryption" in data and "data" in data

    def _detect_format(self, file_path: str) -> str:
        """Автоопределение формата по расширению и содержимому."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.csjson': return 'csjson'
        if ext == '.csv': return 'csv'
        if ext == '.csshare': return 'csjson'

        # Попытка прочитать как JSON для Bitwarden
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)  # needs import json
                if "items" in data and "folders" in data:
                    return 'bitwarden_json'
        except:
            pass

        return 'csv'

    def _sanitize_entry(self, entry: Dict) -> Dict:
        """
        IMP-2: Очистка от вредоносного контента (XSS prevention).
        Удаляем теги <script>, обрезаем пробелы.
        """
        safe_entry = {}
        for key, value in entry.items():
            if isinstance(value, str):
                # Экранирование HTML сущностей
                value = html.escape(value.strip())
            safe_entry[key] = value
        return safe_entry

    def _clear_vault(self):
        """Очистка хранилища при режиме Replace."""
        all_entries = self.entry_manager.get_all_entries()
        for entry in all_entries:
            self.entry_manager.delete_entry(entry['id'], soft_delete=False)

    def _validate_entry(self, entry: Dict) -> bool:
        """IMP-2: Проверка обязательных полей."""
        # Должен быть хотя бы сервис или пароль
        if not entry.get('service') and not entry.get('password'):
            return False
        return True

