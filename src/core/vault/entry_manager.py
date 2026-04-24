import json
import os
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal

# Импортируем сервис шифрования
from .encryption_service import EncryptionService
from .password_generator import PasswordGenerator

from thefuzz import fuzz


class EntryManager(QObject):
    #Централизованный контроллер для операций управляет шифрованием, транзакциями и событиями
    #  события
    EntryCreated = pyqtSignal(int)
    EntryUpdated = pyqtSignal(int)
    EntryDeleted = pyqtSignal(int)
    # инткграция к 4 спринту
    EntryCopied = pyqtSignal(int)

    def __init__(self, db_helper, key_manager):
        super().__init__()
        self.db = db_helper
        self.encryption = EncryptionService(key_manager)

    def create_entry(self, data: dict) -> int:
        #создание новой записи

        from src.core.events import event_bus, EventType
        event_bus.publish(EventType.ENTRY_ADDED, entry_id)
        try:
            # пготовка данных
            payload_data = {
                "service": data.get('service', ''),
                "username": data.get('username', ''),
                "password": data.get('password', ''),
                "url": data.get('url', ''),
                "category": data.get('category', 'Uncategorized'),
                "notes": data.get('notes', ''),

                # интеграции на будущие спринты
                "totp_secret": data.get('totp_secret', ''),
                "sharing_metadata": data.get('sharing_metadata', {})
            }

            # шифрование данных
            encrypted_blob = self.encryption.encrypt_entry(payload_data)

            # сохраниев бд
            tags = data.get('category', '')
            entry_id = self.db.add_entry(encrypted_blob, tags=tags)

            # интеграция на 5 спринт
            self._log_audit_event("CREATE", entry_id)

            #  Публикуем событие
            self.EntryCreated.emit(entry_id)
            return entry_id

        except Exception as e:
            print(f"Error creating entry: {e}")
            raise e
    def get_entry(self, entry_id: int) -> dict:
        #Получение и расшифровка одной записи
        try:
            record = self.db.get_entry(entry_id)
            if not record:
                raise ValueError("Entry not found")

            # расшифровка
            decrypted_data = self.encryption.decrypt_entry(record['encrypted_data'])

            # добавление метаданных в бд
            decrypted_data['id'] = record['id']
            decrypted_data['created_at'] = record['created_at']
            decrypted_data['updated_at'] = record['updated_at']
            decrypted_data['tags'] = record['tags']

            return decrypted_data
        except Exception as e:
            print(f"Error getting entry: {e}")
            raise e

    def get_all_entries(self) -> list[dict]:
        #Получение списка всех записей
        try:
            records = self.db.get_all_entries()
            result = []

            for rec in records:
                try:
                    data = self.encryption.decrypt_entry(rec['encrypted_data'])
                    data['id'] = rec['id']
                    data['created_at'] = rec['created_at']
                    data['updated_at'] = rec['updated_at']
                    data['tags'] = rec['tags']
                    result.append(data)
                except Exception as e:
                    print(f"Skipping corrupted entry {rec['id']}: {e}")
                    # заглушка что бы список не ломался
                    result.append({
                        'id': rec['id'],
                        'title': 'ERROR',
                        'username': '',
                        'password': '',
                        'url': '',
                        'notes': f'Corrupted data: {e}'
                    })

            return result
        except Exception as e:
            print(f"Error getting all entries: {e}")
            raise e

    def update_entry(self, entry_id: int, data: dict) -> int:
        #обновление записи
        try:
            # Подготовка данных с интеграционными полями
            payload_data = {
                "service": data.get('service', ''),
                "username": data.get('username', ''),
                "password": data.get('password', ''),
                "url": data.get('url', ''),
                "category": data.get('category', 'Uncategorized'),
                "notes": data.get('notes', ''),
                "totp_secret": data.get('totp_secret', ''),
                "sharing_metadata": data.get('sharing_metadata', {})
            }

            encrypted_blob = self.encryption.encrypt_entry(payload_data)

            tags = data.get('category', '')
            self.db.update_entry(entry_id, encrypted_blob, tags=tags)

            # интеграция на будущие спринты
            self._log_audit_event("UPDATE", entry_id)

            self.EntryUpdated.emit(entry_id)
            return entry_id
        except Exception as e:
            print(f"Error updating entry: {e}")
            raise e

    def delete_entry(self, entry_id: int, soft_delete: bool = True):
        #удаление записи
        try:
            if soft_delete:
                self.db.soft_delete_entry(entry_id)
            else:
                self.db.hard_delete_entry(entry_id)

            # интеграция на спринты
            self._log_audit_event("DELETE", entry_id)

            self.EntryDeleted.emit(entry_id)

        except Exception as e:
            print(f"Error deleting entry: {e}")
            raise e

        # Sprint 4 Placeholder: Clipboard Integration
    def copy_to_clipboard_secure(self, entry_id: int):
        self.EntryCopied.emit(entry_id)
        print(f"[Integration] EntryCopied signal emitted for ID {entry_id}")

        #  Security: Constant-time algorithms

    @staticmethod
    def _secure_compare(a: str, b: str) -> bool:
        """
        Constant-time comparison to prevent timing attacks.
        Uses hmac.compare_digest.
        """
        return hmac.compare_digest(a, b)

    def _log_audit_event(self, action: str, entry_id: int):
        # интеграция с журналом аудита 5 спринт
        pass

    def _calculate_strength(self, password):
        # оценка силы пароля для фильтрации
        if not password: return 0
        score = 0
        if len(password) >= 8: score += 1
        if len(password) >= 12: score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in "!@#$%^&*()_+-=" for c in password): score += 1
        return score

    def filter_entries(self, all_entries, query):
        #Продвинутая фильтрация (нечеткий поиск, поиск через: фильтрация по силе пароля
        if not query:
            return all_entries

        query = query.lower().strip()
        filtered = []

        # разбор поискового запроса
        # извлекаем специальные фильтры
        filters = {}
        text_query = query

        #  реализация "key:value"
        parts = query.split()
        clean_parts = []

        for part in parts:
            if ":" in part:
                try:
                    key, val = part.split(":", 1)
                    filters[key.strip()] = val.strip()
                except ValueError:
                    pass
            else:
                clean_parts.append(part)

        # поиск
        search_text_query = " ".join(clean_parts)

        for entry in all_entries:
            match = True

            #  применение фильтра key:value
            for key, val in filters.items():
                entry_val = ""

                # отображение полей
                if key in ["title", "service"]:
                    entry_val = str(entry.get('service', entry.get('title', '')))
                elif key in ["user", "username"]:
                    entry_val = str(entry.get('username', ''))
                elif key in ["url"]:
                    entry_val = str(entry.get('url', ''))
                elif key in ["note", "notes"]:
                    entry_val = str(entry.get('notes', ''))
                elif key in ["cat", "category"]:
                    entry_val = str(entry.get('category', ''))
                elif key == "strength":
                    #  фильтр силы пароля
                    pwd = entry.get('password', '')
                    strength_score = self._calculate_strength(pwd)

                    is_strong = strength_score >= 4
                    is_medium = 2 <= strength_score < 4
                    is_weak = strength_score < 2

                    if val == "strong" and not is_strong:
                        match = False
                    elif val == "medium" and not is_medium:
                        match = False
                    elif val == "weak" and not is_weak:
                        match = False
                    continue  # переход к следующему фильтру

                # проверка на частичное совпадение
                if val not in entry_val.lower():
                    match = False
                    break

            if not match:
                continue

            #  полнотекстовый и нечеткий поиск
            if search_text_query:
                # сборка строкм для поиска
                full_text = f"{entry.get('service', '')} {entry.get('title', '')} {entry.get('username', '')} {entry.get('notes', '')} {entry.get('url', '')}".lower()

                # точное нахождение
                if search_text_query in full_text:
                    filtered.append(entry)
                # нечеткий поиск 
                elif fuzz.partial_ratio(search_text_query, full_text) > 75:  
                    filtered.append(entry)
            else:
                # Если только фильтры без текста
                filtered.append(entry)

        return filtered