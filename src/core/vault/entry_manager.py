import json
import os
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal

# Импортируем сервис шифрования
from .encryption_service import EncryptionService
from .password_generator import PasswordGenerator

from thefuzz import fuzz


class EntryManager(QObject):
    """
    Централизованный контроллер для операций CRUD (CRUD-1).
    Управляет шифрованием, транзакциями и событиями.
    """

    # CRUD-3: События
    EntryCreated = pyqtSignal(int)  # entry_id
    EntryUpdated = pyqtSignal(int)  # entry_id
    EntryDeleted = pyqtSignal(int)  # entry_id

    def __init__(self, db_helper, key_manager):
        super().__init__()
        self.db = db_helper
        self.encryption = EncryptionService(key_manager)

    def create_entry(self, data: dict) -> int:
        """
        Создание новой записи.
        Args:
            data: dict с ключами service, username, password, url, category, notes
        Returns:
            entry_id (int)
        """
        try:
            # 1. Шифруем данные
            encrypted_blob = self.encryption.encrypt_entry(data)

            # 2. Сохраняем в БД (теги берем из категории для поиска)
            tags = data.get('category', '')
            entry_id = self.db.add_entry(encrypted_blob, tags=tags)

            # 3. Публикуем событие
            self.EntryCreated.emit(entry_id)
            return entry_id

        except Exception as e:
            # CRUD-2: Обработка ошибок (транзакционность обеспечивается внутри db.add_entry)
            print(f"Error creating entry: {e}")
            raise e

    def get_entry(self, entry_id: int) -> dict:
        """Получение и расшифровка одной записи."""
        try:
            record = self.db.get_entry(entry_id)
            if not record:
                raise ValueError("Запись не найдена")

            # Расшифровываем
            decrypted_data = self.encryption.decrypt_entry(record['encrypted_data'])

            # Добавляем метаданные БД
            decrypted_data['id'] = record['id']
            decrypted_data['created_at'] = record['created_at']
            decrypted_data['updated_at'] = record['updated_at']
            decrypted_data['tags'] = record['tags']

            return decrypted_data
        except Exception as e:
            print(f"Error getting entry: {e}")
            raise e

    def get_all_entries(self) -> list[dict]:
        """Получение списка всех записей (массив словарей)."""
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
                    # Можно добавить заглушку, чтобы не ломать список
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
        """Обновление записи."""
        try:
            # Шифруем новые данные
            encrypted_blob = self.encryption.encrypt_entry(data)

            # Обновляем
            tags = data.get('category', '')
            self.db.update_entry(entry_id, encrypted_blob, tags=tags)

            self.EntryUpdated.emit(entry_id)
            return entry_id
        except Exception as e:
            print(f"Error updating entry: {e}")
            raise e

    def delete_entry(self, entry_id: int, soft_delete: bool = True):
        """
        Удаление записи.
        Args:
            entry_id: ID записи
            soft_delete: Если True, переносит в deleted_entries (CRUD-4). Если False - удаляет совсем.
        """
        try:
            if soft_delete:
                # Перемещаем в корзину
                self.db.soft_delete_entry(entry_id)
            else:
                # Полное удаление (из корзины)
                self.db.hard_delete_entry(entry_id)

            self.EntryDeleted.emit(entry_id)

        except Exception as e:
            print(f"Error deleting entry: {e}")
            raise e

    def _calculate_strength(self, password):
        """Простая оценка силы пароля для фильтрации"""
        if not password: return 0
        score = 0
        if len(password) >= 8: score += 1
        if len(password) >= 12: score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in "!@#$%^&*()_+-=" for c in password): score += 1
        return score

    def filter_entries(self, all_entries, query):
        """
        Part 8: Продвинутая фильтрация.
        Поддерживает:
        - field:value (title:google, user:admin)
        - strength:weak/medium/strong
        - нечеткий поиск
        """
        if not query:
            return all_entries

        query = query.lower().strip()
        filtered = []

        # Разбор поискового запроса
        # Извлекаем специальные фильтры
        filters = {}
        text_query = query

        # Простая реализация парсинга "key:value"
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

        # Текст для полнотекстового поиска (все, что не key:value)
        search_text_query = " ".join(clean_parts)

        for entry in all_entries:
            match = True

            # 1. Применение фильтров (key:value)
            for key, val in filters.items():
                entry_val = ""

                # Маппинг полей
                if key in ["title", "service"]:
                    entry_val = str(entry.get('service', ''))
                elif key in ["user", "username"]:
                    entry_val = str(entry.get('username', ''))
                elif key in ["url"]:
                    entry_val = str(entry.get('url', ''))
                elif key in ["note", "notes"]:
                    entry_val = str(entry.get('notes', ''))
                elif key in ["cat", "category"]:
                    entry_val = str(entry.get('category', ''))
                elif key == "strength":
                    # Специальный фильтр силы пароля
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
                    continue  # Переходим к следующему фильтру

                # Проверка вхождения (частичное совпадение)
                if val not in entry_val.lower():
                    match = False
                    break

            if not match:
                continue

            # 2. Полнотекстовый и нечеткий поиск
            if search_text_query:
                # Собираем строку для поиска
                full_text = f"{entry.get('service', '')} {entry.get('username', '')} {entry.get('notes', '')} {entry.get('url', '')}".lower()

                # Точное вхождение
                if search_text_query in full_text:
                    filtered.append(entry)
                # Нечеткий поиск (терпимость к опечаткам)
                elif fuzz.partial_ratio(search_text_query, full_text) > 75:  # Порог 75%
                    filtered.append(entry)
            else:
                # Если только фильтры без текста
                filtered.append(entry)

        return filtered