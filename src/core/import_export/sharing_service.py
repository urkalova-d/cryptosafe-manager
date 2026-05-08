from datetime import datetime, timedelta
import uuid


class SharingService:
    """
    SHR-1: Обеспечивает безопасный обмен отдельными записями.
    """

    def __init__(self, entry_manager, db_helper):
        self.entry_manager = entry_manager
        self.db = db_helper

    def share_entry(self, entry_id: int, method: str, expiration_days: int = 7) -> dict:
        """
        Создает пакет для шаринга.

        Args:
            entry_id: ID записи.
            method: Метод ('password' или 'public_key').
            expiration_days: Срок действия.

        Returns:
            dict: Данные о шаринге (share_id, пакет).
        """
        # 1. Получаем запись
        entry = self.entry_manager.get_entry(entry_id)
        if not entry:
            raise ValueError("Entry not found")

        # 2. Генерируем Share ID
        share_id = str(uuid.uuid4())

        # 3. Логика создания зашифрованного пакета (будет реализована позже)
        # Сейчас возвращаем заглушку
        share_package = {
            "share_id": share_id,
            "expires_at": (datetime.utcnow() + timedelta(days=expiration_days)).isoformat(),
            "entry_preview": entry.get('service', 'Unknown')
        }

        # TODO: Сохранение в таблицу shared_entries (DB-1)

        return share_package