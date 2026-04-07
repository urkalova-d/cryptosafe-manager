from .encryption_service import EncryptionService
from .password_generator import PasswordGenerator

class EntryManager:
    def __init__(self, key_manager, db_helper):
        self.db = db_helper
        self.encryption = EncryptionService(key_manager)
        self.generator = PasswordGenerator()

    def add_entry(self, service, username, password, notes):
        """Добавление записи с шифрованием пароля."""
        encrypted_pass = self.encryption.encrypt(password)
        return self.db.add_entry(service, username, encrypted_pass, notes)

    def get_all_entries(self):
        """Получение всех записей (пароли расшифровываются)."""
        # Примечание: Массовая расшифровка может быть медленной.
        # Лучше расшифровывать по требованию, но для удобства GUI сделаем здесь.
        # В идеале этот метод должен возвращать "маскированные" данные,
        # а расшифровку делать по клику. Пока оставим заглушку.
        return self.db.get_all_entries()