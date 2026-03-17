import time


class AuthenticationService:
    def __init__(self, key_manager, db_manager, timeout_seconds=60):
        self.key_manager = key_manager
        self.db_manager = db_manager
        self.timeout_seconds = timeout_seconds
        self._is_authenticated = False
        self._last_activity = 0

    def login(self, password: str) -> bool:
        # Получение сохраненного хеша из базы
        stored_hash = self.db_manager.get_setting("master_hash")

        if not stored_hash:
            return False

        if self.key_manager.kdf.verify_password(password, stored_hash):
            # Если хеш верен, генерируем и разблокируем ключи в памяти
            if self.key_manager.verify_and_unlock(password):
                self._is_authenticated = True
                self.update_activity()
                return True

        return False

    def logout(self):
        #завершение сессии и очистка ключей из памяти
        self._is_authenticated = False
        self.key_manager.storage.clear()
        print("Сессия завершена, ключи удалены.")

    def update_activity(self):
        # обновление времени от последнего действия
        self._last_activity = time.time()

    def check_session(self) -> bool:
        if not self._is_authenticated:
            return True  # если еще не вошли то не закрывать

        import time
        elapsed = time.time() - self._last_activity
        # print(f"прошло времени: {int(elapsed)} сек. лимит: {self.timeout_seconds}")
        if elapsed > self.timeout_seconds:
            #print("таймаут закрытие сессии")
            self.logout()  # очистка ключа
            return False  # конец сессии

        return True

    def is_authenticated(self):
        return self._is_authenticated and self.check_session()