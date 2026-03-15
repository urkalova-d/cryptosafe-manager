import time


class AuthenticationService:
    def __init__(self, key_manager, timeout_seconds=300):
        self.key_manager = key_manager
        self.timeout_seconds = timeout_seconds
        self._is_authenticated = False
        self._last_activity = 0

    def login(self, password: str) -> bool:
        #попытка входа и начало сессии
        if self.key_manager.verify_and_unlock(password):
            self._is_authenticated = True
            self._last_activity = time.time()  #фиксирование времени входа
            return True
        return False

    def logout(self):
        #завершение сессии и очистка ключей из памяти
        self._is_authenticated = False
        self.key_manager.storage.clear()
        print("Сессия завершена, ключи удалены.")

    def _update_activity(self):
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