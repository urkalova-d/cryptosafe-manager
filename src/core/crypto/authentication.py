import time
from PyQt6.QtCore import QObject, pyqtSignal


class AuthenticationService(QObject):
    UserLoggedIn = pyqtSignal()
    UserLoggedOut = pyqtSignal()

    def __init__(self, key_manager, db_manager, timeout_seconds=3600):
        super().__init__()

        self.key_manager = key_manager
        self.db_manager = db_manager
        self.timeout_seconds = timeout_seconds

        self._is_authenticated = False
        self._last_activity = 0
        self._login_timestamp = 0

        # четчики
        self._failed_attempts = 0
        self._last_failed_time = 0

    def verify_mfa(self, code: str) -> bool:#метод для интеграции с будущими спринтами
        if not code:
            return True
        return True

    def is_mfa_enabled(self) -> bool:
        #проверка включен ли mfa
        return False

    def login(self, password: str) -> bool:
        # Проверяет пароль и разблокирует ключи
        stored_hash = self.db_manager.get_setting("master_hash")
        if not stored_hash:
            return False

        # проверка пароля
        if self.key_manager.kdf.verify_password(password, stored_hash):
            if self.key_manager.verify_and_unlock(password):
                self._is_authenticated = True
                self._failed_attempts = 0  # сброс счетчика
                self.update_activity()
                self._login_timestamp = time.time()
                self.UserLoggedIn.emit()
                return True

        # при не правилном пароле фиксируется попытка
        self._register_failed_attempt()
        return False

    def apply_login_delay(self):
         #задержка после неудачной попытки.
        delay = self._calculate_delay()
        if delay > 0:
            print(f"Security delay applied: {delay}s")
            time.sleep(delay)

    def _calculate_delay(self) -> int:
        # сброс счетчика когда прошло 5 минут
        if time.time() - self._last_failed_time > 300:
            self._failed_attempts = 0

        if self._failed_attempts < 2:
            return 0
        elif self._failed_attempts < 4:
            return 5
        else:
            return 30

    def _register_failed_attempt(self):
        self._failed_attempts += 1
        self._last_failed_time = time.time()

    def logout(self):
        self._is_authenticated = False
        self._login_timestamp = 0
        if hasattr(self, 'key_manager'):
            self.key_manager.storage.clear()
        self.UserLoggedOut.emit()

    def update_activity(self):
        self._last_activity = time.time()

    def check_session(self) -> bool:
        if not self._is_authenticated:
            return True

        elapsed = time.time() - self._last_activity
        if elapsed > self.timeout_seconds:
            self.logout()
            return False

        return True

    def is_authenticated(self):
        return self._is_authenticated and self.check_session()