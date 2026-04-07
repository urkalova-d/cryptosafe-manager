import time
import traceback
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

        # счетчики
        self._failed_attempts = 0
        self._last_failed_time = 0

    def verify_mfa(self, code: str) -> bool:
        """метод для интеграции с будущими спринтами"""
        if not code:
            return True
        return True

    def is_mfa_enabled(self) -> bool:
        """проверка включен ли mfa"""
        return False

    def login(self, password: str) -> bool:
        """Проверяет пароль и разблокирует ключи"""
        try:
            # Используем verify_and_unlock для разблокировки
            if self.key_manager.verify_and_unlock(password):
                self._is_authenticated = True
                self._failed_attempts = 0
                self.update_activity()
                self._login_timestamp = time.time()

                print("Аутентификация успешна, ключи загружены")

                # Проверяем, что ключи действительно загружены
                enc_key = self.key_manager.get_encryption_key()
                if enc_key is None:
                    print("ОШИБКА: Ключи не загружены после verify_and_unlock!")
                    return False

                print(f"Ключ шифрования загружен, длина: {len(enc_key)}")
                self.UserLoggedIn.emit()
                return True
            else:
                print("Неверный пароль или ошибка разблокировки")
                self._register_failed_attempt()
                return False

        except Exception as e:
            print(f"Ошибка при входе: {e}")
            import traceback
            traceback.print_exc()
            return False

    def apply_login_delay(self):
        """задержка после неудачной попытки"""
        delay = self._calculate_delay()
        if delay > 0:
            print(f"Security delay applied: {delay}s")
            time.sleep(delay)

    def _calculate_delay(self) -> int:
        """расчет задержки на основе количества неудачных попыток"""
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
        """регистрация неудачной попытки входа"""
        self._failed_attempts += 1
        self._last_failed_time = time.time()

    def logout(self):
        """выход из системы с очисткой ключей"""
        print("Выход из системы, очистка ключей")
        self._is_authenticated = False
        self._login_timestamp = 0
        if hasattr(self, 'key_manager'):
            self.key_manager.storage.clear()
        self.UserLoggedOut.emit()

    def update_activity(self):
        """обновление времени последней активности"""
        self._last_activity = time.time()

    def check_session(self) -> bool:
        """проверка активности сессии"""
        if not self._is_authenticated:
            return True

        elapsed = time.time() - self._last_activity
        if elapsed > self.timeout_seconds:
            print(f"Сессия истекла через {elapsed:.0f} секунд")
            self.logout()
            return False

        return True

    def is_authenticated(self) -> bool:
        """проверка состояния аутентификации"""
        return self._is_authenticated and self.check_session()