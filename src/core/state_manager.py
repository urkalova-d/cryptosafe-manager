# src/core/state_manager.py
import time
from src.core.events import event_bus, EventType


class StateManager:
    def __init__(self):
        # Состояние сессии
        self.is_locked = False

        # Таймер бездействия (заглушка для Спринта 7)
        self.last_activity = time.time()

        # ДЛЯ ЭКСПОНЕНЦИАЛЬНОЙ ЗАДЕРЖКИ (AUTH-3)
        self.failed_attempts = 0
        self.last_failed_time = 0

        # Таймер буфера обмена (заглушка для Спринта 4)
        self.clipboard_content = None
        self.clipboard_timer = 0

        # Подписываемся на события для обновления состояния
        event_bus.subscribe(EventType.USER_LOGGED_IN, self._on_login)
        event_bus.subscribe(EventType.USER_LOGGED_OUT, self._on_logout)

    def get_login_delay(self) -> int:
        """Возвращает задержку в секундах для экспоненциального backoff (AUTH-3)"""
        if self.failed_attempts <= 2:
            return 1
        elif self.failed_attempts <= 4:
            return 5
        else:
            return 30

    def record_failed_attempt(self):
        """Фиксирует неудачную попытку входа"""
        self.failed_attempts += 1
        self.last_failed_time = time.time()
        print(f"[STATE] Неудачная попытка #{self.failed_attempts}")

    def reset_failed_attempts(self):
        """Сбрасывает счётчик после успешного входа"""
        self.failed_attempts = 0

    def lock_app(self):
        """Блокировка приложения"""
        self.is_locked = True
        print("[STATE] Приложение заблокировано")
        event_bus.publish(EventType.USER_LOGGED_OUT)

    def unlock_app(self):
        """Разблокировка приложения"""
        self.is_locked = False
        self.last_activity = time.time()
        print("[STATE] Приложение разблокировано")
        event_bus.publish(EventType.USER_LOGGED_IN)

    def _on_login(self, data):
        self.is_locked = False

    def _on_logout(self, data):
        self.is_locked = True


# Глобальный экземпляр менеджера состояний
state_manager = StateManager()