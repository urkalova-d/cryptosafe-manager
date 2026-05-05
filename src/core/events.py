from enum import Enum, auto

class EventType(Enum):
    # Аутентификация
    AUTH_LOGIN_SUCCESS = auto()
    AUTH_LOGIN_FAILURE = auto()
    AUTH_LOGOUT = auto()
    AUTH_PASSWORD_CHANGE = auto()
    AUTH_LOCK = auto()
    AUTH_UNLOCK = auto()

    # Хранилище
    VAULT_ENTRY_CREATED = auto()
    VAULT_ENTRY_UPDATED = auto()
    VAULT_ENTRY_DELETED = auto()
    VAULT_ENTRY_READ = auto()  # При просмотре/расшифровке

    #Буфер обмена
    CLIPBOARD_COPY = auto()  # Копирование данных
    CLIPBOARD_CLEARED = auto()  # Очистка буфера
    CLIPBOARD_TIMEOUT = auto()  # Авто-очистка по таймеру

    # Система
    SYSTEM_STARTUP = auto()
    SYSTEM_SHUTDOWN = auto()
    SYSTEM_SETTINGS_CHANGED = auto()
    SYSTEM_PANIC_MODE = auto()


class EventBus:
    def __init__(self):
        self.subscribers = {}

    def subscribe(self, event_type, callback):
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(callback)

    def publish(self, event_type, data=None):
        if event_type in self.subscribers:
            for callback in self.subscribers[event_type]:
                callback(data)

# Создаем глобальный объект шины событий
event_bus = EventBus()