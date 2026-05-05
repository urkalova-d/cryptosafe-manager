from enum import Enum, auto

class EventType(Enum):
    # Системные
    SETTINGS_CHANGED = auto()
    DATABASE_UPDATED = auto()

    # Аутентификация
    AUTH_SUCCESS = auto()
    AUTH_FAILURE = auto()
    USER_LOGGED_IN = auto()
    USER_LOGGED_OUT = auto()

    # Хранилище
    ENTRY_ADDED = auto()
    ENTRY_UPDATED = auto()
    ENTRY_DELETED = auto()
    ENTRY_READ = auto()
    ENTRY_COPIED = auto()

    # Буфер обмена
    CLIPBOARD_COPY = auto()
    CLIPBOARD_CLEAR = auto()


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