# src/core/events.py
from enum import Enum, auto

class EventType(Enum):
    SETTINGS_CHANGED = auto()  # Тот самый пропущенный пункт
    DATABASE_UPDATED = auto()
    AUTH_SUCCESS = auto()

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