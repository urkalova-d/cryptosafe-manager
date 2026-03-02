# src/core/audit_logger.py
from src.core.events import event_bus, EventType

class AuditLogger:
    def __init__(self):
        # Подписываемся на ключевые события
        event_bus.subscribe(EventType.ENTRY_ADDED, self.log_event)
        event_bus.subscribe(EventType.USER_LOGGED_IN, self.log_event)

    def log_event(self, data: Any):
        """Заглушка записи в журнал (ЭВТ-2)"""
        print(f"[AUDIT LOG] Событие: {data}")