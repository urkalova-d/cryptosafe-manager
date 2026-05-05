import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
from src.core.events import event_bus, EventType


class AuditLogger:
    """
    Центральный контроллер аудита.
    Требования: ARC-2 (Decoupling), CRY-4 (Hash Chain), LOG-3 (Sanitization)
    """

    def __init__(self, db_helper, signer):
        self.db = db_helper
        self.signer = signer
        self._initialized = False

    def start(self):
        """Инициализация: проверка цепочки и создание Genesis-записи."""
        if not self.signer.initialize():
            print("[Audit] Failed to initialize signer.")
            return

        # Сохраняем публичный ключ в БД для будущей верификации
        pub_key = self.signer.get_public_key_hex()
        stored_key = self.db.get_active_public_key()

        if not stored_key:
            self.db.save_audit_public_key(pub_key)
        elif stored_key != pub_key:
            # Это случай, когда мастер-пароль сменен (Sprint 2 key rotation)
            # Для Sprint 5 пока считаем, что ключ статичен, или обновляем его
            print("[Audit] Warning: Audit signing key changed. Updating public key.")
            self.db.save_audit_public_key(pub_key)

        # Создаем Genesis запись, если лог пуст
        last_entry = self.db.get_last_audit_entry()
        if not last_entry:
            self._create_genesis_entry()

        self._initialized = True
        self._subscribe_events()

    def _subscribe_events(self):
        """Подписка на глобальные события (ARC-2)."""
        # Хранилище
        event_bus.subscribe(EventType.VAULT_ENTRY_CREATED, self.on_vault_event)
        event_bus.subscribe(EventType.VAULT_ENTRY_UPDATED, self.on_vault_event)
        event_bus.subscribe(EventType.VAULT_ENTRY_DELETED, self.on_vault_event)

        # Аутентификация
        event_bus.subscribe(EventType.AUTH_LOGIN_SUCCESS, self.on_auth_event)
        event_bus.subscribe(EventType.AUTH_LOGIN_FAILURE, self.on_auth_event)
        event_bus.subscribe(EventType.AUTH_LOGOUT, self.on_auth_event)

        # Буфер обмена
        event_bus.subscribe(EventType.CLIPBOARD_COPY, self.on_clipboard_event)
        event_bus.subscribe(EventType.CLIPBOARD_CLEARED, self.on_clipboard_event)

    def _create_genesis_entry(self):
        """Создает первую запись в журнале (Start of Chain)."""
        genesis_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'SYSTEM_GENESIS',
            'severity': 'INFO',
            'source': 'audit_logger',
            'user_id': 'system',
            'details': {'message': 'Audit log initialized'}
        }
        # Previous hash for genesis is 64 zeros
        self._write_entry(genesis_data, prev_hash='0' * 64)

    def log_event(self, event_type: str, severity: str, source: str,
                  details: Dict[str, Any], user_id: str = 'default'):
        """Публичный метод для ручного логирования событий."""
        if not self._initialized:
            print("[Audit] Logger not initialized.")
            return

        entry_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'severity': severity,
            'source': source,
            'user_id': user_id,
            'details': self._sanitize_details(details)
        }
        self._write_entry(entry_data)

    def on_vault_event(self, data: dict):
        """Обработчик событий хранилища."""
        # Определяем тип и важность
        event_type_map = {
            'create': ('VAULT_CREATE', 'INFO'),
            'update': ('VAULT_UPDATE', 'INFO'),
            'delete': ('VAULT_DELETE', 'WARN'),
            'read': ('VAULT_READ', 'INFO')
        }

        action = data.get('action', 'unknown')
        e_type, severity = event_type_map.get(action, ('VAULT_OP', 'INFO'))

        self.log_event(
            event_type=e_type,
            severity=severity,
            source='vault_manager',
            details={
                'entry_id': data.get('entry_id'),
                'action': action,
                'service_name': data.get('service_name', '[REDACTED]')  # Можно передавать имя сервиса
            }
        )
    def on_auth_event(self, data: dict):
        """Обработчик событий аутентификации."""
        action = data.get('action', 'unknown')

        # Определяем важность: неудачный вход - WARN, остальное - INFO
        severity = 'WARN' if 'failure' in action or action == 'login_failure' else 'INFO'

        self.log_event(
            event_type=f"AUTH_{action.upper()}",
            severity=severity,
            source='auth_service',
            details={
                'user_id': data.get('user_id', 'default'),
                'reason': data.get('reason')
            }
        )

    def _sanitize_details(self, details: Dict) -> Dict:
        """Удаление чувствительных данных (LOG-3)."""
        sensitive_keys = ['password', 'secret', 'token', 'key', 'credential']
        sanitized = {}
        for k, v in details.items():
            if any(s in k.lower() for s in sensitive_keys):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = v
        return sanitized

    def _write_entry(self, entry_data: Dict, prev_hash: str = None):
        """Запись в БД с вычислением хеша и подписи."""
        try:
            # 1. Получаем хеш предыдущей записи (для цепочки)
            if prev_hash is None:
                last_entry = self.db.get_last_audit_entry()
                # last_entry is tuple (seq, hash)
                prev_hash = last_entry[1] if last_entry else '0' * 64

            # Добавляем хеш предыдущей записи в данные для подписи
            entry_data['previous_hash'] = prev_hash

            # 2. Сериализация
            # Важно: сортировка ключей для детерминированного JSON
            entry_json = json.dumps(entry_data, sort_keys=True)

            # 3. Вычисление хеша текущей записи (SHA-256)
            entry_hash = hashlib.sha256(entry_json.encode('utf-8')).hexdigest()

            # 4. Подпись
            signature = self.signer.sign(entry_json.encode('utf-8'))
            signature_hex = signature.hex()

            # 5. Запись в БД
            self.db.add_audit_entry(entry_data, signature_hex, entry_hash, prev_hash)

        except Exception as e:
            print(f"[AuditLogger] Critical error writing entry: {e}")

    def verify_integrity(self) -> bool:
        """Проверка целостности цепочки (VER-1)."""
        # Реализуем в следующем пункте (Log Verifier)
        pass

    def on_clipboard_event(self, data: dict):
        """Обработчик событий буфера обмена."""
        action = data.get('action', 'copy')

        self.log_event(
            event_type=f"CLIPBOARD_{action.upper()}",
            severity='INFO',
            source='clipboard_service',
            details={
                'entry_id': data.get('entry_id'),
                'data_type': data.get('data_type', 'unknown'),  # password/username
                'auto_clear': data.get('auto_clear', False)
            }
        )