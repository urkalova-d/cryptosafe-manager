import json
import hashlib
import threading
import queue
import time
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

        # Асинхронное логирование
        self.log_queue = queue.Queue()
        self.worker_thread = None
        self.running = False

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
            self._write_entry_sync(self._create_genesis_data())

        # Запускаем рабочий поток
        self.running = True
        self.worker_thread = threading.Thread(target=self._log_worker, daemon=True)
        self.worker_thread.start()

        self._initialized = True
        self._subscribe_events()
        print("[AuditLogger] Started with async worker thread.")

    def _log_worker(self):
        """Фоновый поток для записи логов (PERF-5)."""
        while self.running:
            try:
                # Получаем задачу из очереди с таймаутом
                entry_data = self.log_queue.get(timeout=1.0)
                if entry_data:
                    self._write_entry_sync(entry_data)
                    self.log_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[AuditLogger] Worker error: {e}")

    def stop(self):
        """Остановка потока."""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)



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

    def _create_genesis_data(self):
        return {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'SYSTEM_GENESIS',
            'severity': 'INFO',
            'source': 'audit_logger',
            'user_id': 'system',
            'details': {'message': 'Audit log initialized'},
            'previous_hash': '0' * 64
        }

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
        self.log_queue.put(entry_data)

    def on_vault_event(self, data: dict):
        """Обработчик событий хранилища."""
        event_type_map = {
            'create': ('VAULT_CREATE', 'INFO'),
            'update': ('VAULT_UPDATE', 'INFO'),
            'delete': ('VAULT_DELETE', 'WARN'),
            'read': ('VAULT_READ', 'INFO')
        }
        action = data.get('action', 'unknown')
        e_type, severity = event_type_map.get(action, ('VAULT_OP', 'INFO'))

        # Явно передаем важные поля
        self.log_event(
            event_type=e_type,
            severity=severity,
            source='vault_manager',
            details={
                'entry_id': data.get('entry_id'),
                'action': action,
                'service_name': data.get('service_name', '[REDACTED]')
            }
        )
    def on_auth_event(self, data: dict):
        """Обработчик событий аутентификации."""
        action = data.get('action', 'unknown')
        severity = 'WARN' if 'failure' in action or action == 'login_failure' else 'INFO'

        self.log_event(
            event_type=f"AUTH_{action.upper()}",
            severity=severity,
            source='auth_service',
            details={
                'user_id': data.get('user_id', 'default'),
                'reason': data.get('reason'), # Причина ошибки, если есть
                'attempts': data.get('attempts') # Кол-во попыток, если есть
            }
        )



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
                'data_type': data.get('data_type', 'unknown'),
                'auto_clear': data.get('auto_clear', False)
            }
        )

    def _sanitize_details(self, details: Dict) -> Dict:
        sensitive_keys = ['password', 'secret', 'token', 'key', 'credential']
        return {k: ("[REDACTED]" if any(s in k.lower() for s in sensitive_keys) else v) for k, v in details.items()}

    def _write_entry_sync(self, entry_data: Dict):
        """Синхронная запись в БД (выполняется в рабочем потоке)."""
        try:
            # Получаем хеш предыдущей записи
            # Внимание: при асинхронной записи возможен race condition,
            # если много логов пишется одновременно.
            # Для высокой нагрузки нужно кэшировать последний хеш в памяти.
            # Упрощенный вариант: берем из БД.

            # Оптимизация: кэшируем последний хеш в памяти потока
            if not hasattr(self, '_last_hash_cache'):
                last_entry = self.db.get_last_audit_entry()
                self._last_hash_cache = last_entry[1] if last_entry else '0' * 64

            prev_hash = self._last_hash_cache
            entry_data['previous_hash'] = prev_hash

            entry_json = json.dumps(entry_data, sort_keys=True)
            entry_hash = hashlib.sha256(entry_json.encode('utf-8')).hexdigest()
            signature = self.signer.sign(entry_json.encode('utf-8'))

            self.db.add_audit_entry(entry_data, signature.hex(), entry_hash, prev_hash)

            # Обновляем кэш
            self._last_hash_cache = entry_hash

        except Exception as e:
            print(f"[AuditLogger] Error writing entry: {e}")