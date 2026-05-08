import pytest
import time
import json
import hashlib
import sqlite3
from datetime import datetime
from src.core.events import event_bus, EventType
from src.core.audit.log_verifier import LogVerifier
from src.core.audit.log_exporter import LogExporter


# Integrity Test

class TestAuditIntegrity:

    def test_tamper_detection(self, audit_logger, db):
        #тест1: Проверка обнаружения вмешательства
        # генерация 1000 записей
        count = 1000
        for i in range(count):
            audit_logger.log_event(
                event_type="TEST_EVENT",
                severity="INFO",
                source="test_runner",
                details={"index": i}
            )

        # ожидание завершения записи
        audit_logger.log_queue.join()

        # Проверка количество
        cursor = db.conn.execute("SELECT COUNT(*) FROM audit_log")
        actual_count = cursor.fetchone()[0]
        assert actual_count == count + 1, f"Expected {count + 1} entries, got {actual_count}"

        # Вмешиваемся в запись
        cursor = db.conn.execute("SELECT sequence_number FROM audit_log LIMIT 1 OFFSET 500")
        target_seq = cursor.fetchone()[0]

        db.conn.execute("DROP TRIGGER IF EXISTS prevent_audit_update")

        tampered_json = json.dumps({"message": "I AM HACKED"})

        db.conn.execute(
            "UPDATE audit_log SET details = ? WHERE sequence_number = ?",
            (tampered_json, target_seq,)
        )
        db.conn.commit()

        # верификация
        verifier = LogVerifier(db, audit_logger.signer)
        results = verifier.verify_all()

        assert results['verified'] == False, "Verifier should detect tampering"
        assert len(results['invalid_hashes']) > 0, "Should detect invalid hashes"

    def test_chain_continuity(self, audit_logger, db):
        #Проверка целостности цепочки (удаление записи)
        audit_logger.log_event("EVENT_A", "INFO", "test", {})
        audit_logger.log_event("EVENT_B", "INFO", "test", {})
        audit_logger.log_event("EVENT_C", "INFO", "test", {})
        audit_logger.log_queue.join()

        db.conn.execute("DROP TRIGGER IF EXISTS prevent_audit_delete")

        cursor = db.conn.execute("SELECT sequence_number FROM audit_log WHERE event_type='EVENT_B'")
        row = cursor.fetchone()
        assert row is not None, "EVENT_B not found"
        seq_to_delete = row[0]

        db.conn.execute("DELETE FROM audit_log WHERE sequence_number = ?", (seq_to_delete,))
        db.conn.commit()

        verifier = LogVerifier(db, audit_logger.signer)
        results = verifier.verify_all()

        assert results['verified'] == False
        assert len(results['chain_breaks']) > 0


#Performance Test

class TestPerformance:

    def test_logging_throughput(self, audit_logger, db):
        #тест2: Производительность логирования
        count = 10000

        start_time = time.time()

        for i in range(count):
            audit_logger.log_event(
                event_type="PERF_TEST",
                severity="INFO",
                source="perf_runner",
                details={"idx": i, "data": "x" * 50}
            )

        audit_logger.log_queue.join()
        total_time = time.time() - start_time

        avg_time_ms = (total_time / count) * 1000
        print(f"\n[PERF] Avg time per entry: {avg_time_ms:.3f} ms")

        assert avg_time_ms < 10.0

        verifier = LogVerifier(db, audit_logger.signer)

        start_verify = time.time()
        results = verifier.verify_all(limit=1000)
        verify_time = time.time() - start_verify

        print(f"[PERF] Verification of 1000 entries took: {verify_time:.3f}s")
        assert verify_time < 1.0


# Export/Import Test

class TestExportImport:

    def test_export_verification(self, audit_logger, db, tmp_path):
        #тест3: Экспорт в JSON и независимая проверка подписи
        audit_logger.log_event("EXPORT_EVENT", "INFO", "test", {"val": 123})
        audit_logger.log_queue.join()

        export_file = tmp_path / "audit_export.json"
        rows, _ = db.get_filtered_audit_logs(limit=100, offset=0, filters={})
        pub_key = audit_logger.signer.get_public_key_hex()

        success, msg = LogExporter.export_to_json(rows, pub_key, str(export_file))
        assert success, f"Export failed: {msg}"

        with open(export_file, 'r') as f:
            data = json.load(f)

        assert data['public_key'] == pub_key
        assert len(data['log_entries']) > 0

        entry = data['log_entries'][0]
        entry_data_reconstructed = {
            'timestamp': entry['timestamp'],
            'event_type': entry['event_type'],
            'severity': entry['severity'],
            'source': entry['source'],
            'user_id': entry['user_id'],
            'details': json.loads(entry['details']),
            'previous_hash': entry['previous_hash']
        }
        serialized_data = json.dumps(entry_data_reconstructed, sort_keys=True).encode()

        from cryptography.hazmat.primitives.asymmetric import ed25519

        pub_key_bytes = bytes.fromhex(data['public_key'])
        verify_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_key_bytes)

        try:
            verify_key.verify(bytes.fromhex(entry['signature']), serialized_data)
            is_valid = True
        except Exception:
            is_valid = False

        assert is_valid


#  Failure Recovery Test
class TestFailureRecovery:

    def test_graceful_degradation(self, audit_logger, db):
        #тест4: Graceful degradation
        audit_logger.log_event("BAD_DATA", "INFO", "test", {"key": "v" * 10000})
        audit_logger.log_queue.join()

        assert audit_logger.running == True
        count = db.conn.execute("SELECT COUNT(*) FROM audit_log WHERE event_type='BAD_DATA'").fetchone()[0]
        assert count == 1


# Security Test

class TestSecurity:

    def test_sql_injection_prevention(self, audit_logger, db):
        #тест-5: Защита от SQL Injection
        malicious_payload = "'; DROP TABLE audit_log; --"

        audit_logger.log_event(
            event_type="INJECTION_ATTEMPT",
            severity="WARN",
            source="attacker",
            details={"query": malicious_payload}
        )
        audit_logger.log_queue.join()

        cursor = db.conn.execute("SELECT COUNT(*) FROM audit_log")
        assert cursor.fetchone()[0] > 0

        cursor = db.conn.execute("SELECT details FROM audit_log WHERE event_type='INJECTION_ATTEMPT'")
        row = cursor.fetchone()
        details = json.loads(row[0])
        assert details['query'] == malicious_payload

    def test_db_triggers_protection(self, db, audit_logger):
        #Проверка защиты БД на уровне триггеров
        audit_logger.log_event("IMMUTABLE_TEST", "INFO", "test", {})
        audit_logger.log_queue.join()

        cursor = db.conn.execute("SELECT sequence_number FROM audit_log WHERE event_type='IMMUTABLE_TEST'")
        seq = cursor.fetchone()[0]

        with pytest.raises(sqlite3.IntegrityError) as excinfo:
            db.conn.execute("UPDATE audit_log SET severity='HACKED' WHERE sequence_number=?", (seq,))

        assert "SECURITY" in str(excinfo.value)

        with pytest.raises(sqlite3.IntegrityError) as excinfo:
            db.conn.execute("DELETE FROM audit_log WHERE sequence_number=?", (seq,))

        assert "SECURITY" in str(excinfo.value)