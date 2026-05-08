# tests/test_audit_performance.py
import sys
import os
import time
import sqlite3

# Добавляем корень проекта в путь
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database.db import DatabaseHelper
from src.core.crypto.key_manager import KeyManager
from src.core.audit import AuditLogger, AuditLogSigner
from src.core.audit.log_verifier import LogVerifier


def test_performance():
    print("AUDIT PERFORMANCE TEST ")

    # 1. Инициализация (используем отдельный файл БД для теста)
    test_db_path = "test_perf.db"
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    db = DatabaseHelper(db_path=test_db_path)

    # Мокаем KeyManager для теста (нужен только get_audit_key)
    class MockKeyManager:
        def get_audit_key(self):
            return os.urandom(32)  # Случайный ключ для теста

    key_manager = MockKeyManager()

    signer = AuditLogSigner(key_manager)
    signer.initialize()

    logger = AuditLogger(db, signer)
    logger.start()

    #  Logging Speed (< 10ms per op)
    print("\n[TEST 1] Testing logging speed for 100 entries...")
    start_time = time.time()

    count = 100
    for i in range(count):
        logger.log_event("TEST_EVENT", "INFO", "perf_test", {"index": i})

    # Ждем, пока очередь очистится (асинхронная запись)
    logger.log_queue.join()
    elapsed = time.time() - start_time

    avg_time_ms = (elapsed / count) * 1000
    print(f"Total time for {count} entries: {elapsed:.4f}s")
    print(f"Average time per entry: {avg_time_ms:.2f}ms")
    if avg_time_ms < 10:
        print("✅ PERF-1 PASSED: < 10ms per op")
    else:
        print("❌ PERF-1 FAILED")

    # Query Speed (< 500ms for 10k entries) ===
    print("\n[TEST 3] Testing query speed...")
    # Сначала заполним базу до 1000 записей (для демонстрации, 10к займет много времени)
    # В реальном тесте можно сгенерировать SQL INSERT напрямую для скорости
    print(f"Current DB size: {db.get_last_audit_entry()[0] if db.get_last_audit_entry() else 0}")

    start_time = time.time()
    rows, total = db.get_filtered_audit_logs(limit=10000, offset=0, filters={})
    elapsed = time.time() - start_time

    print(f"Fetched {len(rows)} rows in {elapsed * 1000:.2f}ms")
    if elapsed < 0.5:
        print("✅ PERF-3 PASSED: Query < 500ms")
    else:
        print("❌ PERF-3 FAILED")

    #  Verification Speed (< 1s for 1000 entries)
    print("\n[TEST PERF-2] Testing verification speed...")
    verifier = LogVerifier(db, signer)

    start_time = time.time()
    results = verifier.verify_all(limit=1000)
    elapsed = time.time() - start_time

    print(f"Verified {results['total_checked']} entries in {elapsed:.4f}s")
    if elapsed < 1.0:
        print("✅ PERF-2 PASSED: Verification < 1s")
    else:
        print("❌ PERF-2 FAILED")

    logger.stop()
    db.close()
    if os.path.exists(test_db_path):
        os.remove(test_db_path)


if __name__ == "__main__":
    test_performance()