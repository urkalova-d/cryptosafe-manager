import sys
import os
import pytest
import time
import threading
import ctypes
import struct

# --- PATH FIX FOR IMPORTS ---
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt6.QtCore import QTimer
from unittest.mock import Mock, MagicMock

# Импорты тестируемых классов
from src.core.clipboard.clipboard_service import ClipboardService, SECURITY_PROFILES
from src.core.clipboard.platform_adapter import PlatformAdapter
from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.crypto.key_storage import KeyStorage


class MemoryScanner:
    #Класс для сканирования памяти текущего процесса.
    def __init__(self):
        self.found_addresses = []
        self.platform = sys.platform

    def scan(self, target_bytes: bytes) -> bool:
        #Сканирует всю доступную память процесса в поисках target_bytes
        if self.platform == "win32":
            return self._scan_windows(target_bytes)
        elif self.platform.startswith("linux"):
            return self._scan_linux(target_bytes)
        else:
            print(f"[Scanner] Platform {self.platform} not supported for deep scan.")
            return False

    def _scan_windows(self, target_bytes: bytes) -> bool:
        """Реализация для Windows через VirtualQueryEx/ReadProcessMemory."""
        kernel32 = ctypes.windll.kernel32

        # Константы WinAPI
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        MEM_COMMIT = 0x1000
        PAGE_READWRITE = 0x04
        PAGE_EXECUTE_READWRITE = 0x40

        # Получаем хендл текущего процесса
        pid = os.getpid()
        process_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

        if not process_handle:
            print("[Scanner] Failed to open process handle.")
            return False

        try:
            address = 0
            mbi = ctypes.c_buffer(60)  # MEMORY_BASIC_INFORMATION size
            found = False

            while True:
                # Запрашиваем информацию о регионе памяти
                result = kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), mbi, ctypes.sizeof(mbi))

                if result == 0:
                    break  # Дошли до конца адресного пространства

                # Распаковываем структуру (BaseAddress, AllocationBase, RegionSize, State, Protect)
                # Формат зависит от разрядности, но для x64:
                # typedef struct _MEMORY_BASIC_INFORMATION {
                #   PVOID BaseAddress;
                #   PVOID AllocationBase;
                #   DWORD AllocationProtect;
                #   SIZE_T RegionSize;
                #   DWORD State;
                #   DWORD Protect;
                #   DWORD Type;
                # } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

                # Простая распаковка для x64 (8+8+4+8+4+4+4 = 40 байт, но выравнивание делает 48 или 60)
                # Безопаснее использовать структуру, но для теста распарсим "в лоб".

                # Используем struct для надежности
                # 'QQQIIII' -> Base(8), AllocBase(8), AllocProt(4), RegionSize(8 - как size_t), State(4), Prot(4), Type(4)
                # Обратите внимание: выравнивание может отличаться.

                # Альтернативный, более надежный способ извлечения:
                base_address = int.from_bytes(mbi.raw[0:8], 'little')
                region_size = int.from_bytes(mbi.raw[16:24], 'little')
                state = int.from_bytes(mbi.raw[24:28], 'little')
                protect = int.from_bytes(mbi.raw[32:36], 'little')

                # Проверяем, можно ли читать регион
                if state == MEM_COMMIT and (protect == PAGE_READWRITE or protect == PAGE_EXECUTE_READWRITE):
                    # Читаем регион
                    buffer = (ctypes.c_char * region_size)()
                    bytes_read = ctypes.c_size_t()

                    if kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(base_address), buffer, region_size,
                                                  ctypes.byref(bytes_read)):
                        # Ищем в буфере
                        if target_bytes in buffer.raw:
                            print(f"[Scanner] FOUND PLAINTEXT at 0x{base_address:X}")
                            found = True
                            break

                # Переходим к следующему региону
                address = base_address + region_size
                if address <= 0: break  # Защита от переполнения

            return found

        finally:
            kernel32.CloseHandle(process_handle)

    def _scan_linux(self, target_bytes: bytes) -> bool:
        """Реализация для Linux через /proc/self/maps."""
        try:
            maps_file = open("/proc/self/maps", "r")
            mem_file = open("/proc/self/mem", "rb", 0)

            found = False
            for line in maps_file:
                # Парсим строку: адреса права ...
                parts = line.split()
                if len(parts) < 6: continue
                addr_range = parts[0]
                perms = parts[1]

                # Ищем читаемые регионы (r--)
                if 'r' not in perms: continue

                start, end = [int(x, 16) for x in addr_range.split('-')]
                size = end - start

                try:
                    mem_file.seek(start)
                    data = mem_file.read(size)
                    if target_bytes in data:
                        print(f"[Scanner] FOUND PLAINTEXT at 0x{start:X}")
                        found = True
                        break
                except Exception:
                    continue

            maps_file.close()
            mem_file.close()
            return found
        except Exception as e:
            print(f"[Scanner] Linux scan failed: {e}")
            return False



@pytest.fixture
def mock_db_helper():
    helper = Mock()
    helper.get_setting = Mock(return_value="standard")
    helper.save_setting = Mock()
    helper.add_audit_log = Mock()
    return helper


@pytest.fixture
def mock_key_storage():
    storage = Mock(spec=KeyStorage)
    storage.is_locked = Mock(return_value=False)
    # Эмуляция защиты
    storage.protect_data = Mock(side_effect=lambda x: bytearray(x))
    storage.unprotect_data = Mock(side_effect=lambda x: bytes(x))
    storage.zero_buffer = Mock()
    return storage


@pytest.fixture
def real_key_storage():
    storage = KeyStorage()
    storage._is_locked = False
    return storage


@pytest.fixture
def mock_adapter():
    adapter = Mock(spec=PlatformAdapter)
    adapter.copy_to_clipboard = Mock(return_value=True)
    adapter.clear_clipboard = Mock(return_value=True)
    adapter.get_clipboard_content = Mock(return_value="")
    return adapter


@pytest.fixture
def clipboard_monitor(qtbot):
    monitor = ClipboardMonitor()
    return monitor


@pytest.fixture
def clipboard_service(qtbot, mock_adapter, clipboard_monitor, mock_db_helper):
    service = ClipboardService(mock_adapter, clipboard_monitor, mock_db_helper)
    return service



def test_auto_clear_timing(qtbot, clipboard_service, mock_adapter, mock_key_storage):
    clipboard_service.set_key_storage(mock_key_storage)
    test_timeout = 1
    clipboard_service._timeout_duration = test_timeout

    start_time = time.time()
    clear_signal_time = None

    def on_cleared():
        nonlocal clear_signal_time
        clear_signal_time = time.time()

    clipboard_service.clipboard_cleared.connect(on_cleared)
    clipboard_service.copy_password(1, "test_password")

    with qtbot.wait_signal(clipboard_service.clipboard_cleared, timeout=2000):
        pass

    assert clear_signal_time is not None
    elapsed_time = clear_signal_time - start_time
    print(f"Elapsed time: {elapsed_time:.3f}s (Expected: {test_timeout}s)")
    assert abs(elapsed_time - test_timeout) < 0.3
    mock_adapter.clear_clipboard.assert_called()


# TEST-3

def test_memory_security_plaintext_not_found(clipboard_service, real_key_storage):

    clipboard_service.set_key_storage(real_key_storage)

    #отключение автоотчистки
    original_timeout = clipboard_service._timeout_duration
    clipboard_service._timeout_duration = 300
    clipboard_service._clear_timer.stop()
    # копирование
    secret_password = "UNIQUE_SECRET_TEST_PASSWORD_12345_XYZ"
    entry_id = 999999
    clipboard_service.copy_password(entry_id, secret_password)
    time.sleep(0.1)

    #проверка маски
    xor_mask_valid = True
    xor_mask_stored = clipboard_service._xor_mask

    if xor_mask_stored:
        if len(xor_mask_stored) != len(secret_password.encode('utf-8')):
            xor_mask_valid = False

        target_bytes = secret_password.encode('utf-8')
        if target_bytes in bytes(xor_mask_stored) if isinstance(xor_mask_stored,
                                                                bytearray) else target_bytes in xor_mask_stored:
            xor_mask_valid = False

        if all(b == 0 for b in xor_mask_stored):
            xor_mask_valid = False

    #дамп памяти и проверка на плейнтекст
    scanner = MemoryScanner()
    target_bytes = secret_password.encode('utf-8')

    plaintext_found = False
    for attempt in range(3):
        if scanner.scan(target_bytes):
            plaintext_found = True
            break
        time.sleep(0.05)

    #проверка очистки памяти
    clipboard_service.clear_now()
    time.sleep(0.05)

    residue_found = False
    for attempt in range(3):
        if scanner.scan(target_bytes):
            residue_found = True
            break
        time.sleep(0.05)

    clipboard_service._timeout_duration = original_timeout

    assert not plaintext_found, \
        f"FAILED: Plaintext password found in memory during copy!"

    assert not residue_found, \
        f"BONUS CHECK FAILED: Memory not properly cleared after clear_now()!"

    assert xor_mask_valid, \
        f"BONUS CHECK FAILED: XOR mask is invalid, missing, or contains plaintext!"

    print(f"[OK] Memory security test passed for entry {entry_id}")
    print(f"[OK] XOR mask validation passed - mask length: {len(xor_mask_stored) if xor_mask_stored else 0}")
    print(f"[OK] Cleanup verification passed - no memory residue detected")


def test_concurrency(qtbot, clipboard_service, mock_key_storage):
    clipboard_service.set_key_storage(mock_key_storage)
    results = []
    lock = threading.Lock()

    def copy_task(task_id):
        try:
            password = f"pass_{task_id}"
            clipboard_service.copy_password(task_id, password)
            with lock:
                results.append(True)
        except Exception as e:
            print(f"Error in thread {task_id}: {e}")

    threads = []
    for i in range(50):
        t = threading.Thread(target=copy_task, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(results) == 50
    assert clipboard_service._secure_data is not None


def test_recovery_on_failure(qtbot, clipboard_service, mock_adapter, mock_key_storage):
    clipboard_service.set_key_storage(mock_key_storage)

    # сбой копирования
    mock_adapter.copy_to_clipboard.side_effect = RuntimeError("Simulated OS Crash")

    with pytest.raises(RuntimeError):
        clipboard_service.copy_password(1, "TopSecretData")

    assert clipboard_service._secure_data is None
    assert clipboard_service._xor_mask is None

    # ресет
    mock_adapter.copy_to_clipboard.side_effect = None
    mock_adapter.copy_to_clipboard.return_value = True

    # явный сбой
    mock_adapter.clear_clipboard.return_value = False
    clipboard_service.copy_password(2, "Test")
    clipboard_service.clear_now()

    assert clipboard_service._secure_data is None