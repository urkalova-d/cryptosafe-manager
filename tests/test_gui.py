import pytest
from PyQt6.QtCore import Qt
from src.gui.main_window import MainWindow


@pytest.fixture
def window(qtbot, db_helper):
    #фикстура для подготовки окна и базы
    # создание нужных таблиц через соединение
    conn = getattr(db_helper, 'conn', getattr(db_helper, 'connection', None))
    if conn:
        with conn:
            conn.execute("CREATE TABLE IF NOT EXISTS settings (setting_key TEXT PRIMARY KEY, setting_value TEXT)")
            conn.execute("INSERT OR IGNORE INTO settings VALUES ('master_hash', 'dummy_hash')")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS vault_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT, username TEXT, encrypted_password TEXT, notes TEXT)")

    #Создание экземпляра окна
    win = MainWindow()
    win.check_first_run = lambda: None
    win.db_helper = db_helper
    win.db = db_helper

    # очистка таблицы от демо записей
    if hasattr(win, 'table'):
        win.table.setRowCount(0)

    qtbot.add_widget(win)
    return win


def test_gui_01_title(window):
    assert "CryptoSafe" in window.windowTitle()


def test_gui_02_add_record(qtbot, window):
    # тестирование добавления записей
    window.handle_save("TestService", "Login", "Pass", "Note")
    qtbot.waitUntil(lambda: window.table.rowCount() > 0, timeout=2000)
    assert window.table.item(0, 0).text() == "TestService"


def test_gui_03_load_async(qtbot, window, db_helper):
    # добавление данныех в бд напрямую
    db_helper.add_entry("AsyncService", "User", "Pass", "Note")

    #Запуск загрузки через поток
    window.load_data()

    # ожидание появления данных
    qtbot.waitUntil(lambda: window.table.rowCount() > 0, timeout=5000)

    found = False
    for i in range(window.table.rowCount()):
        if window.table.item(i, 0).text() == "AsyncService":
            found = True
            break
    assert found