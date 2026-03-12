import pytest
from PyQt6.QtWidgets import QApplication
from src.gui.main_window import MainWindow

# Фикстура для создания приложения (нужна для Qt)
@pytest.fixture
def app(qtbot):
    test_app = MainWindow()
    qtbot.addWidget(test_app)
    return test_app


def test_main_window_initial_state(app):
    #Проверка,что окно загружается с нужным заголовком
    assert app.windowTitle() == "CryptoSafe Password Manager"
    assert app.table.columnCount() == 5


def test_clipboard_logic(app, qtbot):
    #тест копирования в буфер обмена
    test_pass = "secret_clipboard_123"

    # вызов копирования
    app.copy_to_clipboard(test_pass)

    # проверка системного буфера обмена
    clipboard = QApplication.clipboard()
    assert clipboard.text() == test_pass