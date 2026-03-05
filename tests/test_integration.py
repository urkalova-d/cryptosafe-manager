# tests/test_integration.py
import pytest
from unittest.mock import MagicMock
from src.gui.main_window import MainWindow
from src.gui.setup_wizard import SetupWizard
from src.core.config import Config


# tests/test_integration.py
from src.core.config import DevelopmentConfig, Config

def test_config_loading():
    """Проверка загрузки конфигурации (CFG-3)"""
    # Если ты хочешь проверить именно класс DevelopmentConfig:
    config = DevelopmentConfig()
    assert config.DEBUG is True
    assert config.DB_PATH == "dev_vault.db"


# Тесты GUI требуют настройки отображения в ОС,
# поэтому проверяем логику без отрисовки (mocking)
def test_setup_wizard_flow():
    """Проверка логики мастера настройки (GUI-3)"""
    callback_mock = MagicMock()
    wizard = SetupWizard(callback=callback_mock)

    # Имитируем ввод паролей
    wizard.pass1.entry.insert(0, "masterpass")
    wizard.pass2.entry.insert(0, "masterpass")

    # Нажимаем завершение
    wizard.finish()

    assert callback_mock.called