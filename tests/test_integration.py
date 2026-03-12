import pytest
from unittest.mock import MagicMock
from src.gui.main_window import MainWindow
from src.gui.setup_wizard import SetupWizard
from src.core.config import Config

from src.core.config import DevelopmentConfig, Config

def test_config_loading():
    #Проверка загрузки конфигурации
    config = DevelopmentConfig()
    assert config.DEBUG is True
    assert config.DB_PATH == "dev_vault.db"

def test_setup_wizard_flow(qtbot):
    from src.gui.setup_wizard import SetupWizard
    from PyQt6.QtCore import Qt

    wizard = SetupWizard()
    qtbot.addWidget(wizard)

    wizard.pass1.setText("masterpass123")
    wizard.pass2.setText("masterpass123")

    with qtbot.waitSignal(wizard.setup_finished) as blocker:
        qtbot.mouseClick(wizard.btn_finish, Qt.MouseButton.LeftButton)

    assert blocker.args == ["masterpass123"]