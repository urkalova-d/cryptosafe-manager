# src/core/clipboard/platform_adapter.py
import sys
import subprocess
from typing import Optional


class PlatformAdapter:
    """
    Адаптер для работы с системным буфером обмена на разных платформах.
    Инкапсулирует вызовы pyperclip или нативных API.
    """

    def __init__(self):
        self.platform = sys.platform

    def copy_to_clipboard(self, text: str) -> bool:
        """Копирует текст в системный буфер обмена."""
        try:
            # Предпочитаем PyQt6, так как он уже используется в проекте
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            return True
        except Exception as e:
            print(f"[PlatformAdapter] Error copying to clipboard: {e}")
            return False

    def clear_clipboard(self) -> bool:
        """
        Безопасно очищает буфер обмена.
        ИСПОЛЬЗУЕТСЯ ПЕРЕЗАПИСЬ вместо простого clear(),
        так как Windows Clipboard History может игнорировать очистку.
        """
        try:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()

            # 1. Копируем пустую строку (или пробел)
            clipboard.setText("")

            # 2. Принудительно синхронизируем (для Windows)
            # Это заставляет систему зафиксировать изменение прямо сейчас
            clipboard.setText("")

            # 3. Только после перезаписи вызываем clear
            clipboard.clear()

            return True
        except Exception as e:
            print(f"[PlatformAdapter] Error clearing clipboard: {e}")
            return False

    def get_clipboard_content(self) -> Optional[str]:
        """Получает текущее содержимое буфера (для проверки)."""
        try:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            return clipboard.text()
        except Exception:
            return None

    def get_platform_name(self) -> str:
        return self.platform