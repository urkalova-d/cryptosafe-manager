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

        try:
            import pyperclip
            pyperclip.copy(text)
            print("[PlatformAdapter] Fallback to pyperclip successful.")
            return True
        except ImportError:
            print("[PlatformAdapter] CRITICAL: pyperclip not installed. Fallback unavailable.")
        except Exception as e:
            print(f"[PlatformAdapter] CRITICAL: Fallback failed: {e}")

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

            if clipboard:
                # Перезапись пустой строкой + Clear
                clipboard.setText("")
                clipboard.clear()
                return True
        except Exception as e:
            print(f"[PlatformAdapter] Error clearing clipboard: {e}")

        try:
            import pyperclip
            # pyperclip.copy перезаписывает содержимое
            pyperclip.copy("")
            return True
        except Exception as e:
            print(f"[PlatformAdapter] Fallback clear failed: {e}")

        return False

    def get_clipboard_content(self) -> Optional[str]:
        """Получает текущее содержимое буфера (для проверки)."""
        try:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            return clipboard.text()
        except Exception:
            pass

        try:
            import pyperclip
            return pyperclip.paste()
        except Exception:
            return None

    def get_platform_name(self) -> str:
        return self.platform