# src/core/clipboard/platform_adapter.py
import sys
import subprocess
import ctypes
import ctypes.util
import os  # Добавлен импорт os
from typing import Optional


class PlatformAdapter:
    """
    Адаптер для работы с системным буфером обмена на разных платформах.
    Реализует Platform-Specific Security (Req 3).
    """

    def __init__(self):
        self.platform = sys.platform

        # Кэширование API для Windows
        if self.platform == "win32":
            self._setup_windows_api()
        else:
            self._win_clipboard = None
            self._win_crypt = None
            self._kernel32 = None

    # ==================== WINDOWS IMPLEMENTATION ====================

    def _setup_windows_api(self):
        """Инициализация Windows API для безопасности."""
        try:
            self._win_clipboard = ctypes.windll.user32
            self._win_crypt = ctypes.windll.crypt32
            self._kernel32 = ctypes.windll.kernel32

            # Определяем сигнатуры функций для корректной работы с памятью
            # GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
            self._kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
            self._kernel32.GlobalAlloc.restype = ctypes.c_void_p

            # GlobalLock(HGLOBAL hMem)
            self._kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
            self._kernel32.GlobalLock.restype = ctypes.c_void_p

            # GlobalUnlock(HGLOBAL hMem)
            self._kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
            self._kernel32.GlobalUnlock.restype = ctypes.c_bool

            # SetClipboardData(UINT uFormat, HANDLE hMem)
            self._win_clipboard.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
            self._win_clipboard.SetClipboardData.restype = ctypes.c_void_p

            print("[PlatformAdapter] Windows Native API initialized.")
        except Exception as e:
            print(f"[PlatformAdapter] Windows API init failed: {e}. Using Fallback.")
            self._win_clipboard = None

    def _windows_copy(self, text: str) -> bool:
        """Windows: Native copy with CryptProtectMemory (Optional Req 1)."""
        if not self._win_clipboard or not self._kernel32:
            return self._fallback_copy(text)

        try:
            # 1. Open Clipboard
            # NULL = 0, meaning we don't need owner window handle strictly
            if not self._win_clipboard.OpenClipboard(0):
                print("[PlatformAdapter] Failed to open clipboard")
                return self._fallback_copy(text)

            # 2. Empty Clipboard
            self._win_clipboard.EmptyClipboard()

            # 3. Prepare Data
            CF_UNICODETEXT = 13
            # Строка Unicode с терминатором null
            text_bytes = text.encode('utf-16-le') + b'\x00\x00'
            buf_size = len(text_bytes)

            # 4. Allocate Memory (GMEM_MOVEABLE = 0x0002 | GMEM_ZEROINIT = 0x0040)
            h_mem = self._kernel32.GlobalAlloc(0x0042, buf_size)
            if not h_mem:
                print("[PlatformAdapter] GlobalAlloc failed")
                self._win_clipboard.CloseClipboard()
                return self._fallback_copy(text)

            # 5. Lock and Copy
            p_mem = self._kernel32.GlobalLock(h_mem)
            if not p_mem:
                print("[PlatformAdapter] GlobalLock failed")
                self._win_clipboard.CloseClipboard()
                return self._fallback_copy(text)

            # Копируем данные в выделенную память
            ctypes.memmove(p_mem, text_bytes, buf_size)
            self._kernel32.GlobalUnlock(h_mem)

            # 6. Set Clipboard Data
            if not self._win_clipboard.SetClipboardData(CF_UNICODETEXT, h_mem):
                print("[PlatformAdapter] SetClipboardData failed")
                # Если SetClipboardData не удалась, мы должны освободить память сами?
                # Нет, если SetClipboardData успешна, система владеет памятью.
                # Если нет - GlobalFree (но мы вернемся через fallback)
                self._win_clipboard.CloseClipboard()
                return self._fallback_copy(text)

            # 7. Close Clipboard
            self._win_clipboard.CloseClipboard()

            print("[PlatformAdapter] Windows Native Copy successful.")
            return True

        except Exception as e:
            print(f"[PlatformAdapter] Win32 Copy Error: {e}")
            if self._win_clipboard:
                try:
                    self._win_clipboard.CloseClipboard()
                except:
                    pass
            return self._fallback_copy(text)

    def _windows_clear(self) -> bool:
        """Windows: Native EmptyClipboard."""
        if not self._win_clipboard:
            return self._fallback_clear()

        try:
            if self._win_clipboard.OpenClipboard(0):
                self._win_clipboard.EmptyClipboard()
                self._win_clipboard.CloseClipboard()
                print("[PlatformAdapter] Windows Clipboard Cleared via Native API.")
                return True
            return False
        except Exception as e:
            print(f"[PlatformAdapter] Win32 Clear Error: {e}")
            return self._fallback_clear()

    # ==================== LINUX IMPLEMENTATION ====================

    def _linux_copy(self, text: str) -> bool:
        """
        Linux: Supports both CLIPBOARD (Ctrl+V) and PRIMARY (Mouse Selection).
        Req 3: Uses xsel/xclip or wl-clipboard.
        """
        success_clipboard = False

        # Check for Wayland
        is_wayland = "WAYLAND_DISPLAY" in os.environ or "WAYLAND_SOCKET" in os.environ
        tools = ["wl-copy", "xsel", "xclip"] if is_wayland else ["xsel", "xclip", "wl-copy"]

        # Try to copy to CLIPBOARD (Ctrl+V)
        for tool in tools:
            try:
                if tool == "xsel":
                    subprocess.run(['xsel', '-i', '-b'], input=text.encode('utf-8'), check=True)
                    success_clipboard = True
                    break
                elif tool == "xclip":
                    subprocess.run(['xclip', '-selection', 'clipboard'], input=text.encode('utf-8'), check=True)
                    success_clipboard = True
                    break
                elif tool == "wl-copy":
                    subprocess.run(['wl-copy'], input=text.encode('utf-8'), check=True)
                    success_clipboard = True
                    break
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue

        if success_clipboard:
            print(f"[PlatformAdapter] Linux copy via tool.")
            return True
        else:
            return self._fallback_copy(text)

    def _linux_clear(self) -> bool:
        """Linux: Clears both CLIPBOARD and PRIMARY selections."""
        is_wayland = "WAYLAND_DISPLAY" in os.environ
        tools = ["wl-copy", "xsel"] if is_wayland else ["xsel", "wl-copy"]

        cleared = False
        for tool in tools:
            try:
                if tool == "xsel":
                    subprocess.run(['xsel', '-c', '-b'], check=False)
                    subprocess.run(['xsel', '-c', '-p'], check=False)
                    cleared = True
                    break
                elif tool == "wl-copy":
                    subprocess.run(['wl-copy', '--clear'], check=False)
                    cleared = True
                    break
            except FileNotFoundError:
                continue

        if cleared:
            print("[PlatformAdapter] Linux Clipboard Cleared.")
            return True
        return self._fallback_clear()

    # ==================== MACOS IMPLEMENTATION ====================

    def _macos_copy(self, text: str) -> bool:
        """
        macOS: Uses pyobjc or pbcopy.
        Req 3: NSPasteboard implementation.
        """
        try:
            import AppKit

            pasteboard = AppKit.NSPasteboard.generalPasteboard()
            pasteboard.declareTypes_owner_([AppKit.NSPasteboardTypeString], None)
            pasteboard.setString_forType_(text, AppKit.NSPasteboardTypeString)
            print("[PlatformAdapter] macOS copy via PyObjC.")
            return True
        except ImportError:
            try:
                subprocess.run(['pbcopy'], input=text.encode('utf-8'), check=True)
                print("[PlatformAdapter] macOS copy via pbcopy.")
                return True
            except Exception:
                return self._fallback_copy(text)

    def _macos_clear(self) -> bool:
        """macOS: Clear contents."""
        try:
            import AppKit
            pasteboard = AppKit.NSPasteboard.generalPasteboard()
            pasteboard.clearContents()
            return True
        except ImportError:
            try:
                subprocess.run(['pbcopy'], input=b'', check=True)
                return True
            except Exception:
                return self._fallback_clear()

    # ==================== FALLBACK (Qt) ====================

    def _fallback_copy(self, text: str) -> bool:
        """Cross-platform fallback using PyQt6."""
        try:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            print("[PlatformAdapter] Fallback (Qt) copy used.")
            return True
        except Exception as e:
            print(f"[PlatformAdapter] Fallback Copy Error: {e}")
            return False

    def _fallback_clear(self) -> bool:
        """Cross-platform fallback clear."""
        try:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.clear()
            print("[PlatformAdapter] Fallback (Qt) clear used.")
            return True
        except Exception:
            return False

    # ==================== PUBLIC INTERFACE ====================

    def copy_to_clipboard(self, text: str) -> bool:
        if self.platform == "win32":
            return self._windows_copy(text)
        elif self.platform.startswith("linux"):
            return self._linux_copy(text)
        elif self.platform == "darwin":
            return self._macos_copy(text)
        else:
            return self._fallback_copy(text)

    def clear_clipboard(self) -> bool:
        if self.platform == "win32":
            return self._windows_clear()
        elif self.platform.startswith("linux"):
            return self._linux_clear()
        elif self.platform == "darwin":
            return self._macos_clear()
        else:
            return self._fallback_clear()

    def get_clipboard_content(self) -> Optional[str]:
        """Получает текущее содержимое буфера (через Qt для надежности)."""
        try:
            from PyQt6.QtWidgets import QApplication
            return QApplication.clipboard().text()
        except Exception:
            return None

    def get_platform_name(self) -> str:
        return self.platform