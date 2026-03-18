import sys
import ctypes
import platform
import ctypes.util

class KeyStorage:
    def __init__(self):
        self._auth_key = None
        self._encryption_key = None

    def set_keys(self, auth_key, enc_key):
        self.clear()
        if auth_key is not None:
            self._auth_key = bytearray(auth_key)
        if enc_key is not None:
            self._encryption_key = bytearray(enc_key)

    def get_auth_key(self) -> bytes:
        if self._auth_key is None: return None
        return bytes(self._auth_key)

    def get_enc_key(self) -> bytes:
        if self._encryption_key is None: return None
        return bytes(self._encryption_key)

    def clear(self):
        def _zero_out(buffer):
            if buffer:
                for i in range(len(buffer)):
                    buffer[i] = 0

        _zero_out(self._auth_key)
        _zero_out(self._encryption_key)
        self._auth_key = None
        self._encryption_key = None