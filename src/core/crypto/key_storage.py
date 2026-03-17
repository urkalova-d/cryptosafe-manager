class KeyStorage:
    def __init__(self):
        self._auth_key = None
        self._encryption_key = None

    def set_keys(self, auth_key: bytes, enc_key: bytes):
        self._auth_key = auth_key
        self._encryption_key = enc_key

    def get_auth_key(self) -> bytes:
        return self._auth_key

    def get_enc_key(self) -> bytes:
        return self._encryption_key

    def clear(self):
        self._auth_key = None
        self._encryption_key = None