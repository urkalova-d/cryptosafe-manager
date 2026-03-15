class KeyStorage:
    def __init__(self):
        self._derived_key = None

    def set_key(self, key: bytes):
        #сохранение ключа в памяти сессии
        self._derived_key = key

    def get_key(self) -> bytes:
        # возвращение текущего ключа
        return self._derived_key

    def clear(self):
        # Стирает ключ
        self._derived_key = None