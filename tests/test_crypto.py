import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))#добавление пути к папке src

import pytest
from src.core.crypto.placeholder import AES256Placeholder

def test_xor_encryption_decryption():
    service = AES256Placeholder()
    key = b"1234567890123456"
    data = b"secret_data"

    encrypted = service.encrypt(data, key)
    decrypted = service.decrypt(encrypted, key)

    assert data == decrypted
    assert data != encrypted  #проверка что данные изменились