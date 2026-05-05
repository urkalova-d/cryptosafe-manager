from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import base64


class AuditLogSigner:
    """
    Отвечает за генерацию и проверку цифровых подписей Ed25519 для записей аудита.
    Требование: CRY-1 (Ed25519 preferred)
    """

    def __init__(self, key_manager):
        self.key_manager = key_manager
        self._private_key = None
        self._public_key = None

    def initialize(self):
        """
        Инициализирует ключи подписи.
        Ключ деривируется из мастер-пароля через KeyManager.
        Требование: CRY-2 (Key Separation)
        """
        try:
            # Получаем ключ через специальный метод KeyManager
            # ВНИМАНИЕ: Убедитесь, что в key_manager.py метод get_audit_key использует контекст "audit-signing"
            signing_seed = self.key_manager.get_audit_key()

            if not signing_seed:
                raise ValueError("Failed to derive audit signing key.")

            # Ed25519 требует 32 или 57 байт seed. Используем первые 32 байта.
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(signing_seed[:32])
            self._public_key = self._private_key.public_key()
            return True
        except Exception as e:
            print(f"[AuditSigner] Init error: {e}")
            return False

    def sign(self, data: bytes) -> bytes:
        """Подписывает данные приватным ключом."""
        if not self._private_key:
            raise RuntimeError("Signer not initialized")
        return self._private_key.sign(data)

    def verify(self, data: bytes, signature: bytes, public_key_bytes: bytes = None) -> bool:
        """
        Проверяет подпись.
        Если public_key_bytes не передан, используется текущий публичный ключ.
        """
        try:
            if public_key_bytes:
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            elif self._public_key:
                pub_key = self._public_key
            else:
                return False

            pub_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"[AuditSigner] Verification error: {e}")
            return False

    def get_public_key_hex(self) -> str:
        """Возвращает публичный ключ в hex-формате для экспорта/хранения."""
        if not self._public_key:
            return ""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()