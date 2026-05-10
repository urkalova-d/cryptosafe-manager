# src/core/import_export/key_exchange.py
import qrcode
import qrcode.image.svg
import io
import json
import base64
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


class KeyExchangeService:
    """
    QR-1, QR-3: Генерация ключей и QR кодов.
    """

    def __init__(self, db_helper):
        self.db = db_helper

    def generate_key_pair(self):
        """
        QR-3: Генерирует пару RSA-2048 ключей.
        Возвращает (private_key_pem, public_key_pem).
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Сериализация приватного ключа (PEM)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # Сериализация публичного ключа (PEM)
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return private_pem, public_pem

    def generate_qr_code(self, data: str) -> io.BytesIO:
        """
        QR-1: Генерирует QR-код изображения.
        """
        qr = qrcode.QRCode(
            version=None,  # Авто-выбор версии
            error_correction=qrcode.constants.ERROR_CORRECT_M,  # M уровень коррекции
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        return buffer

    def create_share_payload(self, public_key_pem: str, user_name: str) -> str:
        """
        QR-4: Создает JSON строку для QR кода с метаданными безопасности.
        """
        payload = {
            "version": "1.0",
            "type": "cryptosafe_pk_exchange",
            "user": user_name,
            "public_key": public_key_pem,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "valid_until": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        }
        return json.dumps(payload)

    def parse_qr_payload(self, payload_str: str) -> dict:
        """
        QR-2: Парсит данные из QR кода.
        Проверяет валидность JSON и структуру.
        """
        try:
            data = json.loads(payload_str)

            # Проверка типа
            if data.get("type") != "cryptosafe_pk_exchange":
                raise ValueError("Неверный тип QR кода.")

            # Проверка срока действия (QR-4)
            valid_until_str = data.get("valid_until")
            if valid_until_str:
                valid_until = datetime.fromisoformat(valid_until_str.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > valid_until:
                    raise ValueError("Срок действия QR кода истек.")

            return {
                "valid": True,
                "user": data.get("user", "Unknown"),
                "public_key": data.get("public_key"),
                "timestamp": data.get("timestamp")
            }
        except json.JSONDecodeError:
            raise ValueError("Невалидный JSON в QR коде.")
        except Exception as e:
            raise ValueError(f"Ошибка обработки QR: {e}")

    def save_contact(self, name: str, public_key_pem: str):
        """
        QR-3: Сохраняет контакт в БД.
        """
        # Вычисляем отпечаток (fingerprint) для верификации
        fingerprint = self._calculate_fingerprint(public_key_pem)

        query = """
            INSERT INTO contacts (name, public_key_pem, fingerprint, created_at)
            VALUES (?, ?, ?, datetime('now'))
        """
        self.db.conn.execute(query, (name, public_key_pem, fingerprint))
        self.db.conn.commit()

    def get_all_contacts(self):
        """Возвращает список контактов."""
        cursor = self.db.conn.execute("SELECT id, name, fingerprint, created_at FROM contacts ORDER BY name")
        return cursor.fetchall()

    def _calculate_fingerprint(self, public_key_pem: str) -> str:
        """Вычисляет SHA256 хеш от ключа для отображения пользователю."""
        import hashlib
        return hashlib.sha256(public_key_pem.encode()).hexdigest()[:16].upper()