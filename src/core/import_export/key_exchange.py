import qrcode
import io


class KeyExchangeService:
    """
    QR-1: Генерация и сканирование QR кодов для обмена ключами.
    """

    def generate_qr_code(self, data: str) -> io.BytesIO:
        """
        Генерирует QR-код из строки данных.

        Args:
            data: Строка для кодирования (например, публичный ключ).

        Returns:
            BytesIO: Поток с изображением PNG.
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Сохраняем в буфер памяти
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        return buffer

    def generate_key_pair(self):
        """
        Генерирует пару ключей RSA для безопасного обмена.
        (Заготовка для CRY-2)
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        # Генерация приватного ключа
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Сериализация публичного ключа для передачи
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_key, public_key