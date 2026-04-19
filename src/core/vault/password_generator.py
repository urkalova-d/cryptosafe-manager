import string
import secrets
import hashlib
from typing import List, Tuple

# Для проверки сложности (Req 4)
try:
    from zxcvbn import zxcvbn

    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False
    print("Warning: 'zxcvbn' not installed. Strength check disabled.")


class PasswordGenerator:
    # Базовые наборы символов (Req 2)
    UPPER = string.ascii_uppercase
    LOWER = string.ascii_lowercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*"

    # Неоднозначные символы (Req 2)
    AMBIGUOUS = "lI1oO0"

    @classmethod
    def generate(cls, length: int = 16, exclude_ambiguous: bool = True, db_helper=None) -> Tuple[str, int]:
        """
        Генерация пароля.
        Args:
            length: Длина пароля (8-64, по умолчанию 16)
            exclude_ambiguous: Исключать ли неоднозначные символы
            db_helper: Ссылка на БД для проверки истории (Req 5)
        Returns:
            Tuple[str, int]: (пароль, оценка силы 0-4)
        """
        # Req 2: Валидация длины
        if length < 8:
            length = 8
        if length > 64:
            length = 64

        # Формируем наборы символов с учетом исключений
        # Вычисляем их здесь, внутри метода, чтобы избежать ошибок области видимости класса
        if exclude_ambiguous:
            upper_set = ''.join(c for c in cls.UPPER if c not in cls.AMBIGUOUS)
            lower_set = ''.join(c for c in cls.LOWER if c not in cls.AMBIGUOUS)
            digits_set = ''.join(c for c in cls.DIGITS if c not in cls.AMBIGUOUS)
            symbols_set = ''.join(c for c in cls.SYMBOLS if c not in cls.AMBIGUOUS)
        else:
            upper_set = cls.UPPER
            lower_set = cls.LOWER
            digits_set = cls.DIGITS
            symbols_set = cls.SYMBOLS

        char_sets = [upper_set, lower_set, digits_set, symbols_set]
        # Фильтруем пустые наборы (если вдруг какой-то набор стал пустым после исключений)
        char_sets = [s for s in char_sets if s]
        all_chars = ''.join(char_sets)

        if not all_chars:
            raise ValueError("No character sets selected")

        max_attempts = 100
        for _ in range(max_attempts):
            password = []

            # Req 3: Гарантируем наличие минимум одного символа из каждого набора
            for char_set in char_sets:
                password.append(secrets.choice(char_set))

            # Заполняем оставшуюся длину случайными символами
            remaining_length = length - len(password)
            password.extend(secrets.choice(all_chars) for _ in range(remaining_length))

            # Перемешиваем результат (Fisher-Yates shuffle)
            # Req 1: Используем secrets для перемешивания
            for i in range(len(password) - 1, 0, -1):
                j = secrets.randbelow(i + 1)
                password[i], password[j] = password[j], password[i]

            result = ''.join(password)

            # Req 4: Проверка сложности zxcvbn
            score = 0
            if ZXCVBN_AVAILABLE:
                results = zxcvbn(result)
                score = results['score']
                if score < 3:
                    continue

            # Req 5: Проверка истории
            if db_helper:
                pwd_hash = hashlib.sha256(result.encode()).hexdigest()
                if db_helper.is_password_in_history(pwd_hash):
                    continue

                db_helper.add_password_to_history(pwd_hash)

            return result, score

        raise RuntimeError("Failed to generate strong unique password after 100 attempts")

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        """Проверка надежности пароля (для пользовательских паролей)"""
        import re
        if len(password) < 12:
            return False, "Пароль должен быть не менее 12 символов."
        if not re.search(r"[a-z]", password):
            return False, "Добавьте строчные буквы."
        if not re.search(r"[A-Z]", password):
            return False, "Добавьте заглавные буквы."
        if not re.search(r"\d", password):
            return False, "Добавьте цифры."
        if not re.search(r"[^a-zA-Z0-9]", password):
            return False, "Добавьте спецсимволы."
        common_patterns = ["password", "qwerty", "123456", "admin"]
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Пароль слишком простой."
        return True, "Пароль надежен."