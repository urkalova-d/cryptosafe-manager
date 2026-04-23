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
        """Стандартная генерация (использует настройки по умолчанию)"""
        return cls.generate_custom(
            length=length,
            use_upper=True, use_lower=True, use_digits=True, use_symbols=True,
            exclude_ambiguous=exclude_ambiguous,
            db_helper=db_helper
        )

    @classmethod
    def generate_custom(cls, length: int = 16,
                        use_upper: bool = True, use_lower: bool = True,
                        use_digits: bool = True, use_symbols: bool = True,
                        exclude_ambiguous: bool = True, db_helper=None) -> Tuple[str, int]:
        """
        Генерация с кастомными параметрами.
        Req 1: Configuration options.
        """
        if length < 8: length = 8
        if length > 64: length = 64

        # Формируем наборы
        sets = []
        if use_upper:
            s = cls.UPPER
            sets.append(''.join(c for c in s if c not in cls.AMBIGUOUS) if exclude_ambiguous else s)
        if use_lower:
            s = cls.LOWER
            sets.append(''.join(c for c in s if c not in cls.AMBIGUOUS) if exclude_ambiguous else s)
        if use_digits:
            s = cls.DIGITS
            sets.append(''.join(c for c in s if c not in cls.AMBIGUOUS) if exclude_ambiguous else s)
        if use_symbols:
            s = cls.SYMBOLS
            # Из символов тоже убираем неоднозначные, если нужно
            sets.append(''.join(c for c in s if c not in cls.AMBIGUOUS) if exclude_ambiguous else s)

        # Фильтруем пустые наборы
        sets = [s for s in sets if s]
        if not sets:
            raise ValueError("Должен быть выбран хотя бы один набор символов")

        all_chars = ''.join(sets)

        max_attempts = 100
        for _ in range(max_attempts):
            password = []

            # Req 3: Гарантируем наличие символа из каждого набора
            for s in sets:
                password.append(secrets.choice(s))

            # Остальное заполняем случайно
            remaining = length - len(password)
            password.extend(secrets.choice(all_chars) for _ in range(remaining))

            # Перемешиваем
            for i in range(len(password) - 1, 0, -1):
                j = secrets.randbelow(i + 1)
                password[i], password[j] = password[j], password[i]

            result = ''.join(password)

            # Проверка силы
            score = 0
            if ZXCVBN_AVAILABLE:
                res = zxcvbn(result)
                score = res['score']
                if score < 3: continue

            # Проверка истории
            if db_helper:
                h = hashlib.sha256(result.encode()).hexdigest()
                if db_helper.is_password_in_history(h):
                    continue
                db_helper.add_password_to_history(h)

            return result, score

        raise RuntimeError("Could not generate password")

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