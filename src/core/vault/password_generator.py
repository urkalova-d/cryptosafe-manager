import string
import secrets

class PasswordGenerator:
    @staticmethod
    def generate(length=20, use_upper=True, use_lower=True, use_digits=True, use_special=True):
        #генерация криптостойкого пароля с использованием secrets (CSPRNG)
        characters = ""
        if use_upper:
            characters += string.ascii_uppercase
        if use_lower:
            characters += string.ascii_lowercase
        if use_digits:
            characters += string.digits
        if use_special:
            characters += string.punctuation

        if not characters:
            raise ValueError("Должен быть выбран хотя бы один набор символов")

        # генерация безопасного пароля
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password