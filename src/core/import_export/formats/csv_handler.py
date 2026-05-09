# src/core/import_export/formats/csv_handler.py
import csv
import io
from typing import List, Dict


class CsvFormatHandler:
    """
    Обработчик формата CSV (Plaintext).
    EXP-1: Для миграции.
    """

    def __init__(self):
        self.extension = ".csv"

    def export_data(self, entries: List[Dict], password: str = None, options: dict = None) -> bytes:
        """
        Создает CSV файл. Пароль игнорируется (форматы CSV обычно не шифруются).
        """
        output = io.StringIO()

        # Определяем заголовки
        fieldnames = ['title', 'service', 'username', 'password', 'url', 'notes', 'category']

        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')

        writer.writeheader()
        for entry in entries:
            # Фильтруем только нужные поля
            row = {k: entry.get(k, '') for k in fieldnames}
            writer.writerow(row)

        return output.getvalue().encode('utf-8-sig')  # BOM для корректного открытия в Excel