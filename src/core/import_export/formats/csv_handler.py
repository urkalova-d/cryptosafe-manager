# src/core/import_export/formats/csv_handler.py
import csv
import io
from typing import List, Dict


class CsvFormatHandler:
    """Обработчик формата CSV."""

    def __init__(self):
        self.extension = ".csv"

    def export_data(self, entries: List[Dict], password: str = None, options: dict = None) -> bytes:
        """Экспорт в CSV."""
        output = io.StringIO()
        fieldnames = ['service', 'username', 'password', 'url', 'notes', 'category']
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')

        writer.writeheader()
        for entry in entries:
            # Проверяем наличие ключей для надежности
            row = {
                'service': entry.get('service') or entry.get('title', ''),
                'username': entry.get('username', ''),
                'password': entry.get('password', ''),
                'url': entry.get('url', ''),
                'notes': entry.get('notes', ''),
                'category': entry.get('category', 'Uncategorized')
            }
            writer.writerow(row)

        return output.getvalue().encode('utf-8-sig')

    def import_data(self, file_path: str, password=None) -> list:
        """Импорт из CSV."""
        entries = []
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                # Автоопределение диалекта
                dialect = csv.Sniffer().sniff(f.read(1024))
                f.seek(0)

                reader = csv.DictReader(f, dialect=dialect)

                for row in reader:
                    # Маппинг полей (приводим к нижнему регистру ключей)
                    row_lower = {k.lower().strip(): v for k, v in row.items()}

                    entry = {
                        'service': row_lower.get('service') or row_lower.get('title') or row_lower.get('name',
                                                                                                       'Unknown'),
                        'username': row_lower.get('username') or row_lower.get('login') or row_lower.get('user', ''),
                        'password': row_lower.get('password') or row_lower.get('pass', ''),
                        'url': row_lower.get('url') or row_lower.get('site') or row_lower.get('website', ''),
                        'notes': row_lower.get('notes') or row_lower.get('extra') or row_lower.get('info', ''),
                        'category': row_lower.get('category') or row_lower.get('group', 'Uncategorized')
                    }
                    entries.append(entry)

            return entries
        except Exception as e:
            raise ValueError(f"Ошибка чтения CSV: {e}")