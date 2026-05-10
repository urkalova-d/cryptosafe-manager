# src/core/import_export/formats/bitwarden_handler.py
import json


class BitwardenHandler:
    """Обработчик формата Bitwarden JSON."""

    def import_data(self, file_path: str, password=None) -> list:
        entries = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Структура Bitwarden: {"encrypted": false, "items": [...]}
            items = data.get('items', [])
            folders = data.get('folders', [])

            # Маппинг ID папок в имена
            folder_map = {f['id']: f['name'] for f in folders}

            for item in items:
                # Пропускаем не логины (например, карты, заметки)
                if item.get('type') != 1:
                    continue

                login_data = item.get('login', {})

                # Обработка URL (может быть списком)
                url = ''
                uris = login_data.get('uris')
                if uris and isinstance(uris, list) and len(uris) > 0:
                    url = uris[0].get('uri', '')

                entry = {
                    'service': item.get('name', 'Unknown'),
                    'username': login_data.get('username', ''),
                    'password': login_data.get('password', ''),
                    'url': url,
                    'notes': item.get('notes', ''),
                    'category': folder_map.get(item.get('folderId'), 'Uncategorized')
                }
                entries.append(entry)

            return entries
        except Exception as e:
            raise ValueError(f"Ошибка чтения Bitwarden JSON: {e}")