import json
import csv
from datetime import datetime
from PyQt6.QtGui import QTextDocument
from PyQt6.QtPrintSupport import QPrinter
from datetime import datetime, timezone

class LogExporter:
    @staticmethod
    def export_to_json(rows: list, public_key_hex: str, file_path: str):
        #Экспорт в подписанный JSON

        export_data = {
            "metadata": {
                "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "tool": "CryptoSafe Manager",
                "total_entries": len(rows)
            },
            "public_key": public_key_hex,
            "log_entries": [dict(row) for row in rows]
        }

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=4, ensure_ascii=False)
            return True, f"Успешно экспортировано {len(rows)} записей."
        except Exception as e:
            return False, str(e)

    @staticmethod
    def export_to_csv(rows: list, file_path: str):
        # Экспорт в CSV для аналитики

        if not rows:
            return False, "Нет данных для экспорта."

        try:
            #ключи из первой строки для заголовков
            headers = rows[0].keys()

            with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:  # utf-8-sig для Excel
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                for row in rows:
                    writer.writerow(dict(row))
            return True, f"Успешно экспортировано {len(rows)} записей."
        except Exception as e:
            return False, str(e)

    @staticmethod
    def export_to_pdf(rows: list, file_path: str):
        #экспорт в PDF

        try:
            document = QTextDocument()
            html = "<h1> CryptoSafe Audit Log Report </h1>"
            html += f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
            html += "<hr>"
            html += "<table border='1' cellspacing='0' cellpadding='3' width='100%'>"
            html += "<thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>Details</th></tr></thead>"
            html += "<tbody>"

            for row in rows:
                d = dict(row)
                color = "#fff"
                if d.get('severity') == 'WARN':
                    color = "#fff3cd"
                elif d.get('severity') in ['ERROR', 'CRITICAL']:
                    color = "#f8d7da"

                html += f"<tr bgcolor='{color}'>"
                html += f"<td>{d.get('timestamp', '')}</td>"
                html += f"<td>{d.get('event_type', '')}</td>"
                html += f"<td>{d.get('severity', '')}</td>"
                details = str(d.get('details', ''))[:50] + "..."
                html += f"<td><pre>{details}</pre></td>"
                html += "</tr>"

            html += "</tbody></table>"

            document.setHtml(html)

            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(file_path)
            document.print(printer)

            return True, f"PDF отчет создан."
        except Exception as e:
            return False, str(e)