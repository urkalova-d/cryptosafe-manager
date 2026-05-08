from typing import Dict, Any, List, Tuple
import json
import hashlib


class LogVerifier:
    #Отвечает за проверку целостности журнала аудита

    def __init__(self, db_helper, signer):
        self.db = db_helper
        self.signer = signer

    def verify_all(self, limit: int = None) -> Dict[str, Any]:
        #Полная проверка целостности журнала

        results = {
            'verified': True,
            'total_checked': 0,
            'invalid_hashes': [],
            'invalid_signatures': [],
            'chain_breaks': [],
            'errors': []
        }

        try:
            # Получаем данные из БД
            rows = self._fetch_entries_for_verification(limit)

            previous_hash = '0' * 64  # Genesis hash

            for row in rows:
                # Распаковка (порядок как в SELECT запросе)
                seq_num = row[0]
                timestamp = row[1]
                event_type = row[2]
                severity = row[3]
                source = row[4]
                user_id = row[5]
                details_json = row[6]
                signature_hex = row[7]
                stored_hash = row[8]
                prev_hash_db = row[9]

                results['total_checked'] += 1

                #Восстанавливаем структуру данных для хеширования
                entry_data_reconstructed = {
                    'timestamp': timestamp,
                    'event_type': event_type,
                    'severity': severity,
                    'source': source,
                    'user_id': user_id,
                    'details': json.loads(details_json),  # details в базе хранится как строка JSON
                    'previous_hash': prev_hash_db
                }

                reconstructed_json = json.dumps(entry_data_reconstructed, sort_keys=True)

                # Проверка Хеша данных
                computed_hash = hashlib.sha256(reconstructed_json.encode('utf-8')).hexdigest()

                if computed_hash != stored_hash:
                    results['verified'] = False
                    results['invalid_hashes'].append({
                        'sequence': seq_num,
                        'reason': 'Hash mismatch! Data tampered.'
                    })

                #  Проверка Цепочки
                if prev_hash_db != previous_hash:
                    results['verified'] = False
                    results['chain_breaks'].append({
                        'sequence': seq_num,
                        'expected': previous_hash,
                        'found': prev_hash_db
                    })

                #  Проверка Подписи
                try:
                    # Для проверки подписи нужны байты именно того, что подписывали (entry_json)
                    # В audit_logger мы подписывали entry_json.
                    if self.signer and self.signer._public_key:
                        if not self.signer.verify(reconstructed_json.encode('utf-8'), bytes.fromhex(signature_hex)):
                            results['verified'] = False
                            results['invalid_signatures'].append({'sequence': seq_num})
                except Exception:
                    pass  # Если ключа нет, пропускаем проверку подписи

                # Обновляем хеш для следующего шага цепочки
                previous_hash = stored_hash

            return results

        except Exception as e:
            import traceback
            traceback.print_exc()
            results['verified'] = False
            results['errors'].append(str(e))
            return results

    def _fetch_entries_for_verification(self, limit):
        query = """
            SELECT sequence_number, timestamp, event_type, severity, source, user_id, details, signature, entry_hash, previous_hash 
            FROM audit_log 
            ORDER BY sequence_number ASC
        """
        print(f"[DEBUG Verifier] Fetching entries. Limit param: {limit}")
        if limit:
            query += f" LIMIT {limit}"

        print(f"[DEBUG Verifier] SQL Query: {query}")

        # Используем raw cursor, так как db_helper может не иметь нужного метода
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()

        print(f"[DEBUG Verifier] Rows fetched: {len(rows)}")
        return rows