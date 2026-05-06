import json
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QHeaderView, QPushButton, QLabel,
                             QComboBox, QLineEdit, QTextEdit, QWidget, QDateEdit,
                             QGroupBox, QMessageBox)
from PyQt6.QtCore import Qt, QDate
from PyQt6.QtGui import QFont


class AuditViewer(QDialog):
    """
    GUI-1: Audit Log Viewer with filtering and pagination.
    """

    def __init__(self, db_helper, parent=None):
        super().__init__(parent)
        self.db = db_helper
        self.current_page = 1
        self.page_size = 50
        self.total_pages = 1

        self.setWindowTitle("📜 Журнал аудита безопасности")
        self.resize(1100, 700)

        self.init_ui()
        self.load_data()

    def init_ui(self):
        main_layout = QVBoxLayout(self)

        # === Верхняя панель: Фильтры (GUI-1) ===
        filter_group = QGroupBox("Фильтры")
        filter_layout = QHBoxLayout(filter_group)

        # Тип события
        filter_layout.addWidget(QLabel("Тип:"))
        self.filter_type = QComboBox()
        self.filter_type.addItem("Все", None)
        self.filter_type.addItem("AUTH", "AUTH_LOGIN_SUCCESS")  # Пример, лучше загрузить из БД уникальные
        self.filter_type.addItem("VAULT", "VAULT_CREATE")
        self.filter_type.addItem("CLIPBOARD", "CLIPBOARD_COPY")
        self.filter_type.addItem("SYSTEM", "SYSTEM_GENESIS")
        filter_layout.addWidget(self.filter_type)

        # Критичность
        filter_layout.addWidget(QLabel("Важность:"))
        self.filter_severity = QComboBox()
        self.filter_severity.addItems(["Все", "INFO", "WARN", "ERROR", "CRITICAL"])
        filter_layout.addWidget(self.filter_severity)

        # Дата
        filter_layout.addWidget(QLabel("От:"))
        self.date_from = QDateEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDate(QDate.currentDate().addMonths(-1))
        filter_layout.addWidget(self.date_from)

        filter_layout.addWidget(QLabel("До:"))
        self.date_to = QDateEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDate(QDate.currentDate())
        filter_layout.addWidget(self.date_to)

        # Поиск
        filter_layout.addWidget(QLabel("Поиск:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Текст в деталях...")
        filter_layout.addWidget(self.search_input)

        # Кнопки
        apply_btn = QPushButton("Применить")
        apply_btn.clicked.connect(self.apply_filters)
        filter_layout.addWidget(apply_btn)

        reset_btn = QPushButton("Сброс")
        reset_btn.clicked.connect(self.reset_filters)
        filter_layout.addWidget(reset_btn)

        main_layout.addWidget(filter_group)

        # === Центральная часть: Таблица и Детали ===
        content_layout = QHBoxLayout()

        # Таблица (GUI-1)
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Время", "Событие", "Важность", "Пользователь", "Источник", "ID Записи"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.itemClicked.connect(self.show_details)

        content_layout.addWidget(self.table, 3)

        # Панель деталей (GUI-2)
        details_group = QGroupBox("Детали записи")
        details_layout = QVBoxLayout(details_group)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Consolas", 9))
        details_layout.addWidget(self.details_text)

        content_layout.addWidget(details_group, 1)

        main_layout.addLayout(content_layout)

        # === Нижняя панель: Пагинация и Статистика (GUI-1, GUI-3) ===
        footer_layout = QHBoxLayout()

        # Пагинация
        self.btn_prev = QPushButton("◀ Назад")
        self.btn_prev.clicked.connect(self.prev_page)
        self.btn_next = QPushButton("Вперед ▶")
        self.btn_next.clicked.connect(self.next_page)

        self.page_label = QLabel("Страница 1 из 1")

        footer_layout.addWidget(self.btn_prev)
        footer_layout.addWidget(self.page_label)
        footer_layout.addWidget(self.btn_next)

        footer_layout.addStretch()

        # Статистика (GUI-3)
        self.stats_label = QLabel("Всего записей: 0")
        footer_layout.addWidget(self.stats_label)

        main_layout.addLayout(footer_layout)

    def load_data(self):
        """Загрузка данных в таблицу с учетом фильтров."""
        offset = (self.current_page - 1) * self.page_size

        # Сбор фильтров
        filters = {}

        # 1. Фильтр по типу события (используем LIKE, так как типы имеют приставки VAULT_, AUTH_ и т.д.)
        event_type = self.filter_type.currentText()
        if event_type != "Все":
            # Если выбрали AUTH, ищем все события, начинающиеся с AUTH
            filters['event_type_like'] = event_type + "%"

            # 2. Фильтр по важности
        severity = self.filter_severity.currentText()
        if severity != "Все":
            filters['severity'] = severity

        # 3. Даты
        if self.date_from.date().isValid():
            filters['start_date'] = self.date_from.date().toString("yyyy-MM-dd") + "T00:00:00"
        if self.date_to.date().isValid():
            filters['end_date'] = self.date_to.date().toString("yyyy-MM-dd") + "T23:59:59"

        # 4. Поиск
        search_text = self.search_input.text().strip()
        if search_text:
            # Добавляем % по краям, чтобы искать вхождение
            filters['search_text_like'] = f"%{search_text}%"

        rows, total_count = self.db.get_filtered_audit_logs(self.page_size, offset, filters)

        # Обновление таблицы
        self.table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            # row is a sqlite3.Row object
            # SQLite Row поддерживает доступ по ключу, но иногда нужно конвертировать
            row_dict = dict(row)

            self.table.setItem(i, 0, QTableWidgetItem(str(row_dict.get('timestamp', ''))))
            self.table.setItem(i, 1, QTableWidgetItem(str(row_dict.get('event_type', ''))))

            # Цветовое кодирование важности
            sev = str(row_dict.get('severity', 'INFO'))
            severity_item = QTableWidgetItem(sev)
            if sev == 'WARN':
                severity_item.setBackground(Qt.GlobalColor.yellow)
            elif sev in ['ERROR', 'CRITICAL']:
                severity_item.setBackground(Qt.GlobalColor.red)
                severity_item.setForeground(Qt.GlobalColor.white)
            self.table.setItem(i, 2, severity_item)

            self.table.setItem(i, 3, QTableWidgetItem(str(row_dict.get('user_id', ''))))
            self.table.setItem(i, 4, QTableWidgetItem(str(row_dict.get('source', ''))))

            # Извлекаем entry_id из details JSON
            details_str = row_dict.get('details', '{}')
            entry_id = "-"
            try:
                data = json.loads(details_str)
                if 'entry_id' in data:
                    entry_id = str(data['entry_id'])
            except:
                pass

            self.table.setItem(i, 5, QTableWidgetItem(entry_id))

            # Сохраняем полные данные для клика
            item_key = QTableWidgetItem(str(row_dict.get('timestamp', '')))
            item_key.setData(Qt.ItemDataRole.UserRole, row_dict)
            self.table.setItem(i, 0, item_key)

        # Обновление UI
        self.total_pages = max(1, (total_count + self.page_size - 1) // self.page_size)
        self.page_label.setText(f"Страница {self.current_page} из {self.total_pages}")
        self.stats_label.setText(f"Всего записей: {total_count}")

        self.btn_prev.setEnabled(self.current_page > 1)
        self.btn_next.setEnabled(self.current_page < self.total_pages)

    def show_details(self, item):
        """GUI-2: Показ деталей выбранной записи."""
        # Получаем строку
        row = item.row()
        # Достаем сохраненные данные из первой колонки
        data_item = self.table.item(row, 0)
        if not data_item: return

        row_data = data_item.data(Qt.ItemDataRole.UserRole)
        if not row_data: return

        # Формируем красивый отчет
        report = f"<b>Время:</b> {row_data['timestamp']}<br>"
        report += f"<b>Событие:</b> {row_data['event_type']}<br>"
        report += f"<b>Источник:</b> {row_data['source']}<br>"
        report += f"<b>Хеш записи:</b> <span style='font-family: monospace; font-size: 10px;'>{row_data['entry_hash'][:16]}...</span><br>"
        report += "<hr>"

        # JSON Details
        try:
            details_json = json.loads(row_data['details'])
            formatted_json = json.dumps(details_json, indent=4, ensure_ascii=False)
            report += f"<pre>{formatted_json}</pre>"
        except:
            report += f"<pre>{row_data['details']}</pre>"

        self.details_text.setHtml(report)

    def apply_filters(self):
        self.current_page = 1
        self.load_data()

    def reset_filters(self):
        self.filter_type.setCurrentIndex(0)
        self.filter_severity.setCurrentText("Все")
        self.date_from.setDate(QDate.currentDate().addMonths(-1))
        self.date_to.setDate(QDate.currentDate())
        self.search_input.clear()
        self.apply_filters()

    def next_page(self):
        if self.current_page < self.total_pages:
            self.current_page += 1
            self.load_data()

    def prev_page(self):
        if self.current_page > 1:
            self.current_page -= 1
            self.load_data()