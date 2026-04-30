from PyQt6.QtWidgets import (QTableWidget, QTableWidgetItem, QPushButton,
                             QWidget, QHBoxLayout, QHeaderView, QApplication, QMenu, QAbstractItemView)
from urllib.parse import urlparse
from PyQt6.QtCore import Qt, QSize, pyqtSignal
from PyQt6.QtGui import QAction, QIcon

class SecureTable(QTableWidget):
    # сигналы для связи с MainWindow
    edit_requested = pyqtSignal(int)
    delete_requested = pyqtSignal(int)
    copy_requested = pyqtSignal(int)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels(["Сервис", "Логин", "URL", "Категория", "Пароль",  "Действие"])

        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        # Настройки таблицы
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)  # Multi-select
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.setSortingEnabled(True)  # Sortable

        # Разрешаем изменение размеров колонок и перестановку
        self.horizontalHeader().setSectionsMovable(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        # Растягиваем последнюю колонку
        self.horizontalHeader().setStretchLastSection(True)

        # Устанавливаем ширину колонок по умолчанию
        self.setColumnWidth(0, 200)  # Сервис
        self.setColumnWidth(1, 150)  # Логин
        self.setColumnWidth(2, 200)  # URL
        self.setColumnWidth(3, 100)  # Категория
        self.setColumnWidth(4, 120)  # Пароль
        self.setColumnWidth(5, 100)  # Действие

        # Переменные для хранения состояния видимости
        self._passwords_visible = False
        self._password_data = {}  # Храним ID -> пароль

        #  Контекстное меню
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def add_record(self, service, login, category, password, notes, copy_callback=None, record_id=None,
                   modified_date=None, url="", password_getter=None):
        #Добавление записи с маскировкой.

        row_position = self.rowCount()
        self.insertRow(row_position)

        # Сохраняем метаданные строки в словарь
        self._password_data[row_position] = {
            'id': record_id,
            'visible': False,
            'getter': password_getter
        }


        #  Сервис
        item_service = QTableWidgetItem(str(service))
        if record_id:
            item_service.setData(Qt.ItemDataRole.UserRole, record_id)
        self.setItem(row_position, 0, item_service)

        #  Логин (маскированный)
        if len(str(login)) > 4:
            masked_login = str(login)[:4] + "••••"
        else:
            masked_login = str(login)
        item_login = QTableWidgetItem(masked_login)
        item_login.setToolTip(str(login))
        self.setItem(row_position, 1, item_login)

        # 3. URL
        domain = self._extract_domain(str(url))
        item_url = QTableWidgetItem(domain)
        item_url.setToolTip(str(url))
        self.setItem(row_position, 2, item_url)

        # 4. Категория
        self.setItem(row_position, 3, QTableWidgetItem(str(category)))

        # 5. Пароль (всегда скрыт изначально)
        item_pass = QTableWidgetItem("••••••••")
        self.setItem(row_position, 4, item_pass)

        # 6. Кнопки действий
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(2)

        # Кнопка копирования
        copy_btn = QPushButton("📋")
        copy_btn.setToolTip("Копировать")
        copy_btn.setFixedSize(QSize(30, 24))

        if copy_callback and record_id is not None:
            # Используем default argument capture (eid=record_id)
            copy_btn.clicked.connect(lambda checked=False, eid=record_id: copy_callback(eid))

        # Кнопка показа
        toggle_btn = QPushButton("👁")
        toggle_btn.setToolTip("Показать/Скрыть")
        toggle_btn.setFixedSize(QSize(30, 24))

        # Фиксируем row_position через аргумент функции по умолчанию
        toggle_btn.clicked.connect(lambda checked=False, r=row_position: self.toggle_row_password(r))

        layout.addWidget(copy_btn)
        layout.addWidget(toggle_btn)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Устанавливаем виджет в ячейку
        self.setCellWidget(row_position, 5, container)

    def display_data(self, records, copy_callback=None, password_getter=None):
        #Обновление таблицы при поиске
        self.secure_clear()
        # Отключаем сортировку для ускорения вставки
        self.setSortingEnabled(False)

        for rec in records:
            service = rec.get('service', rec.get('title', 'Unknown'))
            login = rec.get('username', '')
            # Пароль не передаем явно, используем геттер
            url = rec.get('url', '')
            category = rec.get('category', 'Uncategorized')
            notes = rec.get('notes', '')
            rec_id = rec.get('id')
            modified = rec.get('updated_at', '')

            self.add_record(
                service, login, category, "", notes,
                copy_callback, rec_id, modified, url,
                password_getter=password_getter
            )

        self.setSortingEnabled(True)

    def _extract_domain(self, url):
        if not url:
            return ""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            parsed = urlparse(url)
            return parsed.netloc if parsed.netloc else url
        except:
            return url

    def toggle_row_password(self, row):
        #Безопасное переключение видимости пароля
        # Проверяем валидность строки
        if row < 0 or row >= self.rowCount():
            return

        data = self._password_data.get(row)
        if not data:
            return

        item = self.item(row, 4)
        if not item:
            return

        # Переключаем флаг
        data['visible'] = not data['visible']

        if data['visible']:
            # Показываем пароль через геттер (безопасность SEC-1)
            if data['getter'] and data['id']:
                try:
                    real_pass = data['getter'](data['id'])
                    item.setText(real_pass if real_pass else "")
                except Exception as e:
                    print(f"Error getting password: {e}")
                    item.setText("ERR")
            else:
                item.setText("N/A")
        else:
            # Скрываем пароль
            item.setText("••••••••")

    def toggle_all_passwords(self, visible: bool):
        # переключение видимости
        self._passwords_visible = visible

        # Блокируем сигналы для ускорения
        self.blockSignals(True)

        for row in range(self.rowCount()):
            item = self.item(row, 4)
            if item:
                if visible:
                    data = self._password_data.get(row)
                    if data and data['getter'] and data['id']:
                        try:
                            real_pass = data['getter'](data['id'])
                            item.setText(real_pass if real_pass else "")
                            data['visible'] = True
                        except Exception:
                            item.setText("ERR")
                else:
                    item.setText("••••••••")
                    if row in self._password_data:
                        self._password_data[row]['visible'] = False

        self.blockSignals(False)

    def show_context_menu(self, pos):
        item = self.itemAt(pos)
        if not item:
            return

        # Получаем ID записи из первого столбца выбранной строки
        row = item.row()
        id_item = self.item(row, 0)
        if not id_item:
            return

        record_id = id_item.data(Qt.ItemDataRole.UserRole)

        menu = QMenu(self)

        copy_action = menu.addAction("Копировать пароль")
        edit_action = menu.addAction("Редактировать")
        delete_action = menu.addAction("Удалить")

        action = menu.exec(self.mapToGlobal(pos))

        if action == copy_action:
            # Испускаем сигнал вместо прямой работы с буфером
            self.copy_requested.emit(record_id)
        elif action == edit_action:
            self.edit_requested.emit(record_id)
        elif action == delete_action:
            self.delete_requested.emit(record_id)

    def secure_clear(self):
        #удаление изз памяти
        for row in self._password_data:
            # заполнение 0
            # удаление ссылки
            self._password_data[row] = ""

        self._password_data.clear()
        self.setRowCount(0)

    def clear(self):
        #очистка
        self.secure_clear()