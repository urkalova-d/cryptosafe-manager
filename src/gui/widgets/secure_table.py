from PyQt6.QtWidgets import (QTableWidget, QTableWidgetItem, QPushButton,
                             QWidget, QHBoxLayout, QHeaderView, QApplication, QMenu)
from urllib.parse import urlparse
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QAction, QIcon

class SecureTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels(["Сервис", "Логин", "URL", "Категория", "Пароль",  "Действие"])

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
                   modified_date=None, url=""):
        #Добавление записи с маскировкой
        row_position = self.rowCount()
        self.insertRow(row_position)

        # Сохраняем ID строки
        self._password_data[row_position] = password

        #  Обработка данных 

        #  Title
        item_service = QTableWidgetItem(str(service))
        # Сохраняем ID в данных айтема для быстрого доступа
        if record_id:
            item_service.setData(Qt.ItemDataRole.UserRole, record_id)
        self.setItem(row_position, 0, item_service)

        # Username под маской
        if len(login) > 4:
            masked_login = login[:4] + "••••"
        else:
            masked_login = login
        item_login = QTableWidgetItem(masked_login)
        item_login.setToolTip(login)  # Показываем полный при наведении
        self.setItem(row_position, 1, item_login)

        # URL 
        domain = self._extract_domain(url)
        item_url = QTableWidgetItem(domain)
        item_url.setToolTip(url)  # Полный URL в тултипе
        self.setItem(row_position, 2, item_url)

        #  категории
        self.setItem(row_position, 3, QTableWidgetItem(str(category)))

        # пароль
        # По умолчанию маскирован
        item_pass = QTableWidgetItem("••••••••")
        self.setItem(row_position, 4, item_pass)

        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(2)

        #  копирование
        copy_btn = QPushButton("📋")
        copy_btn.setToolTip("Копировать")
        copy_btn.setFixedSize(QSize(30, 24))
        if copy_callback:
            copy_btn.clicked.connect(lambda: copy_callback(password))

        # глаз
        toggle_btn = QPushButton("👁")
        toggle_btn.setToolTip("Показать/Скрыть")
        toggle_btn.setFixedSize(QSize(30, 24))
        toggle_btn.clicked.connect(lambda: self.toggle_row_password(row_position))

        layout.addWidget(copy_btn)
        layout.addWidget(toggle_btn)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.setCellWidget(row_position, 5, container)

    def display_data(self, records, copy_callback=None):
        #обновлении таблицы при поиске
        # Безопасная очистка предыдущих данных перед загрузкой новых
        self.secure_clear()

        # Временно отключаем сортировку для ускорения массовой вставки
        self.setSortingEnabled(False)

        for rec in records:
            # Маппинг ключей словаря к аргументам add_record
            service = rec.get('service', rec.get('title', 'Unknown'))
            login = rec.get('username', '')
            password = rec.get('password', '')
            url = rec.get('url', '')
            category = rec.get('category', 'Uncategorized')
            notes = rec.get('notes', '')
            rec_id = rec.get('id')
            modified = rec.get('updated_at', '')

            self.add_record(
                service, login, category, password, notes,
                copy_callback, rec_id, modified, url
            )

        # Включаем сортировку обратно
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
        # переключение видимости
        item = self.item(row, 4)
        if not item: return

        current_text = item.text()
        real_pass = self._password_data.get(row, "")

        if current_text == "••••••••":
            item.setText(real_pass)
        else:
            item.setText("••••••••")

    def toggle_all_passwords(self, visible: bool):
        #глобальное переклюение
        self._passwords_visible = visible
        for row in range(self.rowCount()):
            item = self.item(row, 4)
            if item:
                if visible:
                    item.setText(self._password_data.get(row, ""))
                else:
                    item.setText("••••••••")

    def show_context_menu(self, pos):
        #контекстное меню
        item = self.itemAt(pos)
        if not item:
            return

        menu = QMenu(self)

        copy_action = menu.addAction("Копировать пароль")
        edit_action = menu.addAction("Редактировать")
        delete_action = menu.addAction("Удалить")

        action = menu.exec(self.mapToGlobal(pos))

        if action == copy_action:
            # Эмитируем сигнал или вызываем колбэк, тут упрощенно:
            row = item.row()
            pass_data = self._password_data.get(row)
            if pass_data:
                QApplication.clipboard().setText(pass_data)

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