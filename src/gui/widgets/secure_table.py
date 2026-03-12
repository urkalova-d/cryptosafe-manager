from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QPushButton, QWidget, QHBoxLayout, QHeaderView
from PyQt6.QtCore import Qt

class SecureTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # ВАЖНО: Укажи 5 колонок
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["Сервис", "Логин", "Пароль", "Заметки", "Действие"])

        # Растягиваем колонки, чтобы они занимали все место
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

    def add_record(self, service, login, password, notes, copy_callback=None):
        row_position = self.rowCount()
        self.insertRow(row_position)

        self.setItem(row_position, 0, QTableWidgetItem(str(service)))
        self.setItem(row_position, 1, QTableWidgetItem(str(login)))
        self.setItem(row_position, 2, QTableWidgetItem("********"))
        self.setItem(row_position, 3, QTableWidgetItem(str(notes)))

        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)

        copy_btn = QPushButton("Копировать")
        copy_btn.setFixedWidth(100)

        # Если нам передали функцию для копирования, привязываем её
        if copy_callback:
            copy_btn.clicked.connect(lambda: copy_callback(password))

        layout.addWidget(copy_btn)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setCellWidget(row_position, 4, container)