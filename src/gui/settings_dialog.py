from PyQt6.QtWidgets import QDialog, QVBoxLayout, QCheckBox, QPushButton, QLabel


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки")
        self.setFixedSize(300, 200)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Конфигурация приложения:"))

        self.dark_mode = QCheckBox("Темная тема")
        layout.addWidget(self.dark_mode)

        self.auto_lock = QCheckBox("Автоблокировка (5 мин)")
        layout.addWidget(self.auto_lock)

        btn_close = QPushButton("Закрыть")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)

        self.setLayout(layout)