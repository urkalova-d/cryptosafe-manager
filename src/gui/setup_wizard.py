from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt6.QtCore import pyqtSignal

class SetupWizard(QDialog):
    # сигнал для передачи пароля в main window
    setup_finished = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Первая настройка")
        self.setFixedSize(400, 300)
        self.setModal(True)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("<h2>Придумайте мастер-пароль</h2>"))
        layout.addWidget(QLabel("Этот пароль будет защищать все ваши данные."))

        # поле 1
        self.pass1 = QLineEdit()
        self.pass1.setPlaceholderText("Новый пароль")
        self.pass1.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pass1)

        # поле 2
        self.pass2 = QLineEdit()
        self.pass2.setPlaceholderText("Повторите пароль")
        self.pass2.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pass2)

        # кнопка
        self.btn_finish = QPushButton("Завершить настройку")
        self.btn_finish.clicked.connect(self.save_and_exit)
        layout.addWidget(self.btn_finish)

        self.setLayout(layout)

    def save_and_exit(self):
        p1 = self.pass1.text()
        p2 = self.pass2.text()

        if len(p1) < 8:
            QMessageBox.warning(self, "Ошибка", "Пароль слишком короткий (мин. 8 символов)")
            return

        if p1 != p2:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают")
            return

        #отправление сигнала в mainw indow
        self.setup_finished.emit(p1)
        self.accept()