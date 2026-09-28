"""Encrypted team-chat screen with explicit device trust state."""

from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from stoa_desktop.chat import ChatService


class ChatView(QWidget):
    def __init__(self, service: ChatService) -> None:
        super().__init__()
        self.service = service
        self.records: list[dict[str, object]] = []
        layout = QVBoxLayout(self)
        title = QLabel("Encrypted team chat")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        description = QLabel(
            "Messages are encrypted and authenticated on this device. The server relays "
            "ciphertext only. Verify recipient devices before sharing sensitive information."
        )
        description.setWordWrap(True)
        description.setObjectName("body")
        layout.addWidget(description)
        device_row = QHBoxLayout()
        self.device_name = QLineEdit()
        self.device_name.setPlaceholderText("This device name")
        register = QPushButton("Register device")
        register.clicked.connect(self._register)
        device_row.addWidget(self.device_name, 1)
        device_row.addWidget(register)
        layout.addLayout(device_row)
        self.recipient = QComboBox()
        self.recipient.setAccessibleName("Verified recipient device")
        recipient_row = QHBoxLayout()
        recipient_row.addWidget(self.recipient, 1)
        verify = QPushButton("Mark verified")
        verify.setToolTip("Only after comparing the device fingerprint out of band")
        verify.clicked.connect(self._verify)
        recipient_row.addWidget(verify)
        layout.addLayout(recipient_row)
        self.messages = QListWidget()
        layout.addWidget(self.messages, 1)
        send_row = QHBoxLayout()
        self.composer = QLineEdit()
        self.composer.setPlaceholderText("Write an encrypted message")
        send = QPushButton("Send encrypted")
        send.setObjectName("primary")
        send.clicked.connect(self._send)
        receive = QPushButton("Check messages")
        receive.clicked.connect(self._receive)
        send_row.addWidget(self.composer, 1)
        send_row.addWidget(send)
        send_row.addWidget(receive)
        layout.addLayout(send_row)

    def _register(self) -> None:
        try:
            self.service.register(self.device_name.text() or "Stoá desktop")
            self._refresh_devices()
        except Exception as error:
            QMessageBox.critical(self, "Device registration failed", str(error))

    def _refresh_devices(self) -> None:
        self.records = self.service.devices()
        self.recipient.clear()
        for record in self.records:
            state = "verified" if record.get("verified_at") else "unverified"
            self.recipient.addItem(f"{record['name']} · {state}")

    def _send(self) -> None:
        try:
            record = self.records[self.recipient.currentIndex()]
            if not record.get("verified_at"):
                raise RuntimeError("verify the recipient device before sending")
            self.service.send(record, self.composer.text())
            self.messages.addItem(f"You: {self.composer.text()}")
            self.composer.clear()
        except Exception as error:
            QMessageBox.critical(self, "Message not sent", str(error))

    def _verify(self) -> None:
        try:
            record = self.records[self.recipient.currentIndex()]
            self.service.verify(str(record["id"]))
            self._refresh_devices()
        except Exception as error:
            QMessageBox.critical(self, "Verification failed", str(error))

    def _receive(self) -> None:
        try:
            for message in self.service.receive():
                self.messages.addItem(f"Received: {message}")
        except Exception as error:
            QMessageBox.critical(self, "Messages unavailable", str(error))
