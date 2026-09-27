"""First-run central service connection dialog."""

from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from stoa_desktop.background import BackgroundTask, TaskRunner
from stoa_desktop.session import DesktopSession


class OnboardingDialog(QDialog):
    """Collect only the information required to connect an existing account."""

    connected = Signal(dict)

    def __init__(self, session: DesktopSession, runner: TaskRunner, parent: Any = None) -> None:
        super().__init__(parent)
        self.session = session
        self.runner = runner
        self._task: BackgroundTask | None = None
        self.setWindowTitle("Connect Stoá")
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        heading = QLabel("Connect to your team workspace")
        heading.setObjectName("heading")
        description = QLabel(
            "Configuration and queued metadata remain on this device. Credentials are sent "
            "only to the selected central service and the resulting token is stored in the "
            "operating-system credential vault."
        )
        description.setObjectName("body")
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)

        form = QFormLayout()
        self.server = QLineEdit(session.settings.api_url)
        self.server.setAccessibleName("Central service URL")
        self.email = QLineEdit()
        self.email.setAccessibleName("Email")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setAccessibleName("Password")
        form.addRow("Server URL", self.server)
        form.addRow("Email", self.email)
        form.addRow("Password", self.password)
        layout.addLayout(form)

        self.error = QLabel()
        self.error.setObjectName("error")
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Connect")
        self.buttons.accepted.connect(self._connect)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def _connect(self) -> None:
        server = self.server.text().strip()
        email = self.email.text().strip()
        password = self.password.text()
        if not server or not email or not password:
            self.error.setText("Server URL, email, and password are required.")
            return
        self._set_busy(True)

        def operation() -> dict[str, Any]:
            return self.session.sign_in(server, email, password)

        self._task = self.runner.submit(operation)
        self._task.signals.succeeded.connect(self._connected)
        self._task.signals.failed.connect(self._failed)

    def _connected(self, principal: object) -> None:
        if isinstance(principal, dict):
            self.connected.emit(principal)
            self.accept()

    def _failed(self, message: str) -> None:
        self.error.setText(message or "Unable to connect to the central service.")
        self._set_busy(False)

    def _set_busy(self, busy: bool) -> None:
        self.buttons.setEnabled(not busy)
        self.server.setEnabled(not busy)
        self.email.setEnabled(not busy)
        self.password.setEnabled(not busy)
