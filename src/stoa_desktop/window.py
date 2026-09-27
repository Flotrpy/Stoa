"""Desktop navigation shell and connection controls."""

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from stoa_desktop.api_client import Connectivity
from stoa_desktop.background import BackgroundTask, TaskRunner
from stoa_desktop.enrollment import EnrollmentService
from stoa_desktop.onboarding import OnboardingDialog
from stoa_desktop.session import DesktopSession
from stoa_desktop.theme import Theme, stylesheet


class MainWindow(QMainWindow):
    """Accessible shell with explicit local and central-service state."""

    navigation = (
        "Dashboard",
        "Endpoints",
        "Jobs",
        "Findings",
        "Alerts",
        "Modules",
        "Chat",
        "Reports",
        "Policies",
        "Audit Log",
        "Settings",
    )

    def __init__(self, session: DesktopSession | None = None) -> None:
        super().__init__()
        self.session = session or DesktopSession()
        self.runner = TaskRunner()
        self._task: BackgroundTask | None = None
        self._nav_buttons: dict[str, QPushButton] = {}
        self.setWindowTitle("Stoá")
        self.setMinimumSize(1000, 680)
        self.resize(1240, 800)
        self._theme = Theme(self.session.settings.theme)
        self.setCentralWidget(self._build_shell())
        self.setStyleSheet(stylesheet(self._theme))
        self._show_connectivity(Connectivity.LOCAL_ONLY)

    def _build_shell(self) -> QWidget:
        shell = QWidget()
        layout = QHBoxLayout(shell)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._build_sidebar())
        self.pages = QStackedWidget()
        self.dashboard = self._build_dashboard()
        self.settings_page = self._build_settings()
        self.pages.addWidget(self.dashboard)
        self.pages.addWidget(self.settings_page)
        layout.addWidget(self.pages, 1)
        return shell

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(226)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(20, 24, 20, 18)
        layout.setSpacing(5)
        brand = QLabel("STOÁ")
        brand.setObjectName("brand")
        brand.setAccessibleName("Stoá home")
        layout.addWidget(brand)
        layout.addSpacing(23)
        for label in self.navigation:
            button = QPushButton(label)
            button.setObjectName("nav")
            button.setProperty("active", label == "Dashboard")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setEnabled(label in {"Dashboard", "Settings"})
            if not button.isEnabled():
                button.setToolTip(f"{label} arrives in its scheduled delivery phase")
            button.clicked.connect(lambda checked=False, name=label: self._navigate(name))
            self._nav_buttons[label] = button
            layout.addWidget(button)
        layout.addItem(
            QSpacerItem(10, 10, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )
        theme_picker = QComboBox()
        theme_picker.setAccessibleName("Color theme")
        theme_picker.addItems(["Light", "Dark"])
        theme_picker.setCurrentText(self._theme.value.title())
        theme_picker.currentTextChanged.connect(self._change_theme)
        layout.addWidget(theme_picker)
        return sidebar

    def _build_dashboard(self) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 34, 40, 34)
        layout.setSpacing(22)
        eyebrow = QLabel("LOCAL WORKSPACE")
        eyebrow.setObjectName("eyebrow")
        heading = QLabel("Security operations overview")
        heading.setObjectName("heading")
        self.summary = QLabel(
            "Connect the central service to synchronize authorized team metadata. Local state "
            "remains usable when the service is unavailable."
        )
        self.summary.setObjectName("body")
        self.summary.setWordWrap(True)
        layout.addWidget(eyebrow)
        layout.addWidget(heading)
        layout.addWidget(self.summary)
        actions = QHBoxLayout()
        self.connect_button = QPushButton("Connect team workspace")
        self.connect_button.setObjectName("primary")
        self.connect_button.clicked.connect(self._open_onboarding)
        self.enroll_button = QPushButton("Enroll this endpoint")
        self.enroll_button.clicked.connect(self._enroll_endpoint)
        self.enroll_button.setEnabled(False)
        actions.addWidget(self.connect_button)
        actions.addWidget(self.enroll_button)
        actions.addStretch(1)
        layout.addLayout(actions)
        grid = QGridLayout()
        grid.setSpacing(14)
        cards = (
            ("Enrolled endpoints", "0", "Central metadata"),
            ("Active jobs", "0", "No operations running"),
            ("Queued events", str(len(self.session.offline_queue.pending())), "Stored locally"),
            ("Connection", "Local", "Central service not connected"),
        )
        self.connection_value: QLabel | None = None
        for index, (title, value, detail) in enumerate(cards):
            card, value_label = self._metric_card(title, value, detail)
            if title == "Connection":
                self.connection_value = value_label
            grid.addWidget(card, index // 2, index % 2)
        layout.addLayout(grid)
        layout.addStretch(1)
        return page

    def _build_settings(self) -> QWidget:
        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 34, 40, 34)
        heading = QLabel("Settings")
        heading.setObjectName("heading")
        body = QLabel("Non-secret preferences are saved locally. Tokens never enter this file.")
        body.setObjectName("body")
        layout.addWidget(heading)
        layout.addWidget(body)
        form = QFormLayout()
        self.api_url = QLineEdit(self.session.settings.api_url)
        self.settings_theme = QComboBox()
        self.settings_theme.addItems(["light", "dark"])
        self.settings_theme.setCurrentText(self.session.settings.theme)
        form.addRow("Central service URL", self.api_url)
        form.addRow("Theme", self.settings_theme)
        layout.addLayout(form)
        save = QPushButton("Save settings")
        save.setObjectName("primary")
        save.clicked.connect(self._save_settings)
        layout.addWidget(save, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addStretch(1)
        return page

    @staticmethod
    def _metric_card(title: str, value: str, detail: str) -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 18, 20, 18)
        title_label = QLabel(title)
        title_label.setObjectName("eyebrow")
        value_label = QLabel(value)
        value_label.setObjectName("metric")
        detail_label = QLabel(detail)
        detail_label.setObjectName("body")
        card_layout.addWidget(title_label)
        card_layout.addWidget(value_label)
        card_layout.addWidget(detail_label)
        return card, value_label

    def _navigate(self, name: str) -> None:
        self.pages.setCurrentWidget(self.settings_page if name == "Settings" else self.dashboard)
        for label, button in self._nav_buttons.items():
            button.setProperty("active", label == name)
            button.style().unpolish(button)
            button.style().polish(button)

    def _open_onboarding(self) -> None:
        dialog = OnboardingDialog(self.session, self.runner, self)
        dialog.connected.connect(self._connected)
        dialog.exec()

    def restore_session(self) -> None:
        """Restore a previous safe session without blocking the UI thread."""

        self._task = self.runner.submit(self.session.restore)
        self._task.signals.succeeded.connect(self._restored)

    def _restored(self, state: object) -> None:
        if isinstance(state, Connectivity):
            self._show_connectivity(state)
        if state is Connectivity.CONNECTED and self.session.principal is not None:
            self._connected(self.session.principal)

    def _connected(self, principal: dict[str, Any]) -> None:
        self._show_connectivity(Connectivity.CONNECTED)
        self.summary.setText(
            f"Connected to {principal['team']['name']} as {principal['user']['display_name']}. "
            "Endpoint enrollment still requires explicit approval."
        )
        self.enroll_button.setEnabled(self.session.settings.endpoint_id is None)
        self.connect_button.setText("Reconnect account")

    def _enroll_endpoint(self) -> None:
        self.enroll_button.setEnabled(False)
        service = EnrollmentService(self.session.client, self.session.config_store)

        def operation() -> Any:
            return service.enroll(self.session.settings)

        self._task = self.runner.submit(operation)
        self._task.signals.succeeded.connect(self._enrolled)
        self._task.signals.failed.connect(self._operation_failed)

    def _enrolled(self, settings: object) -> None:
        if hasattr(settings, "endpoint_id"):
            self.session.settings = settings  # type: ignore[assignment]
        self.summary.setText(
            "This endpoint is registered and pending administrator approval before it can run jobs."
        )
        self.statusBar().showMessage("Central service connected · Endpoint pending approval")

    def _operation_failed(self, message: str) -> None:
        self.summary.setText(message or "The operation could not be completed.")
        self.enroll_button.setEnabled(True)

    def _save_settings(self) -> None:
        try:
            self.session.update_preferences(
                api_url=self.api_url.text().strip(), theme=self.settings_theme.currentText()
            )
        except ValueError as error:
            self.statusBar().showMessage(str(error))
            return
        self._change_theme(self.settings_theme.currentText().title())
        self.statusBar().showMessage("Local settings saved")

    def _change_theme(self, value: str) -> None:
        self._theme = Theme.DARK if value.casefold() == "dark" else Theme.LIGHT
        self.setStyleSheet(stylesheet(self._theme))

    def _show_connectivity(self, state: Connectivity) -> None:
        labels = {
            Connectivity.LOCAL_ONLY: ("Local", "Local workspace · Central service not connected"),
            Connectivity.CONNECTED: ("Online", "Local workspace · Central service connected"),
            Connectivity.OFFLINE: ("Offline", "Local workspace · Central service unavailable"),
            Connectivity.AUTH_REQUIRED: ("Sign in", "Local workspace · Authentication required"),
        }
        value, message = labels[state]
        if self.connection_value is not None:
            self.connection_value.setText(value)
        self.statusBar().showMessage(message)

    def closeEvent(self, event: QCloseEvent) -> None:
        event.accept()
