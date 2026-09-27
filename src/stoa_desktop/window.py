"""The first production-shaped desktop shell."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)

from stoa_desktop.theme import Theme, stylesheet


class MainWindow(QMainWindow):
    """Accessible navigation shell used while feature screens are delivered."""

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

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Stoá")
        self.setMinimumSize(1000, 680)
        self.resize(1240, 800)
        self._theme = Theme.LIGHT
        self.setCentralWidget(self._build_shell())
        self.setStyleSheet(stylesheet(self._theme))
        self.statusBar().showMessage("Local workspace · Central service not connected")

    def _build_shell(self) -> QWidget:
        shell = QWidget()
        layout = QHBoxLayout(shell)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._build_sidebar())
        layout.addWidget(self._build_dashboard(), 1)
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

        for index, label in enumerate(self.navigation):
            button = QPushButton(label)
            button.setObjectName("nav")
            button.setProperty("active", index == 0)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setEnabled(index == 0)
            if index != 0:
                button.setToolTip(f"{label} arrives in its scheduled delivery phase")
            layout.addWidget(button)

        layout.addItem(
            QSpacerItem(10, 10, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )
        theme_picker = QComboBox()
        theme_picker.setAccessibleName("Color theme")
        theme_picker.addItems(["Light", "Dark"])
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
        body = QLabel(
            "The foundation is ready. Connect the central service after setup to begin enrolling "
            "authorized endpoints."
        )
        body.setObjectName("body")
        body.setWordWrap(True)
        layout.addWidget(eyebrow)
        layout.addWidget(heading)
        layout.addWidget(body)

        grid = QGridLayout()
        grid.setSpacing(14)
        cards = (
            ("Enrolled endpoints", "0", "No endpoints registered"),
            ("Active jobs", "0", "No operations running"),
            ("Open findings", "0", "Nothing requires review"),
            ("Unresolved alerts", "0", "No active alerts"),
        )
        for index, (title, value, detail) in enumerate(cards):
            grid.addWidget(self._metric_card(title, value, detail), index // 2, index % 2)
        layout.addLayout(grid)
        layout.addStretch(1)
        return page

    @staticmethod
    def _metric_card(title: str, value: str, detail: str) -> QFrame:
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
        return card

    def _change_theme(self, value: str) -> None:
        self._theme = Theme.DARK if value == "Dark" else Theme.LIGHT
        self.setStyleSheet(stylesheet(self._theme))

    def closeEvent(self, event: QCloseEvent) -> None:
        event.accept()
