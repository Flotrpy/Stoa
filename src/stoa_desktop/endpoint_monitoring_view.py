"""Endpoint integrity monitoring screen."""

from pathlib import Path
from uuid import UUID

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from stoa_desktop.endpoint_monitoring import EndpointMonitoringService


class EndpointMonitoringView(QWidget):
    def __init__(self, service: EndpointMonitoringService) -> None:
        super().__init__()
        self.service = service
        layout = QVBoxLayout(self)
        heading = QLabel("Endpoint monitoring")
        heading.setObjectName("pageTitle")
        layout.addWidget(heading)
        summary = QLabel(
            "Approve a SHA-256 baseline, review tamper-evident file changes, and investigate "
            "metadata-only input-monitoring indicators. Stoá never captures keystrokes."
        )
        summary.setWordWrap(True)
        summary.setObjectName("body")
        layout.addWidget(summary)
        form = QFormLayout()
        self.root = QLineEdit()
        browse = QPushButton("Choose folder")
        browse.clicked.connect(self._choose_root)
        row = QHBoxLayout()
        row.addWidget(self.root, 1)
        row.addWidget(browse)
        form.addRow("Directory", row)
        self.scope = QComboBox()
        form.addRow("Authorization scope", self.scope)
        self.reason = QLineEdit("Monitor approved endpoint configuration for unexpected changes")
        form.addRow("Business justification", self.reason)
        self.recursive = QCheckBox("Include subdirectories")
        self.recursive.setChecked(True)
        form.addRow("Traversal", self.recursive)
        layout.addLayout(form)
        self.run_button = QPushButton("Approve baseline / scan changes")
        self.run_button.clicked.connect(self._run)
        layout.addWidget(self.run_button)
        self.results = QTableWidget(0, 4)
        self.results.setHorizontalHeaderLabels(["Severity", "Event", "Subject", "Explanation"])
        layout.addWidget(self.results, 1)

    def showEvent(self, event: object) -> None:
        super().showEvent(event)  # type: ignore[arg-type]
        if self.scope.count() == 0:
            try:
                for scope in self.service.options()["scopes"]:
                    self.scope.addItem(scope["name"], scope["id"])
            except Exception:
                return

    def _choose_root(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Choose monitored directory")
        if selected:
            self.root.setText(selected)

    def _run(self) -> None:
        try:
            root = Path(self.root.text())
            result = self.service.run(
                root=root,
                scope_id=UUID(self.scope.currentData()),
                justification=self.reason.text(),
                baseline_path=root / ".stoa-baseline.json",
                recursive=self.recursive.isChecked(),
            )
            observations = result["observations"]
            self.results.setRowCount(len(observations))
            for row, item in enumerate(observations):
                for column, value in enumerate(
                    (item["severity"], item["title"], item["subject"], item["explanation"])
                ):
                    self.results.setItem(row, column, QTableWidgetItem(str(value)))
        except Exception as error:
            QMessageBox.critical(self, "Endpoint monitoring failed", str(error))
