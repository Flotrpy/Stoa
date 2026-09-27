"""Qt workflow for authorized port and service scanning."""

from pathlib import Path
from typing import Any
from uuid import UUID

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from stoa_desktop.port_scanner import PortScanService


class ScanSignals(QObject):
    progress = Signal(int, int)
    succeeded = Signal(dict)
    failed = Signal(str)
    finished = Signal()


class ScanTask(QRunnable):
    def __init__(self, service: PortScanService, values: dict[str, Any]) -> None:
        super().__init__()
        self.service = service
        self.values = values
        self.signals = ScanSignals()

    @Slot()
    def run(self) -> None:
        try:
            result = self.service.run(
                **self.values,
                progress=lambda current, total: self.signals.progress.emit(current, total),
            )
            self.signals.succeeded.emit(result)
        except Exception as error:
            self.signals.failed.emit(str(error))
        finally:
            self.signals.finished.emit()


class PortScannerView(QWidget):
    def __init__(self, service: PortScanService) -> None:
        super().__init__()
        self.setObjectName("page")
        self.service = service
        self._task: ScanTask | None = None
        self._last_job_id: str | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 34, 40, 34)
        heading = QLabel("Port & service scanner")
        heading.setObjectName("heading")
        body = QLabel(
            "TCP connect scans run only against a current central authorization scope from this "
            "approved endpoint. Attempts are bounded by the scope rate policy."
        )
        body.setObjectName("body")
        body.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(body)

        form = QFormLayout()
        self.target = QLineEdit()
        self.target.setPlaceholderText("127.0.0.1 or authorized host")
        self.ports = QLineEdit("common")
        self.ports.setPlaceholderText("22,80,443 or approved preset")
        self.scope = QComboBox()
        self.scope.addItem("Load authorization scopes", None)
        self.justification = QLineEdit()
        self.justification.setPlaceholderText("Why this scan is required")
        form.addRow("Target", self.target)
        form.addRow("Ports", self.ports)
        form.addRow("Authorization scope", self.scope)
        form.addRow("Business justification", self.justification)
        layout.addLayout(form)

        actions = QHBoxLayout()
        refresh = QPushButton("Refresh authorization")
        refresh.clicked.connect(self.refresh)
        self.run_button = QPushButton("Run authorized scan")
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self.run_scan)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.service.cancel)
        self.export_json = QPushButton("Export JSON")
        self.export_json.setEnabled(False)
        self.export_json.clicked.connect(lambda: self._export("json"))
        self.export_text = QPushButton("Export text")
        self.export_text.setEnabled(False)
        self.export_text.clicked.connect(lambda: self._export("text"))
        for button in (
            refresh,
            self.run_button,
            self.cancel_button,
            self.export_json,
            self.export_text,
        ):
            actions.addWidget(button)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        self.status = QLabel("No scan has run.")
        self.status.setObjectName("body")
        layout.addWidget(self.status)
        self.results = QTableWidget(0, 5)
        self.results.setHorizontalHeaderLabels(["Port", "State", "Service", "Latency", "Banner"])
        self.results.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.results, 1)

    def refresh(self) -> None:
        try:
            options = self.service.options()
        except Exception as error:
            self.status.setText(str(error))
            return
        self.scope.clear()
        for scope in options["scopes"]:
            allowed = scope["allowed_modules"]
            if scope["is_active"] and "port-scanner" in allowed:
                self.scope.addItem(f"{scope['name']} · {scope['target_pattern']}", scope["id"])
        self.status.setText(f"Loaded {self.scope.count()} active scanner scope(s).")

    def run_scan(self) -> None:
        scope_id = self.scope.currentData()
        if scope_id is None:
            self.status.setText("Select an active authorization scope first.")
            return
        if len(self.justification.text().strip()) < 10:
            self.status.setText("Provide a business justification of at least 10 characters.")
            return
        values = {
            "target": self.target.text().strip(),
            "port_specification": self.ports.text().strip(),
            "scope_id": UUID(str(scope_id)),
            "justification": self.justification.text().strip(),
        }
        self._set_running(True)
        self.status.setText("Authorization accepted; starting bounded TCP connections…")
        self._task = ScanTask(self.service, values)
        self._task.signals.progress.connect(self._progressed)
        self._task.signals.succeeded.connect(self._completed)
        self._task.signals.failed.connect(self._failed)
        self._task.signals.finished.connect(lambda: self._set_running(False))
        QThreadPool.globalInstance().start(self._task)

    def _progressed(self, current: int, total: int) -> None:
        self.progress.setRange(0, total)
        self.progress.setValue(current)
        self.status.setText(f"Scanned {current} of {total} ports")

    def _completed(self, result: dict[str, Any]) -> None:
        observations = result["observations"]
        self.results.setRowCount(len(observations))
        for row, item in enumerate(observations):
            values = (
                str(item["port"]),
                item["state"],
                item.get("service") or "—",
                f"{item['latency_ms']:.2f} ms" if item.get("latency_ms") is not None else "—",
                item.get("banner") or "—",
            )
            for column, value in enumerate(values):
                self.results.setItem(row, column, QTableWidgetItem(value))
        self._last_job_id = result["job"]["id"]
        self.status.setText(f"Scan {result['job']['state']}: {len(observations)} observations")
        self.export_json.setEnabled(True)
        self.export_text.setEnabled(True)

    def _failed(self, message: str) -> None:
        self.status.setText(message or "Scan failed safely.")

    def _set_running(self, running: bool) -> None:
        self.run_button.setEnabled(not running)
        self.cancel_button.setEnabled(running)

    def _export(self, report_format: str) -> None:
        if self._last_job_id is None:
            return
        suffix = "json" if report_format == "json" else "txt"
        selected, _ = QFileDialog.getSaveFileName(
            self, "Export scan report", f"stoa-port-scan.{suffix}"
        )
        if not selected:
            return
        content = self.service.session.client.get_text(
            f"/api/v1/jobs/{self._last_job_id}/port-scan-report?format={report_format}"
        )
        Path(selected).write_text(content, encoding="utf-8", newline="\n")
        self.status.setText("Report exported.")
