"""Qt workflow for authorized web security scans."""

from pathlib import Path
from typing import Any
from uuid import UUID

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from stoa_desktop.web_scanner import WebScanService


class WebScanSignals(QObject):
    succeeded = Signal(dict)
    failed = Signal(str)
    finished = Signal()


class WebScanTask(QRunnable):
    def __init__(self, service: WebScanService, values: dict[str, Any]) -> None:
        super().__init__()
        self.service = service
        self.values = values
        self.signals = WebScanSignals()

    @Slot()
    def run(self) -> None:
        try:
            self.signals.succeeded.emit(self.service.run(**self.values))
        except Exception as error:
            self.signals.failed.emit(str(error))
        finally:
            self.signals.finished.emit()


class WebScannerView(QWidget):
    def __init__(self, service: WebScanService) -> None:
        super().__init__()
        self.setObjectName("page")
        self.service = service
        self._task: WebScanTask | None = None
        self._last_job_id: str | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 34, 40, 34)
        heading = QLabel("Web security scanner")
        heading.setObjectName("heading")
        body = QLabel(
            "Crawls stay same-origin and run only under a current central authorization scope. "
            "Uploaded evidence is redacted metadata; response bodies and cookies stay local."
        )
        body.setObjectName("body")
        body.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(body)

        form = QFormLayout()
        self.target = QLineEdit()
        self.target.setPlaceholderText("https://authorized.example.test/")
        self.scope = QComboBox()
        self.scope.addItem("Load authorization scopes", None)
        self.justification = QLineEdit()
        self.justification.setPlaceholderText("Why this web scan is required")
        self.crawl_depth = QSpinBox()
        self.crawl_depth.setRange(0, 5)
        self.crawl_depth.setValue(2)
        self.page_limit = QSpinBox()
        self.page_limit.setRange(1, 500)
        self.page_limit.setValue(25)
        self.active = QCheckBox("Active canary checks")
        self.forms = QCheckBox("Allow safe form canary submission")
        form.addRow("Start URL", self.target)
        form.addRow("Authorization scope", self.scope)
        form.addRow("Business justification", self.justification)
        form.addRow("Crawl depth", self.crawl_depth)
        form.addRow("Page limit", self.page_limit)
        form.addRow("Checks", self.active)
        form.addRow("Forms", self.forms)
        layout.addLayout(form)

        actions = QHBoxLayout()
        refresh = QPushButton("Refresh authorization")
        refresh.clicked.connect(self.refresh)
        self.run_button = QPushButton("Run authorized scan")
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self.run_scan)
        self.export_json = QPushButton("Export JSON")
        self.export_json.setEnabled(False)
        self.export_json.clicked.connect(lambda: self._export("json"))
        self.export_text = QPushButton("Export text")
        self.export_text.setEnabled(False)
        self.export_text.clicked.connect(lambda: self._export("text"))
        for button in (refresh, self.run_button, self.export_json, self.export_text):
            actions.addWidget(button)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.status = QLabel("No web scan has run.")
        self.status.setObjectName("body")
        layout.addWidget(self.status)
        self.results = QTableWidget(0, 5)
        self.results.setHorizontalHeaderLabels(["Severity", "Confidence", "Rule", "URL", "Title"])
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
            if scope["is_active"] and "web-scanner" in scope["allowed_modules"]:
                self.scope.addItem(f"{scope['name']} · {scope['target_pattern']}", scope["id"])
        self.status.setText(f"Loaded {self.scope.count()} active web scanner scope(s).")

    def run_scan(self) -> None:
        scope_id = self.scope.currentData()
        if scope_id is None:
            self.status.setText("Select an active authorization scope first.")
            return
        if len(self.justification.text().strip()) < 10:
            self.status.setText("Provide a business justification of at least 10 characters.")
            return
        values = {
            "target_url": self.target.text().strip(),
            "scope_id": UUID(str(scope_id)),
            "justification": self.justification.text().strip(),
            "max_depth": self.crawl_depth.value(),
            "max_pages": self.page_limit.value(),
            "active_checks": self.active.isChecked(),
            "allow_form_submission": self.forms.isChecked(),
        }
        self._set_running(True)
        self.status.setText("Authorization accepted; crawling same-origin pages.")
        self._task = WebScanTask(self.service, values)
        self._task.signals.succeeded.connect(self._completed)
        self._task.signals.failed.connect(self._failed)
        self._task.signals.finished.connect(lambda: self._set_running(False))
        QThreadPool.globalInstance().start(self._task)

    def _completed(self, result: dict[str, Any]) -> None:
        findings = result["findings"]
        self.results.setRowCount(len(findings))
        for row, item in enumerate(findings):
            values = (
                item["severity"],
                f"{item['confidence']:.2f}",
                item["rule_id"],
                item["url"],
                item["title"],
            )
            for column, value in enumerate(values):
                self.results.setItem(row, column, QTableWidgetItem(value))
        self._last_job_id = result["job"]["id"]
        self.status.setText(f"Scan {result['job']['state']}: {len(findings)} finding(s)")
        self.export_json.setEnabled(True)
        self.export_text.setEnabled(True)

    def _failed(self, message: str) -> None:
        self.status.setText(message or "Web scan failed safely.")

    def _set_running(self, running: bool) -> None:
        self.run_button.setEnabled(not running)

    def _export(self, report_format: str) -> None:
        if self._last_job_id is None:
            return
        suffix = "json" if report_format == "json" else "txt"
        selected, _ = QFileDialog.getSaveFileName(
            self, "Export web scan report", f"stoa-web-scan.{suffix}"
        )
        if not selected:
            return
        content = self.service.session.client.get_text(
            f"/api/v1/jobs/{self._last_job_id}/web-scan-report?format={report_format}"
        )
        Path(selected).write_text(content, encoding="utf-8", newline="\n")
        self.status.setText("Report exported.")
