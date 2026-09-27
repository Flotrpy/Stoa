"""Qt workflow for firewall simulation."""

import json
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
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from stoa_desktop.firewall_simulator import FirewallSimulatorService

DEFAULT_POLICY = {
    "default_action": "block",
    "rules": [
        {
            "order": 1,
            "name": "Allow HTTPS from lab subnet",
            "direction": "outbound",
            "action": "allow",
            "protocol": "tcp",
            "source": "192.0.2.0/24",
            "destination": "198.51.100.10/32",
            "destination_ports": [[443, 443]],
            "enabled": True,
        }
    ],
}


class FirewallSignals(QObject):
    succeeded = Signal(dict)
    failed = Signal(str)
    finished = Signal()


class FirewallTask(QRunnable):
    def __init__(self, service: FirewallSimulatorService, values: dict[str, Any]) -> None:
        super().__init__()
        self.service = service
        self.values = values
        self.signals = FirewallSignals()

    @Slot()
    def run(self) -> None:
        try:
            self.signals.succeeded.emit(self.service.run(**self.values))
        except Exception as error:
            self.signals.failed.emit(str(error))
        finally:
            self.signals.finished.emit()


class FirewallSimulatorView(QWidget):
    def __init__(self, service: FirewallSimulatorService) -> None:
        super().__init__()
        self.setObjectName("page")
        self.service = service
        self._task: FirewallTask | None = None
        self._last_job_id: str | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 34, 40, 34)
        heading = QLabel("Firewall simulator")
        heading.setObjectName("heading")
        body = QLabel(
            "Simulates ordered allow/block rules without changing Windows Firewall, nftables, "
            "iptables, or host network settings."
        )
        body.setObjectName("body")
        body.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(body)

        form = QFormLayout()
        self.target = QLineEdit("policy://local")
        self.scope = QComboBox()
        self.scope.addItem("Load authorization scopes", None)
        self.justification = QLineEdit()
        self.justification.setPlaceholderText("Why this simulation is required")
        form.addRow("Policy target", self.target)
        form.addRow("Authorization scope", self.scope)
        form.addRow("Business justification", self.justification)
        layout.addLayout(form)

        self.policy = QTextEdit()
        self.policy.setPlainText(json.dumps(DEFAULT_POLICY, indent=2))
        layout.addWidget(self.policy, 1)

        actions = QHBoxLayout()
        refresh = QPushButton("Refresh authorization")
        refresh.clicked.connect(self.refresh)
        self.run_button = QPushButton("Run simulation")
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self.run_simulation)
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

        self.status = QLabel("No simulation has run.")
        self.status.setObjectName("body")
        layout.addWidget(self.status)
        self.results = QTableWidget(0, 4)
        self.results.setHorizontalHeaderLabels(["Action", "Matched rule", "Packet", "Explanation"])
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
            if scope["is_active"] and "firewall-simulator" in scope["allowed_modules"]:
                self.scope.addItem(f"{scope['name']} · {scope['target_pattern']}", scope["id"])
        self.status.setText(f"Loaded {self.scope.count()} active firewall scope(s).")

    def run_simulation(self) -> None:
        scope_id = self.scope.currentData()
        if scope_id is None:
            self.status.setText("Select an active authorization scope first.")
            return
        if len(self.justification.text().strip()) < 10:
            self.status.setText("Provide a business justification of at least 10 characters.")
            return
        try:
            policy = json.loads(self.policy.toPlainText())
        except json.JSONDecodeError as error:
            self.status.setText(f"Policy JSON error: {error.msg}")
            return
        values = {
            "target": self.target.text().strip(),
            "scope_id": UUID(str(scope_id)),
            "justification": self.justification.text().strip(),
            "policy": policy,
        }
        self._set_running(True)
        self._task = FirewallTask(self.service, values)
        self._task.signals.succeeded.connect(self._completed)
        self._task.signals.failed.connect(self._failed)
        self._task.signals.finished.connect(lambda: self._set_running(False))
        QThreadPool.globalInstance().start(self._task)

    def _completed(self, result: dict[str, Any]) -> None:
        observations = result["observations"]
        self.results.setRowCount(len(observations))
        for row, item in enumerate(observations):
            packet = item["packet"]
            packet_text = (
                f"{packet['protocol']} {packet['source']}:{packet.get('source_port') or '-'} -> "
                f"{packet['destination']}:{packet.get('destination_port') or '-'}"
            )
            values = (
                item["action"],
                item.get("matched_rule") or "default",
                packet_text,
                item["explanation"],
            )
            for column, value in enumerate(values):
                self.results.setItem(row, column, QTableWidgetItem(value))
        self._last_job_id = result["job"]["id"]
        self.status.setText(f"Simulation {result['job']['state']}: {len(observations)} packet(s)")
        self.export_json.setEnabled(True)
        self.export_text.setEnabled(True)

    def _failed(self, message: str) -> None:
        self.status.setText(message or "Firewall simulation failed safely.")

    def _set_running(self, running: bool) -> None:
        self.run_button.setEnabled(not running)

    def _export(self, report_format: str) -> None:
        if self._last_job_id is None:
            return
        suffix = "json" if report_format == "json" else "txt"
        selected, _ = QFileDialog.getSaveFileName(
            self, "Export firewall simulation report", f"stoa-firewall-simulation.{suffix}"
        )
        if not selected:
            return
        content = self.service.session.client.get_text(
            f"/api/v1/jobs/{self._last_job_id}/firewall-simulation-report?format={report_format}"
        )
        Path(selected).write_text(content, encoding="utf-8", newline="\n")
        self.status.setText("Report exported.")
