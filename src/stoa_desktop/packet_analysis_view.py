"""Packet metadata capture and deterministic replay screen."""

from pathlib import Path
from uuid import UUID

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from stoa_desktop.packet_analysis import PacketAnalysisService
from stoa_security.ids import Indicator
from stoa_security.packet_analysis import PacketMetadata, summarize


class PacketAnalysisView(QWidget):
    packet_received = Signal(object, object)

    def __init__(self, service: PacketAnalysisService) -> None:
        super().__init__()
        self.setObjectName("page")
        self.service = service
        self.packet_received.connect(self._append_packet)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 34, 40, 34)
        heading = QLabel("Packet analysis & IDS")
        heading.setObjectName("heading")
        note = QLabel(
            "PCAP files and packet payloads stay on this endpoint. Only bounded findings and "
            "traffic counts are sent to the central service. Live capture may require Npcap "
            "on Windows or capture capabilities on Linux."
        )
        note.setObjectName("body")
        note.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(note)

        controls = QHBoxLayout()
        self.interface = QComboBox()
        self.scope = QComboBox()
        self.justification = QLineEdit()
        self.justification.setPlaceholderText("Business justification")
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        self.start = QPushButton("Start authorized capture")
        self.start.setObjectName("primary")
        self.start.clicked.connect(self.start_capture)
        self.stop = QPushButton("Stop")
        self.stop.setEnabled(False)
        self.stop.clicked.connect(self.stop_capture)
        replay = QPushButton("Open PCAP")
        replay.clicked.connect(self.open_pcap)
        for widget in (
            self.interface,
            self.scope,
            self.justification,
            refresh,
            self.start,
            self.stop,
            replay,
        ):
            controls.addWidget(widget)
        layout.addLayout(controls)

        filters = QHBoxLayout()
        self.protocol = QComboBox()
        self.protocol.addItems(["all", "tcp", "udp", "icmp", "arp", "dns", "http", "tls"])
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search packet metadata")
        self.search.textChanged.connect(self.apply_filter)
        self.protocol.currentTextChanged.connect(self.apply_filter)
        filters.addWidget(self.protocol)
        filters.addWidget(self.search, 1)
        layout.addLayout(filters)
        self.status = QLabel("No capture loaded.")
        self.status.setObjectName("body")
        layout.addWidget(self.status)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Protocol", "Source", "Destination", "Src port", "Dst port", "Details"]
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table, 1)

    def refresh(self) -> None:
        try:
            options = self.service.options()
        except Exception as error:
            self.status.setText(str(error))
            return
        self.interface.clear()
        self.interface.addItems(options["interfaces"])
        self.scope.clear()
        for scope in options["scopes"]:
            if scope["is_active"] and "packet-analysis" in scope["allowed_modules"]:
                self.scope.addItem(
                    f"{scope['name']} · {scope['target_pattern']}",
                    (scope["id"], scope["target_pattern"]),
                )
        self.status.setText("Capture interfaces and authorization scopes refreshed.")

    def start_capture(self) -> None:
        selected = self.scope.currentData()
        if selected is None or len(self.justification.text().strip()) < 10:
            self.status.setText("Select a scope and provide a business justification.")
            return
        scope_id, target = selected
        try:
            self.service.start_live(
                interface=self.interface.currentText(),
                scope_id=UUID(scope_id),
                target_network=target,
                justification=self.justification.text().strip(),
                handler=lambda metadata, indicators: self.packet_received.emit(
                    metadata, indicators
                ),
            )
        except Exception as error:
            self.status.setText(f"Capture permission or setup error: {error}")
            return
        self.start.setEnabled(False)
        self.stop.setEnabled(True)
        self.status.setText("Capturing authorized traffic locally…")

    def stop_capture(self) -> None:
        try:
            result = self.service.stop_live()
        except Exception as error:
            self.status.setText(str(error))
            return
        self.start.setEnabled(True)
        self.stop.setEnabled(False)
        self.status.setText(
            f"Capture {result['state']}; {result['alerts_created']} alert(s) created."
        )

    def open_pcap(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP", filter="PCAP (*.pcap *.pcapng)"
        )
        if not selected:
            return
        try:
            rows, indicators = self.service.replay(Path(selected))
        except Exception as error:
            self.status.setText(f"PCAP could not be read: {error}")
            return
        self._render(rows)
        summary = summarize(rows)
        self.status.setText(
            f"Local replay: {summary.packet_count} packets, {summary.byte_count} bytes, "
            f"{len(indicators)} indicator(s). Nothing was uploaded."
        )

    def apply_filter(self) -> None:
        protocol = self.protocol.currentText()
        rows = self.service.filtered(None if protocol == "all" else protocol, self.search.text())
        self._render(rows)

    def _append_packet(self, metadata: PacketMetadata, indicators: tuple[Indicator, ...]) -> None:
        del indicators
        self.apply_filter()

    def _render(self, rows: list[PacketMetadata]) -> None:
        self.table.setRowCount(len(rows))
        for row_index, item in enumerate(rows):
            detail = (
                item.dns_query or item.http_host or item.tls_version or item.arp_operation or "—"
            )
            values = (
                item.observed_at.astimezone().strftime("%H:%M:%S.%f")[:-3],
                item.protocol.upper(),
                item.source or "—",
                item.destination or "—",
                str(item.source_port) if item.source_port else "—",
                str(item.destination_port) if item.destination_port else "—",
                detail,
            )
            for column, value in enumerate(values):
                self.table.setItem(row_index, column, QTableWidgetItem(value))
