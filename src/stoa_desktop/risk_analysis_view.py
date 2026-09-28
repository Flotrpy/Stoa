"""Professional local risk-analysis workspace."""

from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from stoa_desktop.risk_analysis import RiskAnalysisService
from stoa_security.phishing import PageFacts


class RiskAnalysisView(QWidget):
    def __init__(self, service: RiskAnalysisService) -> None:
        super().__init__()
        self.service = service
        layout = QVBoxLayout(self)
        heading = QLabel("Risk analysis")
        heading.setObjectName("pageTitle")
        layout.addWidget(heading)
        note = QLabel(
            "Explainable phishing triage and a bounded, offline password-audit lab. "
            "Hashes, candidates, and recovered values never leave this device."
        )
        note.setWordWrap(True)
        note.setObjectName("body")
        layout.addWidget(note)
        tabs = QTabWidget()
        tabs.addTab(self._phishing_tab(), "Phishing assessment")
        tabs.addTab(self._password_tab(), "Offline password lab")
        layout.addWidget(tabs, 1)

    def _phishing_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        form = QFormLayout()
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://site.example/sign-in")
        form.addRow("Page URL", self.url)
        self.brand = QLineEdit()
        form.addRow("Expected brand (optional)", self.brand)
        self.title = QLineEdit()
        form.addRow("Observed page title", self.title)
        self.form_action = QLineEdit()
        form.addRow("Form destination (optional)", self.form_action)
        layout.addLayout(form)
        run = QPushButton("Assess page facts")
        run.clicked.connect(self._assess_page)
        layout.addWidget(run)
        self.phishing_result = QPlainTextEdit()
        self.phishing_result.setReadOnly(True)
        layout.addWidget(self.phishing_result, 1)
        return page

    def _password_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        warning = QLabel(
            "Educational local demonstration only. Supports hexadecimal MD5, SHA-256, and "
            "SHA-512 fixtures; never use against accounts or online services."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)
        self.digest = QLineEdit()
        self.digest.setEchoMode(QLineEdit.EchoMode.Password)
        self.digest.setPlaceholderText("Local demonstration hash")
        layout.addWidget(self.digest)
        self.words = QPlainTextEdit()
        self.words.setPlaceholderText("Local candidate words, one per line")
        layout.addWidget(self.words, 1)
        limits = QHBoxLayout()
        self.attempts = QSpinBox()
        self.attempts.setRange(1, 1_000_000)
        self.attempts.setValue(10_000)
        limits.addWidget(QLabel("Maximum attempts"))
        limits.addWidget(self.attempts)
        layout.addLayout(limits)
        run = QPushButton("Run bounded local audit")
        run.clicked.connect(self._audit_password)
        layout.addWidget(run)
        self.password_result = QLabel("No audit run")
        self.password_result.setWordWrap(True)
        layout.addWidget(self.password_result)
        return page

    def _assess_page(self) -> None:
        try:
            result = self.service.assess_page(
                PageFacts(
                    url=self.url.text(),
                    title=self.title.text(),
                    expected_brand=self.brand.text() or None,
                    form_actions=(self.form_action.text(),) if self.form_action.text() else (),
                    password_fields=1 if self.form_action.text() else 0,
                )
            )
            explanations = "\n".join(f"• {item}" for item in result["explanations"])
            self.phishing_result.setPlainText(
                f"Risk: {result['level'].upper()} ({result['score']:.0%})\n"
                f"Model: {result['model_version']}\n\n{explanations or 'No heuristic warnings.'}"
            )
        except Exception as error:
            QMessageBox.critical(self, "Assessment failed", str(error))

    def _audit_password(self) -> None:
        try:
            result = self.service.audit_password_hash(
                self.digest.text(),
                self.words.toPlainText().splitlines(),
                max_attempts=self.attempts.value(),
                max_seconds=10,
            )
            self.password_result.setText(
                f"{result['finding']} after {result['attempts']:,} attempts. "
                f"{result['remediation']}"
            )
        except Exception as error:
            QMessageBox.critical(self, "Audit failed", str(error))
