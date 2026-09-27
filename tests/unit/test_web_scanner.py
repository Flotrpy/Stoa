from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import httpx
import pytest

from stoa_security.web_scanner import AuthorizedWebScanner, WebScanConfig, redacted_url
from stoa_security.zap_adapter import ZapImportConfig, import_zap_alerts


class WebFixture(BaseHTTPRequestHandler):
    stored: ClassVar[str] = ""

    def do_GET(self) -> None:
        body = "<html><title>Fixture</title><a href='/search?q=home'>Search</a>"
        if self.path.startswith("/search"):
            query = self.path.split("q=", maxsplit=1)[-1]
            if "%27" in self.path or "'" in self.path:
                body += "SQLite error near quoted string"
            body += f"<main>{query}</main>"
        if self.path.startswith("/submit"):
            body += f"<section>{self.stored}</section>"
        body += "<form method='post' action='/submit'><input name='comment'></form></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=abc123")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        self.__class__.stored = self.rfile.read(length).decode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:
        del format, args


@pytest.fixture
def fixture_url() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), WebFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_web_scanner_crawls_same_origin_and_redacts_active_evidence(fixture_url: str) -> None:
    report = AuthorizedWebScanner(
        WebScanConfig(
            start_url=fixture_url,
            max_depth=1,
            max_pages=5,
            active_checks=True,
            allow_form_submission=True,
            max_requests_per_second=50,
        )
    ).scan()

    rule_ids = {finding.rule_id for finding in report.findings}
    assert report.page_count >= 2
    assert {"STOA-WEB-002", "STOA-WEB-003", "STOA-WEB-004", "STOA-WEB-005"} <= rule_ids
    assert any(finding.rule_id == "STOA-WEB-006" for finding in report.findings)
    assert "abc123" not in str(report)
    assert "REDACTED" in redacted_url(f"{fixture_url}search?q=secret")


def test_zap_import_requires_local_api_and_redacts_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    original_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/JSON/core/view/alerts/"
        return httpx.Response(
            200,
            json={
                "alerts": [
                    {
                        "alert": "Fixture alert",
                        "risk": "Low",
                        "confidence": "High",
                        "url": "http://127.0.0.1/search?q=secret",
                        "pluginId": "1",
                        "solution": "Fix it",
                    }
                ]
            },
        )

    def client_factory(**kwargs: object) -> httpx.Client:
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)
    findings = import_zap_alerts(ZapImportConfig(), "http://127.0.0.1/")

    assert findings[0].rule_id == "STOA-WEB-ZAP"
    assert findings[0].url == "http://127.0.0.1/search?q=REDACTED"
    with pytest.raises(ValueError):
        ZapImportConfig(api_url="https://zap.example.test")
