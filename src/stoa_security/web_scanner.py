"""Authorized same-origin web security scanner with bounded evidence."""

from __future__ import annotations

import re
import ssl
import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

SQL_ERROR_PATTERNS = (
    "sql syntax",
    "sqlite error",
    "postgresql",
    "mysql",
    "ora-",
    "unclosed quotation",
    "syntax error at or near",
)
TEXT_INPUT_TYPES = {"", "text", "search", "email", "url", "tel"}
SENSITIVE_FIELD_NAMES = {"password", "pass", "token", "secret", "csrf", "auth", "key"}


@dataclass(frozen=True, slots=True)
class DiscoveredForm:
    method: str
    action: str
    inputs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DiscoveredPage:
    url: str
    status_code: int
    title: str | None
    links: tuple[str, ...]
    forms: tuple[DiscoveredForm, ...]
    parameters: tuple[str, ...]
    headers: dict[str, str]
    cookies: tuple[str, ...]
    redirect_chain: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WebFinding:
    rule_id: str
    title: str
    severity: str
    confidence: float
    url: str
    evidence: dict[str, str | int | float]
    remediation: str
    category: str = "web"


@dataclass(frozen=True, slots=True)
class WebScanReport:
    target_url: str
    pages: tuple[DiscoveredPage, ...]
    findings: tuple[WebFinding, ...]
    cancelled: bool = False

    @property
    def page_count(self) -> int:
        return len(self.pages)


@dataclass(frozen=True, slots=True)
class WebScanConfig:
    start_url: str
    max_depth: int = 2
    max_pages: int = 25
    max_requests_per_second: int = 5
    timeout_seconds: float = 5.0
    active_checks: bool = False
    allow_form_submission: bool = False
    user_agent: str = "StoaAuthorizedWebScanner/0.1"

    def __post_init__(self) -> None:
        parsed = urlparse(self.start_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("start_url must be an absolute http or https URL")
        if not 0 <= self.max_depth <= 5:
            raise ValueError("max_depth must be between 0 and 5")
        if not 1 <= self.max_pages <= 500:
            raise ValueError("max_pages must be between 1 and 500")
        if not 1 <= self.max_requests_per_second <= 50:
            raise ValueError("max_requests_per_second must be between 1 and 50")
        if not 0.1 <= self.timeout_seconds <= 15:
            raise ValueError("timeout_seconds must be between 0.1 and 15")


class _DiscoveryParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()
        self.forms: list[DiscoveredForm] = []
        self.title: str | None = None
        self._in_title = False
        self._form_action: str | None = None
        self._form_method = "get"
        self._form_inputs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        if tag == "title":
            self._in_title = True
        if tag == "a" and values.get("href"):
            self.links.add(urljoin(self.base_url, values["href"]))
        if tag == "form":
            self._form_action = urljoin(self.base_url, values.get("action") or self.base_url)
            self._form_method = (values.get("method") or "get").casefold()
            self._form_inputs = []
        if tag == "input" and self._form_action is not None:
            name = values.get("name", "").strip()
            input_type = values.get("type", "").casefold()
            if (
                name
                and input_type in TEXT_INPUT_TYPES
                and name.casefold() not in SENSITIVE_FIELD_NAMES
            ):
                self._form_inputs.append(name[:120])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag == "form" and self._form_action is not None:
            self.forms.append(
                DiscoveredForm(
                    method=self._form_method if self._form_method in {"get", "post"} else "get",
                    action=self._form_action,
                    inputs=tuple(dict.fromkeys(self._form_inputs)),
                )
            )
            self._form_action = None
            self._form_inputs = []

    def handle_data(self, data: str) -> None:
        if self._in_title and self.title is None:
            title = " ".join(data.split())
            self.title = title[:160] if title else None


class AuthorizedWebScanner:
    def __init__(self, config: WebScanConfig) -> None:
        self.config = config
        self._origin = _origin(config.start_url)
        self._last_request_at = 0.0

    def scan(self) -> WebScanReport:
        findings: list[WebFinding] = []
        pages: list[DiscoveredPage] = []
        queue: deque[tuple[str, int]] = deque([(canonical_url(self.config.start_url), 0)])
        visited: set[str] = set()
        with httpx.Client(
            follow_redirects=True,
            timeout=self.config.timeout_seconds,
            headers={"User-Agent": self.config.user_agent},
        ) as client:
            while queue and len(pages) < self.config.max_pages:
                url, depth = queue.popleft()
                if url in visited or not self._same_origin(url):
                    continue
                visited.add(url)
                response = self._request(client, "GET", url)
                if response is None:
                    continue
                page = self._page_from_response(response)
                pages.append(page)
                findings.extend(passive_findings(page))
                findings.extend(
                    cookie_findings(str(response.url), response.headers.get_list("set-cookie"))
                )
                if depth < self.config.max_depth:
                    for link in page.links:
                        normalized = canonical_url(link)
                        if normalized not in visited and self._same_origin(normalized):
                            queue.append((normalized, depth + 1))
            if self.config.active_checks:
                findings.extend(self._active_findings(client, pages))
        unique = _deduplicate_findings(findings)
        return WebScanReport(
            target_url=canonical_url(self.config.start_url),
            pages=tuple(pages),
            findings=tuple(unique),
        )

    def _request(
        self, client: httpx.Client, method: str, url: str, **kwargs: Any
    ) -> httpx.Response | None:
        if not self._same_origin(url):
            return None
        interval = 1 / self.config.max_requests_per_second
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < interval:
            time.sleep(interval - elapsed)
        self._last_request_at = time.monotonic()
        try:
            response = client.request(method, url, **kwargs)
        except httpx.HTTPError:
            return None
        if not self._same_origin(str(response.url)):
            return None
        return response

    def _page_from_response(self, response: httpx.Response) -> DiscoveredPage:
        content_type = response.headers.get("content-type", "")
        parser = _DiscoveryParser(str(response.url))
        if "html" in content_type.casefold():
            parser.feed(response.text[:250_000])
        links = tuple(sorted(link for link in parser.links if self._same_origin(link)))
        forms = tuple(form for form in parser.forms if self._same_origin(form.action))
        parsed = urlparse(str(response.url))
        parameters = tuple(
            sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        )
        headers = {
            key.lower()[:80]: value[:300]
            for key, value in response.headers.items()
            if key.lower()
            in {
                "content-security-policy",
                "strict-transport-security",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
                "server",
                "location",
            }
        }
        cookies = tuple(sorted(response.cookies.keys()))
        redirects = tuple(redacted_url(str(item.url)) for item in response.history)
        return DiscoveredPage(
            url=redacted_url(str(response.url)),
            status_code=response.status_code,
            title=parser.title,
            links=tuple(redacted_url(item) for item in links),
            forms=forms,
            parameters=parameters,
            headers=headers,
            cookies=cookies,
            redirect_chain=redirects,
        )

    def _active_findings(
        self, client: httpx.Client, pages: Iterable[DiscoveredPage]
    ) -> list[WebFinding]:
        findings: list[WebFinding] = []
        canary = "stoa-canary-6b7b4f"
        for page in pages:
            raw_url = _unredacted_with_blank_values(page.url)
            for parameter in page.parameters[:8]:
                findings.extend(self._probe_query_parameter(client, raw_url, parameter, canary))
            if self.config.allow_form_submission:
                for form in page.forms[:3]:
                    findings.extend(self._probe_form(client, form, canary))
        return findings

    def _probe_query_parameter(
        self, client: httpx.Client, url: str, parameter: str, canary: str
    ) -> list[WebFinding]:
        findings: list[WebFinding] = []
        sql_url = replace_query_value(url, parameter, "'")
        response = self._request(client, "GET", sql_url)
        if response is not None and _contains_sql_error(response.text):
            findings.append(
                WebFinding(
                    rule_id="STOA-WEB-004",
                    title="SQL error pattern after quoted parameter probe",
                    severity="medium",
                    confidence=0.65,
                    url=redacted_url(sql_url),
                    evidence={"parameter": parameter, "status_code": response.status_code},
                    remediation=(
                        "Use parameterized database queries and return generic server errors."
                    ),
                )
            )
        xss_url = replace_query_value(url, parameter, canary)
        reflected = self._request(client, "GET", xss_url)
        if reflected is not None and canary in reflected.text:
            findings.append(
                WebFinding(
                    rule_id="STOA-WEB-005",
                    title="Reflected input marker in response body",
                    severity="medium",
                    confidence=0.75,
                    url=redacted_url(xss_url),
                    evidence={"parameter": parameter, "marker": canary},
                    remediation=(
                        "Encode untrusted input in the response context and add regression tests."
                    ),
                )
            )
        return findings

    def _probe_form(
        self, client: httpx.Client, form: DiscoveredForm, canary: str
    ) -> list[WebFinding]:
        if not form.inputs or form.method != "post":
            return []
        data = {name: canary for name in form.inputs[:8]}
        response = self._request(client, "POST", form.action, data=data)
        if response is None:
            return []
        refetch = self._request(client, "GET", form.action)
        if refetch is None or canary not in refetch.text:
            return []
        return [
            WebFinding(
                rule_id="STOA-WEB-006",
                title="Submitted marker persisted and reappeared",
                severity="medium",
                confidence=0.7,
                url=redacted_url(form.action),
                evidence={"inputs": ",".join(form.inputs[:8]), "marker": canary},
                remediation=(
                    "Validate stored input, encode output on render, and add content "
                    "security policy."
                ),
            )
        ]

    def _same_origin(self, url: str) -> bool:
        return _origin(url) == self._origin


def passive_findings(page: DiscoveredPage) -> list[WebFinding]:
    findings: list[WebFinding] = []
    if page.url.startswith("https://"):
        required = {
            "strict-transport-security": (
                "STOA-WEB-001",
                "Missing HSTS header",
                "low",
                "Send Strict-Transport-Security on HTTPS responses after validating "
                "preload impact.",
            ),
        }
    else:
        required = {}
        findings.append(
            WebFinding(
                rule_id="STOA-WEB-002",
                title="Page served without HTTPS",
                severity="medium",
                confidence=0.9,
                url=page.url,
                evidence={"scheme": "http"},
                remediation="Serve authenticated and sensitive workflows over HTTPS.",
            )
        )
    required.update(
        {
            "content-security-policy": (
                "STOA-WEB-007",
                "Missing Content Security Policy",
                "low",
                "Define a restrictive Content-Security-Policy for script and framing controls.",
            ),
            "x-content-type-options": (
                "STOA-WEB-008",
                "Missing X-Content-Type-Options",
                "info",
                "Send X-Content-Type-Options: nosniff on HTML and script responses.",
            ),
        }
    )
    for header, (rule_id, title, severity, remediation) in required.items():
        if header not in page.headers:
            findings.append(
                WebFinding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    confidence=0.85,
                    url=page.url,
                    evidence={"missing_header": header},
                    remediation=remediation,
                )
            )
    return findings


def cookie_findings(url: str, set_cookie_headers: Iterable[str]) -> list[WebFinding]:
    findings: list[WebFinding] = []
    for header in set_cookie_headers:
        name = header.split("=", maxsplit=1)[0][:80]
        lower = header.casefold()
        missing = [
            flag
            for flag in ("secure", "httponly", "samesite")
            if flag not in lower and (flag != "secure" or url.startswith("https://"))
        ]
        if missing:
            findings.append(
                WebFinding(
                    rule_id="STOA-WEB-003",
                    title="Cookie missing security attribute",
                    severity="low",
                    confidence=0.8,
                    url=redacted_url(url),
                    evidence={"cookie": name, "missing": ",".join(missing)},
                    remediation="Set Secure, HttpOnly, and SameSite where compatible.",
                )
            )
    return findings


def tls_observation(url: str, timeout_seconds: float = 3.0) -> dict[str, str | int] | None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    port = parsed.port or 443
    try:
        certificate = ssl.get_server_certificate((parsed.hostname, port), timeout=timeout_seconds)
    except OSError:
        return {"host": parsed.hostname, "port": port, "certificate": "unavailable"}
    return {"host": parsed.hostname, "port": port, "certificate_pem_bytes": len(certificate)}


def canonical_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", query, ""))


def redacted_url(url: str) -> str:
    parsed = urlparse(url)
    query = urlencode(
        [(name, "REDACTED") for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    )
    return urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", query, ""))


def replace_query_value(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not any(name == parameter for name, _ in pairs):
        pairs.append((parameter, value))
    else:
        pairs = [(name, value if name == parameter else item) for name, item in pairs]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(pairs), ""))


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, (parsed.hostname or "").casefold(), port


def _contains_sql_error(body: str) -> bool:
    snippet = body[:20_000].casefold()
    return any(pattern in snippet for pattern in SQL_ERROR_PATTERNS)


def _deduplicate_findings(findings: Iterable[WebFinding]) -> list[WebFinding]:
    unique: dict[tuple[str, str, str], WebFinding] = {}
    for finding in findings:
        unique.setdefault((finding.rule_id, finding.url, str(finding.evidence)), finding)
    return list(unique.values())


def _unredacted_with_blank_values(url: str) -> str:
    return re.sub(r"=REDACTED(?=&|$)", "=", url)
