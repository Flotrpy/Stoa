"""Typed desktop client for versioned Stoá APIs."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx


class Connectivity(StrEnum):
    LOCAL_ONLY = "local_only"
    CONNECTED = "connected"
    OFFLINE = "offline"
    AUTH_REQUIRED = "auth_required"


class ApiClientError(RuntimeError):
    pass


@dataclass(slots=True)
class ApiClient:
    base_url: str
    token: str | None = None
    timeout_seconds: float = 10.0
    transport: httpx.BaseTransport | None = None

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def health(self) -> Connectivity:
        try:
            response = self._request("GET", "/api/v1/health", authenticated=False)
            response.raise_for_status()
            return Connectivity.CONNECTED if self.token else Connectivity.AUTH_REQUIRED
        except (httpx.HTTPError, OSError):
            return Connectivity.OFFLINE

    def login(self, email: str, password: str) -> str:
        try:
            response = self._request(
                "POST",
                "/api/v1/auth/token",
                authenticated=False,
                json={"email": email, "password": password},
            )
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise ApiClientError("sign in failed") from error
        self.token = str(response.json()["access_token"])
        return self.token

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("POST", path, json=payload)

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._request(method, path, **kwargs)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as error:
            if error.response.status_code == 401:
                raise ApiClientError("authentication required") from error
            raise ApiClientError("server request failed") from error
        except httpx.HTTPError as error:
            raise ApiClientError("server unavailable") from error

    def _request(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        headers = self._headers() if authenticated else {}
        with httpx.Client(
            base_url=self.base_url.rstrip("/"),
            timeout=self.timeout_seconds,
            transport=self.transport,
        ) as client:
            return client.request(method, path, headers=headers, **kwargs)
