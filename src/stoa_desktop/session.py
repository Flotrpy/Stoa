"""Crash-safe desktop session orchestration."""

from dataclasses import replace
from typing import Any, cast
from uuid import UUID

from stoa_desktop.api_client import ApiClient, Connectivity
from stoa_desktop.config import ConfigStore
from stoa_desktop.offline_queue import OfflineQueue
from stoa_desktop.secrets import SecureTokenStore
from stoa_desktop.sync import OfflineSynchronizer


class DesktopSession:
    """Own connection state while keeping credentials in the OS keyring."""

    def __init__(
        self,
        config_store: ConfigStore | None = None,
        token_store: SecureTokenStore | None = None,
        offline_queue: OfflineQueue | None = None,
    ) -> None:
        self.config_store = config_store or ConfigStore()
        self.token_store = token_store or SecureTokenStore()
        self.offline_queue = offline_queue or OfflineQueue()
        self.settings = self.config_store.load()
        self.client = ApiClient(self.settings.api_url, self.token_store.get())
        self.connectivity = Connectivity.LOCAL_ONLY
        self.principal: dict[str, Any] | None = None

    def restore(self) -> Connectivity:
        self.connectivity = self.client.health()
        if self.connectivity is Connectivity.CONNECTED:
            try:
                self.principal = self.client.get("/api/v1/auth/me")
                OfflineSynchronizer(self.client, self.offline_queue).flush()
            except Exception:
                self.token_store.clear()
                self.client.token = None
                self.principal = None
                self.connectivity = Connectivity.AUTH_REQUIRED
        return self.connectivity

    def sign_in(self, api_url: str, email: str, password: str) -> dict[str, Any]:
        self.client = ApiClient(api_url)
        token = self.client.login(email, password)
        principal = cast(dict[str, Any], self.client.get("/api/v1/auth/me"))
        self.token_store.set(token)
        self.settings = replace(
            self.settings,
            api_url=api_url.rstrip("/"),
            team_id=UUID(str(principal["team"]["id"])),
        )
        self.config_store.save(self.settings)
        self.principal = principal
        self.connectivity = Connectivity.CONNECTED
        OfflineSynchronizer(self.client, self.offline_queue).flush()
        return principal

    def update_preferences(self, *, api_url: str, theme: str) -> None:
        self.settings = replace(self.settings, api_url=api_url.rstrip("/"), theme=theme)
        self.config_store.save(self.settings)
        self.client.base_url = self.settings.api_url

    def sign_out(self) -> None:
        self.token_store.clear()
        self.client.token = None
        self.principal = None
        self.connectivity = Connectivity.AUTH_REQUIRED
