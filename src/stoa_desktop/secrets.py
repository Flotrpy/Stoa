"""Operating-system credential-vault integration."""

from typing import Protocol

import keyring


class CredentialBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


class SecureTokenStore:
    """Store access tokens outside configuration files using the OS vault."""

    service = "stoa-desktop"

    def __init__(self, backend: CredentialBackend | None = None) -> None:
        self.backend = backend or keyring

    def get(self, profile: str = "default") -> str | None:
        try:
            return self.backend.get_password(self.service, profile)
        except keyring.errors.KeyringError:
            return None

    def set(self, token: str, profile: str = "default") -> None:
        if not token:
            raise ValueError("token cannot be empty")
        try:
            self.backend.set_password(self.service, profile, token)
        except keyring.errors.KeyringError as error:
            raise RuntimeError("the operating-system credential vault is unavailable") from error

    def clear(self, profile: str = "default") -> None:
        try:
            self.backend.delete_password(self.service, profile)
        except keyring.errors.KeyringError:
            return
