import pytest
from pydantic import ValidationError

from stoa_shared.settings import Settings


def test_settings_use_safe_loopback_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("STOA_API_HOST", "STOA_API_PORT", "STOA_ENV"):
        monkeypatch.delenv(name, raising=False)
    settings = Settings(_env_file=None)

    assert settings.api_host == "127.0.0.1"
    assert settings.api_port == 8787
    assert settings.env == "development"


def test_settings_reject_invalid_port() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, api_port=70000)
