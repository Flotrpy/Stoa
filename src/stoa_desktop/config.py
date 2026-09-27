"""Non-secret desktop configuration with atomic persistence."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from uuid import UUID

from platformdirs import user_config_path


@dataclass(frozen=True, slots=True)
class DesktopSettings:
    api_url: str = "http://127.0.0.1:8787"
    theme: str = "light"
    endpoint_id: UUID | None = None
    team_id: UUID | None = None

    def __post_init__(self) -> None:
        if self.theme not in {"light", "dark"}:
            raise ValueError("theme must be light or dark")
        if not self.api_url.startswith(("http://", "https://")):
            raise ValueError("api_url must use HTTP or HTTPS")


class ConfigStore:
    """Persist non-secret settings without mixing them with credentials."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or user_config_path("Stoa", "Flotrpy") / "settings.json"

    def load(self) -> DesktopSettings:
        if not self.path.exists():
            return DesktopSettings()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return DesktopSettings(
            api_url=str(data.get("api_url", DesktopSettings().api_url)),
            theme=str(data.get("theme", "light")),
            endpoint_id=_uuid_or_none(data.get("endpoint_id")),
            team_id=_uuid_or_none(data.get("team_id")),
        )

    def save(self, settings: DesktopSettings) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = asdict(settings)
        payload["endpoint_id"] = str(settings.endpoint_id) if settings.endpoint_id else None
        payload["team_id"] = str(settings.team_id) if settings.team_id else None
        with NamedTemporaryFile(
            "w", encoding="utf-8", dir=self.path.parent, delete=False, newline="\n"
        ) as temporary:
            json.dump(payload, temporary, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary_path = Path(temporary.name)
        temporary_path.replace(self.path)


def _uuid_or_none(value: object) -> UUID | None:
    return UUID(str(value)) if value else None
