"""Versioned cross-process data contracts."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ServiceStatus(StrEnum):
    """Machine-readable service state."""

    OK = "ok"
    READY = "ready"
    NOT_READY = "not_ready"


class HealthResponse(BaseModel):
    """Liveness response returned by every Stoá service."""

    model_config = ConfigDict(extra="forbid")

    status: ServiceStatus = ServiceStatus.OK
    service: str = "stoa-api"
    version: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReadinessResponse(BaseModel):
    """Readiness response with dependency-safe detail."""

    model_config = ConfigDict(extra="forbid")

    status: ServiceStatus
    checks: dict[str, ServiceStatus]
