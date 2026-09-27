"""Minimal worker contracts established before queue implementation."""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLED = "cancelled"
    FAILED = "failed"
    SUCCEEDED = "succeeded"


@dataclass(frozen=True, slots=True)
class JobReference:
    """Non-sensitive identifier passed between the control plane and workers."""

    job_id: UUID
    correlation_id: UUID
