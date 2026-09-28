"""Local endpoint integrity and input-monitoring risk indicators.

The process inspection functions never capture keyboard input. They score supplied
process metadata and keep evidence deliberately small and non-sensitive.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

ChangeKind = Literal["created", "changed", "deleted", "renamed", "permission-error"]


@dataclass(frozen=True, slots=True)
class FileRecord:
    path: str
    size: int
    modified_ns: int
    sha256: str | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class IntegrityEvent:
    kind: ChangeKind
    path: str
    previous_path: str | None = None
    previous_sha256: str | None = None
    sha256: str | None = None
    chain_hash: str = ""


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    pid: int
    name: str
    executable: str
    command_line: str = ""
    loaded_modules: tuple[str, ...] = ()
    signed: bool | None = None


@dataclass(frozen=True, slots=True)
class KeyloggerIndicator:
    rule_id: str
    title: str
    severity: Literal["low", "medium", "high"]
    confidence: float
    process_id: int
    process_name: str
    explanation: str
    evidence: tuple[str, ...]


def build_baseline(
    root: Path,
    *,
    recursive: bool = True,
    include: tuple[str, ...] = ("*",),
    exclude: tuple[str, ...] = (),
    maximum_file_bytes: int = 100_000_000,
) -> dict[str, FileRecord]:
    """Create a SHA-256 manifest without following directory symlinks."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("monitoring root must be a directory")
    records: dict[str, FileRecord] = {}
    iterator = root.rglob("*") if recursive else root.glob("*")
    for path in sorted(iterator):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.is_file() or not _selected(relative, include, exclude):
            continue
        try:
            stat = path.stat()
            digest = _hash_file(path) if stat.st_size <= maximum_file_bytes else None
            records[relative] = FileRecord(relative, stat.st_size, stat.st_mtime_ns, digest)
        except PermissionError:
            records[relative] = FileRecord(relative, 0, 0, None, "permission denied")
    return records


def compare_baselines(
    previous: dict[str, FileRecord], current: dict[str, FileRecord], *, seed: str = ""
) -> tuple[IntegrityEvent, ...]:
    """Return deterministic changes, pairing equal hashes as rename events."""
    created = set(current) - set(previous)
    deleted = set(previous) - set(current)
    pairs: dict[str, str] = {}
    for old in sorted(deleted):
        old_hash = previous[old].sha256
        if old_hash is None:
            continue
        match = next((new for new in sorted(created) if current[new].sha256 == old_hash), None)
        if match:
            pairs[old] = match
            created.remove(match)
    raw: list[tuple[ChangeKind, str, str | None, str | None, str | None]] = []
    for old, new in pairs.items():
        deleted.remove(old)
        raw.append(("renamed", new, old, previous[old].sha256, current[new].sha256))
    for path in sorted(deleted):
        raw.append(("deleted", path, None, previous[path].sha256, None))
    for path in sorted(created):
        raw.append(("created", path, None, None, current[path].sha256))
    for path in sorted(set(previous) & set(current)):
        before, after = previous[path], current[path]
        if after.error:
            raw.append(("permission-error", path, None, before.sha256, None))
        elif (before.sha256, before.size) != (after.sha256, after.size):
            raw.append(("changed", path, None, before.sha256, after.sha256))
    events: list[IntegrityEvent] = []
    chain = seed
    for kind, path, old_path, old_hash, new_hash in raw:
        material = json.dumps(
            [chain, kind, path, old_path, old_hash, new_hash], separators=(",", ":")
        )
        chain = hashlib.sha256(material.encode()).hexdigest()
        events.append(IntegrityEvent(kind, path, old_path, old_hash, new_hash, chain))
    return tuple(events)


def verify_event_chain(events: Iterable[IntegrityEvent], *, seed: str = "") -> bool:
    chain = seed
    for event in events:
        material = json.dumps(
            [
                chain,
                event.kind,
                event.path,
                event.previous_path,
                event.previous_sha256,
                event.sha256,
            ],
            separators=(",", ":"),
        )
        chain = hashlib.sha256(material.encode()).hexdigest()
        if chain != event.chain_hash:
            return False
    return True


def baseline_to_json(records: dict[str, FileRecord]) -> str:
    return json.dumps({key: asdict(value) for key, value in sorted(records.items())}, indent=2)


def detect_keylogger_indicators(
    processes: Iterable[ProcessSnapshot], *, platform: Literal["windows", "linux"]
) -> tuple[KeyloggerIndicator, ...]:
    """Score metadata indicators; this is triage, never proof of a keylogger."""
    results: list[KeyloggerIndicator] = []
    capture_terms = (
        ("setwindowshookex", "getasynckeystate")
        if platform == "windows"
        else (
            "/dev/input/event",
            "xrecord",
            "xinput test",
        )
    )
    persistence_terms = (
        ("\\run\\", "\\startup\\", "appdata")
        if platform == "windows"
        else ("/tmp/", "/dev/shm/", ".config/autostart")  # noqa: S108 - risk indicators
    )
    for process in processes:
        searchable = " ".join(
            (process.name, process.executable, process.command_line, *process.loaded_modules)
        ).casefold()
        evidence: list[str] = []
        if any(term in searchable for term in capture_terms):
            evidence.append("input-capture API or device reference")
        if any(term in searchable for term in persistence_terms):
            evidence.append("execution from a user-writable or persistence location")
        if process.signed is False and platform == "windows":
            evidence.append("unsigned executable")
        if len(evidence) < 2:
            continue
        confidence = round(min(0.95, 0.45 + 0.2 * len(evidence)), 2)
        severity: Literal["medium", "high"] = "high" if confidence >= 0.85 else "medium"
        results.append(
            KeyloggerIndicator(
                rule_id=f"STOA-END-{platform.upper()}-001",
                title="Process exhibits input-monitoring risk indicators",
                severity=severity,
                confidence=confidence,
                process_id=process.pid,
                process_name=process.name[:160],
                explanation=(
                    "Multiple metadata indicators warrant investigation; this does not establish "
                    "that keystrokes were captured."
                ),
                evidence=tuple(evidence),
            )
        )
    return tuple(results)


def _selected(path: str, include: tuple[str, ...], exclude: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in include) and not any(
        fnmatch.fnmatch(path, pattern) for pattern in exclude
    )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
