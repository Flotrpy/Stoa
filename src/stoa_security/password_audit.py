"""Strictly offline, bounded password-auditing demonstrations."""

from __future__ import annotations

import hashlib
import itertools
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

SUPPORTED_FORMATS = {32: "md5-demo", 64: "sha256-demo", 128: "sha512-demo"}


@dataclass(frozen=True, slots=True)
class AuditResult:
    format: str
    matched: bool
    candidate: str | None
    attempts: int
    elapsed_seconds: float
    cancelled: bool
    finding: str
    remediation: str


def detect_hash_format(value: str) -> str:
    normalized = value.strip().casefold()
    if len(normalized) not in SUPPORTED_FORMATS or any(
        char not in "0123456789abcdef" for char in normalized
    ):
        raise ValueError(
            "only hexadecimal MD5, SHA-256, and SHA-512 demonstration hashes are supported"
        )
    return SUPPORTED_FORMATS[len(normalized)]


def rule_candidates(words: Iterable[str]) -> Iterator[str]:
    for word in words:
        clean = word.rstrip("\r\n")
        if not clean or len(clean) > 128:
            continue
        yield clean
        yield clean.capitalize()
        yield f"{clean}1"
        yield f"{clean.capitalize()}1"
        yield f"{clean}!"


def brute_force_candidates(alphabet: str, maximum_length: int) -> Iterator[str]:
    if not alphabet or len(set(alphabet)) != len(alphabet) or len(alphabet) > 64:
        raise ValueError("alphabet must contain 1-64 unique characters")
    if not 1 <= maximum_length <= 6:
        raise ValueError("demonstration length must be between 1 and 6")
    for length in range(1, maximum_length + 1):
        yield from ("".join(candidate) for candidate in itertools.product(alphabet, repeat=length))


def audit_hash(
    digest: str,
    candidates: Iterable[str],
    *,
    max_attempts: int = 100_000,
    max_seconds: float = 10.0,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[[int], None] | None = None,
) -> AuditResult:
    if not 1 <= max_attempts <= 1_000_000 or not 0.1 <= max_seconds <= 60:
        raise ValueError("audit limits exceed the local demonstration boundary")
    format_name = detect_hash_format(digest)
    algorithm = format_name.removesuffix("-demo")
    expected = digest.strip().casefold()
    start = time.monotonic()
    attempts = 0
    match: str | None = None
    was_cancelled = False
    for candidate in candidates:
        if attempts >= max_attempts or time.monotonic() - start >= max_seconds:
            break
        if cancelled and cancelled():
            was_cancelled = True
            break
        attempts += 1
        if hashlib.new(algorithm, candidate.encode()).hexdigest() == expected:
            match = candidate
            break
        if progress and attempts % 1000 == 0:
            progress(attempts)
    elapsed = time.monotonic() - start
    return AuditResult(
        format=format_name,
        matched=match is not None,
        candidate=match,
        attempts=attempts,
        elapsed_seconds=elapsed,
        cancelled=was_cancelled,
        finding=(
            "Candidate recovered in the bounded offline demonstration"
            if match
            else "No candidate recovered within the configured limits"
        ),
        remediation=(
            "Use a unique passphrase and store credentials with Argon2id, scrypt, or bcrypt; "
            "fast legacy digests are not password-storage formats."
        ),
    )
