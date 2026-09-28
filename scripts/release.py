"""Reproducible release checks, SPDX SBOM, checksums, and SQLite backup drills."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def checksums(directory: Path) -> Path:
    artifacts = sorted(
        path for path in directory.iterdir() if path.is_file() and path.name != "SHA256SUMS"
    )
    if not artifacts:
        raise RuntimeError("release directory contains no artifacts")
    output = directory / "SHA256SUMS"
    output.write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in artifacts), encoding="utf-8"
    )
    return output


def sbom(output: Path) -> Path:
    packages = [
        {
            "SPDXID": f"SPDXRef-Package-{index}",
            "name": distribution.metadata["Name"],
            "versionInfo": distribution.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }
        for index, distribution in enumerate(
            sorted(
                importlib.metadata.distributions(),
                key=lambda item: item.metadata["Name"].casefold(),
            ),
            start=1,
        )
    ]
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "stoa-platform-0.1.0",
        "documentNamespace": "https://stoa.invalid/spdx/stoa-platform-0.1.0",
        "creationInfo": {
            "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: stoa-release.py"],
        },
        "packages": packages,
    }
    output.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return output


def backup_sqlite(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as source_db, sqlite3.connect(destination) as destination_db:
        source_db.backup(destination_db)
    if not _sqlite_ok(destination):
        raise RuntimeError("backup integrity check failed")


def restore_sqlite(backup: Path, destination: Path) -> None:
    if not _sqlite_ok(backup):
        raise RuntimeError("refusing to restore an invalid SQLite backup")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".restore")
    shutil.copy2(backup, temporary)
    if not _sqlite_ok(temporary):
        temporary.unlink(missing_ok=True)
        raise RuntimeError("restored database integrity check failed")
    temporary.replace(destination)


def _sqlite_ok(path: Path) -> bool:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        return connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    except sqlite3.Error:
        return False
    finally:
        if connection is not None:
            connection.close()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    checksum_parser = subparsers.add_parser("checksums")
    checksum_parser.add_argument("directory", type=Path)
    sbom_parser = subparsers.add_parser("sbom")
    sbom_parser.add_argument("output", type=Path)
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("source", type=Path)
    backup_parser.add_argument("destination", type=Path)
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("backup", type=Path)
    restore_parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.command == "checksums":
        checksums(args.directory)
    elif args.command == "sbom":
        sbom(args.output)
    elif args.command == "backup":
        backup_sqlite(args.source, args.destination)
    else:
        restore_sqlite(args.backup, args.destination)


if __name__ == "__main__":
    main()
