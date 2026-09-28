import sqlite3
from pathlib import Path

import pytest
from scripts.release import backup_sqlite, checksums, restore_sqlite, sbom


def test_backup_restore_checksums_and_sbom(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE evidence (value TEXT)")
        connection.execute("INSERT INTO evidence VALUES ('verified')")
    backup = tmp_path / "backup" / "stoa.db"
    restored = tmp_path / "restored.db"
    backup_sqlite(source, backup)
    restore_sqlite(backup, restored)
    with sqlite3.connect(restored) as connection:
        assert connection.execute("SELECT value FROM evidence").fetchone() == ("verified",)
    sbom_path = sbom(tmp_path / "sbom.spdx.json")
    checksum_path = checksums(tmp_path)
    assert '"spdxVersion": "SPDX-2.3"' in sbom_path.read_text(encoding="utf-8")
    assert "restored.db" in checksum_path.read_text(encoding="utf-8")


def test_restore_rejects_invalid_backup(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.db"
    invalid.write_text("not a database", encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid SQLite"):
        restore_sqlite(invalid, tmp_path / "target.db")
