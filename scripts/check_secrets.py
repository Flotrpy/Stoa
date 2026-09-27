"""Fail the build when common committed-secret patterns are detected."""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 - fixed git invocation, no user input
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(rb"gh[oprsu]_[A-Za-z0-9_]{30,}"),
    "AWS access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
}
ALLOWED = {Path("scripts/check_secrets.py")}


def tracked_files() -> list[Path]:
    """List version-controlled files using a fixed, non-shell command."""

    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required for the secret scan")
    result = subprocess.run(  # nosec B603  # noqa: S603
        [git, "ls-files", "-co", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [Path(line) for line in result.stdout.splitlines() if line]


def main() -> int:
    findings: list[str] = []
    for relative in tracked_files():
        if relative in ALLOWED:
            continue
        path = ROOT / relative
        if not path.is_file() or path.stat().st_size > 5_000_000:
            continue
        try:
            content = path.read_bytes()
        except OSError as error:
            findings.append(f"{relative}: could not inspect ({error})")
            continue
        for label, pattern in PATTERNS.items():
            if pattern.search(content):
                findings.append(f"{relative}: possible {label}")
    if findings:
        print("Secret scan failed:")
        print("\n".join(f"- {finding}" for finding in findings))
        return 1
    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
