"""Validate that expected, non-empty release inputs were produced."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    dist = ROOT / "dist"
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    distribution = str(project["name"]).replace("-", "_")
    version = str(project["version"])
    patterns = (f"{distribution}-{version}-*.whl", f"{distribution}-{version}.tar.gz")
    missing = [
        pattern
        for pattern in patterns
        if not any(path.stat().st_size > 0 for path in dist.glob(pattern))
    ]
    if missing:
        print(f"Packaging validation failed; missing: {', '.join(missing)}")
        return 1
    print("Packaging validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
