"""Validate that expected, non-empty release inputs were produced."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    dist = ROOT / "dist"
    expected = [
        dist / "stoa_platform-0.1.0-py3-none-any.whl",
        dist / "stoa_platform-0.1.0.tar.gz",
    ]
    missing = [path.name for path in expected if not path.is_file() or path.stat().st_size == 0]
    if missing:
        print(f"Packaging validation failed; missing: {', '.join(missing)}")
        return 1
    print("Packaging validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
