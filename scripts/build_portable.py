"""Build the native Stoá desktop executable with PyInstaller."""

from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).resolve().parents[1]

PyInstaller.__main__.run(
    [
        str(ROOT / "src" / "stoa_desktop" / "__main__.py"),
        "--name=Stoa",
        "--windowed",
        "--onefile",
        "--clean",
        "--noconfirm",
        f"--paths={ROOT / 'src'}",
        f"--distpath={ROOT / 'release'}",
        f"--workpath={ROOT / 'build' / 'pyinstaller'}",
        f"--specpath={ROOT / 'build'}",
    ]
)
