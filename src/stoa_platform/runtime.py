"""Supported-platform detection without requesting elevated privileges."""

import sys
from enum import StrEnum


class SupportedPlatform(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"


def current_platform() -> SupportedPlatform:
    """Return the current supported platform or fail with a useful message."""

    if sys.platform == "win32":
        return SupportedPlatform.WINDOWS
    if sys.platform.startswith("linux"):
        return SupportedPlatform.LINUX
    msg = f"Stoá supports Windows and Linux; detected {sys.platform!r}."
    raise RuntimeError(msg)
