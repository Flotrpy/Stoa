from unittest.mock import patch

import pytest

from stoa_platform.runtime import SupportedPlatform, current_platform


@pytest.mark.parametrize(
    ("value", "expected"),
    [("win32", SupportedPlatform.WINDOWS), ("linux", SupportedPlatform.LINUX)],
)
def test_supported_platforms(value: str, expected: SupportedPlatform) -> None:
    with patch("stoa_platform.runtime.sys.platform", value):
        assert current_platform() is expected


def test_unsupported_platform_has_actionable_message() -> None:
    with (
        patch("stoa_platform.runtime.sys.platform", "darwin"),
        pytest.raises(RuntimeError, match="supports Windows and Linux"),
    ):
        current_platform()
