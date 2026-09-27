import pytest

from stoa_desktop.theme import Theme, stylesheet


@pytest.mark.parametrize("theme", list(Theme))
def test_every_theme_has_complete_stylesheet(theme: Theme) -> None:
    result = stylesheet(theme)

    assert "QMainWindow" in result
    assert "QPushButton#nav" in result
    assert "QFrame#card" in result
    assert "font-size: 14px" in result


def test_only_light_and_dark_themes_are_available() -> None:
    assert list(Theme) == [Theme.LIGHT, Theme.DARK]
