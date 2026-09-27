"""Intentional light and dark palettes for the desktop shell."""

from enum import StrEnum


class Theme(StrEnum):
    LIGHT = "light"
    DARK = "dark"


_TOKENS: dict[Theme, dict[str, str]] = {
    Theme.LIGHT: {
        "bg": "#f4f6f8",
        "surface": "#ffffff",
        "sidebar": "#111820",
        "sidebar_text": "#d7dee7",
        "text": "#17202a",
        "muted": "#5e6c7b",
        "border": "#dce2e8",
        "accent": "#176b87",
        "accent_soft": "#dceff4",
    },
    Theme.DARK: {
        "bg": "#0d1218",
        "surface": "#151c24",
        "sidebar": "#090d12",
        "sidebar_text": "#d6dde5",
        "text": "#f0f4f8",
        "muted": "#9ba8b5",
        "border": "#29333d",
        "accent": "#4aa8c7",
        "accent_soft": "#173744",
    },
}


def stylesheet(theme: Theme) -> str:
    """Return the global Qt stylesheet for the selected theme."""

    token = _TOKENS[theme]
    return f"""
        QMainWindow, QWidget#page {{ background: {token["bg"]}; color: {token["text"]}; }}
        QWidget#sidebar {{ background: {token["sidebar"]}; color: {token["sidebar_text"]}; }}
        QLabel#brand {{ color: white; font-size: 22px; font-weight: 700; }}
        QLabel#eyebrow {{ color: {token["muted"]}; font-size: 12px; font-weight: 600; }}
        QLabel#heading {{ color: {token["text"]}; font-size: 26px; font-weight: 700; }}
        QLabel#body {{ color: {token["muted"]}; font-size: 14px; }}
        QLabel#error {{ color: #c13d3d; font-size: 13px; }}
        QPushButton#nav {{
            color: {token["sidebar_text"]}; background: transparent; border: 0;
            border-radius: 6px; padding: 10px 12px; text-align: left; font-size: 14px;
        }}
        QPushButton#nav:hover {{ background: rgba(255,255,255,0.07); }}
        QPushButton#nav[active="true"] {{ background: {token["accent"]}; color: white; }}
        QFrame#card {{
            background: {token["surface"]}; border: 1px solid {token["border"]};
            border-radius: 8px;
        }}
        QLabel#metric {{ color: {token["text"]}; font-size: 28px; font-weight: 700; }}
        QComboBox, QLineEdit {{
            color: {token["text"]}; background: {token["surface"]};
            border: 1px solid {token["border"]}; border-radius: 6px; padding: 7px 10px;
        }}
        QPushButton#primary {{
            color: white; background: {token["accent"]}; border: 0;
            border-radius: 6px; padding: 9px 14px; font-weight: 600;
        }}
        QStatusBar {{ background: {token["surface"]}; color: {token["muted"]}; }}
    """
