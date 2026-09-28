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
        "danger": "#b42318",
        "success": "#16803c",
        "hover": "#eef3f6",
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
        "danger": "#ff8a80",
        "success": "#62d48a",
        "hover": "#1c2630",
    },
}


def stylesheet(theme: Theme) -> str:
    """Return the global Qt stylesheet for the selected theme."""

    token = _TOKENS[theme]
    return f"""
        * {{ font-family: "Segoe UI", "Inter", sans-serif; }}
        QMainWindow, QWidget {{ background: {token["bg"]}; color: {token["text"]}; }}
        QWidget#sidebar {{ background: {token["sidebar"]}; color: {token["sidebar_text"]}; }}
        QLabel#brand {{ color: white; font-size: 22px; font-weight: 700; }}
        QLabel#eyebrow {{ color: {token["muted"]}; font-size: 12px; font-weight: 600; }}
        QLabel#heading, QLabel#pageTitle {{
            color: {token["text"]}; font-size: 26px; font-weight: 700;
        }}
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
        QComboBox, QLineEdit, QPlainTextEdit, QSpinBox {{
            color: {token["text"]}; background: {token["surface"]};
            border: 1px solid {token["border"]}; border-radius: 6px; padding: 8px 10px;
        }}
        QComboBox:focus, QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus {{
            border: 2px solid {token["accent"]};
        }}
        QPushButton {{
            color: {token["text"]}; background: {token["surface"]};
            border: 1px solid {token["border"]}; border-radius: 6px;
            padding: 8px 13px; font-weight: 600;
        }}
        QPushButton:hover {{ background: {token["hover"]}; }}
        QPushButton:focus {{ border: 2px solid {token["accent"]}; }}
        QPushButton:disabled {{ color: {token["muted"]}; background: transparent; }}
        QPushButton#primary {{
            color: white; background: {token["accent"]}; border: 0;
            border-radius: 6px; padding: 9px 14px; font-weight: 600;
        }}
        QTabWidget::pane {{
            background: {token["surface"]}; border: 1px solid {token["border"]};
            border-radius: 8px; top: -1px;
        }}
        QTabBar::tab {{
            color: {token["muted"]}; background: transparent; padding: 10px 16px;
            border-bottom: 2px solid transparent;
        }}
        QTabBar::tab:selected {{ color: {token["text"]}; border-bottom-color: {token["accent"]}; }}
        QTableWidget {{
            color: {token["text"]}; background: {token["surface"]};
            alternate-background-color: {token["bg"]}; border: 1px solid {token["border"]};
            border-radius: 8px; gridline-color: {token["border"]};
            selection-background-color: {token["accent_soft"]};
        }}
        QHeaderView::section {{
            color: {token["muted"]}; background: {token["surface"]}; border: 0;
            border-bottom: 1px solid {token["border"]}; padding: 9px; font-weight: 600;
        }}
        QToolTip {{
            color: {token["text"]}; background: {token["surface"]};
            border: 1px solid {token["border"]}; padding: 6px;
        }}
        QStatusBar {{ background: {token["surface"]}; color: {token["muted"]}; }}
    """
