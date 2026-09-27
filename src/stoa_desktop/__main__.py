"""Desktop application entry point."""

import sys

from PySide6.QtWidgets import QApplication

from stoa_desktop.window import MainWindow


def main() -> None:
    """Launch the Stoá desktop client."""

    app = QApplication(sys.argv)
    app.setApplicationName("Stoá")
    app.setOrganizationName("Flotrpy")
    window = MainWindow()
    window.show()
    raise SystemExit(app.exec())


if __name__ == "__main__":
    main()
