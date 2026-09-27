import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from stoa_desktop.window import MainWindow


def test_desktop_shell_constructs_without_network_or_privileges() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()

    assert window.windowTitle() == "Stoá"
    assert window.minimumWidth() >= 1000
    assert "Local workspace" in window.statusBar().currentMessage()

    window.close()
    app.processEvents()
