"""CyberSentinel entry point.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from gui.login import LoginScreen
from gui.main_window import MainWindow


def launch_main_app() -> None:
    """Launch the main application window.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    MainWindow().run()


def main() -> None:
    """Show login screen then launch app.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    LoginScreen(launch_main_app).run()


if __name__ == "__main__":
    main()
