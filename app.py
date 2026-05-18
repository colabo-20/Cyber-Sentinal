"""CyberSentinel v2.0.0 entry point.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(os.path.dirname(os.path.abspath(__file__)))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import SETTINGS  # noqa: E402
from gui.login import LoginScreen  # noqa: E402
from gui.main_window import MainWindow  # noqa: E402


def launch_main_app() -> None:
    """Launch the main CyberSentinel application window.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    _ = SETTINGS
    app = MainWindow()
    app.run()


def main() -> None:
    """Run the CyberSentinel application.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    login = LoginScreen(on_success_callback=launch_main_app)
    login.run()


if __name__ == "__main__":
    main()
