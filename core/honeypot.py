"""CyberSentinel Honeypot System.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import HONEYPOT_DIR
from utils import format_timestamp


class HoneypotManager:
    """Manage honeypot decoy files.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    DECOY_TEMPLATES = [
        ("passwords.txt", "admin:Password123\nroot:RootPass!"),
        ("bank_details.csv", "account,amount\n123456,9999"),
        ("private_key.pem", "-----BEGIN RSA PRIVATE KEY-----\n[HONEYPOT]\n-----END RSA PRIVATE KEY-----"),
        ("salary_report_2026.xlsx.txt", "Employee,Salary\nAlice,90000"),
        ("api_keys.env", "AWS_KEY=AKIAFAKEKEY\nAWS_SECRET=FAKESECRET"),
        ("database_backup.sql", "-- Fake DB dump\nCREATE TABLE users(id INT);"),
        ("vpn_config.ovpn", "client\nremote vpn.example.com"),
        ("bitcoin_wallet.dat", "FAKEWALLETDATA"),
    ]

    def __init__(self, db_manager=None) -> None:
        self.db_manager = db_manager
        self.deployments_path = HONEYPOT_DIR / "deployments.json"
        self._deployments: Dict[str, Dict[str, object]] = {}
        self._monitor_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._load_deployments()

    def _load_deployments(self) -> None:
        try:
            if self.deployments_path.exists():
                with open(self.deployments_path, "r", encoding="utf-8") as f:
                    self._deployments = json.load(f)
        except Exception:
            self._deployments = {}

    def _save_deployments(self) -> None:
        try:
            HONEYPOT_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.deployments_path, "w", encoding="utf-8") as f:
                json.dump(self._deployments, f, indent=2)
        except Exception:
            pass

    def deploy_honeypots(self, target_directory: str) -> None:
        """Deploy honeypot files.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            for filename, content in self.DECOY_TEMPLATES:
                path = os.path.join(target_directory, filename)
                if not os.path.exists(path):
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(content)
                stat = os.stat(path)
                self._deployments[path] = {
                    "mtime": stat.st_mtime,
                    "size": stat.st_size,
                    "atime": stat.st_atime,
                }
            self._save_deployments()
        except Exception:
            pass

    def remove_honeypots(self, target_directory: str) -> None:
        """Remove honeypot files from target directory.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            for path in list(self._deployments.keys()):
                if path.startswith(target_directory):
                    try:
                        os.remove(path)
                    except Exception:
                        pass
                    self._deployments.pop(path, None)
            self._save_deployments()
        except Exception:
            pass

    def check_honeypots(self) -> List[Dict[str, object]]:
        """Check honeypot integrity.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        events: List[Dict[str, object]] = []
        for path, meta in list(self._deployments.items()):
            try:
                if not os.path.exists(path):
                    events.append(self._event(path, "deleted", "critical"))
                    self._deployments.pop(path, None)
                    continue
                stat = os.stat(path)
                if stat.st_mtime != meta.get("mtime"):
                    events.append(self._event(path, "modified", "critical"))
                if stat.st_atime != meta.get("atime"):
                    events.append(self._event(path, "accessed", "high"))
            except Exception:
                continue
        if events and self.db_manager:
            for event in events:
                try:
                    self.db_manager.log_honeypot_event(event["honeypot_file"], event["event_type"], event["details"])
                except Exception:
                    pass
        if events:
            self._save_deployments()
        return events

    def _event(self, path: str, event_type: str, severity: str) -> Dict[str, object]:
        return {
            "honeypot_file": path,
            "event_type": event_type,
            "details": f"Honeypot {event_type}",
            "severity": severity,
            "timestamp": format_timestamp(),
        }

    def start_monitoring(self, interval: int = 10) -> None:
        """Start honeypot monitor thread.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,), daemon=True)
        self._monitor_thread.start()

    def _monitor_loop(self, interval: int) -> None:
        while not self._stop_event.is_set():
            try:
                self.check_honeypots()
            except Exception:
                pass
            time.sleep(interval)

    def stop_monitoring(self) -> None:
        """Stop honeypot monitor.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        self._stop_event.set()
