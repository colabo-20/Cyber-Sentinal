"""CyberSentinel File Monitoring Engine.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import os
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import SETTINGS
from core.hasher import FileHasher
from core.threat_intel import ThreatIntelEngine
from core.rules_engine import RulesEngine
from utils import format_timestamp, get_file_permissions


class FileMonitorEngine:
    """File monitoring engine with snapshot diffing.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self, message_queue: Optional[queue.Queue] = None, alert_manager=None, audit_trail=None,
                 quarantine_manager=None, db_manager=None) -> None:
        self.settings = SETTINGS
        self.monitor_path = Path(self.settings.get("monitor_path", ""))
        self.scan_interval = max(1, int(self.settings.get("scan_interval", 5)))
        self.enable_hashing = bool(self.settings.get("enable_hashing", True))
        self.hash_algorithm = self.settings.get("hash_algorithm", "sha256")
        self.message_queue = message_queue or queue.Queue()
        self.alert_manager = alert_manager
        self.audit_trail = audit_trail
        self.quarantine_manager = quarantine_manager
        self.db_manager = db_manager
        self.hasher = FileHasher(self.hash_algorithm)
        self.threat_engine = ThreatIntelEngine()
        self.rules_engine = RulesEngine()
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._previous_snapshot: Dict[str, Dict[str, str]] = {}

    def _log_message(self, message: str, color: str = "#00D4AA") -> None:
        try:
            self.message_queue.put((message, color))
        except Exception:
            pass

    def _snapshot_directory(self, directory: Path) -> Dict[str, Dict[str, str]]:
        snapshot: Dict[str, Dict[str, str]] = {}
        try:
            for root, _, files in os.walk(directory):
                for name in files:
                    filepath = os.path.join(root, name)
                    try:
                        stat = os.stat(filepath)
                        file_hash = self.hasher.compute_hash(filepath) if self.enable_hashing else ""
                        snapshot[filepath] = {
                            "size": str(stat.st_size),
                            "mtime": str(stat.st_mtime),
                            "permissions": get_file_permissions(filepath),
                            "hash": file_hash or "",
                        }
                    except Exception:
                        continue
        except Exception:
            pass
        return snapshot

    def _compare_snapshots(self, old: Dict[str, Dict[str, str]], new: Dict[str, Dict[str, str]]):
        changes = {"new": [], "deleted": [], "modified": [], "perm": [], "integrity": []}
        old_keys = set(old.keys())
        new_keys = set(new.keys())
        for added in new_keys - old_keys:
            changes["new"].append(added)
        for removed in old_keys - new_keys:
            changes["deleted"].append(removed)
        for common in old_keys & new_keys:
            old_meta = old[common]
            new_meta = new[common]
            if old_meta.get("permissions") != new_meta.get("permissions"):
                changes["perm"].append(common)
            if old_meta.get("mtime") != new_meta.get("mtime") or old_meta.get("size") != new_meta.get("size"):
                changes["modified"].append(common)
            elif self.enable_hashing and old_meta.get("hash") and new_meta.get("hash") and old_meta.get("hash") != new_meta.get("hash"):
                changes["integrity"].append(common)
        return changes

    def _handle_changes(self, changes):
        timestamp = format_timestamp()
        for change_type in ["new", "deleted", "modified", "perm", "integrity"]:
            for filepath in changes.get(change_type, []):
                message = f"[{timestamp}] {change_type.upper()}: {filepath}"
                color = "#00D4AA"
                if change_type in {"deleted", "integrity"}:
                    color = "#FF1744"
                elif change_type == "modified":
                    color = "#FF9800"
                elif change_type == "perm":
                    color = "#3B82F6"
                self._log_message(message, color)
                if self.db_manager:
                    try:
                        self.db_manager.log_file_change(change_type, filepath, "", 0, "info", message)
                    except Exception:
                        pass
                if self.audit_trail:
                    try:
                        self.audit_trail.log_event("file_change", "info", message, source=filepath)
                    except Exception:
                        pass

        # Threat analysis for new/modified files
        for filepath in set(changes.get("new", [])) | set(changes.get("modified", [])):
            threats = self.threat_engine.analyze_file(filepath)
            for threat in threats:
                if self.alert_manager:
                    try:
                        self.alert_manager.add_alert(
                            "threat",
                            threat.get("severity", "high"),
                            threat.get("type", "Threat Detected"),
                            threat.get("description", ""),
                            source=filepath,
                        )
                    except Exception:
                        pass
                if self.db_manager:
                    try:
                        self.db_manager.log_threat_alert(
                            threat.get("type", "threat"),
                            threat.get("severity", "high"),
                            filepath,
                            threat.get("description", ""),
                            "logged",
                        )
                    except Exception:
                        pass
                if self.quarantine_manager and self.settings.get("enable_quarantine", True):
                    if threat.get("severity") in {"critical", "high"}:
                        try:
                            self.quarantine_manager.quarantine_file(filepath, threat.get("description", "Threat"))
                        except Exception:
                            pass

            # Custom rules
            try:
                rule_hits = self.rules_engine.evaluate_file(filepath)
                for hit in rule_hits:
                    if self.alert_manager:
                        self.alert_manager.add_alert(
                            "rule",
                            hit.get("severity", "medium"),
                            hit.get("name", "Rule Triggered"),
                            hit.get("description", ""),
                            source=filepath,
                        )
            except Exception:
                pass

        # Rapid file creation and mass deletion
        try:
            rapid = self.threat_engine.check_rapid_file_creation(changes)
            if rapid and self.alert_manager:
                self.alert_manager.add_alert("behavior", "critical", "Rapid File Creation", rapid["description"], source=self.monitor_path)
            mass = self.threat_engine.check_mass_deletion(changes)
            if mass and self.alert_manager:
                self.alert_manager.add_alert("behavior", "critical", "Mass Deletion", mass["description"], source=self.monitor_path)
        except Exception:
            pass

    def start(self) -> None:
        """Start monitoring in a daemon thread.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._pause_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop monitoring.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        self._stop_event.set()

    def pause(self) -> None:
        """Pause monitoring.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        self._pause_event.set()

    def resume(self) -> None:
        """Resume monitoring.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        self._pause_event.clear()

    def _run_loop(self) -> None:
        self._previous_snapshot = self._snapshot_directory(self.monitor_path)
        while not self._stop_event.is_set():
            start = time.time()
            if not self._pause_event.is_set():
                current = self._snapshot_directory(self.monitor_path)
                changes = self._compare_snapshots(self._previous_snapshot, current)
                if any(changes.values()):
                    self._handle_changes(changes)
                self._previous_snapshot = current
            elapsed = time.time() - start
            sleep_time = max(1, self.scan_interval - elapsed)
            time.sleep(sleep_time)
