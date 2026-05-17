"""CyberSentinel Encrypted Audit Trail.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from hashlib import sha256
from typing import Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptography.fernet import Fernet

from config import AUDIT_DIR, SETTINGS
from utils import format_timestamp


class AuditTrail:
    """Encrypted audit trail with chain hashing.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self) -> None:
        self.audit_dir = AUDIT_DIR
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.encryption_enabled = SETTINGS.get("enable_audit_encryption", True)
        self.key_path = self.audit_dir / "audit.key"
        self.fernet = None
        if self.encryption_enabled:
            self._init_encryption()
        date_str = datetime.now().strftime("%Y-%m-%d")
        self.log_file = self.audit_dir / f"audit_{date_str}.log"
        self.enc_file = self.audit_dir / f"audit_{date_str}.enc"

    def _init_encryption(self) -> None:
        """Initialize encryption.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            if self.key_path.exists():
                key = self.key_path.read_bytes()
            else:
                key = Fernet.generate_key()
                self.key_path.write_bytes(key)
            self.fernet = Fernet(key)
        except Exception:
            self.fernet = None

    def log_event(self, event_type: str, severity: str, description: str, source: str | None = None, metadata=None) -> None:
        """Log an audit event.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        entry = {
            "timestamp": format_timestamp(),
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "source": source,
            "metadata": metadata or {},
            "chain_hash": self._compute_chain_hash(),
        }
        self._write_entry(entry)

    def _compute_chain_hash(self) -> str:
        """Compute chain hash from previous entry.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            if not self.log_file.exists():
                return sha256(b"genesis").hexdigest()
            with open(self.log_file, "rb") as f:
                last_line = None
                for line in f:
                    last_line = line
            if not last_line:
                return sha256(b"genesis").hexdigest()
            return sha256(last_line.strip()).hexdigest()
        except Exception:
            return sha256(b"genesis").hexdigest()

    def _write_entry(self, entry: Dict[str, object]) -> None:
        """Write entry to logs.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            line = json.dumps(entry, sort_keys=True).encode("utf-8")
            with open(self.log_file, "ab") as f:
                f.write(line + b"\n")
            if self.encryption_enabled and self.fernet:
                token = self.fernet.encrypt(line)
                with open(self.enc_file, "ab") as f:
                    f.write(token + b"\n")
        except Exception:
            pass

    def verify_integrity(self) -> bool:
        """Verify chain hash integrity.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            previous = sha256(b"genesis").hexdigest()
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    entry = json.loads(line)
                    expected = sha256(line.strip().encode("utf-8")).hexdigest()
                    if entry.get("chain_hash") != previous:
                        return False
                    previous = expected
        except Exception:
            return False
        return True

    def get_recent_events(self, count: int = 50) -> List[Dict[str, object]]:
        """Get recent audit events.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        events: List[Dict[str, object]] = []
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f.readlines()[-count:]:
                    events.append(json.loads(line))
        except Exception:
            pass
        return events

    def export_audit_report(self, filepath: str) -> None:
        """Export audit report.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        report = {
            "generated_at": format_timestamp(),
            "total_entries": 0,
            "integrity_check": self.verify_integrity(),
            "entries": [],
        }
        try:
            if self.log_file.exists():
                with open(self.log_file, "r", encoding="utf-8") as f:
                    report["entries"] = [json.loads(line) for line in f]
                    report["total_entries"] = len(report["entries"])
            with open(filepath, "w", encoding="utf-8") as out:
                json.dump(report, out, indent=2)
        except Exception:
            pass
