"""CyberSentinel Quarantine Manager.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import QUARANTINE_DIR
from core.hasher import FileHasher


class QuarantineManager:
    """Manage quarantined files.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self, db_manager=None) -> None:
        self.quarantine_dir = QUARANTINE_DIR
        self.db_manager = db_manager
        self.manifest_path = self.quarantine_dir / "manifest.json"
        self._manifest = {"quarantined_files": []}
        self._load_manifest()
        self._hasher = FileHasher("sha256")

    def _load_manifest(self) -> None:
        try:
            if self.manifest_path.exists():
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    self._manifest = json.load(f)
        except Exception:
            self._manifest = {"quarantined_files": []}

    def _save_manifest(self) -> None:
        try:
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(self._manifest, f, indent=2)
        except Exception:
            pass

    def _compute_hash(self, filepath: str) -> Optional[str]:
        return self._hasher.compute_hash(filepath)

    def quarantine_file(self, filepath: str, reason: str) -> Tuple[bool, str]:
        """Move file into quarantine vault.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            if not os.path.exists(filepath):
                return False, "File not found"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            original_name = os.path.basename(filepath)
            quarantine_name = f"{timestamp}_{original_name}.quarantined"
            quarantine_path = self.quarantine_dir / quarantine_name
            file_hash = self._compute_hash(filepath) or ""
            file_size = os.path.getsize(filepath)
            shutil.move(filepath, quarantine_path)
            entry = {
                "id": len(self._manifest["quarantined_files"]) + 1,
                "original_path": filepath,
                "quarantine_path": str(quarantine_path),
                "quarantine_name": quarantine_name,
                "original_name": original_name,
                "file_hash": file_hash,
                "file_size": file_size,
                "reason": reason,
                "timestamp": datetime.now().isoformat(),
                "restored": False,
            }
            self._manifest["quarantined_files"].append(entry)
            self._save_manifest()
            if self.db_manager:
                try:
                    self.db_manager.log_quarantine(filepath, str(quarantine_path), reason, file_hash, False)
                except Exception:
                    pass
            return True, "File quarantined"
        except Exception as exc:
            return False, str(exc)

    def restore_file(self, quarantine_id: int) -> Tuple[bool, str]:
        """Restore a quarantined file.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        for entry in self._manifest.get("quarantined_files", []):
            if entry.get("id") == quarantine_id and not entry.get("restored"):
                try:
                    shutil.move(entry["quarantine_path"], entry["original_path"])
                    entry["restored"] = True
                    entry["restored_at"] = datetime.now().isoformat()
                    self._save_manifest()
                    return True, "Restored"
                except Exception as exc:
                    return False, str(exc)
        return False, "Entry not found"

    def delete_quarantined(self, quarantine_id: int) -> Tuple[bool, str]:
        """Delete quarantined file.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        for entry in self._manifest.get("quarantined_files", []):
            if entry.get("id") == quarantine_id and not entry.get("restored"):
                try:
                    os.remove(entry["quarantine_path"])
                    entry["restored"] = True
                    entry["deleted"] = True
                    entry["deleted_at"] = datetime.now().isoformat()
                    self._save_manifest()
                    return True, "Deleted"
                except Exception as exc:
                    return False, str(exc)
        return False, "Entry not found"

    def get_quarantined_files(self) -> List[Dict[str, object]]:
        """Return active quarantined files.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        return [e for e in self._manifest.get("quarantined_files", []) if not e.get("restored")]

    def get_quarantine_stats(self) -> Dict[str, int]:
        """Return quarantine stats.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        total = len(self._manifest.get("quarantined_files", []))
        restored = len([e for e in self._manifest.get("quarantined_files", []) if e.get("restored")])
        deleted = len([e for e in self._manifest.get("quarantined_files", []) if e.get("deleted")])
        active = total - restored
        return {"total": total, "active": active, "restored": restored, "deleted": deleted}
