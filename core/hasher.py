"""CyberSentinel File Integrity Hasher.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import hashlib
import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils import format_timestamp


class FileHasher:
    """File hashing utility with cache.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self, algorithm: str = "sha256") -> None:
        self.algorithm = algorithm
        self.hash_cache: Dict[str, str] = {}

    def compute_hash(self, filepath: str, block_size: int = 65536) -> Optional[str]:
        """Compute hash for file.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            hasher = hashlib.new(self.algorithm)
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(block_size), b""):
                    hasher.update(chunk)
            digest = hasher.hexdigest()
            self.hash_cache[filepath] = digest
            return digest
        except Exception:
            return None

    def verify_integrity(self, filepath: str, expected_hash: str) -> Optional[bool]:
        """Verify hash integrity.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            current = self.compute_hash(filepath)
            if current is None:
                return None
            return current == expected_hash
        except Exception:
            return None

    def compute_directory_hashes(self, directory: str) -> Dict[str, Dict[str, str]]:
        """Compute hashes for directory.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        results: Dict[str, Dict[str, str]] = {}
        try:
            for root, _, files in os.walk(directory):
                for name in files:
                    filepath = os.path.join(root, name)
                    digest = self.compute_hash(filepath)
                    try:
                        stat = os.stat(filepath)
                        results[filepath] = {
                            "hash": digest or "",
                            "size": str(stat.st_size),
                            "timestamp": format_timestamp(stat.st_mtime),
                        }
                    except Exception:
                        continue
        except Exception:
            pass
        return results

    def find_duplicate_files(self, directory: str) -> List[Dict[str, object]]:
        """Find duplicate files by hash.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        seen: Dict[str, List[str]] = {}
        try:
            for root, _, files in os.walk(directory):
                for name in files:
                    filepath = os.path.join(root, name)
                    digest = self.compute_hash(filepath)
                    if digest:
                        seen.setdefault(digest, []).append(filepath)
        except Exception:
            pass
        duplicates = []
        for digest, files in seen.items():
            if len(files) > 1:
                duplicates.append({"hash": digest, "files": files})
        return duplicates

    def get_cached_hash(self, filepath: str) -> Optional[str]:
        """Return cached hash.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        return self.hash_cache.get(filepath)
