"""CyberSentinel Threat Intelligence Engine.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import os
import re
import sys
from typing import Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import SETTINGS
from utils import format_timestamp, get_file_entropy, get_file_magic_bytes, identify_file_type, is_hidden_file


class ThreatIntelEngine:
    """Threat intelligence analyzer.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self) -> None:
        self.suspicious_extensions = set(SETTINGS.get("suspicious_extensions", []))
        self.ransomware_extensions = set(SETTINGS.get("ransomware_extensions", []))
        self.entropy_threshold = 7.5
        self.suspicious_patterns = [
            (r"password\s*=", "Hardcoded credential", "high"),
            (r"api[_-]?key\s*=", "API key exposure", "high"),
            (r"\b(eval|exec|system|shell_exec|popen)\b", "Code execution function", "high"),
            (r"base64\.b64decode|frombase64|decode\(" , "Base64 decode", "medium"),
            (r"rm\s+-rf|del\s+/f|format\s+c:", "Destructive command", "critical"),
            (r"(wget|curl|invoke-webrequest)\s+https?://", "Remote download", "medium"),
            (r"/dev/tcp|bash\s+-i|nc\s+-e", "Reverse shell", "critical"),
            (r"powershell\s+-enc|FromBase64String", "Encoded PowerShell", "high"),
            (r"net\s+user|localgroup|runas", "Privilege escalation", "high"),
            (r"keylogger|spyware|stealer", "Spyware indicators", "critical"),
            (r"ransom|bitcoin|monero|wallet", "Ransomware reference", "critical"),
            (r"nmap|masscan|shodan|metasploit", "Hacking tool reference", "medium"),
        ]

    def analyze_file(self, filepath: str) -> List[Dict[str, str]]:
        """Analyze a file for threats.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        threats = []
        try:
            ext = os.path.splitext(filepath)[1].lower()
            if ext in self.suspicious_extensions:
                threats.append(self._threat("Suspicious Extension", "high", filepath, f"Extension {ext}"))
            if ext in self.ransomware_extensions:
                threats.append(self._threat("Ransomware Extension", "critical", filepath, f"Extension {ext}"))
            entropy = get_file_entropy(filepath)
            if entropy > self.entropy_threshold:
                threats.append(self._threat("High Entropy", "high", filepath, f"Entropy {entropy}"))
            signature = identify_file_type(filepath)
            if signature in {"PE/EXE", "ELF"} and ext not in {".exe", ".dll", ".sys", ".so"}:
                threats.append(self._threat("Signature Mismatch", "critical", filepath, f"Detected {signature}"))
            base = os.path.basename(filepath)
            if base.count(".") >= 2:
                threats.append(self._threat("Double Extension", "high", filepath, base))
            if is_hidden_file(filepath) and ext in self.suspicious_extensions:
                threats.append(self._threat("Hidden Executable", "high", filepath, base))
            try:
                size = os.path.getsize(filepath)
                if size > 500 * 1024 * 1024:
                    threats.append(self._threat("Large File", "low", filepath, f"{size} bytes"))
            except Exception:
                pass
            # Content patterns for text files
            if ext in {".txt", ".py", ".js", ".ps1", ".bat", ".vbs", ".cmd", ".json", ".env", ".ini"}:
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(50 * 1024)
                    for pattern, desc, severity in self.suspicious_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            threats.append(self._threat("Suspicious Pattern", severity, filepath, desc))
                except Exception:
                    pass
        except Exception:
            pass
        return threats

    def analyze_directory(self, directory: str) -> List[Dict[str, str]]:
        """Analyze directory recursively.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        findings: List[Dict[str, str]] = []
        try:
            for root, _, files in os.walk(directory):
                for name in files:
                    findings.extend(self.analyze_file(os.path.join(root, name)))
        except Exception:
            pass
        return findings

    def check_rapid_file_creation(self, changes, time_window_seconds: int = 60, threshold: int = 20):
        """Detect rapid file creation.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            if len(changes.get("new", [])) >= threshold:
                return self._threat("Rapid File Creation", "critical", "monitor", f"{len(changes['new'])} files in {time_window_seconds}s")
        except Exception:
            return None
        return None

    def check_mass_deletion(self, changes, threshold: int = 10):
        """Detect mass deletion.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            if len(changes.get("deleted", [])) >= threshold:
                return self._threat("Mass Deletion", "critical", "monitor", f"{len(changes['deleted'])} files deleted")
        except Exception:
            return None
        return None

    def get_threat_summary(self, threats: List[Dict[str, str]]) -> Dict[str, int]:
        """Summarize threats by severity.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        summary: Dict[str, int] = {}
        for threat in threats:
            severity = threat.get("severity", "info")
            summary[severity] = summary.get(severity, 0) + 1
        return summary

    def _threat(self, threat_type: str, severity: str, filepath: str, description: str) -> Dict[str, str]:
        return {
            "type": threat_type,
            "severity": severity,
            "description": description,
            "file": filepath,
            "timestamp": format_timestamp(),
        }
