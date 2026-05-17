"""CyberSentinel Process Monitor.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import psutil

from config import SETTINGS


class ProcessMonitor:
    """Monitor system processes.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self) -> None:
        self.suspicious_names = [name.lower() for name in SETTINGS.get("suspicious_process_names", [])]

    def get_running_processes(self) -> List[Dict[str, object]]:
        """Return running processes.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        processes: List[Dict[str, object]] = []
        try:
            for proc in psutil.process_iter(["pid", "name", "status", "cpu_percent", "memory_info", "username", "create_time"]):
                try:
                    info = proc.info
                    memory_mb = round((info.get("memory_info").rss or 0) / (1024 * 1024), 2)
                    process_name = info.get("name") or "unknown"
                    processes.append({
                        "pid": info.get("pid"),
                        "name": process_name,
                        "status": info.get("status"),
                        "cpu_percent": info.get("cpu_percent", 0.0),
                        "memory_mb": memory_mb,
                        "username": info.get("username"),
                        "create_time": info.get("create_time"),
                        "is_suspicious": self._is_suspicious(process_name),
                    })
                except Exception:
                    continue
        except Exception:
            return self._get_processes_fallback()
        return processes

    def _get_processes_fallback(self) -> List[Dict[str, object]]:
        """Fallback to tasklist on Windows.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        processes: List[Dict[str, object]] = []
        try:
            output = subprocess.check_output(["tasklist", "/FO", "CSV", "/NH"], text=True)
            for line in output.splitlines():
                parts = [p.strip('"') for p in line.split(",")]
                if len(parts) >= 2:
                    name = parts[0]
                    pid = int(parts[1]) if parts[1].isdigit() else 0
                    processes.append({"pid": pid, "name": name, "status": "unknown", "cpu_percent": 0.0,
                                     "memory_mb": 0.0, "username": "", "create_time": 0.0,
                                     "is_suspicious": self._is_suspicious(name)})
        except Exception:
            pass
        return processes

    def _is_suspicious(self, process_name: str) -> bool:
        try:
            lname = (process_name or "").lower()
            return any(s in lname for s in self.suspicious_names)
        except Exception:
            return False

    def get_system_stats(self) -> Dict[str, object]:
        """Return system stats.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=0.5)
            cpu_count = psutil.cpu_count()
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net = psutil.net_io_counters()
            return {
                "cpu_percent": cpu_percent,
                "cpu_count": cpu_count,
                "memory_total_gb": round(mem.total / (1024 ** 3), 2),
                "memory_used_gb": round(mem.used / (1024 ** 3), 2),
                "memory_percent": mem.percent,
                "disk_total_gb": round(disk.total / (1024 ** 3), 2),
                "disk_used_gb": round(disk.used / (1024 ** 3), 2),
                "disk_percent": disk.percent,
                "net_bytes_sent": net.bytes_sent,
                "net_bytes_recv": net.bytes_recv,
                "boot_time": psutil.boot_time(),
            }
        except Exception:
            return {
                "cpu_percent": 0,
                "cpu_count": 0,
                "memory_total_gb": 0,
                "memory_used_gb": 0,
                "memory_percent": 0,
                "disk_total_gb": 0,
                "disk_used_gb": 0,
                "disk_percent": 0,
                "net_bytes_sent": 0,
                "net_bytes_recv": 0,
                "boot_time": 0,
            }

    def get_top_processes(self, n: int = 10, sort_by: str = "memory_mb") -> List[Dict[str, object]]:
        """Return top processes.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        processes = self.get_running_processes()
        return sorted(processes, key=lambda p: p.get(sort_by, 0), reverse=True)[:n]

    def get_suspicious_processes(self) -> List[Dict[str, object]]:
        """Return suspicious processes.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        return [p for p in self.get_running_processes() if p.get("is_suspicious")]

    def get_process_count(self) -> int:
        """Return process count.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            return len(list(psutil.process_iter()))
        except Exception:
            return len(self._get_processes_fallback())
