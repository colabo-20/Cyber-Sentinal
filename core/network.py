"""CyberSentinel Network Scanner.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import SETTINGS
from utils import format_timestamp

COMMON_SERVICES = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP", 631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM SSL", 6379: "Redis", 8080: "HTTP Alt", 8443: "HTTPS Alt",
    27017: "MongoDB",
}


class NetworkScanner:
    """Network port scanner.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self) -> None:
        self.suspicious_ports = set(SETTINGS.get("suspicious_ports", []))
        self._scan_results: List[Dict[str, object]] = []

    def scan_port(self, host: str, port: int, timeout: float = 1.0) -> Optional[Dict[str, object]]:
        """Scan single TCP port.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                result = {
                    "port": port,
                    "status": "open",
                    "service": COMMON_SERVICES.get(port, "Unknown"),
                    "protocol": "TCP",
                    "risk_level": self._assess_port_risk(port),
                    "timestamp": format_timestamp(),
                }
                self._scan_results.append(result)
                return result
        except Exception:
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None

    def scan_common_ports(self, host: str = "127.0.0.1", callback=None) -> List[Dict[str, object]]:
        """Scan common and suspicious ports.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        ports = set(COMMON_SERVICES.keys()) | self.suspicious_ports | {4444, 5555, 6666}
        results: List[Dict[str, object]] = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            for port in ports:
                future = executor.submit(self.scan_port, host, port)
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if callback:
                            callback(result)
                except Exception:
                    continue
        return results

    def scan_port_range(self, host: str, start_port: int, end_port: int, callback=None) -> List[Dict[str, object]]:
        """Scan a port range.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        results: List[Dict[str, object]] = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.scan_port, host, port) for port in range(start_port, end_port + 1)]
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if callback:
                            callback(result)
                except Exception:
                    continue
        return results

    def _assess_port_risk(self, port: int) -> str:
        """Assess risk level.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        if port in self.suspicious_ports:
            return "critical"
        if port in {23, 135, 137, 138, 139, 445, 3389, 5900, 5985, 5986}:
            return "high"
        if port in {21, 25, 53, 110, 143, 161, 514, 1080, 8080, 8888, 9090}:
            return "medium"
        if port in {22, 80, 443, 587, 993, 995}:
            return "low"
        return "medium"

    def get_scan_summary(self) -> Dict[str, int]:
        """Get scan summary.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        summary: Dict[str, int] = {}
        for result in self._scan_results:
            level = result.get("risk_level", "info")
            summary[level] = summary.get(level, 0) + 1
        return summary

    @staticmethod
    def get_local_ip() -> str:
        """Get local IP.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def get_hostname() -> str:
        """Get hostname.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            return socket.gethostname()
        except Exception:
            return "localhost"
