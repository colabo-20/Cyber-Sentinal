"""CyberSentinel v2.0.0 Configuration Module.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

APP_NAME = "CyberSentinel"
APP_VERSION = "2.0.0"
APP_AUTHOR = "Saad Zaffar Laghari (FA23-BCS-169)"
APP_DESCRIPTION = "Advanced File Integrity Monitoring & Threat Detection Platform"

BASE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = BASE_DIR / "data"
QUARANTINE_DIR = DATA_DIR / "quarantine"
AUDIT_DIR = DATA_DIR / "audit_logs"
REPORTS_DIR = DATA_DIR / "reports"
RULES_DIR = DATA_DIR / "rules"
HONEYPOT_DIR = DATA_DIR / "honeypots"
CONFIG_FILE = DATA_DIR / "settings.json"
SQLITE_DB = DATA_DIR / "cybersentinel.db"

for _dir in [DATA_DIR, QUARANTINE_DIR, AUDIT_DIR, REPORTS_DIR, RULES_DIR, HONEYPOT_DIR]:
    try:
        _dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

DEFAULT_SETTINGS: Dict[str, Any] = {
    "monitor_path": str(Path.home() / "Desktop" / "monitor_folder"),
    "scan_interval": 5,
    "enable_hashing": True,
    "hash_algorithm": "sha256",
    "enable_email_alerts": False,
    "email_smtp_server": "smtp.gmail.com",
    "email_smtp_port": 587,
    "email_sender": "",
    "email_password": "",
    "email_recipient": "",
    "enable_quarantine": True,
    "enable_honeypots": True,
    "enable_network_scan": True,
    "enable_process_monitor": True,
    "enable_audit_encryption": True,
    "audit_encryption_key": "",
    "alert_on_new_file": True,
    "alert_on_deleted": True,
    "alert_on_modified": True,
    "alert_on_permission_change": True,
    "alert_on_suspicious_file": True,
    "max_log_entries": 10000,
    "db_type": "sqlite",
    "mysql_host": "localhost",
    "mysql_user": "root",
    "mysql_password": "",
    "mysql_database": "cybersentinel",
    "app_password": "",
    "theme": "dark",
    "color_accent": "#00D4AA",
    "suspicious_extensions": [
        ".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".ps1", ".psm1", ".msi", ".msp", ".dll", ".sys", ".drv", ".cpl",
        ".inf", ".reg", ".rgs", ".hta", ".crt", ".ins", ".isp", ".url", ".ws", ".lnk",
    ],
    "ransomware_extensions": [
        ".encrypted", ".locked", ".crypto", ".crypt", ".locky", ".cerber", ".zepto", ".thor",
        ".aesir", ".zzzzz", ".micro", ".enc", ".crypted", ".r5a", ".XRNT", ".XTBL", ".crinf",
        ".crjoker", ".EnCiPhErEd", ".LeChiffre", ".keybtc@inbox_com", ".0x0", ".bleep", ".1999",
        ".vault", ".HA3", ".toxcrypt", ".magic", ".SUPERCRYPT", ".CTBL", ".CTB2", ".locky", ".petya",
    ],
    "suspicious_process_names": [
        "mimikatz", "lazagne", "procdump", "psexec", "netcat", "ncat", "nc",
        "powershell_empire", "meterpreter", "cobalt", "beacon", "keylogger",
    ],
    "suspicious_ports": [4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 65535, 1337, 3389],
}


def load_settings() -> Dict[str, Any]:
    """Load settings from disk, merging with defaults.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    settings = DEFAULT_SETTINGS.copy()
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                if isinstance(saved, dict):
                    settings.update(saved)
    except Exception:
        return DEFAULT_SETTINGS.copy()
    return settings


def save_settings(settings: Dict[str, Any]) -> None:
    """Persist settings to disk.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception:
        pass


SETTINGS = load_settings()
