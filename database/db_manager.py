"""CyberSentinel Database Manager.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import os
import sqlite3
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import mysql.connector

from config import SETTINGS, SQLITE_DB
from utils import format_timestamp


class DatabaseManager:
    """Database abstraction for SQLite and MySQL.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self) -> None:
        self.settings = SETTINGS
        self.db_type = self.settings.get("db_type", "sqlite")
        self.conn = None
        self.placeholder = "?"
        if self.db_type == "mysql":
            if not self._connect_mysql():
                self._connect_sqlite()
        else:
            self._connect_sqlite()
        self._init_tables()

    def _connect_mysql(self) -> bool:
        try:
            self.conn = mysql.connector.connect(
                host=self.settings.get("mysql_host"),
                user=self.settings.get("mysql_user"),
                password=self.settings.get("mysql_password"),
                database=self.settings.get("mysql_database"),
            )
            self.placeholder = "%s"
            return True
        except Exception:
            self.conn = None
            return False

    def _connect_sqlite(self) -> None:
        try:
            SQLITE_DB.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(SQLITE_DB, check_same_thread=False)
            self.placeholder = "?"
        except Exception:
            self.conn = None

    def _init_tables(self) -> None:
        if not self.conn:
            return
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS file_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    change_type TEXT,
                    file_path TEXT,
                    file_hash TEXT,
                    file_size INTEGER,
                    severity TEXT,
                    details TEXT,
                    timestamp TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT,
                    severity TEXT,
                    source TEXT,
                    description TEXT,
                    action_taken TEXT,
                    timestamp TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS quarantine_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT,
                    quarantine_path TEXT,
                    reason TEXT,
                    file_hash TEXT,
                    restored INTEGER,
                    timestamp TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS network_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    port INTEGER,
                    protocol TEXT,
                    service TEXT,
                    status TEXT,
                    risk_level TEXT,
                    timestamp TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS process_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER,
                    name TEXT,
                    status TEXT,
                    cpu_percent REAL,
                    memory_mb REAL,
                    is_suspicious INTEGER,
                    timestamp TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS integrity_baseline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE,
                    file_hash TEXT,
                    file_size INTEGER,
                    permissions TEXT,
                    last_verified TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS honeypot_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    honeypot_file TEXT,
                    event_type TEXT,
                    details TEXT,
                    timestamp TEXT
                )
                """
            )
            self.conn.commit()
        except Exception:
            pass

    def _execute(self, query: str, params: tuple = ()) -> None:
        if not self.conn:
            return
        try:
            cur = self.conn.cursor()
            cur.execute(query, params)
            self.conn.commit()
        except Exception:
            pass

    def log_file_change(self, change_type: str, file_path: str, file_hash: str, file_size: int, severity: str, details: str) -> None:
        query = (
            f"INSERT INTO file_changes (change_type, file_path, file_hash, file_size, severity, details, timestamp) "
            f"VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})"
        )
        self._execute(query, (change_type, file_path, file_hash, file_size, severity, details, format_timestamp()))

    def log_threat_alert(self, alert_type: str, severity: str, source: str, description: str, action_taken: str) -> None:
        query = (
            f"INSERT INTO threat_alerts (alert_type, severity, source, description, action_taken, timestamp) "
            f"VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})"
        )
        self._execute(query, (alert_type, severity, source, description, action_taken, format_timestamp()))

    def log_quarantine(self, original_path: str, quarantine_path: str, reason: str, file_hash: str, restored: bool) -> None:
        query = (
            f"INSERT INTO quarantine_log (original_path, quarantine_path, reason, file_hash, restored, timestamp) "
            f"VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})"
        )
        self._execute(query, (original_path, quarantine_path, reason, file_hash, int(restored), format_timestamp()))

    def log_network_scan(self, port: int, protocol: str, service: str, status: str, risk_level: str) -> None:
        query = (
            f"INSERT INTO network_scans (port, protocol, service, status, risk_level, timestamp) "
            f"VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})"
        )
        self._execute(query, (port, protocol, service, status, risk_level, format_timestamp()))

    def log_process(self, pid: int, name: str, status: str, cpu_percent: float, memory_mb: float, is_suspicious: bool) -> None:
        query = (
            f"INSERT INTO process_log (pid, name, status, cpu_percent, memory_mb, is_suspicious, timestamp) "
            f"VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})"
        )
        self._execute(query, (pid, name, status, cpu_percent, memory_mb, int(is_suspicious), format_timestamp()))

    def update_integrity_baseline(self, file_path: str, file_hash: str, file_size: int, permissions: str) -> None:
        if self.placeholder == "%s":
            query = (
                "INSERT INTO integrity_baseline (file_path, file_hash, file_size, permissions, last_verified) "
                "VALUES (%s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE "
                "file_hash=VALUES(file_hash), file_size=VALUES(file_size), permissions=VALUES(permissions), last_verified=VALUES(last_verified)"
            )
        else:
            query = (
                "INSERT OR REPLACE INTO integrity_baseline (file_path, file_hash, file_size, permissions, last_verified) "
                "VALUES (?, ?, ?, ?, ?)"
            )
        self._execute(query, (file_path, file_hash, file_size, permissions, format_timestamp()))

    def get_baseline_hash(self, file_path: str) -> Optional[str]:
        if not self.conn:
            return None
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT file_hash FROM integrity_baseline WHERE file_path = %s" % self.placeholder, (file_path,))
            row = cur.fetchone()
            return row[0] if row else None
        except Exception:
            return None

    def log_honeypot_event(self, honeypot_file: str, event_type: str, details: str) -> None:
        query = (
            f"INSERT INTO honeypot_events (honeypot_file, event_type, details, timestamp) "
            f"VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})"
        )
        self._execute(query, (honeypot_file, event_type, details, format_timestamp()))

    def get_recent_changes(self, limit: int = 100) -> List[Dict[str, object]]:
        if not self.conn:
            return []
        try:
            cur = self.conn.cursor()
            cur.execute(f"SELECT change_type, file_path, severity, timestamp FROM file_changes ORDER BY id DESC LIMIT {limit}")
            return [
                {"change_type": row[0], "file_path": row[1], "severity": row[2], "timestamp": row[3]}
                for row in cur.fetchall()
            ]
        except Exception:
            return []

    def get_recent_threats(self, limit: int = 50) -> List[Dict[str, object]]:
        if not self.conn:
            return []
        try:
            cur = self.conn.cursor()
            cur.execute(f"SELECT alert_type, severity, source, description, timestamp FROM threat_alerts ORDER BY id DESC LIMIT {limit}")
            return [
                {"alert_type": row[0], "severity": row[1], "source": row[2], "description": row[3], "timestamp": row[4]}
                for row in cur.fetchall()
            ]
        except Exception:
            return []

    def get_quarantined_files(self) -> List[Dict[str, object]]:
        if not self.conn:
            return []
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT original_path, quarantine_path, reason, timestamp FROM quarantine_log ORDER BY id DESC")
            return [
                {"original_path": row[0], "quarantine_path": row[1], "reason": row[2], "timestamp": row[3]}
                for row in cur.fetchall()
            ]
        except Exception:
            return []

    def get_change_stats(self) -> Dict[str, int]:
        if not self.conn:
            return {}
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT change_type, COUNT(*) FROM file_changes GROUP BY change_type")
            return {row[0]: row[1] for row in cur.fetchall()}
        except Exception:
            return {}

    def get_threat_stats(self) -> Dict[str, int]:
        if not self.conn:
            return {}
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT severity, COUNT(*) FROM threat_alerts GROUP BY severity")
            return {row[0]: row[1] for row in cur.fetchall()}
        except Exception:
            return {}

    def get_timeline_data(self, hours: int = 24) -> List[Dict[str, object]]:
        if not self.conn:
            return []
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT timestamp FROM file_changes ORDER BY id DESC")
            rows = cur.fetchall()
            timeline: Dict[str, int] = {}
            for (ts,) in rows:
                hour = ts[:13]
                timeline[hour] = timeline.get(hour, 0) + 1
            return [{"hour": k, "count": v} for k, v in sorted(timeline.items())]
        except Exception:
            return []

    def close(self) -> None:
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
