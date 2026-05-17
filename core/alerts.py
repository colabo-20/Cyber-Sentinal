"""CyberSentinel Alert and Email System.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import os
import smtplib
import sys
from collections import deque
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Deque, Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import SETTINGS
from utils import format_timestamp


class AlertManager:
    """Manage alerts and email notifications.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self) -> None:
        self.alerts: Deque[Dict[str, object]] = deque(maxlen=1000)
        self.settings = SETTINGS

    def add_alert(self, alert_type: str, severity: str, title: str, description: str, source: str | None = None) -> None:
        """Add an alert and optionally send email.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        alert = {
            "id": len(self.alerts) + 1,
            "type": alert_type,
            "severity": severity,
            "title": title,
            "description": description,
            "source": source,
            "timestamp": format_timestamp(),
            "acknowledged": False,
        }
        self.alerts.append(alert)
        if self.settings.get("enable_email_alerts") and severity in {"critical", "high"}:
            try:
                self._send_email_alert(alert)
            except Exception:
                pass

    def _send_email_alert(self, alert: Dict[str, object]) -> None:
        """Send email alert.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        smtp_server = self.settings.get("email_smtp_server")
        smtp_port = int(self.settings.get("email_smtp_port", 587))
        sender = self.settings.get("email_sender")
        password = self.settings.get("email_password")
        recipient = self.settings.get("email_recipient")
        if not all([smtp_server, sender, password, recipient]):
            return
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 {alert['severity'].upper()} Alert - CyberSentinel"
        msg["From"] = sender
        msg["To"] = recipient
        html = f"""
        <html><body style='background:#1a1a2e;color:#fff;font-family:Segoe UI;'>
        <div style='background:#16213e;padding:20px;border-radius:10px;'>
        <h2 style='color:#00D4AA;'>CyberSentinel Alert</h2>
        <table style='width:100%;color:#fff;'>
          <tr><td><b>Severity</b></td><td>{alert['severity']}</td></tr>
          <tr><td><b>Type</b></td><td>{alert['type']}</td></tr>
          <tr><td><b>Title</b></td><td>{alert['title']}</td></tr>
          <tr><td><b>Description</b></td><td>{alert['description']}</td></tr>
          <tr><td><b>Source</b></td><td>{alert.get('source','')}</td></tr>
          <tr><td><b>Timestamp</b></td><td>{alert['timestamp']}</td></tr>
        </table>
        </div></body></html>
        """
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())

    def acknowledge_alert(self, alert_id: int) -> None:
        for alert in self.alerts:
            if alert.get("id") == alert_id:
                alert["acknowledged"] = True

    def get_unacknowledged(self) -> List[Dict[str, object]]:
        return [a for a in self.alerts if not a.get("acknowledged")]

    def get_alerts_by_severity(self, severity: str) -> List[Dict[str, object]]:
        return [a for a in self.alerts if a.get("severity") == severity]

    def get_recent_alerts(self, count: int = 50) -> List[Dict[str, object]]:
        return list(self.alerts)[-count:]

    def get_alert_counts(self) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for alert in self.alerts:
            sev = alert.get("severity", "info")
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    def clear_all(self) -> None:
        self.alerts.clear()
