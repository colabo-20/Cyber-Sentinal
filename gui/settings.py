"""CyberSentinel Settings Panel.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import customtkinter as ctk
from tkinter import filedialog

from config import SETTINGS, save_settings


class SettingsPanel(ctk.CTkToplevel):
    """Settings panel window.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self, parent, on_save=None) -> None:
        super().__init__(parent)
        self.on_save = on_save
        self.geometry("700x600")
        self.title("CyberSentinel Settings")
        self.transient(parent)

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        self.general_tab = self.tabview.add("General")
        self.monitor_tab = self.tabview.add("Monitoring")
        self.alerts_tab = self.tabview.add("Alerts")
        self.db_tab = self.tabview.add("Database")
        self.security_tab = self.tabview.add("Security")

        self._build_general()
        self._build_monitoring()
        self._build_alerts()
        self._build_database()
        self._build_security()

    def _build_general(self) -> None:
        frame = ctk.CTkFrame(self.general_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkLabel(frame, text="Monitor Path").pack(anchor="w")
        self.path_entry = ctk.CTkEntry(frame, width=400)
        self.path_entry.insert(0, SETTINGS.get("monitor_path"))
        self.path_entry.pack(anchor="w")
        ctk.CTkButton(frame, text="Browse", command=self._browse).pack(anchor="w", pady=5)
        ctk.CTkLabel(frame, text="Scan Interval (seconds)").pack(anchor="w", pady=5)
        self.interval_entry = ctk.CTkEntry(frame, width=120)
        self.interval_entry.insert(0, str(SETTINGS.get("scan_interval", 5)))
        self.interval_entry.pack(anchor="w")
        ctk.CTkLabel(frame, text="Theme").pack(anchor="w", pady=5)
        self.theme_var = ctk.StringVar(value=SETTINGS.get("theme", "dark"))
        ctk.CTkSegmentedButton(frame, values=["dark", "light"], variable=self.theme_var).pack(anchor="w")

    def _build_monitoring(self) -> None:
        frame = ctk.CTkFrame(self.monitor_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.hash_var = ctk.BooleanVar(value=SETTINGS.get("enable_hashing", True))
        self.quarantine_var = ctk.BooleanVar(value=SETTINGS.get("enable_quarantine", True))
        self.honeypot_var = ctk.BooleanVar(value=SETTINGS.get("enable_honeypots", True))
        self.network_var = ctk.BooleanVar(value=SETTINGS.get("enable_network_scan", True))
        self.process_var = ctk.BooleanVar(value=SETTINGS.get("enable_process_monitor", True))
        self.audit_var = ctk.BooleanVar(value=SETTINGS.get("enable_audit_encryption", True))
        for label, var in [
            ("SHA-256 Hashing", self.hash_var),
            ("Quarantine System", self.quarantine_var),
            ("Honeypot Files", self.honeypot_var),
            ("Network Scanner", self.network_var),
            ("Process Monitor", self.process_var),
            ("Encrypted Audit Trail", self.audit_var),
        ]:
            ctk.CTkCheckBox(frame, text=label, variable=var).pack(anchor="w")

    def _build_alerts(self) -> None:
        frame = ctk.CTkFrame(self.alerts_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.email_var = ctk.BooleanVar(value=SETTINGS.get("enable_email_alerts", False))
        ctk.CTkCheckBox(frame, text="Enable Email Alerts", variable=self.email_var).pack(anchor="w")
        self.smtp_entry = ctk.CTkEntry(frame, width=300)
        self.smtp_entry.insert(0, SETTINGS.get("email_smtp_server"))
        self.smtp_entry.pack(anchor="w", pady=4)
        self.smtp_port_entry = ctk.CTkEntry(frame, width=120)
        self.smtp_port_entry.insert(0, str(SETTINGS.get("email_smtp_port")))
        self.smtp_port_entry.pack(anchor="w", pady=4)
        self.sender_entry = ctk.CTkEntry(frame, width=300)
        self.sender_entry.insert(0, SETTINGS.get("email_sender"))
        self.sender_entry.pack(anchor="w", pady=4)
        self.password_entry = ctk.CTkEntry(frame, width=300, show="●")
        self.password_entry.insert(0, SETTINGS.get("email_password"))
        self.password_entry.pack(anchor="w", pady=4)
        self.recipient_entry = ctk.CTkEntry(frame, width=300)
        self.recipient_entry.insert(0, SETTINGS.get("email_recipient"))
        self.recipient_entry.pack(anchor="w", pady=4)

    def _build_database(self) -> None:
        frame = ctk.CTkFrame(self.db_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.db_type_var = ctk.StringVar(value=SETTINGS.get("db_type", "sqlite"))
        ctk.CTkSegmentedButton(frame, values=["sqlite", "mysql"], variable=self.db_type_var).pack(anchor="w")
        self.mysql_host = ctk.CTkEntry(frame, width=300)
        self.mysql_host.insert(0, SETTINGS.get("mysql_host"))
        self.mysql_host.pack(anchor="w", pady=4)
        self.mysql_user = ctk.CTkEntry(frame, width=300)
        self.mysql_user.insert(0, SETTINGS.get("mysql_user"))
        self.mysql_user.pack(anchor="w", pady=4)
        self.mysql_pass = ctk.CTkEntry(frame, width=300, show="●")
        self.mysql_pass.insert(0, SETTINGS.get("mysql_password"))
        self.mysql_pass.pack(anchor="w", pady=4)
        self.mysql_db = ctk.CTkEntry(frame, width=300)
        self.mysql_db.insert(0, SETTINGS.get("mysql_database"))
        self.mysql_db.pack(anchor="w", pady=4)

    def _build_security(self) -> None:
        frame = ctk.CTkFrame(self.security_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkLabel(frame, text="New Password").pack(anchor="w")
        self.new_pass = ctk.CTkEntry(frame, width=300, show="●")
        self.new_pass.pack(anchor="w", pady=4)
        ctk.CTkLabel(frame, text="Confirm Password").pack(anchor="w")
        self.confirm_pass = ctk.CTkEntry(frame, width=300, show="●")
        self.confirm_pass.pack(anchor="w", pady=4)
        self.pass_status = ctk.CTkLabel(frame, text="")
        self.pass_status.pack(anchor="w", pady=6)
        ctk.CTkButton(frame, text="Save", fg_color="#00D4AA", text_color="#000", command=self._save).pack(pady=10)

    def _browse(self) -> None:
        folder = filedialog.askdirectory()
        if folder:
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, folder)

    def _save(self) -> None:
        """Save settings and close.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        SETTINGS["monitor_path"] = self.path_entry.get()
        SETTINGS["scan_interval"] = int(self.interval_entry.get() or 5)
        SETTINGS["theme"] = self.theme_var.get()
        SETTINGS["enable_hashing"] = self.hash_var.get()
        SETTINGS["enable_quarantine"] = self.quarantine_var.get()
        SETTINGS["enable_honeypots"] = self.honeypot_var.get()
        SETTINGS["enable_network_scan"] = self.network_var.get()
        SETTINGS["enable_process_monitor"] = self.process_var.get()
        SETTINGS["enable_audit_encryption"] = self.audit_var.get()

        SETTINGS["enable_email_alerts"] = self.email_var.get()
        SETTINGS["email_smtp_server"] = self.smtp_entry.get()
        SETTINGS["email_smtp_port"] = int(self.smtp_port_entry.get() or 587)
        SETTINGS["email_sender"] = self.sender_entry.get()
        SETTINGS["email_password"] = self.password_entry.get()
        SETTINGS["email_recipient"] = self.recipient_entry.get()

        SETTINGS["db_type"] = self.db_type_var.get()
        SETTINGS["mysql_host"] = self.mysql_host.get()
        SETTINGS["mysql_user"] = self.mysql_user.get()
        SETTINGS["mysql_password"] = self.mysql_pass.get()
        SETTINGS["mysql_database"] = self.mysql_db.get()

        if self.new_pass.get() or self.confirm_pass.get():
            if self.new_pass.get() == self.confirm_pass.get():
                hashed = hashlib.sha256(self.new_pass.get().encode("utf-8")).hexdigest() if self.new_pass.get() else ""
                SETTINGS["app_password"] = hashed
                self.pass_status.configure(text="Password updated", text_color="#00E676")
            else:
                self.pass_status.configure(text="Passwords do not match", text_color="#EF4444")
                return

        save_settings(SETTINGS)
        if self.on_save:
            self.on_save()
        self.destroy()
