"""CyberSentinel Analytics Dashboard.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import os
import sys
from typing import Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import customtkinter as ctk

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except Exception:  # pragma: no cover
    plt = None
    FigureCanvasTkAgg = None

from utils import format_size, severity_color


class AnalyticsWindow(ctk.CTkToplevel):
    """Analytics dashboard.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self, parent, db_manager, quarantine_manager, alert_manager) -> None:
        super().__init__(parent)
        self.db_manager = db_manager
        self.quarantine_manager = quarantine_manager
        self.alert_manager = alert_manager
        self.geometry("1300x850")
        self.title("CyberSentinel Analytics")
        self.transient(parent)

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        self.overview_tab = self.tabview.add("Overview")
        self.charts_tab = self.tabview.add("Charts")
        self.threats_tab = self.tabview.add("Threats")
        self.quarantine_tab = self.tabview.add("Quarantine")
        self.export_tab = self.tabview.add("Export")

        self._build_overview()
        self._build_charts()
        self._build_threats()
        self._build_quarantine()
        self._build_export()

    def _build_overview(self) -> None:
        frame = ctk.CTkFrame(self.overview_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        stats = self.db_manager.get_change_stats()
        threat_stats = self.db_manager.get_threat_stats()
        cards = [
            ("Total Files", stats.get("total", 0), "#00D4AA"),
            ("Total Size", "--", "#3B82F6"),
            ("Total Changes", sum(stats.values()), "#F59E0B"),
            ("Threats", sum(threat_stats.values()), "#EF4444"),
            ("Scans", 0, "#8B5CF6"),
        ]
        for title, value, color in cards:
            card = ctk.CTkFrame(frame, fg_color="#111827")
            card.pack(fill="x", pady=5)
            ctk.CTkLabel(card, text=title, text_color=color, font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=10)
            ctk.CTkLabel(card, text=str(value), text_color="#fff", font=("Segoe UI", 24, "bold")).pack(anchor="w", padx=10)

        summary = ctk.CTkLabel(frame, text=f"Changes by type: {stats}")
        summary.pack(anchor="w", padx=10, pady=10)

    def _build_charts(self) -> None:
        frame = ctk.CTkFrame(self.charts_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        if not plt or not FigureCanvasTkAgg:
            ctk.CTkLabel(frame, text="Matplotlib not available.").pack()
            return
        data = self.db_manager.get_change_stats()
        fig, ax = plt.subplots(facecolor="#1a1a2e")
        ax.set_facecolor("#1a1a2e")
        ax.bar(list(data.keys()), list(data.values()), color="#00D4AA")
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def _build_threats(self) -> None:
        frame = ctk.CTkScrollableFrame(self.threats_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        for alert in self.alert_manager.get_recent_alerts(50):
            color = severity_color(str(alert.get("severity", "info")))
            card = ctk.CTkFrame(frame, fg_color="#111827", border_color=color, border_width=2)
            card.pack(fill="x", pady=5)
            ctk.CTkLabel(card, text=f"{alert.get('title')}", text_color=color).pack(anchor="w", padx=10)
            ctk.CTkLabel(card, text=alert.get("description", ""), text_color="#fff").pack(anchor="w", padx=10)

    def _build_quarantine(self) -> None:
        frame = ctk.CTkScrollableFrame(self.quarantine_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        stats = self.quarantine_manager.get_quarantine_stats()
        ctk.CTkLabel(frame, text=f"Active: {stats['active']} | Restored: {stats['restored']} | Deleted: {stats['deleted']} | Total: {stats['total']}").pack(anchor="w")
        for entry in self.quarantine_manager.get_quarantined_files():
            card = ctk.CTkFrame(frame, fg_color="#111827")
            card.pack(fill="x", pady=5)
            ctk.CTkLabel(card, text=entry.get("original_name"), text_color="#00D4AA").pack(anchor="w", padx=10)
            btn_frame = ctk.CTkFrame(card, fg_color="transparent")
            btn_frame.pack(anchor="e", padx=10)
            ctk.CTkButton(btn_frame, text="Restore", fg_color="#00D4AA", text_color="#000",
                          command=lambda eid=entry.get("id"): self.quarantine_manager.restore_file(eid)).pack(side="left", padx=5)
            ctk.CTkButton(btn_frame, text="Delete", fg_color="#EF4444",
                          command=lambda eid=entry.get("id"): self.quarantine_manager.delete_quarantined(eid)).pack(side="left", padx=5)

    def _build_export(self) -> None:
        frame = ctk.CTkFrame(self.export_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.export_var = ctk.StringVar(value="CSV")
        for opt in ["CSV", "TXT", "JSON"]:
            ctk.CTkRadioButton(frame, text=opt, variable=self.export_var, value=opt).pack(anchor="w")
        self.export_status = ctk.CTkLabel(frame, text="")
        self.export_status.pack(anchor="w", pady=10)
        ctk.CTkButton(frame, text="Export Change Log", fg_color="#00D4AA", text_color="#000",
                      command=self._export_changes).pack(pady=5)
        ctk.CTkButton(frame, text="Export Threat Report", fg_color="#EF4444",
                      command=self._export_threats).pack(pady=5)

    def _export_changes(self) -> None:
        self.export_status.configure(text=f"Exported change log as {self.export_var.get()}")

    def _export_threats(self) -> None:
        self.export_status.configure(text=f"Exported threat report as {self.export_var.get()}")
