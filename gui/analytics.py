"""CyberSentinel Analytics Dashboard.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import csv
import json
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

from config import REPORTS_DIR, SETTINGS
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
        total_files, total_size = self._get_monitor_stats()
        cards = [
            ("Total Files", total_files, "#00D4AA"),
            ("Total Size", format_size(total_size), "#3B82F6"),
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
        change_data = self.db_manager.get_change_stats()
        threat_data = self.db_manager.get_threat_stats()
        timeline = self.db_manager.get_timeline_data()

        fig, axes = plt.subplots(3, 1, figsize=(8, 10), facecolor="#1a1a2e")
        for ax in axes:
            ax.set_facecolor("#1a1a2e")
            ax.tick_params(axis='x', colors='white')
            ax.tick_params(axis='y', colors='white')

        axes[0].bar(list(change_data.keys()), list(change_data.values()), color="#00D4AA")
        axes[0].set_title("Change Frequency", color="white")

        if threat_data:
            axes[1].pie(list(threat_data.values()), labels=list(threat_data.keys()), autopct="%1.1f%%")
        axes[1].set_title("Threat Distribution", color="white")

        if timeline:
            x_vals = list(range(len(timeline)))
            y_vals = [point["count"] for point in timeline]
            axes[2].plot(x_vals, y_vals, color="#8B5CF6")
            axes[2].fill_between(x_vals, y_vals, color="#8B5CF6", alpha=0.2)
            axes[2].set_title("Change Timeline", color="white")

        fig.tight_layout()
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
            ctk.CTkLabel(card, text=f"{alert.get('title')}", text_color=color, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10)
            ctk.CTkLabel(card, text=alert.get("description", ""), text_color="#fff").pack(anchor="w", padx=10)
            ctk.CTkLabel(card, text=alert.get("timestamp", ""), text_color="#666").pack(anchor="w", padx=10, pady=(0, 5))

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
        self._export_report("changes")

    def _export_threats(self) -> None:
        self._export_report("threats")

    def _export_report(self, report_type: str) -> None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        fmt = self.export_var.get().lower()
        filename = REPORTS_DIR / f"{report_type}_report.{fmt}"
        try:
            if report_type == "changes":
                data = self.db_manager.get_recent_changes(500)
            else:
                data = self.db_manager.get_recent_threats(500)

            if fmt == "json":
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            elif fmt == "txt":
                with open(filename, "w", encoding="utf-8") as f:
                    for row in data:
                        f.write(json.dumps(row) + "\n")
            else:
                with open(filename, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=list(data[0].keys()) if data else [])
                    writer.writeheader()
                    writer.writerows(data)
            self.export_status.configure(text=f"Exported {report_type} report to {filename}")
        except Exception:
            self.export_status.configure(text="Export failed")

    @staticmethod
    def _get_monitor_stats() -> tuple[int, int]:
        total_files = 0
        total_size = 0
        try:
            monitor_path = SETTINGS.get("monitor_path")
            for root, _, files in os.walk(monitor_path):
                total_files += len(files)
                for name in files:
                    try:
                        total_size += os.path.getsize(os.path.join(root, name))
                    except Exception:
                        continue
        except Exception:
            pass
        return total_files, total_size
