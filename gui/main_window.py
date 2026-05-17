"""CyberSentinel Main Application Window.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import os
import queue
import sys
import threading
import time
from typing import Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import customtkinter as ctk

from config import SETTINGS
from core.alerts import AlertManager
from core.audit import AuditTrail
from core.honeypot import HoneypotManager
from core.monitor import FileMonitorEngine
from core.network import NetworkScanner
from core.process_monitor import ProcessMonitor
from core.quarantine import QuarantineManager
from database.db_manager import DatabaseManager
from gui.analytics import AnalyticsWindow
from gui.settings import SettingsPanel
from utils import format_timestamp, format_size, severity_color


class MainWindow:
    """Main application window.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.root = ctk.CTk()
        self.root.geometry("1500x920")
        self.root.minsize(1200, 800)
        self.root.title("CyberSentinel v2.0.0")

        self.message_queue: queue.Queue = queue.Queue()
        self.db_manager = DatabaseManager()
        self.alert_manager = AlertManager()
        self.audit_trail = AuditTrail()
        self.quarantine_manager = QuarantineManager(self.db_manager)
        self.network_scanner = NetworkScanner()
        self.process_monitor = ProcessMonitor()
        self.honeypot_manager = HoneypotManager(self.db_manager)
        self.file_monitor = FileMonitorEngine(
            message_queue=self.message_queue,
            alert_manager=self.alert_manager,
            audit_trail=self.audit_trail,
            quarantine_manager=self.quarantine_manager,
            db_manager=self.db_manager,
        )

        self.monitoring_active = True
        self.stats: Dict[str, int] = {"changes": 0, "threats": 0, "scans": 0}

        self._build_ui()
        self._start_services()
        self._process_queue()

    def _build_ui(self) -> None:
        header = ctk.CTkFrame(self.root, fg_color="#111827")
        header.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(header, text="🛡️ CyberSentinel", text_color="#00D4AA", font=("Segoe UI", 26, "bold")).pack(
            side="left", padx=10, pady=10
        )
        ctk.CTkLabel(header, text="v2.0.0", text_color="#666", font=("Segoe UI", 12)).pack(side="left", padx=5)

        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right", padx=10)
        self.pause_btn = ctk.CTkButton(btn_frame, text="Pause", fg_color="#FF7043", command=self._toggle_monitoring)
        self.pause_btn.pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Refresh", fg_color="#444", command=self._refresh_panels).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Analytics", fg_color="#3B82F6", command=self._open_analytics).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Net Scan", fg_color="#8B5CF6", command=self._start_network_scan).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Settings", fg_color="#444", command=self._open_settings).pack(side="left", padx=5)

        main = ctk.CTkFrame(self.root, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_box = ctk.CTkTextbox(main, width=600, font=("Consolas", 12), fg_color="#0a0e1a")
        self.log_box.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=5)

        self.tabview = ctk.CTkTabview(main)
        self.tabview.pack(side="right", fill="both", expand=True)
        self.stats_tab = self.tabview.add("📊 Stats")
        self.alerts_tab = self.tabview.add("🚨 Alerts")
        self.system_tab = self.tabview.add("💻 System")
        self.network_tab = self.tabview.add("🌐 Network")

        self._build_stats_tab()
        self._build_alerts_tab()
        self._build_system_tab()
        self._build_network_tab()

        self.status_bar = ctk.CTkFrame(self.root, fg_color="#111827")
        self.status_bar.pack(fill="x", padx=10, pady=(5, 10))
        self.status_label = ctk.CTkLabel(self.status_bar, text="Active", text_color="#00E676")
        self.status_label.pack(side="left", padx=10)
        self.count_label = ctk.CTkLabel(self.status_bar, text="Changes: 0 | Threats: 0")
        self.count_label.pack(side="left", padx=10)
        self.time_label = ctk.CTkLabel(self.status_bar, text="")
        self.time_label.pack(side="right", padx=10)

    def _build_stats_tab(self) -> None:
        self.stats_frame = ctk.CTkFrame(self.stats_tab, fg_color="transparent")
        self.stats_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.stats_labels: Dict[str, ctk.CTkLabel] = {}
        for label in ["Files Monitored", "Total Size", "Changes", "Threats", "Scans", "Last Scan", "Path"]:
            row = ctk.CTkFrame(self.stats_frame, fg_color="#111827")
            row.pack(fill="x", pady=5)
            ctk.CTkLabel(row, text=label, text_color="#00D4AA").pack(side="left", padx=10, pady=5)
            value = ctk.CTkLabel(row, text="--", text_color="#fff")
            value.pack(side="right", padx=10)
            self.stats_labels[label] = value

    def _build_alerts_tab(self) -> None:
        self.alerts_container = ctk.CTkScrollableFrame(self.alerts_tab)
        self.alerts_container.pack(fill="both", expand=True, padx=10, pady=10)

    def _build_system_tab(self) -> None:
        self.system_frame = ctk.CTkFrame(self.system_tab, fg_color="transparent")
        self.system_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.system_stats_label = ctk.CTkLabel(self.system_frame, text="System stats will appear here", justify="left")
        self.system_stats_label.pack(anchor="w", pady=5)
        ctk.CTkButton(self.system_frame, text="Scan Processes", fg_color="#00D4AA", text_color="#000",
                      command=self._start_process_scan).pack(pady=10)
        self.process_list = ctk.CTkTextbox(self.system_frame, height=200, font=("Consolas", 11), fg_color="#0a0e1a")
        self.process_list.pack(fill="both", expand=True, pady=10)

    def _build_network_tab(self) -> None:
        self.network_frame = ctk.CTkFrame(self.network_tab, fg_color="transparent")
        self.network_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.network_status = ctk.CTkLabel(self.network_frame, text="Click 'Net Scan' to start")
        self.network_status.pack(anchor="w", pady=5)
        self.network_results = ctk.CTkTextbox(self.network_frame, font=("Consolas", 11), fg_color="#0a0e1a")
        self.network_results.pack(fill="both", expand=True, pady=10)

    def _start_services(self) -> None:
        try:
            self.file_monitor.start()
            self.honeypot_manager.deploy_honeypots(SETTINGS.get("monitor_path"))
            self.honeypot_manager.start_monitoring()
            self.audit_trail.log_event("app", "info", "CyberSentinel started")
        except Exception:
            pass

    def _toggle_monitoring(self) -> None:
        if self.monitoring_active:
            self.file_monitor.pause()
            self.monitoring_active = False
            self.pause_btn.configure(text="Resume", fg_color="#00D4AA")
            self.status_label.configure(text="Paused", text_color="#FF7043")
        else:
            self.file_monitor.resume()
            self.monitoring_active = True
            self.pause_btn.configure(text="Pause", fg_color="#FF7043")
            self.status_label.configure(text="Active", text_color="#00E676")

    def _process_queue(self) -> None:
        try:
            while not self.message_queue.empty():
                message, color = self.message_queue.get_nowait()
                self.log_box.insert("end", message + "\n")
                self.log_box.tag_add(color, "end-2l", "end-1l")
                self.log_box.tag_config(color, foreground=color)
                self.stats["changes"] += 1
        except Exception:
            pass
        self._update_panels()
        self.root.after(200, self._process_queue)

    def _update_panels(self) -> None:
        self.count_label.configure(text=f"Changes: {self.stats['changes']} | Threats: {self.stats['threats']}")
        self.time_label.configure(text=format_timestamp())
        # Update stats tab
        try:
            monitor_path = SETTINGS.get("monitor_path")
            total_files = 0
            total_size = 0
            for root, _, files in os.walk(monitor_path):
                total_files += len(files)
                for f in files:
                    try:
                        total_size += os.path.getsize(os.path.join(root, f))
                    except Exception:
                        continue
            self.stats_labels["Files Monitored"].configure(text=str(total_files))
            self.stats_labels["Total Size"].configure(text=format_size(total_size))
            self.stats_labels["Changes"].configure(text=str(self.stats["changes"]))
            self.stats_labels["Threats"].configure(text=str(self.stats["threats"]))
            self.stats_labels["Scans"].configure(text=str(self.stats["scans"]))
            self.stats_labels["Path"].configure(text=monitor_path)
        except Exception:
            pass

        self._refresh_alerts_panel()
        self._refresh_system_panel()

    def _refresh_alerts_panel(self) -> None:
        for child in self.alerts_container.winfo_children():
            child.destroy()
        alerts = self.alert_manager.get_recent_alerts(50)
        for alert in alerts:
            color = severity_color(str(alert.get("severity", "info")))
            card = ctk.CTkFrame(self.alerts_container, fg_color="#111827", border_width=2, border_color=color)
            card.pack(fill="x", pady=6)
            title = f"{alert.get('title')} ({alert.get('severity')})"
            ctk.CTkLabel(card, text=title, text_color=color, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10)
            ctk.CTkLabel(card, text=alert.get("description", ""), text_color="#fff").pack(anchor="w", padx=10)
            ctk.CTkLabel(card, text=alert.get("timestamp", ""), text_color="#666").pack(anchor="w", padx=10, pady=(0, 5))

    def _refresh_system_panel(self) -> None:
        stats = self.process_monitor.get_system_stats()
        text = (
            f"CPU: {stats.get('cpu_percent')}%\n"
            f"RAM: {stats.get('memory_percent')}%\n"
            f"Disk: {stats.get('disk_percent')}%\n"
            f"Net Sent: {format_size(stats.get('net_bytes_sent', 0))}\n"
            f"Net Recv: {format_size(stats.get('net_bytes_recv', 0))}\n"
        )
        self.system_stats_label.configure(text=text)

    def _start_network_scan(self) -> None:
        def worker():
            self.network_results.delete("1.0", "end")
            self.network_status.configure(text="Scanning...")
            host = "127.0.0.1"
            results = self.network_scanner.scan_common_ports(host)
            for result in results:
                risk = result.get("risk_level", "info")
                icon = "🟢"
                if risk == "critical":
                    icon = "🔴"
                elif risk == "high":
                    icon = "🟠"
                elif risk == "medium":
                    icon = "🟡"
                line = f"{icon} Port {result['port']} ({result['service']}) - {risk}\n"
                self.network_results.insert("end", line)
                self.db_manager.log_network_scan(result["port"], result["protocol"], result["service"], result["status"], risk)
                if risk in {"critical", "high"}:
                    self.alert_manager.add_alert("network", risk, "Suspicious Port", line.strip(), source=host)
                    self.stats["threats"] += 1
            self.stats["scans"] += 1
            self.network_status.configure(text=f"Scan complete - {len(results)} open ports")
        threading.Thread(target=worker, daemon=True).start()

    def _start_process_scan(self) -> None:
        def worker():
            processes = self.process_monitor.get_top_processes(15)
            self.process_list.delete("1.0", "end")
            for proc in processes:
                flag = "🚨" if proc.get("is_suspicious") else ""
                line = f"{flag} {proc.get('name')} (PID {proc.get('pid')}) - {proc.get('memory_mb')} MB\n"
                self.process_list.insert("end", line)
                self.db_manager.log_process(proc.get("pid", 0), proc.get("name", ""), proc.get("status", ""),
                                            proc.get("cpu_percent", 0.0), proc.get("memory_mb", 0.0),
                                            proc.get("is_suspicious", False))
        threading.Thread(target=worker, daemon=True).start()

    def _refresh_panels(self) -> None:
        self._update_panels()

    def _open_analytics(self) -> None:
        AnalyticsWindow(self.root, self.db_manager, self.quarantine_manager, self.alert_manager)

    def _open_settings(self) -> None:
        SettingsPanel(self.root, on_save=self._refresh_panels)

    def run(self) -> None:
        self.root.mainloop()
