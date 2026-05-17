"""CyberSentinel Login Screen.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import customtkinter as ctk

from config import SETTINGS, save_settings


class LoginScreen:
    """Login screen for CyberSentinel.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """

    def __init__(self, on_success_callback) -> None:
        self.on_success_callback = on_success_callback
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.root = ctk.CTk()
        self.root.geometry("500x650")
        self.root.title("CyberSentinel Login")
        self.root.resizable(False, False)

        self._build_ui()

    def _build_ui(self) -> None:
        self.root.configure(fg_color="#0a0e1a")
        ctk.CTkLabel(self.root, text="🛡️", font=("Segoe UI Emoji", 72)).pack(pady=20)
        ctk.CTkLabel(self.root, text="CyberSentinel", text_color="#00D4AA", font=("Segoe UI", 32, "bold")).pack()
        ctk.CTkLabel(self.root, text="Advanced Threat Detection Platform", text_color="#666", font=("Segoe UI", 12)).pack(pady=4)

        self.password_entry = ctk.CTkEntry(self.root, show="●", width=300, height=45, border_color="#00D4AA",
                                           fg_color="#111827")
        self.password_entry.pack(pady=30)

        self.status_label = ctk.CTkLabel(self.root, text="", text_color="#FF4444", font=("Segoe UI", 12))
        self.status_label.pack()

        self.info_label = ctk.CTkLabel(self.root, text="", text_color="#F59E0B", font=("Segoe UI", 11))
        self.info_label.pack(pady=6)

        button_text = "Authenticate"
        if not SETTINGS.get("app_password"):
            self.info_label.configure(text="First run — set a password or leave blank to skip")
            button_text = "Set Password & Enter"

        self.auth_button = ctk.CTkButton(self.root, text=button_text, width=220, height=44, fg_color="#00D4AA",
                                         text_color="#000", command=self._authenticate)
        self.auth_button.pack(pady=20)

        ctk.CTkLabel(self.root, text="v2.0.0", text_color="#666", font=("Segoe UI", 11)).pack(side="bottom", pady=20)

    def _authenticate(self) -> None:
        """Handle authentication flow.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        try:
            input_password = self.password_entry.get().strip()
            stored = SETTINGS.get("app_password", "")
            if not stored:
                if input_password:
                    hashed = hashlib.sha256(input_password.encode("utf-8")).hexdigest()
                    SETTINGS["app_password"] = hashed
                else:
                    SETTINGS["app_password"] = ""
                save_settings(SETTINGS)
                self.root.destroy()
                self.on_success_callback()
                return
            if stored == hashlib.sha256(input_password.encode("utf-8")).hexdigest():
                self.root.destroy()
                self.on_success_callback()
            else:
                self.status_label.configure(text="Incorrect password")
                self.password_entry.delete(0, "end")
        except Exception:
            self.status_label.configure(text="Authentication error")

    def run(self) -> None:
        """Run the login window.

        Author: Saad Zaffar Laghari (FA23-BCS-169)
        """
        self.root.mainloop()
