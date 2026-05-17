"""CyberSentinel shared utilities.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""
from __future__ import annotations

import ctypes
import math
import os
import platform
import time
from typing import Dict


def format_size(size_bytes: int) -> str:
    """Return a human readable size string.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        if size_bytes < 0:
            return "0 B"
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
    except Exception:
        return "0 B"
    return f"{size_bytes:.2f} TB"


def format_timestamp(ts: float | None = None) -> str:
    """Return formatted timestamp.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        if ts is None:
            ts = time.time()
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return "1970-01-01 00:00:00"


def get_file_permissions(filepath: str) -> str:
    """Return octal permissions for a path.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        mode = os.stat(filepath).st_mode
        return oct(mode)[-3:]
    except Exception:
        return "---"


def get_file_owner(filepath: str) -> str:
    """Return Windows file owner or "Unknown".

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    if platform.system().lower() != "windows":
        return "Unknown"
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        SE_FILE_OBJECT = 1
        OWNER_SECURITY_INFORMATION = 0x00000001
        size = ctypes.c_ulong(0)
        advapi32.GetFileSecurityW(filepath, OWNER_SECURITY_INFORMATION, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetFileSecurityW(filepath, OWNER_SECURITY_INFORMATION, buffer, size, ctypes.byref(size)):
            return "Unknown"
        sid = ctypes.c_void_p()
        defaulted = ctypes.c_int()
        if not advapi32.GetSecurityDescriptorOwner(buffer, ctypes.byref(sid), ctypes.byref(defaulted)):
            return "Unknown"
        name = ctypes.create_unicode_buffer(256)
        domain = ctypes.create_unicode_buffer(256)
        name_len = ctypes.c_ulong(256)
        domain_len = ctypes.c_ulong(256)
        sid_type = ctypes.c_ulong()
        if not advapi32.LookupAccountSidW(None, sid, name, ctypes.byref(name_len), domain, ctypes.byref(domain_len), ctypes.byref(sid_type)):
            return "Unknown"
        return f"{domain.value}\\{name.value}" if domain.value else name.value
    except Exception:
        return "Unknown"


def is_hidden_file(filepath: str) -> bool:
    """Check if file is hidden.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        if platform.system().lower() == "windows":
            attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
            return bool(attrs & 0x02)
        return os.path.basename(filepath).startswith(".")
    except Exception:
        return False


def is_system_file(filepath: str) -> bool:
    """Check if file is system file on Windows.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        if platform.system().lower() == "windows":
            attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
            return bool(attrs & 0x04)
    except Exception:
        return False
    return False


def get_file_entropy(filepath: str, block_size: int = 8192) -> float:
    """Compute Shannon entropy of a file chunk.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read(block_size)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        for c in freq:
            if c:
                p = c / len(data)
                entropy -= p * math.log2(p)
        return round(entropy, 4)
    except Exception:
        return 0.0


def get_file_magic_bytes(filepath: str, num_bytes: int = 8) -> str:
    """Read first N bytes and return hex string.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        with open(filepath, "rb") as f:
            return f.read(num_bytes).hex()
    except Exception:
        return ""


FILE_SIGNATURES: Dict[str, str] = {
    "4d5a": "PE/EXE",
    "7f454c46": "ELF",
    "504b0304": "ZIP",
    "25504446": "PDF",
    "d0cf11e0": "OLE",
    "ffd8ff": "JPEG",
    "89504e47": "PNG",
    "47494638": "GIF",
    "52617221": "RAR",
    "1f8b08": "GZIP",
    "7573746172": "TAR",
    "cafebabe": "Java Class",
    "feedface": "Mach-O 32-bit",
    "feedfacf": "Mach-O 64-bit",
    "cefaedfe": "Mach-O 32-bit (rev)",
}


def identify_file_type(filepath: str) -> str:
    """Identify file type based on magic bytes.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        magic = get_file_magic_bytes(filepath, 8)
        for sig, desc in FILE_SIGNATURES.items():
            if magic.startswith(sig):
                return desc
    except Exception:
        pass
    return "Unknown"


def severity_color(severity: str) -> str:
    """Map severity to color.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    mapping = {
        "critical": "#FF1744",
        "high": "#FF5722",
        "medium": "#FF9800",
        "low": "#FFC107",
        "info": "#00BCD4",
        "safe": "#00E676",
    }
    return mapping.get(severity.lower(), "#00BCD4")
