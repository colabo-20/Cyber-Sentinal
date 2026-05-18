"""Utility helpers for CyberSentinel.

Author: Saad Zaffar Laghari (FA23-BCS-169)
"""

from __future__ import annotations

import ctypes
import math
import os
import time
from typing import Optional


def format_size(size_bytes: float) -> str:
    """Convert bytes to human-readable units.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    if size_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while size_bytes >= 1024 and idx < len(units) - 1:
        size_bytes /= 1024
        idx += 1
    return f"{size_bytes:.2f} {units[idx]}"


def format_timestamp(ts: Optional[float] = None) -> str:
    """Return timestamp formatted as YYYY-MM-DD HH:MM:SS.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    if ts is None:
        ts = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def get_file_permissions(filepath: str) -> str:
    """Return file permissions in octal string format.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        mode = os.stat(filepath).st_mode
        return oct(mode)[-3:]
    except Exception:
        return "000"


def get_file_owner(filepath: str) -> str:
    """Return file owner in Windows domain\user format if possible.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    if os.name != "nt":
        return "Unknown"
    try:
        advapi32 = ctypes.windll.advapi32
        GetFileSecurityW = advapi32.GetFileSecurityW
        GetSecurityDescriptorOwner = advapi32.GetSecurityDescriptorOwner
        LookupAccountSidW = advapi32.LookupAccountSidW

        OWNER_SECURITY_INFORMATION = 0x00000001
        security_descriptor = ctypes.create_string_buffer(1024)
        length_needed = ctypes.c_ulong(0)

        if not GetFileSecurityW(str(filepath), OWNER_SECURITY_INFORMATION, security_descriptor, 1024, ctypes.byref(length_needed)):
            return "Unknown"

        sid = ctypes.c_void_p()
        defaulted = ctypes.c_int()
        if not GetSecurityDescriptorOwner(security_descriptor, ctypes.byref(sid), ctypes.byref(defaulted)):
            return "Unknown"

        name = ctypes.create_unicode_buffer(256)
        domain = ctypes.create_unicode_buffer(256)
        name_size = ctypes.c_ulong(256)
        domain_size = ctypes.c_ulong(256)
        sid_type = ctypes.c_ulong()

        if not LookupAccountSidW(None, sid, name, ctypes.byref(name_size), domain, ctypes.byref(domain_size), ctypes.byref(sid_type)):
            return "Unknown"

        return f"{domain.value}\\{name.value}"
    except Exception:
        return "Unknown"


def is_hidden_file(filepath: str) -> bool:
    """Determine if a file is hidden (Windows or Unix).

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        if os.name == "nt":
            attributes = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
            return attributes != -1 and bool(attributes & 0x02)
        return os.path.basename(filepath).startswith(".")
    except Exception:
        return False


def is_system_file(filepath: str) -> bool:
    """Determine if a file is marked as system (Windows only).

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    if os.name != "nt":
        return False
    try:
        attributes = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
        return attributes != -1 and bool(attributes & 0x04)
    except Exception:
        return False


def get_file_entropy(filepath: str, block_size: int = 8192) -> float:
    """Compute Shannon entropy for the first block of a file.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        with open(filepath, "rb") as file:
            data = file.read(block_size)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)
    except Exception:
        return 0.0


def get_file_magic_bytes(filepath: str, num_bytes: int = 8) -> str:
    """Return magic bytes of file as hex string.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    try:
        with open(filepath, "rb") as file:
            return file.read(num_bytes).hex()
    except Exception:
        return ""


FILE_SIGNATURES = {
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
    "cefaedfe": "Mach-O 32-bit (BE)",
}


def identify_file_type(filepath: str) -> str:
    """Identify file type using magic bytes.

    Author: Saad Zaffar Laghari (FA23-BCS-169)
    """
    magic = get_file_magic_bytes(filepath, 8)
    for signature, file_type in FILE_SIGNATURES.items():
        if magic.startswith(signature):
            return file_type
    return "Unknown"


def severity_color(severity: str) -> str:
    """Map severity to UI color.

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
