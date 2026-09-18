"""
CorruptDisk-Analyzer - Gestionnaire de Disques Physiques
Énumération des périphériques de stockage (SATA, NVMe, USB, SCSI),
vérification des privilèges Administrateur (UAC) et utilitaires d'accès bas niveau.
"""

import sys
import os
import re
import json
import subprocess
import ctypes
from typing import List, Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class PhysicalDriveInfo:
    """Métadonnées d'un disque physique connecté."""
    index: int
    device_id: str             # ex: r'\\.\PHYSICALDRIVE0' ou '/dev/sdb'
    model: str                 # ex: 'Samsung SSD 850 PRO 1TB'
    size_bytes: int            # Capacité totale en octets
    interface_type: str        # 'NVMe', 'SATA', 'USB', 'SCSI', 'IDE'
    media_type: str            # 'Fixed hard disk media', 'External/Removable'
    sector_size: int = 512     # Taille de secteur logique (512 ou 4096)

    @property
    def display_name(self) -> str:
        """Nom formaté pour l'affichage utilisateur."""
        size_gb = self.size_bytes / (1024 ** 3)
        if size_gb >= 1000:
            size_str = f"{size_gb / 1024:.2f} To"
        else:
            size_str = f"{size_gb:.1f} Go"
        return f"Disque {self.index} : {self.model} ({size_str}) [{self.interface_type}]"


def is_admin() -> bool:
    """Vérifie si le processus s'exécute avec les privilèges Administrateur / root."""
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0
        except Exception:
            return False


def relaunch_as_admin(target_device: Optional[str] = None):
    """
    Relance l'application avec élévation UAC sous Windows.
    Préserve les arguments et peut cibler un disque physique précis.
    """
    if sys.platform == "win32":
        if getattr(sys, "frozen", False):
            executable = sys.executable
            params = []
        else:
            executable = sys.executable
            script_path = os.path.abspath(sys.argv[0])
            params = [f'"{script_path}"']

        if target_device:
            params.append(f'"{target_device}"')

        param_str = " ".join(params)

        hinstance = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            param_str if param_str else None,
            None,
            1  # SW_SHOWNORMAL
        )
        if hinstance > 32:
            sys.exit(0)
        else:
            raise PermissionError(f"Élévation UAC refusée par l'utilisateur (Code {hinstance}).")
    else:
        raise OSError("L'élévation UAC automatique est spécifique à Windows.")


def find_windows_drive_letter_for_partition(disk_path: str, start_lba: int, sector_size: int = 512) -> Optional[str]:
    """
    Cherche si une partition d'un disque physique Windows (ex: '\\\\.\\PhysicalDrive1')
    est actuellement montée sous une lettre de lecteur Windows (ex: 'D:').
    """
    if sys.platform != "win32" or not disk_path:
        return None

    try:
        m = re.search(r"PHYSICALDRIVE(\d+)", disk_path, re.IGNORECASE)
        if not m:
            return None
        disk_num = int(m.group(1))

        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0

        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            f"Get-Partition -DiskNumber {disk_num} | Select-Object DriveLetter, Offset | ConvertTo-Json"
        ]

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            startupinfo=startupinfo,
            timeout=5
        )

        output = res.stdout.strip()
        if not output:
            return None

        data = json.loads(output)
        if isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = data
        else:
            items = []

        target_offset = start_lba * sector_size
        for item in items:
            letter = item.get("DriveLetter")
            offset = item.get("Offset")
            if letter and offset is not None:
                # Tolérance d'offset (alignement de partition)
                if abs(int(offset) - target_offset) < (4096 * 16):
                    return f"{str(letter).strip()}:"
    except Exception:
        pass

    return None


def enumerate_physical_drives() -> List[PhysicalDriveInfo]:
    """
    Détecte et énumère tous les disques physiques connectés au système hôte.
    Fonctionne sous Windows (via PowerShell / WMI CimInstance) et Linux (via sysfs).
    Ne nécessite pas obligatoirement les droits administrateur pour l'énumération.
    """
    drives: List[PhysicalDriveInfo] = []

    if sys.platform == "win32":
        drives = _enumerate_windows_drives()
    elif sys.platform.startswith("linux"):
        drives = _enumerate_linux_drives()

    drives.sort(key=lambda d: d.index)
    return drives


def _enumerate_windows_drives() -> List[PhysicalDriveInfo]:
    """Énumération des disques sous Windows via PowerShell Get-CimInstance Win32_DiskDrive."""
    drives: List[PhysicalDriveInfo] = []
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "Get-CimInstance Win32_DiskDrive | Select-Object DeviceID, Index, Model, Size, InterfaceType, MediaType, BytesPerSector | ConvertTo-Json"
    ]

    try:
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            startupinfo=startupinfo,
            timeout=10
        )

        output = res.stdout.strip()
        if not output:
            return drives

        data = json.loads(output)
        if isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = data
        else:
            items = []

        for item in items:
            device_id = str(item.get("DeviceID", "")).strip()
            if not device_id:
                continue

            index_val = item.get("Index")
            if index_val is None:
                m = re.search(r"PHYSICALDRIVE(\d+)", device_id, re.IGNORECASE)
                index_val = int(m.group(1)) if m else 0
            else:
                index_val = int(index_val)

            model = str(item.get("Model") or f"Disque physique {index_val}").strip()
            size = int(item.get("Size") or 0)
            iface = str(item.get("InterfaceType") or "Inconnu").strip()
            media = str(item.get("MediaType") or "Disque fixe").strip()
            bps = int(item.get("BytesPerSector") or 512)

            drives.append(
                PhysicalDriveInfo(
                    index=index_val,
                    device_id=device_id,
                    model=model,
                    size_bytes=size,
                    interface_type=iface,
                    media_type=media,
                    sector_size=bps if bps in (512, 1024, 2048, 4096) else 512
                )
            )
    except Exception:
        pass

    return drives


def _enumerate_linux_drives() -> List[PhysicalDriveInfo]:
    """Énumération des disques sous Linux via /sys/block."""
    drives: List[PhysicalDriveInfo] = []
    sys_block = "/sys/block"
    if not os.path.exists(sys_block):
        return drives

    index = 0
    for name in os.listdir(sys_block):
        if name.startswith(("loop", "ram", "dm-", "sr")):
            continue

        dev_path = f"/dev/{name}"
        sys_dev = os.path.join(sys_block, name)

        size_file = os.path.join(sys_dev, "size")
        size_bytes = 0
        if os.path.exists(size_file):
            try:
                with open(size_file, "r") as f:
                    size_bytes = int(f.read().strip()) * 512
            except Exception:
                pass

        if size_bytes <= 0:
            continue

        model_file = os.path.join(sys_dev, "device", "model")
        model = f"Linux Block Device ({name})"
        if os.path.exists(model_file):
            try:
                with open(model_file, "r") as f:
                    model = f.read().strip()
            except Exception:
                pass

        drives.append(
            PhysicalDriveInfo(
                index=index,
                device_id=dev_path,
                model=model,
                size_bytes=size_bytes,
                interface_type="Block",
                media_type="Fixed/Removable",
                sector_size=512
            )
        )
        index += 1

    return drives
