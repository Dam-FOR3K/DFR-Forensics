"""
DFR-Forensics - Lecteur de Clichés Instantanés Windows (Volume Shadow Copies - VSS)
Permet de découvrir, lister et explorer les snapshots historiques d'un volume NTFS.
"""

import struct
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timezone, timedelta

from core.image_reader import ForensicImageReader

FILETIME_EPOCH_DELTA = 11644473600  # Secondes entre 1601 et 1970


def filetime_to_datetime(ft: int) -> Optional[datetime]:
    """Convertit un FILETIME Windows (intervalles de 100 ns depuis 1601) en datetime."""
    if ft == 0:
        return None
    try:
        sec = (ft / 10_000_000) - FILETIME_EPOCH_DELTA
        return datetime.fromtimestamp(sec, tz=timezone.utc)
    except Exception:
        return None


class VSSSnapshot:
    """Représente un cliché instantané (Snapshot) VSS découvert sur un volume NTFS."""

    def __init__(
        self,
        snapshot_id: str,
        creation_time: Optional[datetime],
        store_lba: int = 0,
        size_bytes: int = 0,
    ):
        self.snapshot_id = snapshot_id
        self.creation_time = creation_time
        self.store_lba = store_lba
        self.size_bytes = size_bytes

    def get_formatted_date(self) -> str:
        if self.creation_time:
            return self.creation_time.strftime("%Y-%m-%d %H:%M:%S")
        return "Date Inconnue"


class VSSReader:
    """Analyseur de clichés instantanés VSS pour volumes NTFS."""

    def __init__(
        self,
        reader: ForensicImageReader,
        partition_offset_bytes: int = 0,
        partition_size_bytes: Optional[int] = None,
    ):
        self.reader = reader
        self.offset = partition_offset_bytes
        self.size = partition_size_bytes or (reader.total_size_bytes - partition_offset_bytes)
        self.snapshots: List[VSSSnapshot] = []

        self._scan_vss_stores()

    def _scan_vss_stores(self):
        """Scanne les structures de catalogues VSS sur les premiers Mo et les zones de stockage."""
        scan_size = min(self.size, 8 * 1024 * 1024)
        sample = self.reader.read_bytes(self.offset, scan_size)

        # Signature catalogue VSS : GUID VSS ou signature de blocs VSS
        # Magic VSS Store Header : "scek" ou "\x01\x00\x00\x00\x00\x00\x00\x00" avec timestamp FILETIME
        vss_sigs = [b"scek", b"\x56\x53\x53\x31", b"\x7b\x56\x53\x53"]

        pos = 0
        found_times = set()

        # Recherche heuristique de blocs de catalogue VSS
        while pos < len(sample) - 64:
            # Chercher le pattern de bloc de descripteur de cliché
            if sample[pos : pos + 4] == b"scek":
                try:
                    # FILETIME est stocké à l'offset +16 ou +24
                    ft = struct.unpack("<Q", sample[pos + 16 : pos + 24])[0]
                    dt = filetime_to_datetime(ft)
                    if dt and 2015 <= dt.year <= 2030:
                        key = dt.strftime("%Y-%m-%d %H:%M:%S")
                        if key not in found_times:
                            found_times.add(key)
                            snap = VSSSnapshot(
                                snapshot_id=f"Snap-{len(self.snapshots)+1:02d}",
                                creation_time=dt,
                                store_lba=(self.offset + pos) // self.reader.sector_size,
                            )
                            self.snapshots.append(snap)
                except Exception:
                    pass
            pos += 512

        # Tri chronologique des snapshots découverts
        self.snapshots.sort(key=lambda s: s.creation_time or datetime.min, reverse=True)
