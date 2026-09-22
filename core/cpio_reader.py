"""
DFR-Forensics - Lecteur d'Archives Linux Initramfs / CPIO
Permet d'explorer l'arborescence et d'extraire les fichiers de démarrage Linux embarqué.
"""

import struct
import zlib
import gzip
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timezone

from core.image_reader import ForensicImageReader


class CPIOFileEntry:
    """Représentation d'une entrée de fichier ou dossier CPIO."""

    def __init__(
        self,
        name: str,
        path: str,
        is_dir: bool,
        size: int = 0,
        inode: int = 0,
        mtime: Optional[datetime] = None,
        data_offset: int = 0,
        data_length: int = 0,
        raw_data: Optional[bytes] = None,
    ):
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.size = size
        self.inode = inode
        self.mtime = mtime
        self.data_offset = data_offset
        self.data_length = data_length
        self.raw_data = raw_data
        self.children: List["CPIOFileEntry"] = []

    def get_formatted_mtime(self) -> str:
        if self.mtime:
            return self.mtime.strftime("%Y-%m-%d %H:%M:%S")
        return ""


class CPIOReader:
    """Lecteur forensic autonome pour archives CPIO (Initramfs brut ou compressé gzip)."""

    def __init__(
        self,
        reader: ForensicImageReader,
        partition_offset_bytes: int = 0,
        partition_size_bytes: Optional[int] = None,
    ):
        self.reader = reader
        self.offset = partition_offset_bytes
        self.size = partition_size_bytes or (reader.total_size_bytes - partition_offset_bytes)
        self.is_valid_cpio: bool = False
        self.format_name: str = "CPIO"
        self.root_entry: Optional[CPIOFileEntry] = None
        self.all_entries: List[CPIOFileEntry] = []
        self._archive_bytes: Optional[bytes] = None

        self._parse()

    def _parse(self):
        sample = self.reader.read_bytes(self.offset, 4096)
        if len(sample) < 6:
            return

        # Détection CPIO brut ou GZIP
        if sample[:6] in (b"070701", b"070702"):
            self.is_valid_cpio = True
            self.format_name = "CPIO (SVR4 newc)"
            # Charger les données (limité à 64 Mo en mémoire pour la fluidité)
            max_read = min(self.size, 64 * 1024 * 1024)
            self._archive_bytes = self.reader.read_bytes(self.offset, max_read)
        elif sample[:2] == b"\x1f\x8b":
            # GZIP potentiel contenant du CPIO
            try:
                max_read = min(self.size, 32 * 1024 * 1024)
                compressed = self.reader.read_bytes(self.offset, max_read)
                decompressed = zlib.decompress(compressed, 16 + zlib.MAX_WBITS)
                if decompressed[:6] in (b"070701", b"070702"):
                    self.is_valid_cpio = True
                    self.format_name = "CPIO Initramfs (GZIP)"
                    self._archive_bytes = decompressed
            except Exception:
                pass

        if not self.is_valid_cpio or not self._archive_bytes:
            return

        self.root_entry = CPIOFileEntry(
            name=f"/ [Linux {self.format_name} Archive]",
            path="/",
            is_dir=True,
            inode=1,
        )
        self.all_entries.append(self.root_entry)
        self._extract_cpio_records()

    def _extract_cpio_records(self):
        data = self._archive_bytes
        if not data:
            return

        pos = 0
        dirs_by_path: Dict[str, CPIOFileEntry] = {"": self.root_entry, "/": self.root_entry}

        while pos < len(data) - 110:
            magic = data[pos : pos + 6]
            if magic not in (b"070701", b"070702"):
                break

            try:
                hdr = data[pos : pos + 110]
                ino = int(hdr[6:14], 16)
                mode = int(hdr[14:22], 16)
                mtime_sec = int(hdr[46:54], 16)
                filesize = int(hdr[54:62], 16)
                namesize = int(hdr[94:102], 16)

                pos += 110
                name_bytes = data[pos : pos + namesize - 1]  # Omettre le trailing null
                name = name_bytes.decode("utf-8", errors="ignore").lstrip("./")

                # Alignement à 4 octets après le nom
                pad_name = (4 - ((110 + namesize) % 4)) % 4
                pos += namesize + pad_name

                if name == "TRAILER!!!":
                    break

                is_dir = (mode & 0xF000) == 0x4000
                mtime_obj = datetime.fromtimestamp(mtime_sec, tz=timezone.utc) if mtime_sec > 0 else None

                file_data = None
                if not is_dir and filesize > 0 and pos + filesize <= len(data):
                    file_data = data[pos : pos + filesize]

                # Alignement à 4 octets après les données
                pad_data = (4 - (filesize % 4)) % 4
                pos += filesize + pad_data

                if name:
                    # Décomposition du chemin en dossiers parents
                    parts = name.split("/")
                    filename = parts[-1]
                    parent_path = "/".join(parts[:-1])

                    entry = CPIOFileEntry(
                        name=filename,
                        path=f"/{name}",
                        is_dir=is_dir,
                        size=filesize,
                        inode=ino,
                        mtime=mtime_obj,
                        raw_data=file_data,
                    )

                    parent_entry = dirs_by_path.get(parent_path, self.root_entry)
                    parent_entry.children.append(entry)
                    self.all_entries.append(entry)

                    if is_dir:
                        dirs_by_path[name] = entry

            except Exception:
                break

    def read_file_data(self, entry: CPIOFileEntry) -> bytes:
        return entry.raw_data or b""

    extract_file_content = read_file_data

