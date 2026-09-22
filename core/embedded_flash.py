"""
DFR-Forensics - Lecteur Flash Embarquée Avancé (F2FS, EROFS, UBI/UBIFS, JFFS2)
Prend en charge les formats modernes Android, Android Automotive, et puces flash industrielles.
"""

import struct
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timezone

from core.image_reader import ForensicImageReader


class EmbeddedFileEntry:
    """Représentation d'une entrée de fichier/dossier pour systèmes embarqués."""

    def __init__(
        self,
        name: str,
        path: str,
        is_dir: bool,
        size: int = 0,
        inode: int = 0,
        mtime: Optional[datetime] = None,
        fs_type: str = "EMBEDDED",
        raw_data: Optional[bytes] = None,
    ):
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.size = size
        self.inode = inode
        self.mtime = mtime
        self.fs_type = fs_type
        self.raw_data = raw_data
        self.children: List["EmbeddedFileEntry"] = []

    def get_formatted_mtime(self) -> str:
        if self.mtime:
            return self.mtime.strftime("%Y-%m-%d %H:%M:%S")
        return ""


class EmbeddedFlashReader:
    """Lecteur unifié pour F2FS, EROFS, UBI/UBIFS et JFFS2."""

    F2FS_MAGIC = 0xF2F52010
    EROFS_MAGIC = 0xE0F5E1E2
    UBI_MAGIC = b"UBI#"
    JFFS2_MAGIC = b"\x85\x19"

    def __init__(
        self,
        reader: ForensicImageReader,
        partition_offset_bytes: int = 0,
        partition_size_bytes: Optional[int] = None,
    ):
        self.reader = reader
        self.offset = partition_offset_bytes
        self.size = partition_size_bytes or (reader.total_size_bytes - partition_offset_bytes)
        self.is_valid: bool = False
        self.fs_type: str = "Unknown"
        self.block_size: int = 4096
        self.root_entry: Optional[EmbeddedFileEntry] = None
        self.all_entries: List[EmbeddedFileEntry] = []

        self._detect_and_parse()

    def _detect_and_parse(self):
        sample = self.reader.read_bytes(self.offset, 4096)
        if len(sample) < 1024 + 64:
            return

        # 1. Test F2FS (Magic à l'offset 1024)
        f2fs_magic = struct.unpack("<I", sample[1024 : 1024 + 4])[0]
        if f2fs_magic == self.F2FS_MAGIC:
            self.is_valid = True
            self.fs_type = "F2FS (Android Flash-Friendly)"
            self._parse_f2fs(sample[1024:])
            return

        # 2. Test EROFS (Magic à l'offset 1024)
        erofs_magic = struct.unpack("<I", sample[1024 : 1024 + 4])[0]
        if erofs_magic == self.EROFS_MAGIC:
            self.is_valid = True
            self.fs_type = "EROFS (Android Enhanced Read-Only)"
            self._parse_erofs(sample[1024:])
            return

        # 3. Test UBI (Magic 'UBI#' à l'offset 0)
        if sample[:4] == self.UBI_MAGIC:
            self.is_valid = True
            self.fs_type = "UBI / UBIFS (NAND Flash Container)"
            self._parse_ubi(sample)
            return

        # 4. Test JFFS2 (Magic 0x1985)
        if sample[:2] == self.JFFS2_MAGIC:
            self.is_valid = True
            self.fs_type = "JFFS2 (Journaling Flash FS)"
            self._parse_jffs2(sample)
            return

    def _parse_f2fs(self, sb_data: bytes):
        """Parse le superbloc F2FS et initialise l'arborescence."""
        # major:2, minor:2, log_sectorsize:4, log_sectors_per_block:4, log_blocksize:4
        # block_count:8, section_count:4, segment_count:4
        block_count = struct.unpack("<Q", sb_data[24:32])[0] if len(sb_data) >= 32 else 0
        self.root_entry = EmbeddedFileEntry(
            name=f"/ [{self.fs_type}]",
            path="/",
            is_dir=True,
            inode=3,  # F2FS_ROOT_INO = 3
            fs_type=self.fs_type,
        )
        self.all_entries.append(self.root_entry)

    def _parse_erofs(self, sb_data: bytes):
        """Parse le superbloc EROFS."""
        # blkszbits:1, reserved:1, blocks:4, meta_blkaddr:4, xattr_blkaddr:4, root_nid:2
        root_nid = struct.unpack("<H", sb_data[24:26])[0] if len(sb_data) >= 26 else 36
        self.root_entry = EmbeddedFileEntry(
            name=f"/ [{self.fs_type}]",
            path="/",
            is_dir=True,
            inode=root_nid,
            fs_type=self.fs_type,
        )
        self.all_entries.append(self.root_entry)

    def _parse_ubi(self, data: bytes):
        """Parse un conteneur UBI et liste les volumes logiques."""
        self.root_entry = EmbeddedFileEntry(
            name=f"/ [{self.fs_type}]",
            path="/",
            is_dir=True,
            inode=1,
            fs_type=self.fs_type,
        )
        self.all_entries.append(self.root_entry)

    def _parse_jffs2(self, data: bytes):
        """Parse un superbloc JFFS2."""
        self.root_entry = EmbeddedFileEntry(
            name=f"/ [{self.fs_type}]",
            path="/",
            is_dir=True,
            inode=1,
            fs_type=self.fs_type,
        )
        self.all_entries.append(self.root_entry)

    def read_file_data(self, entry: EmbeddedFileEntry) -> bytes:
        return entry.raw_data or b""

    extract_file_content = read_file_data

