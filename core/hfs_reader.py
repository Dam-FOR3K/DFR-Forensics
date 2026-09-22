"""
DFR-Forensics - Moteur de Lecture Apple HFS+ (Mac OS Étendu)
Permet d'explorer l'arborescence des volumes Apple HFS+ / HFSX,
d'extraire les fichiers et de cartographier l'espace non alloué ($AllocationFile).
"""

import struct
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timezone, timedelta

from core.image_reader import ForensicImageReader

# Différence d'époque Mac HFS (1er janvier 1904) vs Unix (1er janvier 1970)
MAC_EPOCH_DELTA = 2082844800


def hfs_timestamp_to_datetime(ts: int) -> Optional[datetime]:
    """Convertit un timestamp Apple HFS (secondes depuis 1904) en objet datetime."""
    if ts == 0:
        return None
    try:
        unix_ts = ts - MAC_EPOCH_DELTA
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except Exception:
        return None


class HFSFileEntry:
    """Représentation d'un fichier ou dossier HFS+."""

    def __init__(
        self,
        name: str,
        path: str,
        is_dir: bool,
        size: int = 0,
        inode: int = 0,
        mtime: Optional[datetime] = None,
        is_deleted: bool = False,
        data_extents: Optional[List[Tuple[int, int]]] = None,
    ):
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.size = size
        self.inode = inode
        self.mtime = mtime
        self.is_deleted = is_deleted
        self.data_extents: List[Tuple[int, int]] = data_extents or []
        self.children: List["HFSFileEntry"] = []

    def get_formatted_mtime(self) -> str:
        if self.mtime:
            return self.mtime.strftime("%Y-%m-%d %H:%M:%S")
        return ""


class HFSReader:
    """Lecteur forensic autonome pour systèmes de fichiers Apple HFS+ et HFSX."""

    def __init__(
        self,
        reader: ForensicImageReader,
        partition_offset_bytes: int = 0,
        partition_size_bytes: Optional[int] = None,
    ):
        self.reader = reader
        self.offset = partition_offset_bytes
        self.size = partition_size_bytes or (reader.total_size_bytes - partition_offset_bytes)
        self.is_valid_hfs: bool = False
        self.signature: str = ""
        self.block_size: int = 4096
        self.total_blocks: int = 0
        self.free_blocks: int = 0
        self.allocation_file_extents: List[Tuple[int, int]] = []
        self.catalog_file_extents: List[Tuple[int, int]] = []
        self.root_entry: Optional[HFSFileEntry] = None
        self.all_entries: List[HFSFileEntry] = []

        self._parse()

    def _parse(self):
        # Le Volume Header HFS+ se trouve à l'offset 1024 octets (secteur 2)
        if self.size < 4096:
            return

        hdr = self.reader.read_bytes(self.offset + 1024, 512)
        if len(hdr) < 512:
            return

        sig = hdr[:2]
        if sig == b"H+":
            self.signature = "HFS+"
            self.is_valid_hfs = True
        elif sig == b"HX":
            self.signature = "HFSX"
            self.is_valid_hfs = True
        else:
            return

        # Déballage des champs du Volume Header
        # version:2, attributes:4, lastMountedVersion:4, journalInfoBlock:4
        # createDate:4, modifyDate:4, backupDate:4, checkedDate:4
        # fileCount:4, folderCount:4, blockSize:4, totalBlocks:4, freeBlocks:4
        version, attr, lmv, jib, cdate, mdate, bdate, chkdate, fcount, dcount, bsize, tblocks, fblocks = struct.unpack(
            ">HIIIIIIIIIIII", hdr[2:52]
        )

        if bsize > 0 and (bsize & (bsize - 1)) == 0 and bsize <= 65536:
            self.block_size = bsize
        self.total_blocks = tblocks
        self.free_blocks = fblocks
        vol_mtime = hfs_timestamp_to_datetime(mdate)

        # Extraction des descripteurs d'extents (Allocation File & Catalog File)
        # Allocation File Extents démarre à l'offset 112 dans le Volume Header
        # 8 descripteurs d'extents de 8 octets : (start_block:4, block_count:4)
        self.allocation_file_extents = self._parse_extent_record(hdr[112:176])
        # Catalog File Extents démarre à l'offset 240
        self.catalog_file_extents = self._parse_extent_record(hdr[240:304])

        # Création de la racine
        root_name = f"/ [Apple {self.signature} Volume]"
        self.root_entry = HFSFileEntry(
            name=root_name,
            path="/",
            is_dir=True,
            inode=1,
            mtime=vol_mtime,
        )
        self.all_entries.append(self.root_entry)

        # Lecture du catalogue B-Tree pour extraire l'arborescence des fichiers
        self._parse_catalog_tree()

    def _parse_extent_record(self, data: bytes) -> List[Tuple[int, int]]:
        extents = []
        for i in range(0, min(len(data), 64), 8):
            start_block, block_count = struct.unpack(">II", data[i : i + 8])
            if block_count > 0:
                extents.append((start_block, block_count))
        return extents

    def _parse_catalog_tree(self):
        """Parcourt le B-Tree de catalogue pour extraire les répertoires et fichiers."""
        if not self.catalog_file_extents:
            return

        first_extent_start, first_extent_count = self.catalog_file_extents[0]
        cat_offset = self.offset + (first_extent_start * self.block_size)
        cat_len = min(first_extent_count * self.block_size, 4 * 1024 * 1024)

        try:
            cat_data = self.reader.read_bytes(cat_offset, cat_len)
            # Scan des nœuds feuilles (Leaf Nodes) contenant les enregistrements de fichiers et dossiers
            # En HFS+, les enregistrements de dossier ont le type 0x0001 (Folder) et de fichier 0x0002 (File)
            pos = 512  # Ignorer l'en-tête de nœud B-Tree
            while pos < len(cat_data) - 64:
                rec_type = struct.unpack(">H", cat_data[pos : pos + 2])[0]
                if rec_type in (1, 2):  # 1 = kHFSPlusFolderRecord, 2 = kHFSPlusFileRecord
                    is_dir = (rec_type == 1)
                    # Clé de catalogue : keyLength:2, parentID:4, nodeName (length:2, unicode_chars)
                    # Décodage sécurisé des noms Unicode HFS+
                    name_len = struct.unpack(">H", cat_data[pos + 6 : pos + 8])[0]
                    if 0 < name_len < 256 and pos + 8 + (name_len * 2) <= len(cat_data):
                        raw_chars = cat_data[pos + 8 : pos + 8 + (name_len * 2)]
                        try:
                            name = raw_chars.decode("utf-16-be", errors="ignore").rstrip("\x00")
                        except Exception:
                            name = ""

                        if name and name.isprintable():
                            entry = HFSFileEntry(
                                name=name,
                                path=f"/{name}",
                                is_dir=is_dir,
                                size=0,
                                inode=0,
                            )
                            self.root_entry.children.append(entry)
                            self.all_entries.append(entry)
                            pos += 8 + (name_len * 2)
                            continue
                pos += 2
        except Exception:
            pass

    def get_allocation_bitmap(self) -> bytes:
        """Lit l'intégralité du fichier $AllocationFile contenant le bitmap des blocs."""
        chunks = []
        for start_block, block_count in self.allocation_file_extents:
            ext_offset = self.offset + (start_block * self.block_size)
            ext_bytes = block_count * self.block_size
            chunks.append(self.reader.read_bytes(ext_offset, ext_bytes))
        return b"".join(chunks)

    def read_file_data(self, entry: HFSFileEntry) -> bytes:
        """Lit le contenu d'un fichier HFS+ à partir de ses extents de données."""
        if not entry.data_extents:
            return b""
        chunks = []
        bytes_left = entry.size
        for start_block, block_count in entry.data_extents:
            if bytes_left <= 0:
                break
            ext_offset = self.offset + (start_block * self.block_size)
            ext_size = min(bytes_left, block_count * self.block_size)
            chunks.append(self.reader.read_bytes(ext_offset, ext_size))
            bytes_left -= ext_size
        return b"".join(chunks)

    extract_file_content = read_file_data

