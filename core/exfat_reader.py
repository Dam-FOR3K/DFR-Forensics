"""
DFR-Forensics - Moteur Forensique Pur-Python exFAT
Permet le décodage du Main Boot Sector (VBR), Backup VBR (secteur 12),
la FAT, le heap de clusters, les descripteurs de répertoire (0x85, 0xC0, 0xC1),
l'arborescence des fichiers actifs et supprimés (undelete) et l'extraction de données.
"""

import struct
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timezone
from core.image_reader import ForensicImageReader


def exfat_datetime_to_iso(dt_val: int, ten_ms: int = 0) -> str:
    """Convertit un timestamp 32-bit DOS/exFAT en chaîne ISO-8601 UTC."""
    if dt_val <= 0:
        return ""
    try:
        dos_time = dt_val & 0xFFFF
        dos_date = (dt_val >> 16) & 0xFFFF
        year = ((dos_date >> 9) & 0x7F) + 1980
        month = (dos_date >> 5) & 0x0F
        day = dos_date & 0x1F
        hour = (dos_time >> 11) & 0x1F
        minute = (dos_time >> 5) & 0x3F
        second = (dos_time & 0x1F) * 2 + (ten_ms // 100)
        if month < 1 or month > 12 or day < 1 or day > 31:
            return ""
        dt = datetime(year, month, day, min(23, hour), min(59, minute), min(59, second), tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


class ExFATFileEntry:
    """Représente une entrée de fichier ou dossier extrait d'un système exFAT."""

    def __init__(self, name: str = ""):
        self.name: str = name
        self.is_dir: bool = False
        self.is_deleted: bool = False
        self.source: str = "exFAT"
        self.first_cluster: int = 0
        self.size: int = 0
        self.allocated_size: int = 0
        self.is_contiguous: bool = False
        self.attributes: int = 0
        self.created: str = ""
        self.modified: str = ""
        self.accessed: str = ""
        self.parent_entry: Optional["ExFATFileEntry"] = None
        self.children: List["ExFATFileEntry"] = []

    def __repr__(self):
        status = "DELETED" if self.is_deleted else "ACTIVE"
        kind = "DIR" if self.is_dir else "FILE"
        contig = " [CONTIG]" if self.is_contiguous else ""
        return f"<exFAT [{status}] [{kind}]{contig} '{self.name}' ({self.size} bytes)>"


class ExFATReader:
    """Parseur médico-légal pur-Python pour partitions exFAT avec bascule VBR de secours et Undelete."""

    def __init__(self, reader: ForensicImageReader, partition_offset_bytes: int = 0, partition_size_bytes: int = 0):
        self.reader = reader
        self.part_offset = partition_offset_bytes
        self.part_size = partition_size_bytes or (reader.total_size_bytes - partition_offset_bytes)
        self.is_valid_exfat: bool = False
        self.used_backup_vbr: bool = False

        # Géométrie exFAT
        self.bytes_per_sector: int = 512
        self.sectors_per_cluster: int = 8
        self.cluster_size: int = 4096
        self.fat_offset_sector: int = 0
        self.fat_length_sectors: int = 0
        self.cluster_heap_offset_sector: int = 0
        self.cluster_count: int = 0
        self.root_dir_cluster: int = 0
        self.volume_serial: int = 0
        self.volume_label: str = ""
        self.num_fats: int = 1

        # Arborescence
        self.root_entry: Optional[ExFATFileEntry] = None
        self.all_entries: List[ExFATFileEntry] = []
        self._fat_cache: Dict[int, int] = {}

        self._read_vbr()
        if self.is_valid_exfat:
            self._parse_tree()

    def _read_vbr(self):
        # 1. Tentative sur le secteur 0 (VBR principal)
        vbr = self.reader.read_bytes(self.part_offset, 512)
        if len(vbr) >= 512 and vbr[3:11] == b"EXFAT   " and vbr[510:512] == b"\x55\xaa":
            self._parse_vbr_data(vbr)
            return

        # 2. Secours : Secteur 12 (Backup VBR)
        backup_vbr_offset = self.part_offset + 12 * 512
        b_vbr = self.reader.read_bytes(backup_vbr_offset, 512)
        if len(b_vbr) >= 512 and b_vbr[3:11] == b"EXFAT   " and b_vbr[510:512] == b"\x55\xaa":
            self.used_backup_vbr = True
            self._parse_vbr_data(b_vbr)
            return

        self.is_valid_exfat = False

    def _parse_vbr_data(self, vbr: bytes):
        sec_shift = vbr[0x6C]
        clus_shift = vbr[0x6D]
        if sec_shift < 9 or sec_shift > 12 or clus_shift > 25:
            self.is_valid_exfat = False
            return

        self.bytes_per_sector = 1 << sec_shift
        self.sectors_per_cluster = 1 << clus_shift
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        self.fat_offset_sector = struct.unpack_from("<I", vbr, 0x50)[0]
        self.fat_length_sectors = struct.unpack_from("<I", vbr, 0x54)[0]
        self.cluster_heap_offset_sector = struct.unpack_from("<I", vbr, 0x58)[0]
        self.cluster_count = struct.unpack_from("<I", vbr, 0x5C)[0]
        self.root_dir_cluster = struct.unpack_from("<I", vbr, 0x60)[0]
        self.volume_serial = struct.unpack_from("<I", vbr, 0x64)[0]
        self.num_fats = vbr[0x6E]

        if self.root_dir_cluster < 2:
            self.is_valid_exfat = False
            return

        self.is_valid_exfat = True

    def cluster_to_byte_offset(self, cluster_num: int) -> int:
        if cluster_num < 2:
            return self.part_offset
        rel_cluster = cluster_num - 2
        heap_offset = self.part_offset + self.cluster_heap_offset_sector * self.bytes_per_sector
        return heap_offset + rel_cluster * self.cluster_size

    def _get_next_cluster(self, cluster_num: int) -> int:
        if cluster_num in self._fat_cache:
            return self._fat_cache[cluster_num]

        fat_byte_offset = self.part_offset + self.fat_offset_sector * self.bytes_per_sector + cluster_num * 4
        raw = self.reader.read_bytes(fat_byte_offset, 4)
        if len(raw) < 4:
            return 0xFFFFFFFF

        next_clus = struct.unpack("<I", raw)[0]
        self._fat_cache[cluster_num] = next_clus
        return next_clus

    def read_cluster_chain(self, start_cluster: int, is_contiguous: bool, byte_length: int) -> bytes:
        if start_cluster < 2 or byte_length <= 0:
            return b""

        total_clusters_needed = (byte_length + self.cluster_size - 1) // self.cluster_size
        data = bytearray()

        if is_contiguous:
            for i in range(total_clusters_needed):
                cur_clus = start_cluster + i
                off = self.cluster_to_byte_offset(cur_clus)
                chunk = self.reader.read_bytes(off, self.cluster_size)
                data.extend(chunk)
                if len(data) >= byte_length:
                    break
        else:
            cur_clus = start_cluster
            visited = set()
            while cur_clus >= 2 and cur_clus < 0xFFFFFFF7 and len(data) < byte_length:
                if cur_clus in visited:
                    break
                visited.add(cur_clus)

                off = self.cluster_to_byte_offset(cur_clus)
                chunk = self.reader.read_bytes(off, self.cluster_size)
                data.extend(chunk)

                cur_clus = self._get_next_cluster(cur_clus)

        return bytes(data[:byte_length])

    def _parse_directory_entries(self, dir_bytes: bytes) -> List[ExFATFileEntry]:
        entries: List[ExFATFileEntry] = []
        p = 0
        total_len = len(dir_bytes)

        while p + 32 <= total_len:
            entry_chunk = dir_bytes[p : p + 32]
            entry_type = entry_chunk[0]

            if entry_type == 0x00:
                p += 32
                continue

            # 0x83: Volume Label
            if entry_type == 0x83:
                lbl_len = entry_chunk[1]
                if 1 <= lbl_len <= 11:
                    raw_lbl = entry_chunk[2 : 2 + lbl_len * 2]
                    try:
                        self.volume_label = raw_lbl.decode("utf-16le", errors="ignore").strip()
                    except Exception:
                        pass
                p += 32
                continue

            # 0x85 (Fichier/Dossier Actif) ou 0x05 (Supprimé / Effacé)
            if entry_type in (0x85, 0x05):
                is_deleted = (entry_type == 0x05)
                sec_count = entry_chunk[1]
                file_attrs = struct.unpack_from("<H", entry_chunk, 4)[0]
                is_dir = bool(file_attrs & 0x10)

                c_time = struct.unpack_from("<I", entry_chunk, 8)[0]
                m_time = struct.unpack_from("<I", entry_chunk, 12)[0]
                a_time = struct.unpack_from("<I", entry_chunk, 16)[0]
                c_ms = entry_chunk[20]
                m_ms = entry_chunk[21]

                p += 32
                stream_seen = False
                first_clus = 0
                data_len = 0
                is_contig = False
                name_parts: List[str] = []

                for _ in range(sec_count):
                    if p + 32 > total_len:
                        break
                    sec_chunk = dir_bytes[p : p + 32]
                    sec_type = sec_chunk[0]

                    # 0xC0 (Stream actif) ou 0x40 (Stream supprimé)
                    if sec_type in (0xC0, 0x40):
                        stream_seen = True
                        flags = sec_chunk[1]
                        is_contig = bool(flags & 0x02)
                        first_clus = struct.unpack_from("<I", sec_chunk, 0x14)[0]
                        data_len = struct.unpack_from("<Q", sec_chunk, 0x18)[0]

                    # 0xC1 (Nom actif) ou 0x41 (Nom supprimé)
                    elif sec_type in (0xC1, 0x41):
                        name_bytes = sec_chunk[2:32]
                        try:
                            clean_bytes = bytearray()
                            for i in range(0, len(name_bytes), 2):
                                if name_bytes[i : i + 2] == b"\x00\x00":
                                    break
                                clean_bytes.extend(name_bytes[i : i + 2])
                            name_part = clean_bytes.decode("utf-16le", errors="ignore")
                            name_parts.append(name_part)
                        except Exception:
                            pass

                    p += 32

                full_name = "".join(name_parts).strip()
                if not full_name:
                    full_name = f"recovered_{first_clus}"

                fe = ExFATFileEntry(name=full_name)
                fe.is_dir = is_dir
                fe.is_deleted = is_deleted
                fe.attributes = file_attrs
                fe.first_cluster = first_clus
                fe.size = data_len
                fe.is_contiguous = is_contig
                fe.created = exfat_datetime_to_iso(c_time, c_ms)
                fe.modified = exfat_datetime_to_iso(m_time, m_ms)
                fe.accessed = exfat_datetime_to_iso(a_time)

                entries.append(fe)
                continue

            p += 32

        return entries

    def _parse_tree(self):
        self.root_entry = ExFATFileEntry(name="/")
        self.root_entry.is_dir = True
        self.root_entry.first_cluster = self.root_dir_cluster
        self.all_entries.append(self.root_entry)

        visited_clusters = set()
        self._traverse_dir(self.root_entry, self.root_dir_cluster, is_contig=False, visited=visited_clusters)

    def _traverse_dir(self, parent_fe: ExFATFileEntry, cluster_num: int, is_contig: bool, visited: set, max_depth: int = 15):
        if cluster_num < 2 or cluster_num in visited or max_depth <= 0:
            return
        visited.add(cluster_num)

        dir_data = self.read_cluster_chain(cluster_num, is_contiguous=is_contig, byte_length=16 * 1024 * 1024)
        if not dir_data:
            return

        child_entries = self._parse_directory_entries(dir_data)
        for child in child_entries:
            child.parent_entry = parent_fe
            parent_fe.children.append(child)
            self.all_entries.append(child)

            if child.is_dir and child.first_cluster >= 2 and not child.is_deleted:
                self._traverse_dir(child, child.first_cluster, is_contig=child.is_contiguous, visited=visited, max_depth=max_depth - 1)

    def extract_file_content(self, entry: ExFATFileEntry) -> bytes:
        if entry.is_dir or entry.size == 0 or entry.first_cluster < 2:
            return b""
        return self.read_cluster_chain(entry.first_cluster, entry.is_contiguous, entry.size)
