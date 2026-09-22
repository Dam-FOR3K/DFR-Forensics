"""
DFR-Forensics - Moteur Forensique Pur-Python FAT12 / FAT16 / FAT32
Supporte le décodage des BPB, la détection des discordances d'étiquettes,
l'extraction des fichiers cachés sous attribut 0x08, le décodage LFN et l'undelete FAT.
"""

import struct
from typing import List, Optional, Tuple, Dict
from datetime import datetime, timezone
from core.image_reader import ForensicImageReader


def dos_datetime_to_iso(dos_date: int, dos_time: int) -> str:
    """Convertit une date et heure DOS en chaîne ISO-8601 UTC."""
    try:
        year = ((dos_date >> 9) & 0x7F) + 1980
        month = (dos_date >> 5) & 0x0F
        day = dos_date & 0x1F
        hour = (dos_time >> 11) & 0x1F
        minute = (dos_time >> 5) & 0x3F
        second = (dos_time & 0x1F) * 2
        if month < 1 or month > 12 or day < 1 or day > 31:
            return ""
        dt = datetime(year, month, day, min(23, hour), min(59, minute), min(59, second), tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


class FATFileEntry:
    """Représente un fichier ou répertoire extrait d'un système FAT."""

    def __init__(self):
        self.name: str = ""
        self.is_dir: bool = False
        self.is_deleted: bool = False
        self.is_volume_label: bool = False
        self.is_hidden_volume_file: bool = False
        self.source: str = "FAT"
        self.first_cluster: int = 0
        self.size: int = 0
        self.created: str = ""
        self.modified: str = ""
        self.accessed: str = ""
        self.parent_entry: Optional["FATFileEntry"] = None
        self.children: List["FATFileEntry"] = []

    def __repr__(self):
        status = "DELETED" if self.is_deleted else "ACTIVE"
        kind = "DIR" if self.is_dir else "FILE"
        extra = " [HIDDEN_VOL_FILE]" if self.is_hidden_volume_file else ""
        return f"<FAT [{status}] [{kind}]{extra} '{self.name}' ({self.size} bytes)>"


class FATReader:
    """Parseur médico-légal pour volumes FAT12, FAT16 et FAT32."""

    def __init__(self, reader: ForensicImageReader, partition_offset_bytes: int = 0):
        self.reader = reader
        self.part_offset = partition_offset_bytes
        self.is_valid_fat = False
        self.used_backup_boot_sector: bool = False
        self.fat_type: str = ""  # FAT12, FAT16, FAT32

        # BPB Geometry
        self.bytes_per_sector: int = 512
        self.sectors_per_cluster: int = 1
        self.cluster_size: int = 512
        self.reserved_sectors: int = 0
        self.num_fats: int = 2
        self.root_entries_count: int = 0
        self.fat_size_sectors: int = 0
        self.root_cluster: int = 2
        self.data_start_offset: int = 0

        # Labels & Anomalies
        self.bpb_label: str = ""
        self.root_label: str = ""
        self.label_discrepancy: bool = False
        self.anomalies: List[str] = []

        # Arborescence
        self.root_entry: Optional[FATFileEntry] = None
        self.all_entries: List[FATFileEntry] = []
        self._fat_table: List[int] = []

        self._read_bpb()
        if self.is_valid_fat:
            self._load_fat_table()
            self._parse_tree()

    def _read_bpb(self):
        start_lba = self.part_offset // self.reader.sector_size
        s0 = self.reader.read_sector(start_lba, count=1)
        if len(s0) < 512 or s0[510:512] != b"\x55\xaa":
            self._reconstruct_orphaned_bpb()
            return

        if s0[3:11] in (b"NTFS    ", b"EXFAT   "):
            self.is_valid_fat = False
            return

        self.bytes_per_sector = struct.unpack_from("<H", s0, 0x0B)[0]
        if self.bytes_per_sector not in (512, 1024, 2048, 4096):
            self._reconstruct_orphaned_bpb()
            return

        self.sectors_per_cluster = s0[0x0D]
        if self.sectors_per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128):
            self._reconstruct_orphaned_bpb()
            return

        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.reserved_sectors = struct.unpack_from("<H", s0, 0x0E)[0]
        if self.reserved_sectors == 0:
            self._reconstruct_orphaned_bpb()
            return

        self.num_fats = s0[0x10]
        if self.num_fats not in (1, 2):
            self._reconstruct_orphaned_bpb()
            return

        self.root_entries_count = struct.unpack_from("<H", s0, 0x11)[0]
        total_sectors_16 = struct.unpack_from("<H", s0, 0x13)[0]
        self.fat_size_sectors = struct.unpack_from("<H", s0, 0x16)[0]
        total_sectors_32 = struct.unpack_from("<I", s0, 0x20)[0]

        total_sectors = total_sectors_16 if total_sectors_16 != 0 else total_sectors_32

        # Déterminer FAT32 vs FAT12/16
        if self.fat_size_sectors == 0:
            # FAT32
            self.fat_size_sectors = struct.unpack_from("<I", s0, 0x24)[0]
            self.root_cluster = struct.unpack_from("<I", s0, 0x2C)[0]
            self.bpb_label = s0[0x47 : 0x47 + 11].decode("latin1", "replace").strip()
            self.fat_type = "FAT32"
            root_dir_sectors = 0
        else:
            root_dir_sectors = (self.root_entries_count * 32 + self.bytes_per_sector - 1) // self.bytes_per_sector
            self.bpb_label = s0[0x2B : 0x2B + 11].decode("latin1", "replace").strip()
            data_sectors = total_sectors - (self.reserved_sectors + self.num_fats * self.fat_size_sectors + root_dir_sectors)
            total_clusters = data_sectors // self.sectors_per_cluster
            if total_clusters < 4085:
                self.fat_type = "FAT12"
            else:
                self.fat_type = "FAT16"

        self.data_start_offset = self.part_offset + (self.reserved_sectors + self.num_fats * self.fat_size_sectors + root_dir_sectors) * self.bytes_per_sector
        self.is_valid_fat = True

    def _reconstruct_orphaned_bpb(self):
        """
        Reconstitue mathématiquement la géométrie complète d'un volume FAT (FAT12/16/32)
        lorsque le secteur d'amorçage (LBA 0 / VBR) a été détruit par un wiper ou un écrasement.
        Détermine automatiquement : sectors_per_fat, sectors_per_cluster, root_dir et data_start.
        """
        start_lba = self.part_offset // self.reader.sector_size
        max_scan = min(start_lba + 512, self.reader.total_sectors)

        # 1. Recherche du Boot Sector de secours officiel FAT32 (LBA 6)
        if start_lba + 6 < self.reader.total_sectors:
            s6 = self.reader.read_sector(start_lba + 6, count=1)
            if len(s6) >= 512 and s6[510:512] == b"\x55\xaa":
                bps = struct.unpack_from("<H", s6, 0x0B)[0]
                spc = s6[0x0D]
                res_sec = struct.unpack_from("<H", s6, 0x0E)[0]
                num_f = s6[0x10]
                if bps in (512, 1024, 2048, 4096) and spc in (1, 2, 4, 8, 16, 32, 64, 128) and res_sec > 0 and num_f in (1, 2):
                    self.bytes_per_sector = bps
                    self.sectors_per_cluster = spc
                    self.cluster_size = bps * spc
                    self.reserved_sectors = res_sec
                    self.num_fats = num_f
                    self.fat_size_sectors = struct.unpack_from("<I", s6, 0x24)[0]
                    self.root_cluster = struct.unpack_from("<I", s6, 0x2C)[0]
                    self.bpb_label = s6[0x47 : 0x47 + 11].decode("latin1", "replace").strip()
                    self.fat_type = "FAT32"
                    self.used_backup_boot_sector = True
                    self.data_start_offset = self.part_offset + (self.reserved_sectors + self.num_fats * self.fat_size_sectors) * self.bytes_per_sector
                    self.is_valid_fat = True
                    return

        # 2. Localisation universelle de la première table FAT (FAT1)
        fat1_lba = None
        detected_fat_type = "FAT16"
        for lba in range(start_lba + 1, max_scan):
            sec = self.reader.read_sector(lba)
            if len(sec) < 8:
                continue
            # Ignorer les blocs entièrement remplis de 0xFF (mémoire flash effacée/non formatée)
            if sec[:64] == b"\xff" * 64 or sec == b"\xff" * len(sec):
                continue
            m = sec[0]
            if m in (0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF):
                if sec[1:4] == b"\xff\xff\xff":
                    fat1_lba = lba
                    detected_fat_type = "FAT16"
                    break
                elif sec[1:3] == b"\xff\xff":
                    fat1_lba = lba
                    detected_fat_type = "FAT12"
                    break
                elif sec[1:4] == b"\xff\xff\x0f":
                    fat1_lba = lba
                    detected_fat_type = "FAT32"
                    break

        if not fat1_lba:
            self.is_valid_fat = False
            return

        # 3. Localisation universelle de la seconde table FAT (FAT2)
        # La distance entre FAT1 et FAT2 donne mathématiquement sectors_per_fat
        fat2_lba = None
        scan_fat2_limit = min(fat1_lba + 32768, self.reader.total_sectors)
        for lba in range(fat1_lba + 1, scan_fat2_limit):
            sec = self.reader.read_sector(lba)
            if len(sec) < 8:
                continue
            if sec[:64] == b"\xff" * 64 or sec == b"\xff" * len(sec):
                continue
            if sec[0] == self.reader.read_bytes(fat1_lba * self.reader.sector_size, 1)[0] and sec[1:3] == b"\xff\xff":
                fat2_lba = lba
                break

        if not fat2_lba:
            self.is_valid_fat = False
            return

        sectors_per_fat = fat2_lba - fat1_lba
        self.num_fats = 2
        self.fat_size_sectors = sectors_per_fat
        self.reserved_sectors = fat1_lba - start_lba
        self.bytes_per_sector = 512

        # 4. Localisation du Répertoire Racine
        root_dir_lba = fat2_lba + sectors_per_fat
        root_dir_sectors = 32  # 512 entrées standard FAT16 / FAT12
        root_bytes = self.reader.read_bytes(root_dir_lba * 512, root_dir_sectors * 512)

        files_to_probe = []
        for i in range(0, len(root_bytes), 32):
            chunk = root_bytes[i : i + 32]
            if chunk[0] in (0x00, 0xE5, 0xFF) or chunk == b"\xff" * 32 or chunk[11] == 0x0F:
                continue
            name = chunk[:11].decode("latin1", "replace").strip()
            fclus = struct.unpack("<H", chunk[26:28])[0]
            fsz = struct.unpack("<I", chunk[28:32])[0]
            if fclus >= 2 and fsz > 0:
                files_to_probe.append((name, fclus, fsz))

        if not files_to_probe:
            self.is_valid_fat = False
            return

        data_start_lba = root_dir_lba + root_dir_sectors

        # 5. Détermination dynamique de sectors_per_cluster par corrélation de signatures
        best_spc = 4
        best_matches = -1
        probe_candidates = [f for f in files_to_probe if f[1] > 2]
        if probe_candidates:
            for spc in (1, 2, 4, 8, 16, 32, 64):
                matches = 0
                for name, fclus, fsz in probe_candidates[:8]:
                    flba = data_start_lba + (fclus - 2) * spc
                    hdr = self.reader.read_bytes(flba * 512, 16)
                    if not hdr or hdr == b"\x00" * len(hdr):
                        continue
                    if "JPG" in name and hdr.startswith(b"\xff\xd8\xff"):
                        matches += 1
                    elif "PDF" in name and hdr.startswith(b"%PDF"):
                        matches += 1
                    elif ("DOC" in name or "XLS" in name or "PPT" in name) and hdr.startswith(b"\xd0\xcf\x11\xe0"):
                        matches += 1
                    elif "GIF" in name and hdr.startswith(b"GIF8"):
                        matches += 1
                    elif "ZIP" in name and hdr.startswith(b"PK\x03\x04"):
                        matches += 1
                    elif ("WAV" in name or "AVI" in name) and hdr.startswith(b"RIFF"):
                        matches += 1
                if matches > best_matches:
                    best_matches = matches
                    best_spc = spc

        self.sectors_per_cluster = best_spc
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.root_entries_count = root_dir_sectors * 16
        self.data_start_offset = self.part_offset + data_start_lba * self.bytes_per_sector
        self.bpb_label = "RECONSTRUCTED"
        self.fat_type = detected_fat_type
        self.is_valid_fat = True

    def _load_fat_table(self):
        fat_offset = self.part_offset + self.reserved_sectors * self.bytes_per_sector
        fat_bytes_count = self.fat_size_sectors * self.bytes_per_sector
        raw_fat = self.reader.read_bytes(fat_offset, min(fat_bytes_count, 1024 * 1024 * 32))

        if self.fat_type == "FAT16":
            count = len(raw_fat) // 2
            self._fat_table = list(struct.unpack(f"<{count}H", raw_fat[: count * 2]))
        elif self.fat_type == "FAT32":
            count = len(raw_fat) // 4
            self._fat_table = [x & 0x0FFFFFFF for x in struct.unpack(f"<{count}I", raw_fat[: count * 4])]
        elif self.fat_type == "FAT12":
            entries = []
            for i in range(0, len(raw_fat) - 2, 3):
                b1, b2, b3 = raw_fat[i], raw_fat[i + 1], raw_fat[i + 2]
                val1 = b1 | ((b2 & 0x0F) << 8)
                val2 = (b2 >> 4) | (b3 << 4)
                entries.extend([val1, val2])
            self._fat_table = entries

    def _get_next_cluster(self, cluster: int) -> int:
        if cluster < 2 or cluster >= len(self._fat_table):
            return 0xFFFFFFFF
        val = self._fat_table[cluster]
        if self.fat_type == "FAT12" and val >= 0xFF8:
            return 0xFFFFFFFF
        elif self.fat_type == "FAT16" and val >= 0xFFF8:
            return 0xFFFFFFFF
        elif self.fat_type == "FAT32" and val >= 0x0FFFFFF8:
            return 0xFFFFFFFF
        return val

    def _cluster_to_offset(self, cluster: int) -> int:
        return self.data_start_offset + (cluster - 2) * self.cluster_size

    def _parse_directory_entries(self, dir_data: bytes, parent_entry: Optional[FATFileEntry] = None, is_root: bool = False) -> List[FATFileEntry]:
        entries: List[FATFileEntry] = []
        lfn_parts: Dict[int, str] = {}

        for i in range(0, len(dir_data) - 31, 32):
            raw = dir_data[i : i + 32]
            first_byte = raw[0]
            if first_byte == 0x00:
                break
            if first_byte == 0xFF or raw == b"\xff" * 32:
                continue

            attr = raw[11]

            if attr == 0x0F:
                seq = first_byte & 0x3F
                name_chars = raw[1:11] + raw[14:26] + raw[28:32]
                try:
                    name_str = name_chars.decode("utf-16le", "replace").split("\x00")[0]
                except Exception:
                    name_str = ""
                lfn_parts[seq] = name_str
                continue

            is_deleted = first_byte == 0xE5
            name_83_raw = raw[:11]
            if is_deleted:
                first_char = "_"
                if lfn_parts and 1 in lfn_parts and lfn_parts[1]:
                    first_char = lfn_parts[1][0]
                name_83_str = first_char + name_83_raw[1:11].decode("latin1", "replace")
            else:
                name_83_str = name_83_raw.decode("latin1", "replace")

            main_name = name_83_str[:8].rstrip()
            ext_name = name_83_str[8:11].rstrip()
            short_name = f"{main_name}.{ext_name}" if ext_name else main_name

            if lfn_parts:
                full_name = "".join(lfn_parts[k] for k in sorted(lfn_parts.keys()))
                lfn_parts.clear()
            else:
                full_name = short_name

            clus_hi = struct.unpack_from("<H", raw, 20)[0] if self.fat_type == "FAT32" else 0
            clus_lo = struct.unpack_from("<H", raw, 26)[0]
            first_cluster = (clus_hi << 16) | clus_lo
            file_size = struct.unpack_from("<I", raw, 28)[0]

            created_time = struct.unpack_from("<H", raw, 14)[0]
            created_date = struct.unpack_from("<H", raw, 16)[0]
            modified_time = struct.unpack_from("<H", raw, 22)[0]
            modified_date = struct.unpack_from("<H", raw, 24)[0]
            accessed_date = struct.unpack_from("<H", raw, 18)[0]

            is_volume_label = bool(attr & 0x08)
            is_dir = bool(attr & 0x10)

            if is_root and is_volume_label and not is_deleted:
                self.root_label = full_name.strip()
                if self.bpb_label and self.root_label and self.bpb_label != self.root_label:
                    self.label_discrepancy = True
                    self.anomalies.append(f"Discordance d'étiquette : BPB='{self.bpb_label}' vs Racine='{self.root_label}'")

            is_hidden_volume_file = False
            if is_volume_label and (first_cluster >= 2 or file_size > 0):
                is_hidden_volume_file = True
                self.anomalies.append(
                    f"Fichier caché sous attribut 0x08 (Volume Label) : '{full_name}' (Cluster={first_cluster}, Taille={file_size} B)"
                )

            if is_volume_label and not is_hidden_volume_file:
                continue

            if full_name in (".", ".."):
                continue

            entry = FATFileEntry()
            entry.name = full_name
            entry.is_dir = is_dir
            entry.is_deleted = is_deleted
            entry.is_volume_label = is_volume_label
            entry.is_hidden_volume_file = is_hidden_volume_file
            entry.first_cluster = first_cluster
            entry.size = file_size
            entry.created = dos_datetime_to_iso(created_date, created_time)
            entry.modified = dos_datetime_to_iso(modified_date, modified_time)
            entry.accessed = dos_datetime_to_iso(accessed_date, 0)
            entry.parent_entry = parent_entry

            entries.append(entry)
            self.all_entries.append(entry)

            if is_dir and first_cluster >= 2 and not is_deleted:
                sub_dir_data = self._read_cluster_chain(first_cluster)
                sub_entries = self._parse_directory_entries(sub_dir_data, parent_entry=entry, is_root=False)
                entry.children = sub_entries

        return entries

    def _read_cluster_chain(self, start_cluster: int, max_bytes: Optional[int] = None) -> bytes:
        data = bytearray()
        c = start_cluster
        visited = set()
        while c >= 2 and c not in visited:
            visited.add(c)
            offset = self._cluster_to_offset(c)
            chunk = self.reader.read_bytes(offset, self.cluster_size)
            data.extend(chunk)
            if max_bytes and len(data) >= max_bytes:
                return bytes(data[:max_bytes])
            next_c = self._get_next_cluster(c)
            if next_c >= 0xFFFFFFF8 or next_c == 0xFFFFFFFF or next_c == 0:
                break
            c = next_c
        return bytes(data[:max_bytes] if max_bytes else data)

    def _parse_tree(self):
        root = FATFileEntry()
        root.name = f"/ [{self.fat_type} Root - {self.bpb_label or 'Volume'}]"
        root.is_dir = True
        self.root_entry = root

        if self.fat_type in ("FAT12", "FAT16"):
            root_offset = self.part_offset + (self.reserved_sectors + self.num_fats * self.fat_size_sectors) * self.bytes_per_sector
            root_bytes_count = self.root_entries_count * 32
            root_data = self.reader.read_bytes(root_offset, root_bytes_count)
            root.children = self._parse_directory_entries(root_data, parent_entry=root, is_root=True)
        else:
            root_data = self._read_cluster_chain(self.root_cluster)
            root.children = self._parse_directory_entries(root_data, parent_entry=root, is_root=True)

    def extract_file_content(self, entry: FATFileEntry) -> bytes:
        """Extrait le contenu bit-à-bit d'un fichier FAT."""
        if entry.is_dir or entry.first_cluster < 2:
            return b""
        return self._read_cluster_chain(entry.first_cluster, max_bytes=entry.size)
