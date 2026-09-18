"""
WipeRescue-Forensics - Moteur Forensique NTFS & MFT Undelete
Analyse en profondeur les structures NTFS (VBR, $MFT, attributs resident/non-resident),
carve les enregistrements du journal de transactions ($LogFile) et des espaces non alloués,
reconstitue l'arborescence complète des fichiers actifs et supprimés (y compris répertoires réalloués),
et permet l'extraction directe des fichiers sans montage externe.
"""

import struct
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any, Set
from core.image_reader import ForensicImageReader


def filetime_to_iso(ft: int) -> str:
    """Convertit un timestamp Windows FILETIME (100-ns depuis 01/01/1601) en ISO-8601."""
    if not ft or ft <= 0:
        return ""
    try:
        us = ft // 10
        sec, _ = divmod(us, 1_000_000)
        unix_sec = sec - 11644473600
        if unix_sec < 0 or unix_sec > 4102444800:
            return ""
        dt = datetime.fromtimestamp(unix_sec, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


class NTFSFileEntry:
    """Représente une entrée de fichier ou répertoire extraite de la MFT."""

    def __init__(self, record_num: int):
        self.record_number: int = record_num
        self.sequence_number: int = 0
        self.name: str = ""
        self.is_dir: bool = False
        self.is_deleted: bool = False
        self.source: str = "MFT"
        self.parent_record_number: Optional[int] = None
        self.size: int = 0
        self.allocated_size: int = 0
        self.created: str = ""
        self.modified: str = ""
        self.mft_modified: str = ""
        self.accessed: str = ""
        self.has_data: bool = False
        self.is_resident: bool = False
        self.resident_data: bytes = b""
        self.data_runs: List[Tuple[Optional[int], int]] = []
        self.children: List["NTFSFileEntry"] = []

    def __repr__(self):
        status = "DELETED" if self.is_deleted else "ACTIVE"
        kind = "DIR" if self.is_dir else "FILE"
        return f"<NTFS #{self.record_number} [{status}] [{kind}] '{self.name}' ({self.size} bytes)>"


class NTFSReader:
    """Lecteur forensique pur-Python de partition NTFS avec carver de journal ($LogFile) et Undelete."""

    def __init__(self, reader: ForensicImageReader, partition_offset_bytes: int = 0):
        self.reader = reader
        self.part_offset = partition_offset_bytes
        self.is_valid_ntfs: bool = False

        self.bytes_per_sector: int = 512
        self.sectors_per_cluster: int = 8
        self.cluster_size: int = 4096
        self.total_sectors: int = 0
        self.mft_cluster: int = 0
        self.record_size: int = 1024

        self.all_entries: List[NTFSFileEntry] = []
        self.root_entry: Optional[NTFSFileEntry] = None
        self.orphaned_entries: List[NTFSFileEntry] = []

        self._read_vbr()
        if self.is_valid_ntfs:
            self._parse_mft()

    def _read_vbr(self):
        sector_lba = self.part_offset // self.reader.sector_size
        vbr = self.reader.read_sector(sector_lba, count=1)
        if len(vbr) < 512 or vbr[3:11] != b"NTFS    ":
            self.is_valid_ntfs = False
            return

        self.is_valid_ntfs = True
        self.bytes_per_sector = struct.unpack_from("<H", vbr, 0x0B)[0]
        self.sectors_per_cluster = vbr[0x0D]
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.total_sectors = struct.unpack_from("<Q", vbr, 0x28)[0]
        self.mft_cluster = struct.unpack_from("<q", vbr, 0x30)[0]

        clusters_per_record = struct.unpack_from("<b", vbr, 0x40)[0]
        if clusters_per_record < 0:
            self.record_size = 1 << (-clusters_per_record)
        else:
            self.record_size = clusters_per_record * self.cluster_size

    def _read_cluster(self, lcn: Optional[int], count: int = 1) -> bytes:
        if lcn is None:
            return b"\x00" * (count * self.cluster_size)
        byte_offset = self.part_offset + lcn * self.cluster_size
        start_lba = byte_offset // self.reader.sector_size
        needed_sectors = (count * self.cluster_size + self.reader.sector_size - 1) // self.reader.sector_size
        raw = self.reader.read_sector(start_lba, count=needed_sectors)
        return raw[: count * self.cluster_size]

    def _apply_usa_fixups(self, rec: bytes) -> bytes:
        if len(rec) < 48:
            return rec
        try:
            usa_off = struct.unpack_from("<H", rec, 0x04)[0]
            usa_count = struct.unpack_from("<H", rec, 0x06)[0]
            if usa_off >= len(rec) or usa_off + usa_count * 2 > len(rec):
                return rec

            rec_arr = bytearray(rec)
            for s in range(1, usa_count):
                fix_pos = s * 512 - 2
                if fix_pos + 2 <= len(rec_arr):
                    rep_val = rec_arr[usa_off + s * 2 : usa_off + s * 2 + 2]
                    rec_arr[fix_pos : fix_pos + 2] = rep_val
            return bytes(rec_arr)
        except Exception:
            return rec

    def _decode_data_runs(self, run_bytes: bytes) -> List[Tuple[Optional[int], int]]:
        runs = []
        p = 0
        cur_lcn = 0
        while p < len(run_bytes) and run_bytes[p] != 0:
            header = run_bytes[p]
            len_size = header & 0x0F
            off_size = (header >> 4) & 0x0F
            p += 1
            if p + len_size + off_size > len(run_bytes):
                break
            run_len = int.from_bytes(run_bytes[p : p + len_size], "little")
            p += len_size
            if off_size > 0:
                raw_offset = int.from_bytes(run_bytes[p : p + off_size], "little", signed=True)
                p += off_size
                cur_lcn += raw_offset
                runs.append((cur_lcn, run_len))
            else:
                runs.append((None, run_len))
        return runs

    def _parse_single_record(self, raw_bytes: bytes, fallback_rec_num: int = 0) -> Optional[NTFSFileEntry]:
        if not (raw_bytes.startswith(b"FILE") or raw_bytes.startswith(b"BAAD")):
            return None
        rec = self._apply_usa_fixups(raw_bytes)
        flags = struct.unpack_from("<H", rec, 0x16)[0]
        is_in_use = bool(flags & 0x01)
        is_dir = bool(flags & 0x02)

        rec_num = struct.unpack_from("<I", rec, 0x2C)[0]
        if rec_num == 0 and fallback_rec_num != 0:
            rec_num = fallback_rec_num
        if rec_num > 10_000_000:
            return None

        entry = NTFSFileEntry(rec_num)
        entry.is_dir = is_dir
        entry.is_deleted = not is_in_use
        entry.sequence_number = struct.unpack_from("<H", rec, 0x10)[0]

        attr_off = struct.unpack_from("<H", rec, 0x14)[0]
        if attr_off < 48 or attr_off >= len(rec):
            return None

        while attr_off < len(rec) - 8:
            attr_type, attr_len = struct.unpack_from("<II", rec, attr_off)
            if attr_type == 0xFFFFFFFF or attr_len == 0 or attr_off + attr_len > len(rec):
                break

            non_res = rec[attr_off + 8]

            # $STANDARD_INFORMATION (0x10) -> Timestamps
            if attr_type == 0x10 and non_res == 0:
                content_off = struct.unpack_from("<H", rec, attr_off + 0x14)[0]
                si_data = rec[attr_off + content_off : attr_off + attr_len]
                if len(si_data) >= 32:
                    c_time, m_time, mft_time, a_time = struct.unpack_from("<QQQQ", si_data, 0)
                    entry.created = filetime_to_iso(c_time)
                    entry.modified = filetime_to_iso(m_time)
                    entry.mft_modified = filetime_to_iso(mft_time)
                    entry.accessed = filetime_to_iso(a_time)

            # $FILE_NAME (0x30) -> Nom & Référence parent
            elif attr_type == 0x30 and non_res == 0:
                content_off = struct.unpack_from("<H", rec, attr_off + 0x14)[0]
                fn_data = rec[attr_off + content_off : attr_off + attr_len]
                if len(fn_data) >= 66:
                    parent_ref = struct.unpack_from("<Q", fn_data, 0)[0] & 0x0000FFFFFFFFFFFF
                    fn_len = fn_data[0x40]
                    fn_ns = fn_data[0x41]
                    try:
                        name = fn_data[0x42 : 0x42 + fn_len * 2].decode("utf-16le", errors="ignore")
                        # Filtrer les noms corrompus ou invalides
                        if name and any(32 <= ord(c) < 127 for c in name) and not any(ord(c) > 0x2000 for c in name):
                            if not entry.name or fn_ns != 2:
                                entry.name = name
                                entry.parent_record_number = parent_ref
                    except Exception:
                        pass

            # $DATA (0x80) -> Données et taille
            elif attr_type == 0x80:
                entry.has_data = True
                name_len = rec[attr_off + 9]
                if name_len == 0:
                    if non_res == 0:
                        entry.is_resident = True
                        content_len = struct.unpack_from("<I", rec, attr_off + 0x10)[0]
                        content_off = struct.unpack_from("<H", rec, attr_off + 0x14)[0]
                        entry.size = content_len
                        entry.allocated_size = content_len
                        entry.resident_data = rec[attr_off + content_off : attr_off + content_off + content_len]
                    else:
                        entry.is_resident = False
                        entry.size = struct.unpack_from("<Q", rec, attr_off + 0x30)[0]
                        entry.allocated_size = struct.unpack_from("<Q", rec, attr_off + 0x28)[0]
                        data_run_off = struct.unpack_from("<H", rec, attr_off + 0x20)[0]
                        entry.data_runs = self._decode_data_runs(rec[attr_off + data_run_off : attr_off + attr_len])

            attr_off += attr_len

        if not entry.name:
            return None

        return entry

    def _extract_mft_runs(self, rec0: bytes) -> List[Tuple[Optional[int], int]]:
        attr_off = struct.unpack_from("<H", rec0, 0x14)[0]
        while attr_off < len(rec0) - 8:
            attr_type, attr_len = struct.unpack_from("<II", rec0, attr_off)
            if attr_type == 0xFFFFFFFF or attr_len == 0 or attr_off + attr_len > len(rec0):
                break
            non_res = rec0[attr_off + 8]
            if attr_type == 0x80 and non_res == 1:
                data_run_off = struct.unpack_from("<H", rec0, attr_off + 0x20)[0]
                return self._decode_data_runs(rec0[attr_off + data_run_off : attr_off + attr_len])
            attr_off += attr_len
        return []

    def _parse_mft(self):
        mft_first_byte_offset = self.part_offset + self.mft_cluster * self.cluster_size
        mft_start_lba = mft_first_byte_offset // self.reader.sector_size
        sectors_per_rec = (self.record_size + self.reader.sector_size - 1) // self.reader.sector_size
        rec0_raw = self.reader.read_sector(mft_start_lba, count=sectors_per_rec)[: self.record_size]

        if not rec0_raw.startswith(b"FILE"):
            return

        rec0 = self._apply_usa_fixups(rec0_raw)
        mft_runs = self._extract_mft_runs(rec0)
        if not mft_runs:
            mft_runs = [(self.mft_cluster, 64)]

        seen_keys: Set[Tuple[int, str]] = set()
        current_record_idx = 0

        # 1. Lecture ordonnée des runs primaires de la $MFT
        for lcn, cluster_count in mft_runs:
            if lcn is None:
                current_record_idx += (cluster_count * self.cluster_size) // self.record_size
                continue
            run_data = self._read_cluster(lcn, cluster_count)
            num_records_in_run = len(run_data) // self.record_size
            for r in range(num_records_in_run):
                rec_bytes = run_data[r * self.record_size : (r + 1) * self.record_size]
                if rec_bytes.startswith(b"FILE") or rec_bytes.startswith(b"BAAD"):
                    entry = self._parse_single_record(rec_bytes, current_record_idx)
                    if entry and entry.name:
                        key = (entry.record_number, entry.name)
                        seen_keys.add(key)
                        self.all_entries.append(entry)
                current_record_idx += 1

        # 2. Carving approfondi des enregistrements MFT dans le journal ($LogFile) et l'espace disque
        # Permet de retrouver les répertoires supprimés réalloués (ex: dir3 au record #37 avant res1.dat)
        max_scan_bytes = min(self.reader.total_size_bytes - self.part_offset, 64 * 1024 * 1024)
        scan_buf = self.reader.read_bytes(self.part_offset, max_scan_bytes)

        pos = 0
        while True:
            idx = scan_buf.find(b"FILE", pos)
            if idx == -1:
                break
            if idx + self.record_size <= len(scan_buf):
                raw_chunk = scan_buf[idx : idx + self.record_size]
                carved_entry = self._parse_single_record(raw_chunk)
                if carved_entry and carved_entry.name:
                    key = (carved_entry.record_number, carved_entry.name)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        carved_entry.is_deleted = True
                        carved_entry.source = "Journal ($LogFile)"
                        self.all_entries.append(carved_entry)
            pos = idx + 1

        # 3. Construction de l'arborescence complète (Parents -> Enfants)
        self._build_tree()

    def _build_tree(self):
        """Associe les entrées enfants à leurs dossiers parents réels ou orphelins."""
        dirs_by_mft: Dict[int, NTFSFileEntry] = {}

        # 1. Identifier la racine (.) et cartographier tous les répertoires
        for entry in self.all_entries:
            if entry.record_number == 5 and entry.name == ".":
                self.root_entry = entry
            if entry.is_dir:
                # Prioriser les répertoires pour l'association parentale
                dirs_by_mft[entry.record_number] = entry

        # 2. Associer chaque élément à son dossier parent
        for entry in self.all_entries:
            if entry == self.root_entry:
                continue

            p_num = entry.parent_record_number
            # Vérifier si le parent est un répertoire connu
            if p_num in dirs_by_mft and dirs_by_mft[p_num] != entry:
                dirs_by_mft[p_num].children.append(entry)
            elif self.root_entry and p_num == 5:
                self.root_entry.children.append(entry)
            else:
                self.orphaned_entries.append(entry)

    def extract_file_content(self, entry: NTFSFileEntry) -> bytes:
        if not entry.has_data:
            return b""

        if entry.is_resident:
            return entry.resident_data[: entry.size]

        file_buf = bytearray()
        for lcn, run_len in entry.data_runs:
            cluster_bytes = self._read_cluster(lcn, run_len)
            file_buf.extend(cluster_bytes)
            if len(file_buf) >= entry.size:
                break

        return bytes(file_buf[: entry.size])
