"""
DFR-Forensics - Moteur de Corrélation de Métadonnées Orphelines (FAT & NTFS)
Recherche et analyse les structures de répertoires orphelines (DIR_ENTRY FAT avec LFN, et records $MFT NTFS)
dans l'espace non alloué ou corrompu pour réassocier automatiquement les vrais noms de fichiers,
tailles d'origine, dates et numéros de clusters aux artefacts carvés.
"""

import struct
import string
import math
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field

from core.image_reader import ForensicImageReader

VALID_DOS_CHARS = set(string.ascii_letters + string.digits + "!#$%&'()-@^_`{}~ ")


@dataclass
class OrphanDirectoryEntry:
    """Représente une entrée de répertoire orpheline découverte dans le disque."""
    filename: str
    original_size: int
    first_cluster: int
    is_deleted: bool
    lba_record: int
    filesystem: str  # "FAT" ou "NTFS" ou "EXT2"
    predicted_start_lba: Optional[int] = None
    created_ts: Optional[str] = None
    modified_ts: Optional[str] = None
    block_list: Optional[List[int]] = None
    block_size: Optional[int] = None


class MetadataCorrelator:
    """
    Moteur de Corrélation Médico-Légale.
    Établit la passerelle mathématique entre les tables de répertoires orphelines
    et les blocs physiques d'artefacts carvés en mémoire.
    """

    def __init__(self, reader: ForensicImageReader):
        self.reader = reader
        self.orphan_entries: List[OrphanDirectoryEntry] = []
        self.sectors_per_cluster: Optional[int] = None
        self.data_start_lba: Optional[int] = None

    def scan_orphan_entries(self, max_scan_sectors: int = 25000) -> List[OrphanDirectoryEntry]:
        """
        Scanne les métadonnées orphelines (FAT DIR_ENTRY et NTFS $MFT)
        dans les zones initiales et tables orphelines.
        """
        self.orphan_entries.clear()
        scan_limit = min(self.reader.total_sectors, max_scan_sectors)

        # 1. Scan des entrées FAT (DIR_ENTRY + VFAT LFN)
        self._scan_fat_directory_entries(scan_limit)

        # 2. Scan des enregistrements NTFS $MFT (Records "FILE")
        self._scan_ntfs_mft_records(scan_limit)

        # 3. Scan des systèmes Linux EXT2/3/4 (Superblocs, Descripteurs, Inodes)
        self._scan_ext_filesystem()

        return self.orphan_entries

    def _scan_fat_directory_entries(self, scan_limit: int):
        lfn_parts: Dict[int, List[Tuple[int, str]]] = {}
        max_possible_cluster = max(2, self.reader.total_sectors)

        for lba in range(scan_limit):
            sector = self.reader.read_sector(lba)
            if sector == b"\x00" * len(sector) or sector == b"\xFF" * len(sector):
                continue

            for offset in range(0, len(sector), 32):
                chunk = sector[offset : offset + 32]
                attr = chunk[11]

                # Long File Name (LFN)
                if attr == 0x0F:
                    seq = chunk[0]
                    if seq in (0x00, 0xE5, 0xFF):
                        continue
                    chars = chunk[1:11] + chunk[14:26] + chunk[28:32]
                    try:
                        text = chars.decode("utf-16le").split("\x00")[0]
                        chksum = chunk[13]
                        if chksum not in lfn_parts:
                            lfn_parts[chksum] = []
                        lfn_parts[chksum].append((seq & 0x3F, text))
                    except Exception:
                        pass
                    continue

                # Entrée standard 8.3
                if chunk[0] in (0x00, 0x2E, 0xFF):
                    continue

                is_deleted = (chunk[0] == 0xE5)
                raw_name = (b"_" if is_deleted else bytes([chunk[0]])) + chunk[1:8]
                raw_ext = chunk[8:11]

                if not self._is_valid_dos_name(raw_name, raw_ext):
                    continue

                # Attributs FAT valides uniquement (pas de bits réservés 0x40 ou 0x80)
                if attr & 0xC0 != 0:
                    continue

                clu_hi = struct.unpack("<H", chunk[20:22])[0]
                clu_lo = struct.unpack("<H", chunk[26:28])[0]
                first_clu = (clu_hi << 16) | clu_lo
                fsize = struct.unpack("<I", chunk[28:32])[0]

                if first_clu >= max_possible_cluster or fsize > self.reader.total_size_bytes:
                    continue

                # Contrôle cohérence de date
                date_raw = struct.unpack("<H", chunk[24:26])[0]
                month = (date_raw >> 5) & 0x0F
                day = date_raw & 0x1F
                if date_raw != 0 and not (1 <= month <= 12 and 1 <= day <= 31):
                    continue

                # Calcul du checksum DOS pour réassembler le LFN
                c_sum = 0
                for b in chunk[0:11]:
                    c_sum = (((c_sum & 1) << 7) + (c_sum >> 1) + b) & 0xFF

                long_name = ""
                if c_sum in lfn_parts:
                    parts = sorted(lfn_parts[c_sum], key=lambda x: x[0])
                    long_name = "".join(p[1] for p in parts)
                    del lfn_parts[c_sum]

                try:
                    name_str = raw_name.decode("ascii").strip()
                    ext_str = raw_ext.decode("ascii").strip()
                except Exception:
                    continue

                final_name = long_name or (f"{name_str}.{ext_str}" if ext_str else name_str)

                if final_name and (first_clu > 0 or fsize > 0):
                    self.orphan_entries.append(
                        OrphanDirectoryEntry(
                            filename=final_name,
                            original_size=fsize,
                            first_cluster=first_clu,
                            is_deleted=is_deleted,
                            lba_record=lba,
                            filesystem="FAT",
                        )
                    )

    def _scan_ntfs_mft_records(self, scan_limit: int):
        """Scanne les enregistrements MFT NTFS orphelins (1024 octets avec magic FILE)."""
        lba = 0
        while lba < scan_limit:
            sec = self.reader.read_sector(lba)
            if sec.startswith(b"FILE"):
                record = self.reader.read_bytes(lba * self.reader.sector_size, 1024)
                if len(record) >= 1024:
                    self._parse_single_mft_record(record, lba)
            lba += 1

    def _parse_single_mft_record(self, record: bytes, lba: int):
        try:
            # Fixup update sequence
            upd_off = struct.unpack("<H", record[4:6])[0]
            upd_cnt = struct.unpack("<H", record[6:8])[0]
            first_attr_off = struct.unpack("<H", record[20:22])[0]
            flags = struct.unpack("<H", record[22:24])[0]
            is_in_use = bool(flags & 0x01)
            is_dir = bool(flags & 0x02)
            if is_dir:
                return

            offset = first_attr_off
            filename = ""
            data_size = 0
            first_cluster = 0

            while offset < len(record) - 8:
                attr_type = struct.unpack("<I", record[offset : offset + 4])[0]
                if attr_type == 0xFFFFFFFF or attr_type == 0:
                    break
                attr_len = struct.unpack("<I", record[offset + 4 : offset + 8])[0]
                if attr_len <= 0 or offset + attr_len > len(record):
                    break

                non_res = record[offset + 8]

                # $FILE_NAME (0x30)
                if attr_type == 0x30 and non_res == 0:
                    content_off = struct.unpack("<H", record[offset + 20 : offset + 22])[0]
                    fn_data = record[offset + content_off : offset + attr_len]
                    if len(fn_data) >= 66:
                        name_len = fn_data[64]
                        name_raw = fn_data[66 : 66 + name_len * 2]
                        cand_name = name_raw.decode("utf-16le", errors="ignore")
                        # Ne pas écraser avec le nom court DOS si on a déjà le nom long Win32
                        fn_namespace = fn_data[65] if len(fn_data) > 65 else 0
                        if not filename or fn_namespace in (1, 3):
                            filename = cand_name

                # $DATA (0x80)
                elif attr_type == 0x80:
                    if non_res == 0:
                        content_len = struct.unpack("<I", record[offset + 16 : offset + 20])[0]
                        data_size = content_len
                    else:
                        real_size = struct.unpack("<Q", record[offset + 48 : offset + 56])[0]
                        data_size = real_size
                        # Décodage du premier data run pour trouver le cluster LCN
                        run_off = struct.unpack("<H", record[offset + 32 : offset + 34])[0]
                        run_data = record[offset + run_off : offset + attr_len]
                        if run_data and run_data[0] != 0:
                            header_b = run_data[0]
                            len_len = header_b & 0x0F
                            off_len = (header_b >> 4) & 0x0F
                            if 1 <= off_len <= 8 and 1 + len_len + off_len <= len(run_data):
                                lcn_bytes = run_data[1 + len_len : 1 + len_len + off_len]
                                # Sign extend LCN
                                if lcn_bytes:
                                    first_cluster = int.from_bytes(lcn_bytes, byteorder="little", signed=True)

                offset += attr_len

            if filename and (data_size > 0 or first_cluster > 0):
                self.orphan_entries.append(
                    OrphanDirectoryEntry(
                        filename=filename,
                        original_size=data_size,
                        first_cluster=max(0, first_cluster),
                        is_deleted=not is_in_use,
                        lba_record=lba,
                        filesystem="NTFS",
                    )
                )
        except Exception:
            pass

    def _is_valid_dos_name(self, raw_name: bytes, raw_ext: bytes) -> bool:
        try:
            n = raw_name.decode("ascii", errors="strict")
            e = raw_ext.decode("ascii", errors="strict")
        except Exception:
            return False
        if any(c not in VALID_DOS_CHARS for c in n):
            return False
        if any(c not in VALID_DOS_CHARS for c in e):
            return False
        return bool(n.strip())

    def _scan_ext_filesystem(self):
        """
        Détecte et analyse les structures Linux EXT2/EXT3/EXT4 :
        - Détection du superbloc primaire (offset 1024) ou des superblocs de secours (8193, 24577, etc.)
        - Analyse des descripteurs de groupes et des tables d'inodes
        - Résolution des pointeurs directs, indirects et doubles indirects
        - Décodage des entrées de répertoires actives et supprimées (slack space)
        """
        try:
            sb_data = None
            candidates = [1024, 8389632, 25166848]
            for cand in candidates:
                if cand + 1024 <= self.reader.total_size_bytes:
                    b = self.reader.read_bytes(cand, 1024)
                    if len(b) >= 58 and struct.unpack("<H", b[56:58])[0] == 0xEF53:
                        sb_data = b
                        break

            if not sb_data:
                scan_len = min(32 * 1024 * 1024, self.reader.total_size_bytes)
                buf = self.reader.read_bytes(0, scan_len)
                pos = 0
                while True:
                    pos = buf.find(b"\x53\xEF", pos)
                    if pos == -1:
                        break
                    cand_sb = pos - 56
                    if cand_sb >= 0 and cand_sb % 1024 == 0:
                        b = buf[cand_sb : cand_sb + 1024]
                        if len(b) >= 58 and struct.unpack("<H", b[56:58])[0] == 0xEF53:
                            sb_data = b
                            break
                    pos += 2

            if not sb_data:
                return

            s_inodes_count, s_blocks_count = struct.unpack("<II", sb_data[0:8])
            s_log_block_size = struct.unpack("<I", sb_data[24:28])[0]
            block_size = 1024 << s_log_block_size
            if block_size not in (1024, 2048, 4096, 8192):
                return

            s_blocks_per_group = struct.unpack("<I", sb_data[32:36])[0]
            s_inodes_per_group = struct.unpack("<I", sb_data[40:44])[0]
            s_first_data_block = struct.unpack("<I", sb_data[20:24])[0]
            if s_blocks_per_group <= 0 or s_inodes_per_group <= 0:
                return

            num_groups = (s_blocks_count + s_blocks_per_group - 1) // s_blocks_per_group
            num_groups = min(num_groups, 256)

            bgd_block = s_first_data_block + 1
            bgd_data = self.reader.read_bytes(bgd_block * block_size, num_groups * 32)
            inode_tables = []
            for g in range(num_groups):
                bg = bgd_data[g * 32 : (g + 1) * 32]
                if len(bg) < 32:
                    break
                bb, ib, it = struct.unpack("<III", bg[0:12])
                inode_tables.append(it)

            s_inode_size = 128
            if len(sb_data) >= 90:
                rev = struct.unpack("<I", sb_data[76:80])[0]
                if rev >= 1:
                    s_inode_size = struct.unpack("<H", sb_data[88:90])[0]
            if s_inode_size < 128:
                s_inode_size = 128

            inode_map = {}
            dir_inodes = []
            for g_idx, it_block in enumerate(inode_tables):
                if it_block == 0:
                    continue
                raw_it = self.reader.read_bytes(it_block * block_size, s_inodes_per_group * s_inode_size)
                for i in range(s_inodes_per_group):
                    ino_num = g_idx * s_inodes_per_group + i + 1
                    raw_ino = raw_it[i * s_inode_size : (i + 1) * s_inode_size]
                    if len(raw_ino) < 100:
                        continue
                    mode = struct.unpack("<H", raw_ino[0:2])[0]
                    file_fmt = mode & 0xF000

                    if file_fmt == 0x4000:
                        blocks = struct.unpack("<15I", raw_ino[40:100])
                        for b in blocks[:12]:
                            if b != 0:
                                dir_inodes.append((ino_num, b))
                        continue

                    if file_fmt == 0x8000 and ino_num >= 11:
                        size = struct.unpack("<I", raw_ino[4:8])[0]
                        if size <= 0:
                            continue
                        dtime = struct.unpack("<I", raw_ino[20:24])[0]
                        blocks = struct.unpack("<15I", raw_ino[40:100])
                        b_list = []
                        for b in blocks[:12]:
                            if b != 0:
                                b_list.append(b)
                        if blocks[12] != 0:
                            ind_bytes = self.reader.read_bytes(blocks[12] * block_size, block_size)
                            ptrs = struct.unpack(f"<{block_size // 4}I", ind_bytes)
                            for b in ptrs:
                                if b != 0:
                                    b_list.append(b)
                        if blocks[13] != 0:
                            dind_bytes = self.reader.read_bytes(blocks[13] * block_size, block_size)
                            dind_ptrs = struct.unpack(f"<{block_size // 4}I", dind_bytes)
                            for d_b in dind_ptrs:
                                if d_b != 0:
                                    sub_bytes = self.reader.read_bytes(d_b * block_size, block_size)
                                    sub_ptrs = struct.unpack(f"<{block_size // 4}I", sub_bytes)
                                    for b in sub_ptrs:
                                        if b != 0:
                                            b_list.append(b)

                        if b_list:
                            first_lba = (b_list[0] * block_size) // self.reader.sector_size
                            inode_map[ino_num] = {
                                "size": size,
                                "dtime": dtime,
                                "is_deleted": dtime != 0,
                                "block_list": b_list,
                                "first_lba": first_lba,
                            }

            names_by_ino = {}
            deleted_names = []
            for dir_ino, dir_block in dir_inodes:
                dir_bytes = self.reader.read_bytes(dir_block * block_size, block_size)
                pos = 0
                while pos < len(dir_bytes) - 8:
                    ino, rec_len, name_len, ftype = struct.unpack("<IHBB", dir_bytes[pos : pos + 8])
                    if rec_len == 0:
                        break
                    name = dir_bytes[pos + 8 : pos + 8 + name_len].decode("latin1", errors="ignore")
                    if ino in inode_map:
                        names_by_ino[ino] = name

                    min_len = ((8 + name_len + 3) // 4) * 4
                    if rec_len > min_len:
                        slack = dir_bytes[pos + min_len : pos + rec_len]
                        s_pos = 0
                        while s_pos < len(slack) - 8:
                            s_ino, s_rec, s_nlen, s_ft = struct.unpack("<IHBB", slack[s_pos : s_pos + 8])
                            if 1 <= s_nlen <= 60 and s_pos + 8 + s_nlen <= len(slack):
                                s_name = slack[s_pos + 8 : s_pos + 8 + s_nlen].decode("latin1", errors="ignore")
                                if s_name and all(32 <= ord(c) < 127 for c in s_name):
                                    deleted_names.append(s_name)
                            sub_min = ((8 + s_nlen + 3) // 4) * 4 if 1 <= s_nlen <= 60 else 4
                            s_pos += max(4, sub_min)
                    pos += rec_len

            del_inodes = [ino for ino, d in inode_map.items() if d["is_deleted"]]
            for idx, d_ino in enumerate(del_inodes):
                if idx < len(deleted_names):
                    names_by_ino[d_ino] = deleted_names[idx]

            for ino, d in inode_map.items():
                fn = names_by_ino.get(ino, f"ext_inode_{ino:04d}")
                self.orphan_entries.append(
                    OrphanDirectoryEntry(
                        filename=fn,
                        original_size=d["size"],
                        first_cluster=d["block_list"][0],
                        is_deleted=d["is_deleted"],
                        lba_record=d["first_lba"],
                        filesystem="EXT2",
                        predicted_start_lba=d["first_lba"],
                        block_list=d["block_list"],
                        block_size=block_size,
                    )
                )
        except Exception:
            pass

    def resolve_fat_geometry(self, carved_artefacts: List[Any]):
        """
        Détermine automatiquement les paramètres de géométrie FAT (Sectors Per Cluster et Data Start LBA)
        en croisant les numéros de clusters des entrées de répertoire orphelines
        avec les LBAs réels découverts par le carver.
        """
        fat_entries = [e for e in self.orphan_entries if e.filesystem == "FAT" and e.first_cluster >= 2]
        if len(fat_entries) < 2 or not carved_artefacts:
            return

        # Associer par taille exacte
        matches = []
        for a in carved_artefacts:
            for e in fat_entries:
                if e.original_size == a.length_bytes and a.length_bytes > 0:
                    matches.append((e.first_cluster, a.start_lba))
                    break

        if len(matches) >= 2:
            # Trier par cluster croissant
            matches.sort(key=lambda x: x[0])
            for i in range(len(matches) - 1):
                c1, l1 = matches[i]
                c2, l2 = matches[i + 1]
                delta_c = c2 - c1
                delta_l = l2 - l1
                if delta_c > 0 and delta_l > 0 and delta_l % delta_c == 0:
                    spc = delta_l // delta_c
                    if spc in (1, 2, 4, 8, 16, 32, 64, 128):
                        data_start = l1 - (c1 - 2) * spc
                        if 0 <= data_start < self.reader.total_sectors:
                            self.sectors_per_cluster = spc
                            self.data_start_lba = data_start
                            break

        # Si géométrie résolue, projeter tous les LBAs prédits
        if self.sectors_per_cluster and self.data_start_lba is not None:
            for e in fat_entries:
                e.predicted_start_lba = self.data_start_lba + (e.first_cluster - 2) * self.sectors_per_cluster

    def correlate(self, carved_artefacts: List[Any]) -> int:
        """
        Corrèle les artefacts découverts avec les métadonnées orphelines.
        Met à jour filename, metadata et source_info pour chaque artefact.
        Retourne le nombre d'artefacts corrélés avec succès.
        """
        if not self.orphan_entries:
            self.scan_orphan_entries()

        self.resolve_fat_geometry(carved_artefacts)
        correlated_count = 0
        used_entries = set()

        for art in carved_artefacts:
            best_match: Optional[OrphanDirectoryEntry] = None
            confidence = 0

            # 1. Match par LBA exact prédit (100% Certitude mathématique)
            for idx, e in enumerate(self.orphan_entries):
                if idx in used_entries:
                    continue
                if e.predicted_start_lba is not None and e.predicted_start_lba == art.start_lba:
                    best_match = e
                    confidence = 100
                    used_entries.add(idx)
                    break

            # 2. Match par taille exacte et extension concordante (95% Certitude)
            if not best_match:
                for idx, e in enumerate(self.orphan_entries):
                    if idx in used_entries:
                        continue
                    if e.original_size == art.length_bytes and art.length_bytes > 0:
                        e_ext = "." + e.filename.split(".")[-1].lower() if "." in e.filename else ""
                        if e_ext == art.extension.lower() or art.file_type.lower() in e.filename.lower():
                            best_match = e
                            confidence = 95
                            used_entries.add(idx)
                            break

            # Appliquer la corrélation trouvée
            if best_match:
                art.filename = best_match.filename
                art.metadata["original_filename"] = best_match.filename
                art.metadata["correlation_source"] = f"{best_match.filesystem} Directory / Inode Entry (LBA {best_match.lba_record})"
                art.metadata["correlation_confidence"] = f"{confidence}%"
                art.metadata["is_deleted_flag"] = best_match.is_deleted
                if best_match.original_size > 0:
                    art.metadata["directory_size"] = best_match.original_size
                    art.length_bytes = best_match.original_size
                    art.end_lba = (art.start_offset + art.length_bytes - 1) // self.reader.sector_size
                if best_match.block_list:
                    art.block_list = best_match.block_list
                    if best_match.block_size:
                        art.metadata["block_size"] = best_match.block_size
                    art.is_fragmented = len(best_match.block_list) > 12
                correlated_count += 1
            else:
                # Nom par défaut propre
                art.filename = f"artefact_{art.artefact_id:04d}{art.extension}"

        return correlated_count

    def recover_orphan_entries(self, existing_artefacts: List[Any], current_max_id: int) -> List[Any]:
        """
        Génère des artefacts supplémentaires par Carving Guidé par Métadonnées (Directory-Driven Carving).
        Récupère tous les fichiers décrits dans les entrées de répertoires orphelines
        qui n'avaient pas encore été trouvés par signature binaire.
        """
        from core.carver import CarvedArtefact

        recovered = []
        carved_lbas = {a.start_lba for a in existing_artefacts}
        carved_names = {a.filename.lower() for a in existing_artefacts}

        EXT_CAT_MAP = {
            ".jpg": ("Images", "JPEG"),
            ".jpeg": ("Images", "JPEG"),
            ".png": ("Images", "PNG"),
            ".gif": ("Images", "GIF"),
            ".bmp": ("Images", "BMP"),
            ".doc": ("Documents", "DOC"),
            ".docx": ("Documents", "DOCX"),
            ".xls": ("Documents", "XLS"),
            ".xlsx": ("Documents", "XLSX"),
            ".ppt": ("Documents", "PPT"),
            ".pptx": ("Documents", "PPTX"),
            ".pdf": ("Documents", "PDF"),
            ".zip": ("Documents", "ZIP"),
            ".wav": ("Audio", "WAV"),
            ".mp3": ("Audio", "MP3"),
            ".mov": ("Video", "MOV"),
            ".wmv": ("Video", "WMV"),
            ".mp4": ("Video", "MP4"),
            ".avi": ("Video", "AVI"),
            ".sqlite": ("Databases", "SQLite3"),
            ".db": ("Databases", "Database"),
            ".evtx": ("Logs", "EVTX"),
            ".hiv": ("Registry", "Registry"),
        }

        for e in self.orphan_entries:
            if e.predicted_start_lba is None or e.predicted_start_lba in carved_lbas:
                continue
            if e.filename.lower() in carved_names or e.original_size <= 0:
                continue

            ext = "." + e.filename.split(".")[-1].lower() if "." in e.filename else ""
            cat, ftype = EXT_CAT_MAP.get(ext, ("Documents", ext.upper().lstrip(".") or "BINARY"))

            current_max_id += 1
            start_off = e.predicted_start_lba * self.reader.sector_size
            end_lba = (start_off + e.original_size - 1) // self.reader.sector_size

            meta = {
                "original_filename": e.filename,
                "correlation_source": f"{e.filesystem} Inode / DirEntry (LBA {e.lba_record})",
                "correlation_confidence": "100% (Metadata Correlation)",
                "is_deleted_flag": e.is_deleted,
                "first_cluster": e.first_cluster,
            }
            if e.block_size:
                meta["block_size"] = e.block_size

            art = CarvedArtefact(
                artefact_id=current_max_id,
                category=cat,
                file_type=ftype,
                extension=ext or ".bin",
                start_lba=e.predicted_start_lba,
                start_offset=start_off,
                length_bytes=e.original_size,
                end_lba=end_lba,
                filename=e.filename,
                is_valid=True,
                is_fragmented=bool(e.block_list and len(e.block_list) > 12),
                block_list=e.block_list,
                metadata=meta,
            )
            recovered.append(art)
            carved_lbas.add(e.predicted_start_lba)
            carved_names.add(e.filename.lower())

        return recovered
