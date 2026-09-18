"""
DFR-Forensics - Moteur Forensique Pur-Python Ext2 / Ext3 / Ext4
Permet le décodage du Superblock (offset 1024), de la table des descripteurs de groupes,
des inodes, de l'arbre d'extents EXT4 (magic 0xF30A) et de l'arborescence complète, sans dépendance externe.
"""

import struct
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timezone
from core.image_reader import ForensicImageReader


def unix_timestamp_to_iso(ts: int) -> str:
    try:
        if ts <= 0 or ts > 4102444800:
            return ""
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


class ExtFileEntry:
    """Représente un fichier ou répertoire extrait d'un système Ext2/3/4."""

    def __init__(self, inode_num: int):
        self.inode_number: int = inode_num
        self.name: str = ""
        self.is_dir: bool = False
        self.is_deleted: bool = False
        self.source: str = "EXT"
        self.size: int = 0
        self.mode: int = 0
        self.uid: int = 0
        self.gid: int = 0
        self.created: str = ""
        self.modified: str = ""
        self.accessed: str = ""
        self.blocks: List[int] = []
        self.extents: List[Tuple[int, int, int]] = []
        self.use_extents: bool = False
        self.parent_entry: Optional["ExtFileEntry"] = None
        self.children: List["ExtFileEntry"] = []

    def __repr__(self):
        status = "DELETED" if self.is_deleted else "ACTIVE"
        kind = "DIR" if self.is_dir else "FILE"
        return f"<EXT [#{self.inode_number}] [{status}] [{kind}] '{self.name}' ({self.size} bytes)>"


class ExtReader:
    """Parseur médico-légal pour systèmes de fichiers Linux Ext2, Ext3 et Ext4."""

    def __init__(self, reader: ForensicImageReader, partition_offset_bytes: int = 0):
        self.reader = reader
        self.part_offset = partition_offset_bytes
        self.is_valid_ext = False

        # Superblock
        self.block_size: int = 1024
        self.inodes_count: int = 0
        self.blocks_count: int = 0
        self.first_data_block: int = 1
        self.blocks_per_group: int = 0
        self.inodes_per_group: int = 0
        self.inode_size: int = 128
        self.volume_name: str = ""

        # Arborescence
        self.root_entry: Optional[ExtFileEntry] = None
        self.all_entries: List[ExtFileEntry] = []
        self._bg_descriptors: List[Dict[str, int]] = []

        self._read_superblock()
        if self.is_valid_ext:
            self._read_block_group_descriptors()
            self._parse_tree()

    def _read_superblock(self):
        cand_offsets = [
            self.part_offset + 1024,
            self.part_offset + 8389632,
            self.part_offset + 25166848,
            self.part_offset + 33554432,
        ]
        sb = None
        self.sb_offset = None
        for cand in cand_offsets:
            if cand + 1024 <= self.reader.total_size_bytes:
                b = self.reader.read_bytes(cand, 1024)
                if len(b) >= 58 and struct.unpack_from("<H", b, 56)[0] == 0xEF53:
                    sb = b
                    self.sb_offset = cand
                    break

        if not sb:
            scan_limit = min(32 * 1024 * 1024, max(0, self.reader.total_size_bytes - self.part_offset))
            if scan_limit > 0:
                buf = self.reader.read_bytes(self.part_offset, scan_limit)
                pos = 0
                while True:
                    pos = buf.find(b"\x53\xEF", pos)
                    if pos == -1:
                        break
                    cand_sb = pos - 56
                    if cand_sb >= 0 and cand_sb % 1024 == 0:
                        b = buf[cand_sb : cand_sb + 1024]
                        if len(b) >= 58 and struct.unpack_from("<H", b, 56)[0] == 0xEF53:
                            sb = b
                            self.sb_offset = self.part_offset + cand_sb
                            break
                    pos += 2

        if not sb or len(sb) < 1024:
            self.is_valid_ext = False
            return

        s_magic = struct.unpack_from("<H", sb, 56)[0]
        if s_magic != 0xEF53:
            self.is_valid_ext = False
            return

        self.inodes_count = struct.unpack_from("<I", sb, 0)[0]
        self.blocks_count = struct.unpack_from("<I", sb, 4)[0]
        self.first_data_block = struct.unpack_from("<I", sb, 20)[0]
        s_log_block_size = struct.unpack_from("<I", sb, 24)[0]
        self.block_size = 1024 << s_log_block_size
        self.blocks_per_group = struct.unpack_from("<I", sb, 32)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 40)[0]

        s_rev_level = struct.unpack_from("<I", sb, 76)[0]
        if s_rev_level >= 1 and len(sb) > 88:
            self.inode_size = struct.unpack_from("<H", sb, 88)[0]
        else:
            self.inode_size = 128

        vol_name_raw = sb[120:136]
        self.volume_name = vol_name_raw.split(b"\x00")[0].decode("latin1", "replace").strip()
        self.is_valid_ext = True

    def _read_block_group_descriptors(self):
        if not self.blocks_per_group:
            return
        num_groups = (self.blocks_count + self.blocks_per_group - 1) // self.blocks_per_group
        num_groups = min(num_groups, 256)
        bgd_block = self.first_data_block + 1
        bgd_offset = self.part_offset + bgd_block * self.block_size
        bgd_size = num_groups * 32
        raw_bgd = self.reader.read_bytes(bgd_offset, bgd_size)

        # Si le BGD principal est vide/nul et qu'un superbloc de secours existe,
        # lire le BGD de secours situé après le superbloc de secours
        if (not raw_bgd or raw_bgd == b"\x00" * len(raw_bgd)) and self.sb_offset and self.sb_offset != self.part_offset + 1024:
            backup_bgd_offset = self.sb_offset + self.block_size
            raw_bgd = self.reader.read_bytes(backup_bgd_offset, bgd_size)

        self._bg_descriptors = []
        for i in range(num_groups):
            chunk = raw_bgd[i * 32 : (i + 1) * 32]
            if len(chunk) < 32:
                break
            bg_block_bitmap, bg_inode_bitmap, bg_inode_table = struct.unpack("<III", chunk[:12])
            self._bg_descriptors.append({
                "block_bitmap": bg_block_bitmap,
                "inode_bitmap": bg_inode_bitmap,
                "inode_table": bg_inode_table,
            })

    def _parse_extent_tree(self, extent_chunk: bytes) -> List[Tuple[int, int, int]]:
        """Décode un arbre d'extents EXT4 (magic 0xF30A). Retourne des tuples (logical_blk, phys_blk, count)."""
        if len(extent_chunk) < 12:
            return []
        magic, entries_cnt, max_cnt, depth = struct.unpack_from("<HHHH", extent_chunk, 0)
        if magic != 0xF30A:
            return []

        results: List[Tuple[int, int, int]] = []
        if depth == 0:
            # Feuilles d'extents directes
            for i in range(entries_cnt):
                offset = 12 + i * 12
                if offset + 12 > len(extent_chunk):
                    break
                ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack_from("<IHHI", extent_chunk, offset)
                phys_blk = (ee_start_hi << 32) | ee_start_lo
                actual_len = ee_len if ee_len <= 32768 else (ee_len - 32768)
                results.append((ee_block, phys_blk, actual_len))
        else:
            # Nœuds d'index intermédiaires
            for i in range(entries_cnt):
                offset = 12 + i * 12
                if offset + 12 > len(extent_chunk):
                    break
                ei_block, ei_leaf_lo, ei_leaf_hi = struct.unpack_from("<IIH", extent_chunk, offset)
                child_blk = (ei_leaf_hi << 32) | ei_leaf_lo
                if child_blk > 0:
                    child_bytes = self.reader.read_bytes(self.part_offset + child_blk * self.block_size, self.block_size)
                    results.extend(self._parse_extent_tree(child_bytes))

        return sorted(results, key=lambda x: x[0])

    def _read_inode(self, inode_num: int) -> Optional[Tuple[Dict[str, Any], List[int]]]:
        if inode_num < 1 or inode_num > self.inodes_count:
            return None

        group_idx = (inode_num - 1) // self.inodes_per_group
        if group_idx >= len(self._bg_descriptors):
            return None

        local_idx = (inode_num - 1) % self.inodes_per_group
        bg = self._bg_descriptors[group_idx]
        inode_table_block = bg["inode_table"]

        inode_offset = self.part_offset + inode_table_block * self.block_size + local_idx * self.inode_size
        raw_inode = self.reader.read_bytes(inode_offset, self.inode_size)
        if len(raw_inode) < 128:
            return None

        i_mode = struct.unpack_from("<H", raw_inode, 0)[0]
        i_uid = struct.unpack_from("<H", raw_inode, 2)[0]
        i_size = struct.unpack_from("<I", raw_inode, 4)[0]
        i_atime = struct.unpack_from("<I", raw_inode, 8)[0]
        i_ctime = struct.unpack_from("<I", raw_inode, 12)[0]
        i_mtime = struct.unpack_from("<I", raw_inode, 16)[0]
        i_dtime = struct.unpack_from("<I", raw_inode, 20)[0]
        i_gid = struct.unpack_from("<H", raw_inode, 24)[0]
        i_links = struct.unpack_from("<H", raw_inode, 26)[0]

        i_flags = struct.unpack_from("<I", raw_inode, 32)[0] if len(raw_inode) >= 36 else 0
        use_extents = bool(i_flags & 0x00080000) or (len(raw_inode) >= 42 and raw_inode[40:42] == b"\x0a\xf3")
        extents: List[Tuple[int, int, int]] = []
        if use_extents:
            extents = self._parse_extent_tree(raw_inode[40:100])
            block_pointers = [e[1] for e in extents]
        else:
            # 15 pointeurs de blocs (12 directs, 1 simple indirect, 1 double indirect, 1 triple indirect)
            block_pointers = list(struct.unpack("<15I", raw_inode[40:100]))

        meta = {
            "mode": i_mode,
            "uid": i_uid,
            "gid": i_gid,
            "size": i_size,
            "links": i_links,
            "atime": i_atime,
            "ctime": i_ctime,
            "mtime": i_mtime,
            "dtime": i_dtime,
            "is_dir": bool(i_mode & 0x4000),
            "is_file": bool(i_mode & 0x8000),
            "is_deleted": (i_dtime != 0) or (i_links == 0),
            "use_extents": use_extents,
            "extents": extents,
        }
        return meta, block_pointers

    def _read_file_blocks(self, block_pointers: List[int], file_size: int, extents: Optional[List[Tuple[int, int, int]]] = None) -> bytes:
        data = bytearray()
        needed_bytes = file_size

        # Mode EXT4 Extents
        if extents:
            for l_blk, p_blk, count in extents:
                if len(data) >= needed_bytes:
                    break
                read_len = count * self.block_size
                if p_blk == 0:
                    data.extend(b"\x00" * min(needed_bytes - len(data), read_len))
                else:
                    off = self.part_offset + p_blk * self.block_size
                    chunk = self.reader.read_bytes(off, read_len)
                    data.extend(chunk)
                if len(data) >= needed_bytes:
                    return bytes(data[:needed_bytes])
            return bytes(data[:needed_bytes])

        # 1. 12 Blocs directs
        for blk in block_pointers[:12]:
            if blk == 0:
                data.extend(b"\x00" * min(needed_bytes - len(data), self.block_size))
            else:
                off = self.part_offset + blk * self.block_size
                chunk = self.reader.read_bytes(off, self.block_size)
                data.extend(chunk)
            if len(data) >= needed_bytes:
                return bytes(data[:needed_bytes])

        # 2. Bloc simple indirect (pointer 12)
        if len(block_pointers) > 12:
            indir_blk = block_pointers[12]
            if indir_blk != 0 and len(data) < needed_bytes:
                indir_off = self.part_offset + indir_blk * self.block_size
                indir_data = self.reader.read_bytes(indir_off, self.block_size)
                pointers_count = len(indir_data) // 4
                indirect_ptrs = struct.unpack(f"<{pointers_count}I", indir_data[: pointers_count * 4])
                for blk in indirect_ptrs:
                    if blk == 0:
                        data.extend(b"\x00" * min(needed_bytes - len(data), self.block_size))
                    else:
                        off = self.part_offset + blk * self.block_size
                        chunk = self.reader.read_bytes(off, self.block_size)
                        data.extend(chunk)
                    if len(data) >= needed_bytes:
                        return bytes(data[:needed_bytes])

        # 3. Bloc double indirect (pointer 13)
        if len(block_pointers) > 13:
            dindir_blk = block_pointers[13]
            if dindir_blk != 0 and len(data) < needed_bytes:
                dind_off = self.part_offset + dindir_blk * self.block_size
                dind_data = self.reader.read_bytes(dind_off, self.block_size)
                pointers_count = len(dind_data) // 4
                dind_ptrs = struct.unpack(f"<{pointers_count}I", dind_data[: pointers_count * 4])
                for ind_blk in dind_ptrs:
                    if len(data) >= needed_bytes:
                        break
                    if ind_blk == 0:
                        data.extend(b"\x00" * min(needed_bytes - len(data), self.block_size * pointers_count))
                        continue
                    sub_off = self.part_offset + ind_blk * self.block_size
                    sub_bytes = self.reader.read_bytes(sub_off, self.block_size)
                    sub_ptrs = struct.unpack(f"<{pointers_count}I", sub_bytes[: pointers_count * 4])
                    for blk in sub_ptrs:
                        if blk == 0:
                            data.extend(b"\x00" * min(needed_bytes - len(data), self.block_size))
                        else:
                            off = self.part_offset + blk * self.block_size
                            chunk = self.reader.read_bytes(off, self.block_size)
                            data.extend(chunk)
                        if len(data) >= needed_bytes:
                            return bytes(data[:needed_bytes])

        return bytes(data[:needed_bytes])

    def _find_unallocated_deleted_inodes(self) -> List[Tuple[int, Dict[str, Any], List[int]]]:
        """Détecte les inodes supprimés (dtime != 0 ou links == 0) avec taille > 0 et blocs valides."""
        deleted = []
        for g_idx, bg in enumerate(self._bg_descriptors[:4]):
            it_block = bg["inode_table"]
            if it_block == 0:
                continue
            for i in range(min(self.inodes_per_group, 4096)):
                ino_num = g_idx * self.inodes_per_group + i + 1
                if ino_num < 11:
                    continue
                res = self._read_inode(ino_num)
                if not res:
                    continue
                meta, ptrs = res
                if meta["is_file"] and meta["is_deleted"] and meta["size"] > 0 and ptrs[0] != 0:
                    deleted.append((ino_num, meta, ptrs))
        return deleted

    def _parse_directory(self, inode_num: int, parent_entry: Optional[ExtFileEntry] = None, visited: Optional[set] = None) -> List[ExtFileEntry]:
        if visited is None:
            visited = set()
        if inode_num in visited:
            return []
        visited.add(inode_num)

        res = self._read_inode(inode_num)
        if not res:
            return []
        meta, ptrs = res
        dir_data = self._read_file_blocks(ptrs, meta["size"], extents=meta.get("extents"))

        entries: List[ExtFileEntry] = []
        slack_deleted_names: List[Tuple[int, str]] = []
        pos = 0
        while pos < len(dir_data) and pos < meta["size"]:
            if pos + 8 > len(dir_data):
                break
            child_inode, rec_len, name_len, file_type = struct.unpack_from("<IHBB", dir_data, pos)
            if rec_len == 0:
                break
            if pos + 8 + name_len > len(dir_data):
                break
            name = dir_data[pos + 8 : pos + 8 + name_len].decode("latin1", "replace")

            # Analyser le slack space dans l'intervalle [pos + min_len, pos + rec_len]
            min_len = ((8 + name_len + 3) // 4) * 4
            if rec_len > min_len:
                slack = dir_data[pos + min_len : pos + rec_len]
                s_pos = 0
                while s_pos < len(slack) - 8:
                    s_ino, s_rec, s_nlen, s_ft = struct.unpack_from("<IHBB", slack, s_pos)
                    if 1 <= s_nlen <= 60 and s_pos + 8 + s_nlen <= len(slack):
                        s_name = slack[s_pos + 8 : s_pos + 8 + s_nlen].decode("latin1", "replace")
                        if s_name and all(32 <= ord(c) < 127 for c in s_name) and s_name not in (".", ".."):
                            slack_deleted_names.append((s_ino, s_name))
                    sub_min = ((8 + s_nlen + 3) // 4) * 4 if 1 <= s_nlen <= 60 else 4
                    s_pos += max(4, sub_min)

            pos += rec_len

            if name in (".", "..") or child_inode == 0:
                continue

            child_res = self._read_inode(child_inode)
            if not child_res:
                continue
            c_meta, c_ptrs = child_res

            entry = ExtFileEntry(child_inode)
            entry.name = name
            entry.is_dir = c_meta["is_dir"]
            entry.is_deleted = c_meta["is_deleted"]
            entry.size = c_meta["size"]
            entry.mode = c_meta["mode"]
            entry.uid = c_meta["uid"]
            entry.gid = c_meta["gid"]
            entry.created = unix_timestamp_to_iso(c_meta["ctime"])
            entry.modified = unix_timestamp_to_iso(c_meta["mtime"])
            entry.accessed = unix_timestamp_to_iso(c_meta["atime"])
            entry.blocks = c_ptrs
            entry.extents = c_meta.get("extents", [])
            entry.use_extents = c_meta.get("use_extents", False)
            entry.parent_entry = parent_entry

            entries.append(entry)
            self.all_entries.append(entry)

            if entry.is_dir and not entry.is_deleted:
                entry.children = self._parse_directory(child_inode, parent_entry=entry, visited=visited)

        # Récupération des fichiers supprimés découverts dans le slack space des répertoires
        if slack_deleted_names:
            unalloc_inodes = self._find_unallocated_deleted_inodes()
            used_inodes = {e.inode_number for e in entries}
            available_inodes = [item for item in unalloc_inodes if item[0] not in used_inodes]

            for idx, (s_ino, s_name) in enumerate(slack_deleted_names):
                matched_ino = None
                matched_meta = None
                matched_ptrs = None

                if s_ino != 0:
                    res = self._read_inode(s_ino)
                    if res:
                        matched_ino = s_ino
                        matched_meta, matched_ptrs = res

                if not matched_ino and idx < len(available_inodes):
                    matched_ino, matched_meta, matched_ptrs = available_inodes[idx]

                if matched_ino and matched_meta and matched_ptrs:
                    del_entry = ExtFileEntry(matched_ino)
                    del_entry.name = s_name
                    del_entry.is_dir = matched_meta["is_dir"]
                    del_entry.is_deleted = True
                    del_entry.size = matched_meta["size"]
                    del_entry.mode = matched_meta["mode"]
                    del_entry.uid = matched_meta["uid"]
                    del_entry.gid = matched_meta["gid"]
                    del_entry.created = unix_timestamp_to_iso(matched_meta["ctime"])
                    del_entry.modified = unix_timestamp_to_iso(matched_meta["mtime"])
                    del_entry.accessed = unix_timestamp_to_iso(matched_meta["atime"])
                    del_entry.blocks = matched_ptrs
                    del_entry.extents = matched_meta.get("extents", [])
                    del_entry.use_extents = matched_meta.get("use_extents", False)
                    del_entry.parent_entry = parent_entry

                    entries.append(del_entry)
                    self.all_entries.append(del_entry)

        return entries

    def _parse_tree(self):
        root = ExtFileEntry(2)
        root.name = f"/ [Ext2/Ext3/Ext4 Root - {self.volume_name or 'Linux'}]"
        root.is_dir = True
        self.root_entry = root

        root_res = self._read_inode(2)
        if root_res:
            r_meta, r_ptrs = root_res
            root.blocks = r_ptrs
            root.extents = r_meta.get("extents", [])
            root.use_extents = r_meta.get("use_extents", False)
            root.size = r_meta["size"]
            root.created = unix_timestamp_to_iso(r_meta["ctime"])
            root.modified = unix_timestamp_to_iso(r_meta["mtime"])
            root.accessed = unix_timestamp_to_iso(r_meta["atime"])
            root.children = self._parse_directory(2, parent_entry=root)

    def extract_file_content(self, entry: ExtFileEntry) -> bytes:
        """Extrait le contenu d'un fichier Ext2/3/4."""
        if entry.is_dir:
            return b""
        if entry.use_extents and entry.extents:
            return self._read_file_blocks(entry.blocks, entry.size, extents=entry.extents)
        if not entry.blocks:
            return b""
        return self._read_file_blocks(entry.blocks, entry.size)
