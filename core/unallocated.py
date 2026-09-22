"""
DFR-Forensics - Moteur d'Extraction de l'Espace Non Alloué (Unallocated Space Engine)
Cartographie chirurgicale des blocs libres et clusters effacés à travers :
- NTFS ($Bitmap & MFT active data runs)
- FAT12 / FAT16 / FAT32 (Table d'allocation FAT)
- exFAT (Allocation Bitmap & Heap)
- EXT2 / EXT3 / EXT4 (Block Group Bitmaps)
- QNX4 / QNX6 (Power-Safe Inode & Block Allocation)
- Espace non partitionné (Unpartitioned drive slack)
"""

from typing import List, Tuple, Optional, Set
from core.image_reader import ForensicImageReader
from core.scanner import ScanDiagnostic, GPTPartitionEntry


def merge_lba_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Fusionne les plages LBA adjacentes ou se chevauchant en intervalles optimaux."""
    if not ranges:
        return []
    valid = [(s, e) for s, e in ranges if s <= e]
    if not valid:
        return []
    valid.sort(key=lambda x: x[0])
    merged: List[Tuple[int, int]] = []
    cur_s, cur_e = valid[0]
    for s, e in valid[1:]:
        if s <= cur_e + 1:
            cur_e = max(cur_e, e)
        else:
            merged.append((cur_s, cur_e))
            cur_s, cur_e = s, e
    merged.append((cur_s, cur_e))
    return merged


def extract_unallocated_ntfs(reader: ForensicImageReader, part_offset: int, part_sectors: int) -> List[Tuple[int, int]]:
    """Extrait les plages LBA des clusters libres NTFS via $Bitmap ou MFT."""
    try:
        from core.ntfs_reader import NTFSReader
        ntfs = NTFSReader(reader, partition_offset_bytes=part_offset, partition_size_bytes=part_sectors * 512)
        if not ntfs.is_valid_ntfs:
            return []

        spc = max(1, ntfs.sectors_per_cluster)
        part_lba = part_offset // reader.sector_size

        # Méthode 1 : Fichier $Bitmap (Record 6 de la MFT)
        bitmap_entry = next((e for e in ntfs.all_entries if e.record_number == 6), None)
        if bitmap_entry and bitmap_entry.has_data:
            try:
                bitmap_data = ntfs.extract_file_content(bitmap_entry)
                if bitmap_data:
                    free_ranges: List[Tuple[int, int]] = []
                    in_free = False
                    free_start = 0
                    total_clusters = min(len(bitmap_data) * 8, ntfs.total_sectors // spc if spc else len(bitmap_data) * 8)
                    for cluster_idx in range(total_clusters):
                        byte_pos = cluster_idx >> 3
                        bit_pos = cluster_idx & 7
                        is_allocated = (bitmap_data[byte_pos] >> bit_pos) & 1
                        if not is_allocated:
                            if not in_free:
                                in_free = True
                                free_start = cluster_idx
                        else:
                            if in_free:
                                in_free = False
                                s_lba = part_lba + free_start * spc
                                e_lba = part_lba + cluster_idx * spc - 1
                                free_ranges.append((s_lba, e_lba))
                    if in_free:
                        s_lba = part_lba + free_start * spc
                        e_lba = part_lba + total_clusters * spc - 1
                        free_ranges.append((s_lba, e_lba))
                    if free_ranges:
                        return merge_lba_ranges(free_ranges)
            except Exception:
                pass

        # Méthode 2 (Fallback) : Déduction par soustraction des data runs alloués
        allocated_clusters: Set[int] = set()
        for entry in ntfs.all_entries:
            if not entry.is_deleted and entry.has_data:
                for lcn, run_len in entry.data_runs:
                    if lcn is not None and run_len > 0:
                        for c in range(lcn, lcn + min(run_len, 50000)):
                            allocated_clusters.add(c)

        total_clusters = max(1, (part_sectors + spc - 1) // spc)
        free_ranges = []
        in_free = False
        free_start = 0
        for c in range(total_clusters):
            if c not in allocated_clusters:
                if not in_free:
                    in_free = True
                    free_start = c
            else:
                if in_free:
                    in_free = False
                    free_ranges.append((part_lba + free_start * spc, part_lba + c * spc - 1))
        if in_free:
            free_ranges.append((part_lba + free_start * spc, part_lba + total_clusters * spc - 1))
        return merge_lba_ranges(free_ranges)
    except Exception:
        return []


def extract_unallocated_fat(reader: ForensicImageReader, part_offset: int, part_sectors: int) -> List[Tuple[int, int]]:
    """Extrait les clusters libres de la table d'allocation FAT."""
    try:
        from core.fat_reader import FATReader
        fat = FATReader(reader, partition_offset_bytes=part_offset)
        if not fat.is_valid_fat:
            return []

        fat._load_fat_table()
        if not hasattr(fat, "_fat_table") or not fat._fat_table:
            return []

        data_lba = fat.data_start_offset // reader.sector_size
        spc = max(1, fat.sectors_per_cluster)
        free_ranges: List[Tuple[int, int]] = []
        in_free = False
        free_start = 2

        table_len = len(fat._fat_table)
        for c in range(2, table_len):
            val = fat._fat_table[c]
            if val == 0:
                if not in_free:
                    in_free = True
                    free_start = c
            else:
                if in_free:
                    in_free = False
                    s_lba = data_lba + (free_start - 2) * spc
                    e_lba = data_lba + (c - 2) * spc - 1
                    free_ranges.append((s_lba, e_lba))
        if in_free:
            s_lba = data_lba + (free_start - 2) * spc
            e_lba = data_lba + (table_len - 2) * spc - 1
            free_ranges.append((s_lba, e_lba))

        return merge_lba_ranges(free_ranges)
    except Exception:
        return []


def extract_unallocated_ext(reader: ForensicImageReader, part_offset: int, part_sectors: int) -> List[Tuple[int, int]]:
    """Extrait les blocs libres des Block Group Bitmaps d'une partition EXT2/3/4."""
    try:
        from core.ext_reader import ExtReader
        ext = ExtReader(reader, partition_offset_bytes=part_offset)
        if not ext.is_valid_ext or not ext.blocks_per_group or not ext.block_size:
            return []

        part_lba = part_offset // reader.sector_size
        sectors_per_block = max(1, ext.block_size // reader.sector_size)
        num_groups = (ext.blocks_count + ext.blocks_per_group - 1) // ext.blocks_per_group
        num_groups = min(num_groups, 512)

        free_ranges: List[Tuple[int, int]] = []
        for g_idx in range(num_groups):
            if g_idx >= len(ext._bg_descriptors):
                break
            bg = ext._bg_descriptors[g_idx]
            block_bitmap_num = bg.get("block_bitmap")
            if not block_bitmap_num:
                continue

            bm_offset = part_offset + block_bitmap_num * ext.block_size
            if bm_offset < 0 or bm_offset >= reader.total_size_bytes:
                continue

            bm_bytes = reader.read_bytes(bm_offset, min(ext.block_size, 4096))
            blocks_in_group = min(ext.blocks_per_group, ext.blocks_count - g_idx * ext.blocks_per_group)

            in_free = False
            free_start = 0
            for b_idx in range(blocks_in_group):
                byte_i = b_idx >> 3
                bit_i = b_idx & 7
                if byte_i >= len(bm_bytes):
                    break
                is_allocated = (bm_bytes[byte_i] >> bit_i) & 1
                global_block = ext.first_data_block + g_idx * ext.blocks_per_group + b_idx
                if not is_allocated:
                    if not in_free:
                        in_free = True
                        free_start = global_block
                else:
                    if in_free:
                        in_free = False
                        s_lba = part_lba + free_start * sectors_per_block
                        e_lba = part_lba + global_block * sectors_per_block - 1
                        free_ranges.append((s_lba, e_lba))
            if in_free:
                s_lba = part_lba + free_start * sectors_per_block
                e_lba = part_lba + (ext.first_data_block + g_idx * ext.blocks_per_group + blocks_in_group) * sectors_per_block - 1
                free_ranges.append((s_lba, e_lba))

        return merge_lba_ranges(free_ranges)
    except Exception:
        return []


def extract_unallocated_exfat(reader: ForensicImageReader, part_offset: int, part_sectors: int) -> List[Tuple[int, int]]:
    """Extrait les clusters libres d'un volume exFAT."""
    try:
        from core.exfat_reader import ExFATReader
        exfat = ExFATReader(reader, partition_offset_bytes=part_offset, partition_size_bytes=part_sectors * 512)
        if not exfat.is_valid_exfat:
            return []

        part_lba = part_offset // reader.sector_size
        spc = max(1, exfat.sectors_per_cluster)
        heap_lba = part_lba + exfat.cluster_heap_offset_sector

        allocated_clusters: Set[int] = set()
        for entry in exfat.all_entries:
            if not entry.is_deleted and entry.first_cluster >= 2:
                c_count = max(1, (entry.size + exfat.cluster_size - 1) // exfat.cluster_size) if entry.size > 0 else 1
                for c in range(entry.first_cluster, entry.first_cluster + min(c_count, 10000)):
                    allocated_clusters.add(c)

        free_ranges: List[Tuple[int, int]] = []
        in_free = False
        free_start = 2
        total_clusters = min(exfat.cluster_count, 500000)
        for c in range(2, 2 + total_clusters):
            if c not in allocated_clusters:
                if not in_free:
                    in_free = True
                    free_start = c
            else:
                if in_free:
                    in_free = False
                    s_lba = heap_lba + (free_start - 2) * spc
                    e_lba = heap_lba + (c - 2) * spc - 1
                    free_ranges.append((s_lba, e_lba))
        if in_free:
            s_lba = heap_lba + (free_start - 2) * spc
            e_lba = heap_lba + total_clusters * spc - 1
            free_ranges.append((s_lba, e_lba))

        return merge_lba_ranges(free_ranges)
    except Exception:
        return []


def extract_unallocated_qnx(reader: ForensicImageReader, part_offset: int, part_sectors: int) -> List[Tuple[int, int]]:
    """Extrait les blocs libres QNX4 / QNX6 via le bitmap d'allocation."""
    try:
        from core.crypto_engine import PartitionStream
        part_size = part_sectors * reader.sector_size
        part_lba = part_offset // reader.sector_size

        try:
            import dissect.qnxfs as qnxfs
            import dissect.qnxfs.qnx6 as qnx6
            from dissect.util.stream import RunlistStream

            stream = PartitionStream(reader, part_offset, part_size)
            if qnxfs.is_qnxfs(stream):
                stream.seek(0)
                fs = qnxfs.QNXFS(stream)
                if isinstance(fs, qnxfs.QNX6) and hasattr(fs, "sb") and hasattr(fs.sb, "Bitmap"):
                    bm_node = fs.sb.Bitmap
                    runs = list(qnx6._generate_dataruns(fs, bm_node.size, bm_node.ptr, bm_node.levels))
                    bm_stream = RunlistStream(fs.fh, runs, bm_node.size, fs.block_size)
                    bm = bm_stream.read()

                    spb = max(1, fs.block_size // reader.sector_size)
                    free_ranges: List[Tuple[int, int]] = []
                    in_free = False
                    free_start = 0
                    for b in range(fs.num_blocks):
                        byte_idx = b // 8
                        bit_idx = b % 8
                        is_alloc = ((bm[byte_idx] >> bit_idx) & 1) if byte_idx < len(bm) else 0
                        if not is_alloc:
                            if not in_free:
                                in_free = True
                                free_start = b
                        else:
                            if in_free:
                                in_free = False
                                s_lba = part_lba + free_start * spb
                                e_lba = min(part_lba + part_sectors - 1, part_lba + b * spb - 1)
                                free_ranges.append((s_lba, e_lba))
                    if in_free:
                        s_lba = part_lba + free_start * spb
                        e_lba = min(part_lba + part_sectors - 1, part_lba + fs.num_blocks * spb - 1)
                        free_ranges.append((s_lba, e_lba))
                    return merge_lba_ranges(free_ranges)
        except Exception:
            pass

        return []
    except Exception:
        return []


def extract_unallocated_apfs(reader: ForensicImageReader, part_offset: int, part_sectors: int) -> List[Tuple[int, int]]:
    """
    Extrait les plages LBA des blocs libres APFS via le Space Manager (Spaceman)
    ou par inversion mathématique d'intervalles des conteneurs NXSB.
    """
    try:
        import struct

        hdr = reader.read_bytes(part_offset, 4096)
        if len(hdr) < 64:
            return []

        # En APFS, nx_magic 'NXSB' se trouve à l'offset 32 du bloc
        magic_offset = -1
        if hdr[32:36] == b"NXSB":
            magic_offset = 32
        elif hdr[:4] == b"NXSB":
            magic_offset = 0

        if magic_offset == -1:
            return []

        desc_base = 0
        desc_blocks = 0
        data_base = 0
        data_blocks = 0
        spaceman_oid = 0
        block_size = 4096
        total_blocks = 0

        if magic_offset == 32:
            try:
                import dissect.apfs.c_apfs as c
                sb_c = c.c_apfs.nx_superblock(hdr)
                block_size = getattr(sb_c, "nx_block_size", 4096) or 4096
                total_blocks = getattr(sb_c, "nx_block_count", 0)
                desc_base = getattr(sb_c, "nx_xp_desc_base", 0)
                desc_blocks = getattr(sb_c, "nx_xp_desc_blocks", 0) & 0x7FFFFFFF
                data_base = getattr(sb_c, "nx_xp_data_base", 0)
                data_blocks = getattr(sb_c, "nx_xp_data_blocks", 0) & 0x7FFFFFFF
                spaceman_oid = getattr(sb_c, "nx_spaceman_oid", 0)
            except Exception:
                # Offsets exacts de la spécification Apple APFS nx_superblock_t
                block_size = struct.unpack_from("<I", hdr, 36)[0]
                total_blocks = struct.unpack_from("<Q", hdr, 40)[0]
                desc_blocks = struct.unpack_from("<I", hdr, 104)[0] & 0x7FFFFFFF
                data_blocks = struct.unpack_from("<I", hdr, 108)[0] & 0x7FFFFFFF
                desc_base = struct.unpack_from("<Q", hdr, 112)[0]
                data_base = struct.unpack_from("<Q", hdr, 120)[0]
                spaceman_oid = struct.unpack_from("<Q", hdr, 152)[0]
        else:
            block_size = struct.unpack_from("<I", hdr, 4)[0]
            total_blocks = struct.unpack_from("<Q", hdr, 8)[0]

        if block_size not in (512, 1024, 2048, 4096, 8192, 16384):
            block_size = 4096
        if total_blocks <= 0 or total_blocks > (part_sectors * reader.sector_size // block_size + 1000):
            total_blocks = max(1, part_sectors * reader.sector_size // block_size)

        spb = max(1, block_size // reader.sector_size)
        part_lba = part_offset // reader.sector_size
        free_block_ranges: List[Tuple[int, int]] = []

        # 1. Tentative Spaceman : Balayage de la zone de données de checkpoint (nx_xp_data_base)
        # pour repérer le bloc Spaceman physique (type 0x0005)
        spaceman_block = None
        if data_base and data_blocks:
            search_blocks = min(data_blocks, 1024)
            for b_i in range(search_blocks):
                blk_num = data_base + b_i
                if blk_num >= total_blocks:
                    break
                blk_data = reader.read_bytes(part_offset + blk_num * block_size, block_size)
                if len(blk_data) >= 32:
                    o_oid = struct.unpack_from("<Q", blk_data, 8)[0]
                    o_type = struct.unpack_from("<I", blk_data, 24)[0]
                    if (o_type & 0x0000FFFF) == 0x0005 or (spaceman_oid and o_oid == spaceman_oid):
                        spaceman_block = blk_data
                        break

        if spaceman_block and len(spaceman_block) >= 140:
            try:
                import dissect.apfs.c_apfs as c
                sm = c.c_apfs.spaceman_phys(spaceman_block)
                dev = sm.sm_dev[0]
                dev_cab_count = getattr(dev, "sm_cab_count", 0)
                dev_cib_count = getattr(dev, "sm_cib_count", 0)
                dev_addr_offset = getattr(dev, "sm_addr_offset", 0)

                cib_paddrs: List[int] = []
                if dev_cab_count > 0 and 0 < dev_addr_offset < total_blocks:
                    # Lecture des Chunk Address Blocks (CAB)
                    cab_data = reader.read_bytes(part_offset + dev_addr_offset * block_size, block_size)
                    if len(cab_data) >= 40:
                        cab = c.c_apfs.cib_addr_block(cab_data)
                        for paddr in getattr(cab, "cab_cib_addr", []):
                            if 0 < paddr < total_blocks:
                                cib_paddrs.append(paddr)
                elif dev_cib_count > 0 and 0 < dev_addr_offset < total_blocks:
                    for c_idx in range(min(dev_cib_count, 1024)):
                        c_addr = dev_addr_offset + c_idx
                        if 0 < c_addr < total_blocks:
                            cib_paddrs.append(c_addr)

                for cib_paddr in cib_paddrs:
                    cib_data = reader.read_bytes(part_offset + cib_paddr * block_size, block_size)
                    if len(cib_data) < 40:
                        continue
                    cib = c.c_apfs.chunk_info_block(cib_data)
                    for ci in getattr(cib, "cib_chunk_info", []):
                        ci_addr = getattr(ci, "ci_addr", 0)
                        ci_blocks = getattr(ci, "ci_block_count", 0)
                        ci_free = getattr(ci, "ci_free_count", 0)
                        ci_bm = getattr(ci, "ci_bitmap_addr", 0)

                        if ci_blocks == 0 or ci_addr >= total_blocks:
                            continue

                        if ci_free == ci_blocks:
                            # Chunk 100% libre
                            free_block_ranges.append((ci_addr, ci_addr + ci_blocks - 1))
                        elif 0 < ci_free < ci_blocks and 0 < ci_bm < total_blocks:
                            # Lecture du bitmap d'allocation de ce chunk
                            bm_data = reader.read_bytes(part_offset + ci_bm * block_size, block_size)
                            in_free = False
                            free_start = 0
                            scan_blocks = min(ci_blocks, len(bm_data) * 8)
                            for b_idx in range(scan_blocks):
                                byte_i = b_idx >> 3
                                bit_i = b_idx & 7
                                is_alloc = (bm_data[byte_i] >> bit_i) & 1
                                if not is_alloc:
                                    if not in_free:
                                        in_free = True
                                        free_start = b_idx
                                else:
                                    if in_free:
                                        in_free = False
                                        free_block_ranges.append((ci_addr + free_start, ci_addr + b_idx - 1))
                            if in_free:
                                free_block_ranges.append((ci_addr + free_start, ci_addr + scan_blocks - 1))
            except Exception:
                pass

        # 2. Fallback robuste : Inversion mathématique d'intervalles alloués
        if not free_block_ranges:
            try:
                allocated_intervals: List[Tuple[int, int]] = []
                # Superblock
                allocated_intervals.append((0, 0))
                # Checkpoints
                if desc_blocks:
                    allocated_intervals.append((desc_base, desc_base + (desc_blocks & 0x7FFFFFFF) - 1))
                if data_blocks:
                    allocated_intervals.append((data_base, data_base + (data_blocks & 0x7FFFFFFF) - 1))

                # Extents alloués des volumes via dissect si disponible
                try:
                    import dissect.apfs as apfs
                    from core.crypto_engine import PartitionStream
                    stream = PartitionStream(reader, part_offset, part_sectors * reader.sector_size)
                    container = None
                    try:
                        container = apfs.APFS(stream)
                    except Exception:
                        pass
                    if container:
                        for vol in getattr(container, "volumes", []):
                            if hasattr(vol, "fext_tree") and vol.fext_tree:
                                for _, key, val in vol.fext_tree.records():
                                    paddr = getattr(val, "phys_block_num", 0) or getattr(val, "paddr", 0)
                                    length = getattr(val, "length", 0) or getattr(val, "block_count", 0)
                                    if paddr and length and paddr < total_blocks:
                                        allocated_intervals.append((paddr, min(total_blocks - 1, paddr + length - 1)))
                except Exception:
                    pass

                # Inversion uniquement si nous avons effectivement pu détecter des structures allouées internes
                if len(allocated_intervals) > 1:
                    merged_alloc = merge_lba_ranges(allocated_intervals)
                    curr = 0
                    for a_s, a_e in merged_alloc:
                        if a_s > curr:
                            free_block_ranges.append((curr, a_s - 1))
                        curr = max(curr, a_e + 1)
                    if curr < total_blocks:
                        free_block_ranges.append((curr, total_blocks - 1))
            except Exception:
                pass

        if free_block_ranges:
            lba_ranges = []
            for b_start, b_end in free_block_ranges:
                s_lba = part_lba + b_start * spb
                e_lba = min(part_lba + part_sectors - 1, part_lba + (b_end + 1) * spb - 1)
                if s_lba <= e_lba:
                    lba_ranges.append((s_lba, e_lba))
            return merge_lba_ranges(lba_ranges)

    except Exception:
        pass

    return []



def get_unallocated_ranges_for_partition(
    reader: ForensicImageReader,
    p: GPTPartitionEntry,
) -> List[Tuple[int, int]]:
    """
    Extrait les plages LBA de l'espace non alloué pour une partition spécifique.
    Teste successivement NTFS, FAT, EXT, exFAT, QNX et APFS.
    Si aucun FS n'est exploitable, renvoie une liste vide.
    """
    part_offset = p.first_lba * reader.sector_size
    part_sectors = max(1, p.last_lba - p.first_lba + 1)
    fs_hint = (p.detected_fs or p.type_name or "").upper()

    # 1. Test NTFS
    if "NTFS" in fs_hint or fs_hint == "":
        ranges = extract_unallocated_ntfs(reader, part_offset, part_sectors)
        if ranges:
            return ranges

    # 2. Test FAT
    if "FAT" in fs_hint or fs_hint == "":
        ranges = extract_unallocated_fat(reader, part_offset, part_sectors)
        if ranges:
            return ranges

    # 3. Test EXT
    if "EXT" in fs_hint or fs_hint == "":
        ranges = extract_unallocated_ext(reader, part_offset, part_sectors)
        if ranges:
            return ranges

    # 4. Test exFAT
    if "EXFAT" in fs_hint or fs_hint == "":
        ranges = extract_unallocated_exfat(reader, part_offset, part_sectors)
        if ranges:
            return ranges

    # 5. Test QNX
    if "QNX" in fs_hint:
        ranges = extract_unallocated_qnx(reader, part_offset, part_sectors)
        if ranges:
            return ranges

    # 6. Test Apple APFS
    if "APFS" in fs_hint or "APPLE" in fs_hint or fs_hint == "":
        ranges = extract_unallocated_apfs(reader, part_offset, part_sectors)
        if ranges:
            return ranges

    # 7. Test Apple HFS+
    if "HFS" in fs_hint or fs_hint == "":
        ranges = extract_unallocated_hfs(reader, part_offset, part_sectors)
        if ranges:
            return ranges

    return []


def extract_unallocated_hfs(reader: ForensicImageReader, part_offset: int, part_sectors: int) -> List[Tuple[int, int]]:
    """Extrait les plages de blocs libres d'un volume Apple HFS+ via son fichier $AllocationFile."""
    try:
        from core.hfs_reader import HFSReader
        hfs = HFSReader(reader, partition_offset_bytes=part_offset, partition_size_bytes=part_sectors * reader.sector_size)
        if not hfs.is_valid_hfs or not hfs.allocation_file_extents:
            return []

        part_lba = part_offset // reader.sector_size
        sectors_per_block = max(1, hfs.block_size // reader.sector_size)

        # Lire le bitmap complet d'allocation
        bitmap = hfs.get_allocation_bitmap()
        if not bitmap:
            return []

        total_blocks = min(hfs.total_blocks, len(bitmap) * 8)
        free_ranges: List[Tuple[int, int]] = []
        in_free = False
        free_start = 0

        # En HFS+, bit 1 = bloc alloué, bit 0 = bloc libre !
        for b_idx in range(total_blocks):
            byte_val = bitmap[b_idx // 8]
            bit_val = (byte_val >> (7 - (b_idx % 8))) & 1

            if bit_val == 0:  # Bloc libre
                if not in_free:
                    in_free = True
                    free_start = b_idx
            else:
                if in_free:
                    in_free = False
                    s_lba = part_lba + free_start * sectors_per_block
                    e_lba = part_lba + b_idx * sectors_per_block - 1
                    free_ranges.append((s_lba, e_lba))

        if in_free:
            s_lba = part_lba + free_start * sectors_per_block
            e_lba = part_lba + total_blocks * sectors_per_block - 1
            free_ranges.append((s_lba, e_lba))

        return merge_lba_ranges(free_ranges)
    except Exception:
        return []


def get_unallocated_ranges_for_disk(
    reader: ForensicImageReader,
    diag: Optional[ScanDiagnostic] = None,
    target_partition: Optional[GPTPartitionEntry] = None,
) -> List[Tuple[int, int]]:
    """
    Détermine l'ensemble des plages LBA d'espace non alloué à carver :
    - Si target_partition est fournie : extrait l'espace non alloué de cette partition.
    - Si target_partition est None (Disque entier) : extrait l'espace non alloué de toutes les partitions
      reconnues ainsi que l'espace libre non partitionné (gaps inter-partitions).
    """
    if target_partition:
        ranges = get_unallocated_ranges_for_partition(reader, target_partition)
        # Si le système de fichiers est introuvable, on retourne la plage complète de la partition
        return ranges if ranges else [(target_partition.first_lba, target_partition.last_lba)]

    all_ranges: List[Tuple[int, int]] = []
    tot_sectors = reader.total_sectors

    if not diag or not diag.partitions:
        # Aucun schéma de partition : retourne l'intégralité du disque
        return [(0, tot_sectors - 1)]

    # 1. Trier les partitions par LBA de début
    parts = sorted(diag.partitions, key=lambda p: p.first_lba)

    # 2. Espace non alloué non-partitionné avant la 1ère partition
    if parts[0].first_lba > 34:
        all_ranges.append((34, parts[0].first_lba - 1))

    # 3. Pour chaque partition : espace non alloué interne
    for i, p in enumerate(parts):
        p_ranges = get_unallocated_ranges_for_partition(reader, p)
        if p_ranges:
            all_ranges.extend(p_ranges)
        else:
            # Si le FS de cette partition est inconnu, on inclut toute la partition
            all_ranges.append((p.first_lba, p.last_lba))

        # Espace non partitionné entre partitions
        if i + 1 < len(parts):
            next_start = parts[i + 1].first_lba
            if next_start > p.last_lba + 1:
                all_ranges.append((p.last_lba + 1, next_start - 1))

    # 4. Espace non partitionné après la dernière partition
    if parts[-1].last_lba + 1 < tot_sectors - 34:
        all_ranges.append((parts[-1].last_lba + 1, tot_sectors - 35))

    return merge_lba_ranges(all_ranges)
