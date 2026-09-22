"""
DFR-Forensics - Moteur de scan, diagnostic et carver de signatures
Détecte l'état du MBR, de la GPT primaire, de la GPT secondaire,
la frontière exacte du wipe et les conteneurs/FS survivants.
"""

import struct
from typing import List, Optional, Tuple, Dict, Any
from core.image_reader import ForensicImageReader
from core.gpt_structures import (
    ProtectiveMBR,
    GPTHeader,
    GPTPartitionEntry,
    compute_partition_array_crc32,
    KNOWN_GUIDS,
)


KNOWN_SIGNATURES = [
    (0, b"LUKS\xba\xbe\x00\x01", "LUKS1 Encrypted Container"),
    (0, b"LUKS\xba\xbe\x00\x02", "LUKS2 Encrypted Container"),
    (3, b"NTFS    ", "NTFS Filesystem"),
    (54, b"FAT12   ", "FAT12 Filesystem"),
    (54, b"FAT16   ", "FAT16 Filesystem"),
    (82, b"FAT32   ", "FAT32 Filesystem"),
    (1080, b"\x53\xef", "ext2/ext3/ext4 Filesystem"),
    (3, b"EXFAT   ", "exFAT Filesystem"),
    (3, b"-FVE-FS-", "BitLocker Encrypted Volume"),
    (0, b"NXSB", "Apple APFS Container"),
    (32, b"NXSB", "Apple APFS Container"),
    (0, b"\xeb\x10\x90\x00", "QNX6 Bootblock (Automotive Head Unit)"),
    (8192, b"\x22\x11\x19\x68", "QNX6 Power-Safe Filesystem"),
    (8192, b"\x68\x19\x11\x22", "QNX6 Power-Safe Filesystem"),
    (11776, b"\x22\x11\x19\x68", "QNX6 Power-Safe (Secondary Generation)"),
    (11776, b"\x68\x19\x11\x22", "QNX6 Power-Safe (Secondary Generation)"),
    (4096, b"\x22\x11\x19\x68", "QNX6 Power-Safe Filesystem"),
    (4096, b"\x68\x19\x11\x22", "QNX6 Power-Safe Filesystem"),
    (512, b"/\x00", "QNX4 Filesystem Root Directory"),
    (0, b"XFSB", "XFS Filesystem"),
    (44, b"QSSL_F3S", "QNX Flash Filesystem (F3S)"),
    # Apple HFS+ / HFSX
    (1024, b"H+", "Apple HFS+ Filesystem"),
    (1024, b"HX", "Apple HFSX Filesystem"),
    # Systèmes Linux Embarqués / IoT
    (0, b"hsqs", "SquashFS Filesystem"),
    (0, b"sqsh", "SquashFS Filesystem (Big-Endian)"),
    (0, b"shsq", "SquashFS Filesystem (v3 LE)"),
    (0, b"qshs", "SquashFS Filesystem (v3 BE)"),
    (0, b"\x28\xcd\x3d\x45", "CramFS Filesystem (LE)"),
    (0, b"\x45\x3d\xcd\x28", "CramFS Filesystem (BE)"),
    (0, b"-rom1fs-", "RomFS Filesystem"),
    (0, b"\x19\x85", "JFFS2 Filesystem"),
    (0, b"HDR0", "Broadcom TRX Firmware Container"),
    (0, b"\x27\x05\x19\x56", "U-Boot uImage Container"),
    (0, b"\xd0\x0d\xfe\xed", "U-Boot FIT Image Container"),
    (0, b"ANDROID!", "Android Boot Image"),
    (0, b"070701", "CPIO / Initramfs Archive"),
    (0, b"070702", "CPIO / Initramfs Archive (CRC)"),
    (0, b"UBI#", "UBI Flash Container"),
    (1024, b"\x10\x20\xf5\xf2", "F2FS Filesystem (Android)"),
    (1024, b"\xe2\xe1\xf5\xe0", "EROFS Filesystem (Android)"),
    # Signatures de secours (Backup Boot Sectors)
    (3072 + 82, b"FAT32   ", "FAT32 Filesystem (Backup Boot Sector)"),
    (6144 + 3, b"EXFAT   ", "exFAT Filesystem (Backup VBR)"),
]


def identify_fs_signature(sector_data: bytes) -> Optional[str]:
    """Inspecte un ou plusieurs secteurs de début de partition pour identifier le format."""
    if len(sector_data) >= 512:
        first_512 = sector_data[:512]
        # BitLocker : vérification prioritaire des GUIDs Microsoft BDE/EOW ou signature Vista -FVE-FS-
        bde_guid1 = b";\xd6gI).\xd8J\x83\x99\xf6\xa39\xe3\xd0\x01"   # INFORMATION_OFFSET_GUID (Win 7/8/10/11)
        bde_guid2 = b";M\xa8\x92\x80\xdd\x0eM\x9eN\xb1\xe3(N\xae\xd8" # EOW_INFORMATION_OFFSET_GUID
        if bde_guid1 in first_512 or bde_guid2 in first_512 or first_512[3:11] == b"-FVE-FS-":
            return "BitLocker Encrypted Volume"
        if b"QSSL_F3S" in first_512:
            return "QNX Flash Filesystem (ETFS / F3S)"

    for offset, sig, label in KNOWN_SIGNATURES:
        if len(sector_data) >= offset + len(sig):
            if sector_data[offset : offset + len(sig)] == sig:
                return label
    return None


def detect_all_filesystems(sample_data: bytes) -> List[str]:
    """
    Détecte tous les systèmes de fichiers valides présents dans un échantillon de partition.
    """
    detected = []
    if len(sample_data) >= 512:
        first_512 = sample_data[:512]
        # Détection BitLocker prioritaire (évite la fausse détection FAT32 ou NTFS du secteur d'amorçage)
        bde_guid1 = b";\xd6gI).\xd8J\x83\x99\xf6\xa39\xe3\xd0\x01"
        bde_guid2 = b";M\xa8\x92\x80\xdd\x0eM\x9eN\xb1\xe3(N\xae\xd8"
        if bde_guid1 in first_512 or bde_guid2 in first_512 or first_512[3:11] == b"-FVE-FS-":
            detected.append("BitLocker")

        if sample_data[3:11] == b"NTFS    ":
            detected.append("NTFS")
        if sample_data[54:62] == b"FAT16   ":
            detected.append("FAT16")
        elif sample_data[54:62] == b"FAT12   ":
            detected.append("FAT12")
        elif sample_data[82:90] == b"FAT32   ":
            detected.append("FAT32")
        elif sample_data[3:11] == b"EXFAT   ":
            detected.append("exFAT")
        elif sample_data[:4] == b"NXSB" or (len(sample_data) >= 36 and sample_data[32:36] == b"NXSB"):
            detected.append("APFS")
        elif sample_data[:4] == b"\xeb\x10\x90\x00":
            detected.append("QNX6")
        elif b"QSSL_F3S" in first_512:
            detected.append("QNX")

    # Vérification des secteurs de secours si le secteur 0 a été effacé
    if len(sample_data) >= 3072 + 90:
        if sample_data[3072 + 82 : 3072 + 90] == b"FAT32   " and "FAT32" not in detected:
            detected.append("FAT32")
    if len(sample_data) >= 6144 + 11:
        if sample_data[6144 + 3 : 6144 + 11] == b"EXFAT   " and "exFAT" not in detected:
            detected.append("exFAT")

    # QNX6 Power-Safe Superblock (magic 0x68191122 aux offsets 8192, 11776 et 4096, LE ou BE)
    if len(sample_data) >= 8192 + 4:
        s8192 = sample_data[8192:8196]
        s4096 = sample_data[4096:4100] if len(sample_data) >= 4100 else b""
        s11776 = sample_data[11776:11780] if len(sample_data) >= 11780 else b""
        qnx6_magics = (b"\x22\x11\x19\x68", b"\x68\x19\x11\x22")
        if (s8192 in qnx6_magics or s4096 in qnx6_magics or s11776 in qnx6_magics) and "QNX6" not in detected:
            detected.append("QNX6")

    # QNX4 Superblock (offset 512, root directory "/")
    if len(sample_data) >= 576:
        if sample_data[512:514] == b"/\x00":
            detected.append("QNX4")

    # Ext2/Ext3 Superblock (offset 1024, magic 0xEF53 à 1080)
    if len(sample_data) >= 1082:
        if sample_data[1080:1082] == b"\x53\xef":
            detected.append("Ext2/Ext3")

    # HFS+ / HFSX (offset 1024, magic 'H+' ou 'HX')
    if len(sample_data) >= 1026:
        if sample_data[1024:1026] in (b"H+", b"HX"):
            detected.append("HFS+")

    # SquashFS & Formats IoT Embarqués
    if len(sample_data) >= 4:
        if sample_data[:4] in (b"hsqs", b"sqsh", b"shsq", b"qshs"):
            detected.append("SquashFS")
        elif sample_data[:4] in (b"\x28\xcd\x3d\x45", b"\x45\x3d\xcd\x28"):
            detected.append("CramFS")
        elif sample_data[:4] == b"HDR0":
            detected.append("TRX Container")
        elif sample_data[:4] == b"\x27\x05\x19\x56":
            detected.append("uImage")
        elif sample_data[:4] == b"\xd0\x0d\xfe\xed":
            detected.append("FIT Image")
        elif sample_data[:8] == b"ANDROID!":
            detected.append("Android Boot")
        elif sample_data[:8] == b"-rom1fs-":
            detected.append("RomFS")
        elif sample_data[:2] in (b"\x19\x85", b"\x85\x19"):
            detected.append("JFFS2")
        elif sample_data[:6] in (b"070701", b"070702"):
            detected.append("CPIO")
        elif sample_data[:4] == b"UBI#":
            detected.append("UBI")

    # QNX Flash F3S
    if b"QSSL_F3S" in sample_data[:4096]:
        detected.append("QNX F3S")

    # F2FS / EROFS (offset 1024)
    if len(sample_data) >= 1028:
        if sample_data[1024:1028] == b"\x10\x20\xf5\xf2":
            detected.append("F2FS")
        elif sample_data[1024:1028] == b"\xe2\xe1\xf5\xe0":
            detected.append("EROFS")

    # UFS1 / UFS2 Superblocks
    if len(sample_data) >= 8192 + 2048:
        chunk = sample_data[8192 : 8192 + 4096]
        if b"\x19\x54\x01\x19" in chunk or b"\x54\x19\x01\x19" in chunk:
            detected.append("UFS1")

    if len(sample_data) >= 65536 + 2048:
        chunk = sample_data[65536 : 65536 + 4096]
        if b"\x19\x54\x01\x19" in chunk or b"\x54\x19\x01\x19" in chunk:
            detected.append("UFS2")

    return detected


class ScanDiagnostic:
    """Rapport d'analyse global du disque."""

    def __init__(self):
        self.total_sectors: int = 0
        self.sector_size: int = 512
        self.total_size_bytes: int = 0

        # MBR
        self.mbr_present: bool = False
        self.mbr_valid: bool = False
        self.mbr_is_all_zero: bool = False

        # Primary GPT
        self.primary_gpt_present: bool = False
        self.primary_gpt_valid_crc: bool = False
        self.primary_gpt_header: Optional[GPTHeader] = None
        self.primary_partitions_valid: bool = False

        # Backup GPT
        self.backup_gpt_present: bool = False
        self.backup_gpt_valid_crc: bool = False
        self.backup_gpt_header: Optional[GPTHeader] = None
        self.backup_partitions_valid: bool = False

        # Partitions identifiées
        self.partitions: List[GPTPartitionEntry] = []

        # Frontière d'effacement
        self.wipe_frontier_lba: Optional[int] = None
        self.wiped_sectors_count: int = 0
        self.wiped_bytes: int = 0

        # Drapeaux de mode conteneur
        self.is_standalone_volume: bool = False
        self.is_logical_image: bool = False

        # Recommandation de restauration
        self.can_restore_from_backup: bool = False
        self.status_summary: str = ""


class DiskScanner:
    """Analyseur forensique de géométrie et d'intégrité."""

    def __init__(self, reader: ForensicImageReader):
        self.reader = reader
        self.sector_size = reader.sector_size
        self.total_sectors = reader.total_sectors

    def _enrich_partition_entry(self, entry: GPTPartitionEntry):
        """Détecte les systèmes de fichiers, conteneurs chiffrés et sous-volumes APFS."""
        try:
            read_bytes_count = min(65536 + 4096, max(16384, entry.total_sectors * self.sector_size))
            fs_sample = self.reader.read_bytes(entry.first_lba * self.sector_size, read_bytes_count)
            entry.detected_fs = identify_fs_signature(fs_sample)
            all_fs = detect_all_filesystems(fs_sample)
            entry.coexisting_filesystems = all_fs
            if len(all_fs) > 1:
                entry.multi_fs_warning = True
            if (not entry.detected_fs or entry.detected_fs == "Unknown") and all_fs:
                entry.detected_fs = all_fs[0]

            # Conteneurs chiffrés BitLocker / LUKS
            if entry.detected_fs and any(k in entry.detected_fs for k in ["LUKS", "BitLocker"]):
                try:
                    from core.crypto_engine import EncryptedVolumeHandler
                    h = EncryptedVolumeHandler(self.reader, entry.first_lba, entry.total_sectors)
                    if h.is_encrypted:
                        entry.crypto_metadata = h.metadata
                except Exception:
                    pass

            # Sous-volumes APFS
            if entry.detected_fs and "APFS" in entry.detected_fs.upper():
                try:
                    from core.apfs_reader import APFSReader
                    part_size = entry.total_sectors * self.sector_size
                    apfs_probe = APFSReader(self.reader, partition_offset_bytes=entry.first_lba * self.sector_size, partition_size_bytes=part_size)
                    if apfs_probe.is_valid_apfs and apfs_probe.volumes:
                        entry.sub_volumes = [
                            {
                                "name": v.name,
                                "uuid": v.uuid,
                                "is_encrypted": v.is_encrypted,
                                "fs_type": "Volume APFS",
                            }
                            for v in apfs_probe.volumes
                        ]
                except Exception:
                    pass
        except Exception:
            entry.detected_fs = None

    def run_full_scan(self) -> ScanDiagnostic:
        diag = ScanDiagnostic()
        diag.total_sectors = self.total_sectors
        diag.sector_size = self.sector_size
        diag.total_size_bytes = self.reader.total_size_bytes

        # 0. Cas spécifique Conteneur Logique AD1 (AccessData FTK Imager)
        if hasattr(self.reader, "ad1") or self.reader.__class__.__name__ == "AD1ImageReader":
            diag.is_standalone_volume = True
            diag.is_logical_image = True
            diag.mbr_present = False
            diag.primary_gpt_present = False
            diag.backup_gpt_present = False
            diag.can_restore_from_backup = False

            ad1_obj = getattr(self.reader, "ad1", None)
            file_count = 0
            if ad1_obj and hasattr(ad1_obj, "root"):
                def count_entries(node):
                    c = 1
                    try:
                        for ch in getattr(node, "children", []):
                            c += count_entries(ch)
                    except Exception:
                        pass
                    return c
                file_count = max(0, count_entries(ad1_obj.root) - 1)

            entry = GPTPartitionEntry()
            entry.first_lba = 0
            entry.last_lba = max(0, self.total_sectors - 1)
            entry.name = f"Conteneur Logique FTK Imager ({file_count} éléments)"
            entry.detected_fs = "AD1 Logical Image"
            entry.type_guid = "AD100000-0000-0000-0000-000000000001"
            entry.unique_guid = "AD1-LOGICAL-CONTAINER"

            diag.partitions = [entry]
            diag.status_summary = f"Image logique AccessData FTK Imager ({file_count} fichiers et dossiers)"
            diag.wiper_profile = {
                "fr": "Archive logique médico-légale FTK Imager (AD1)",
                "en": "FTK Imager logical evidence archive (AD1)",
            }
            return diag

        # 1. Vérification LBA 0 (MBR)
        mbr_data = self.reader.read_sector(0)
        diag.mbr_is_all_zero = mbr_data == b"\x00" * 512
        mbr = ProtectiveMBR.parse(mbr_data)
        if mbr:
            diag.mbr_present = True
            diag.mbr_valid = mbr.is_valid()

        # 2. Vérification LBA 1 (Primary GPT)
        primary_data = self.reader.read_sector(1)
        if primary_data.startswith(GPTHeader.SIGNATURE):
            diag.primary_gpt_present = True
            header = GPTHeader.parse(primary_data)
            if header:
                diag.primary_gpt_header = header
                diag.primary_gpt_valid_crc = header.is_crc_valid()
                if diag.primary_gpt_valid_crc:
                    part_lba = header.partition_entries_lba
                    part_count = header.num_partition_entries
                    entry_size = header.entry_size
                    total_part_bytes = part_count * entry_size
                    sectors_needed = (total_part_bytes + self.sector_size - 1) // self.sector_size
                    try:
                        part_bytes = self.reader.read_sector(part_lba, count=sectors_needed)[:total_part_bytes]
                        entries = []
                        for i in range(part_count):
                            entry_raw = part_bytes[i * entry_size : (i + 1) * entry_size]
                            entry = GPTPartitionEntry.parse(entry_raw)
                            if entry and not entry.is_empty():
                                self._enrich_partition_entry(entry)
                                entries.append(entry)
                        diag.partitions = entries
                        diag.primary_partitions_valid = True
                    except Exception:
                        diag.primary_partitions_valid = False

        # 3. Vérification LBA -1 (Backup GPT Header)
        last_lba = self.total_sectors - 1
        backup_data = self.reader.read_sector(last_lba)
        if backup_data.startswith(GPTHeader.SIGNATURE):
            diag.backup_gpt_present = True
            b_header = GPTHeader.parse(backup_data)
            if b_header:
                diag.backup_gpt_header = b_header
                diag.backup_gpt_valid_crc = b_header.is_crc_valid()

                # Lecture du tableau de partitions de backup
                # (situé à b_header.partition_entries_lba)
                part_lba = b_header.partition_entries_lba
                part_count = b_header.num_partition_entries
                entry_size = b_header.entry_size
                total_part_bytes = part_count * entry_size
                sectors_needed = (total_part_bytes + self.sector_size - 1) // self.sector_size

                try:
                    part_bytes = self.reader.read_sector(part_lba, count=sectors_needed)[:total_part_bytes]
                    entries = []
                    for i in range(part_count):
                        entry_raw = part_bytes[i * entry_size : (i + 1) * entry_size]
                        entry = GPTPartitionEntry.parse(entry_raw)
                        if entry and not entry.is_empty():
                            self._enrich_partition_entry(entry)
                            entries.append(entry)

                    if not diag.partitions or len(entries) >= len(diag.partitions):
                        diag.partitions = entries
                    diag.backup_partitions_valid = True
                except Exception:
                    diag.backup_partitions_valid = False

        # 4. Détection du seuil de wipe (frontière d'effacement)
        diag.wipe_frontier_lba = self.find_wipe_frontier()
        if diag.wipe_frontier_lba is not None:
            diag.wiped_sectors_count = diag.wipe_frontier_lba
            diag.wiped_bytes = diag.wiped_sectors_count * self.sector_size

        # 5. Détection Table de Partitions MBR DOS Classique & Chaîne EBR (si pas de GPT)
        if not diag.primary_gpt_present and not diag.backup_gpt_present and mbr_data[510:512] == b"\x55\xaa":
            mbr_partitions = []
            extended_ranges = []
            is_valid_mbr_table = True
            entries_found = 0

            for i in range(4):
                ent = mbr_data[446 + i * 16 : 446 + (i + 1) * 16]
                boot_flag = ent[0]
                ptype = ent[4]
                start_lba = struct.unpack_from("<I", ent, 8)[0]
                num_sec = struct.unpack_from("<I", ent, 12)[0]

                if boot_flag not in (0x00, 0x80):
                    is_valid_mbr_table = False
                    break

                if ptype != 0:
                    if start_lba == 0 or num_sec == 0:
                        is_valid_mbr_table = False
                        break
                    entries_found += 1
                    if ptype in (0x05, 0x0F, 0x85):
                        extended_ranges.append((start_lba, num_sec))
                    else:
                        entry = GPTPartitionEntry()
                        entry.name = f"DOS Primaire #{i+1}"
                        entry.first_lba = start_lba
                        entry.last_lba = start_lba + num_sec - 1
                        entry.type_guid = f"MBR 0x{ptype:02X}"
                        entry.is_mbr = True
                        entry.mbr_type = ptype
                        mbr_partitions.append(entry)

            if is_valid_mbr_table and entries_found > 0:
                diag.mbr_valid = True
                diag.mbr_present = True

                # Décodage de la chaîne EBR (Extended Boot Records - DFTT Test #1)
                logical_idx = 1
                for ext_base, ext_sec in extended_ranges:
                    curr_ebr = ext_base
                    visited_ebrs = set()
                    while curr_ebr and curr_ebr not in visited_ebrs:
                        visited_ebrs.add(curr_ebr)
                        ebr_data = self.reader.read_sector(curr_ebr, count=1)
                        if len(ebr_data) < 512 or ebr_data[510:512] != b"\x55\xaa":
                            break
                        next_ebr = None
                        # Inspecter l'ensemble des 4 entrées de l'EBR (cas d'école Brian Carrier)
                        for j in range(4):
                            jent = ebr_data[446 + j * 16 : 446 + (j + 1) * 16]
                            jptype = jent[4]
                            jlba = struct.unpack_from("<I", jent, 8)[0]
                            jcnt = struct.unpack_from("<I", jent, 12)[0]

                            if jptype == 0 or jcnt == 0:
                                continue
                            if jptype in (0x05, 0x0F, 0x85):
                                next_ebr = ext_base + jlba
                            else:
                                abs_start = curr_ebr + jlba
                                entry = GPTPartitionEntry()
                                entry.name = f"DOS Lecteur Logique #{logical_idx}"
                                entry.first_lba = abs_start
                                entry.last_lba = abs_start + jcnt - 1
                                entry.type_guid = f"MBR 0x{jptype:02X}"
                                entry.is_mbr = True
                                entry.mbr_type = jptype
                                mbr_partitions.append(entry)
                                logical_idx += 1
                        curr_ebr = next_ebr

                # Identifier les systèmes de fichiers et les éventuelles coexistences multi-FS
                multi_fs_warnings_count = 0
                for entry in mbr_partitions:
                    self._enrich_partition_entry(entry)
                    if entry.multi_fs_warning:
                        multi_fs_warnings_count += 1

                diag.partitions = mbr_partitions
                if multi_fs_warnings_count > 0:
                    diag.status_summary = f"Table MBR DOS valide ({len(mbr_partitions)} partitions) - ⚠️ Ambiguïté médico-légale Multi-FS détectée sur {multi_fs_warnings_count} partition(s)"
                else:
                    diag.status_summary = f"Table MBR DOS valide : {len(mbr_partitions)} partition(s) répertoriée(s)"

        # 6. Détection de volume brut autonome (ex: Image APFS, NTFS, FAT ou conteneur sans partitionnement)
        diag.is_standalone_volume = False
        if not diag.primary_gpt_present and not diag.backup_gpt_present and not diag.partitions:
            sample_len = min(self.reader.total_size_bytes, 65536 + 4096)
            vol_sample = self.reader.read_bytes(0, sample_len)
            fs_at_0 = identify_fs_signature(vol_sample[:4096])
            all_fs = detect_all_filesystems(vol_sample)

            if fs_at_0 or all_fs:
                diag.is_standalone_volume = True
                vol_entry = GPTPartitionEntry()
                vol_entry.name = "Conteneur Brut / Volume"
                vol_entry.detected_fs = fs_at_0 or (all_fs[0] if all_fs else None)
                vol_entry.first_lba = 0
                vol_entry.last_lba = max(0, self.total_sectors - 1)
                vol_entry.type_guid = "N/A (Volume Direct)"
                vol_entry.coexisting_filesystems = all_fs
                if len(all_fs) > 1:
                    vol_entry.multi_fs_warning = True
                    diag.status_summary = f"⚠️ Ambiguïté médico-légale : Coexistence de systèmes de fichiers ({', '.join(all_fs)})"
                else:
                    diag.status_summary = f"Volume autonome détecté : {vol_entry.detected_fs} (Image directe sans table de partition)"
                diag.partitions = [vol_entry]
            else:
                # Recherche approfondie de superblocs de secours (ex: Linux EXT2/3/4 avec LBA 0-2 wipé)
                ext_sb = None
                ext_sb_offset = None
                cand_offsets = [8389632, 25166848, 33554432]
                for cand in cand_offsets:
                    if cand + 1024 <= self.reader.total_size_bytes:
                        b = self.reader.read_bytes(cand, 1024)
                        if len(b) >= 58 and struct.unpack_from("<H", b, 56)[0] == 0xEF53:
                            ext_sb = b
                            ext_sb_offset = cand
                            break

                if not ext_sb:
                    scan_len = min(32 * 1024 * 1024, self.reader.total_size_bytes)
                    if scan_len > 0:
                        buf = self.reader.read_bytes(0, scan_len)
                        pos = 0
                        while True:
                            pos = buf.find(b"\x53\xEF", pos)
                            if pos == -1:
                                break
                            cand_sb = pos - 56
                            if cand_sb >= 0 and cand_sb % 1024 == 0:
                                b = buf[cand_sb : cand_sb + 1024]
                                if len(b) >= 58 and struct.unpack_from("<H", b, 56)[0] == 0xEF53:
                                    ext_sb = b
                                    ext_sb_offset = cand_sb
                                    break
                            pos += 2

                if ext_sb and ext_sb_offset is not None:
                    diag.is_standalone_volume = True
                    vol_entry = GPTPartitionEntry()
                    sb_lba = ext_sb_offset // self.sector_size
                    vol_entry.name = f"Linux EXT2/3/4 (Superbloc de secours LBA {sb_lba:,})"
                    vol_entry.detected_fs = "ext2/ext3/ext4 Filesystem"
                    vol_entry.first_lba = 0
                    vol_entry.last_lba = max(0, self.total_sectors - 1)
                    vol_entry.type_guid = "N/A (Volume Direct EXT)"
                    vol_entry.coexisting_filesystems = ["Ext2/Ext3"]
                    diag.status_summary = f"Volume autonome Linux EXT2/3/4 récupéré via Superbloc de secours (LBA {sb_lba:,})"
                    diag.partitions = [vol_entry]

                if not diag.partitions:
                    # Recherche de tables FAT orphelines (ex: FAT12/16/32 avec VBR LBA 0 wipé)
                    try:
                        from core.fat_reader import FATReader
                        fat_probe = FATReader(self.reader, partition_offset_bytes=0)
                        if fat_probe.is_valid_fat and fat_probe.all_entries:
                            diag.is_standalone_volume = True
                            vol_entry = GPTPartitionEntry()
                            vol_entry.name = f"Volume {fat_probe.fat_type} (Reconstitué via Table FAT LBA {fat_probe.reserved_sectors})"
                            vol_entry.detected_fs = f"{fat_probe.fat_type} Filesystem"
                            vol_entry.first_lba = 0
                            vol_entry.last_lba = max(0, self.total_sectors - 1)
                            vol_entry.type_guid = f"N/A (Volume Direct {fat_probe.fat_type})"
                            vol_entry.coexisting_filesystems = [fat_probe.fat_type]
                            diag.status_summary = f"Volume autonome {fat_probe.fat_type} reconstitué dynamiquement (Table FAT LBA {fat_probe.reserved_sectors}, Cluster {fat_probe.cluster_size:,} octets)"
                            diag.partitions = [vol_entry]
                    except Exception:
                        pass

                # 6c. Détection de firmwares embarqués & conteneurs IoT (TRX, U-Boot, SquashFS, CramFS, JFFS2, etc.)
                if not diag.partitions and self.reader.total_size_bytes > 0:
                    fw_parts = self._scan_embedded_firmware()
                    if fw_parts:
                        diag.is_standalone_volume = True
                        diag.partitions = fw_parts
                        diag.status_summary = f"Firmware Embarqué / Image IoT identifiée ({len(fw_parts)} composants cartographiés)"

        # 7. Profilage d'Attaque (Wiper / Ransomware)
        from core.synthesizer import WiperProfiler
        diag.wiper_profile = WiperProfiler.profile_attack(
            total_sectors=self.total_sectors,
            sector_size=self.sector_size,
            wipe_frontier=diag.wipe_frontier_lba,
            mbr_zero=diag.mbr_is_all_zero,
            primary_zero=not diag.primary_gpt_present,
            backup_zero=not diag.backup_gpt_present,
        )

        # 8. Évaluation de la possibilité de restauration
        if diag.backup_gpt_present and diag.backup_gpt_valid_crc and (not diag.primary_gpt_present or not diag.primary_gpt_valid_crc):
            diag.can_restore_from_backup = True
            diag.status_summary = "Restauration possible via la table de secours (Backup GPT intact)"
        elif diag.primary_gpt_present and diag.primary_gpt_valid_crc:
            diag.can_restore_from_backup = False
            diag.status_summary = "Disque sain : Table GPT primaire valide"
        elif diag.mbr_valid and diag.partitions:
            diag.can_restore_from_backup = False
        elif diag.is_standalone_volume:
            diag.can_restore_from_backup = False
        else:
            diag.can_restore_from_backup = False
            diag.status_summary = "Altération sévère : aucune table de partition GPT ou MBR valide détectée"

        return diag

    def find_wipe_frontier(self) -> Optional[int]:
        """
        Détecte avec précision l'index du premier secteur non nul.
        Si le disque ne commence pas par des zéros, renvoie 0.
        Si tout le disque est à zéro, renvoie total_sectors.
        Utilise un balayage adaptatif par blocs (1 Mio à 8 Mio) afin de ne pas être trompé
        par des disques clairsemés (sparse) ou des conteneurs chiffrés discontinus.
        """
        try:
            first_sector = self.reader.read_sector(0)
            if first_sector != b"\x00" * self.sector_size:
                return 0  # Pas de wipe au début
        except Exception:
            return None

        total_bytes = self.reader.total_size_bytes
        if total_bytes <= 0:
            return None

        block_bytes = 1024 * 1024  # 1 Mio
        offset = 0

        while offset < total_bytes:
            cur_len = min(block_bytes, total_bytes - offset)
            try:
                chunk = self.reader.read_bytes(offset, cur_len)
            except Exception:
                break

            if any(chunk):
                for idx, byte_val in enumerate(chunk):
                    if byte_val != 0:
                        exact_byte = offset + idx
                        return exact_byte // self.sector_size
                break

            offset += cur_len
            if offset >= 2 * 1024 * 1024 * 1024 and block_bytes < 8 * 1024 * 1024:
                block_bytes = 8 * 1024 * 1024

        return self.total_sectors

    def _scan_embedded_firmware(self) -> List[GPTPartitionEntry]:
        """Détecte et cartographie les firmwares IoT, conteneurs embarqués et systèmes de fichiers Flash."""
        partitions: List[GPTPartitionEntry] = []
        scan_len = min(self.reader.total_size_bytes, 32 * 1024 * 1024)
        buf = self.reader.read_bytes(0, scan_len)
        if not buf:
            return partitions

        # 1. Conteneur Broadcom TRX (ex: Routeurs Netgear, Linksys, Asus, OpenWrt, DVRF)
        trx_offset = -1
        for candidate in [0, 32, 512, 1024, 2048]:
            if candidate + 28 <= len(buf) and buf[candidate : candidate + 4] == b"HDR0":
                trx_offset = candidate
                break

        if trx_offset != -1:
            try:
                trx_hdr = buf[trx_offset : trx_offset + 28]
                magic, length, crc32, flags, ver, off0, off1, off2 = struct.unpack("<4sIIHHIII", trx_hdr)
                total_fw_len = min(self.reader.total_size_bytes - trx_offset, length)

                # En-tête constructeur précédant TRX (ex: Sercomm PID '1550')
                if trx_offset > 0:
                    ent_hdr = GPTPartitionEntry()
                    ent_hdr.name = "En-tête Constructeur (Sercomm / Netgear PID)"
                    ent_hdr.detected_fs = "Sercomm Firmware Header"
                    ent_hdr.first_lba = 0
                    ent_hdr.last_lba = max(0, (trx_offset - 1) // self.sector_size)
                    ent_hdr.type_guid = "FIRMWARE-HEADER"
                    ent_hdr.byte_offset = 0
                    ent_hdr.byte_size = trx_offset
                    partitions.append(ent_hdr)

                # Partition Noyau Linux
                if off0 > 0 and off0 < total_fw_len:
                    k_start = trx_offset + off0
                    k_end = trx_offset + (off1 if (off1 and off1 > off0) else total_fw_len)
                    ent_k = GPTPartitionEntry()
                    is_gzip = buf[k_start : k_start + 2] == b"\x1f\x8b"
                    ent_k.name = "Noyau Linux (GZIP zImage)" if is_gzip else "Noyau Linux (Kernel Payload)"
                    ent_k.detected_fs = "Linux Kernel (GZIP)" if is_gzip else "Linux Kernel"
                    ent_k.first_lba = k_start // self.sector_size
                    ent_k.last_lba = max(ent_k.first_lba, (k_end - 1) // self.sector_size)
                    ent_k.type_guid = "LINUX-KERNEL"
                    ent_k.byte_offset = k_start
                    ent_k.byte_size = k_end - k_start
                    partitions.append(ent_k)

                # Partition RootFS (Système de fichiers racine)
                if off1 > 0 and off1 < total_fw_len:
                    fs_start = trx_offset + off1
                    fs_end = trx_offset + (off2 if (off2 and off2 > off1) else total_fw_len)
                    fs_sig = buf[fs_start : fs_start + 4]
                    ent_fs = GPTPartitionEntry()
                    if fs_sig in (b"shsq", b"hsqs", b"sqsh", b"qshs"):
                        ent_fs.name = "Système de Fichiers Racine (SquashFS)"
                        ent_fs.detected_fs = "SquashFS Filesystem"
                    elif fs_sig in (b"\x28\xcd\x3d\x45", b"\x45\x3d\xcd\x28"):
                        ent_fs.name = "Système de Fichiers Racine (CramFS)"
                        ent_fs.detected_fs = "CramFS Filesystem"
                    elif fs_sig in (b"\x19\x85", b"\x85\x19"):
                        ent_fs.name = "Système de Fichiers Racine (JFFS2)"
                        ent_fs.detected_fs = "JFFS2 Filesystem"
                    elif fs_sig == b"UBI#":
                        ent_fs.name = "Conteneur Flash UBI"
                        ent_fs.detected_fs = "UBI Flash Container"
                    else:
                        ent_fs.name = "Système de Fichiers Racine (RootFS)"
                        ent_fs.detected_fs = "Embedded Filesystem"
                    ent_fs.first_lba = fs_start // self.sector_size
                    ent_fs.last_lba = max(ent_fs.first_lba, (fs_end - 1) // self.sector_size)
                    ent_fs.type_guid = "ROOTFS"
                    ent_fs.byte_offset = fs_start
                    ent_fs.byte_size = fs_end - fs_start
                    partitions.append(ent_fs)

                # Partition 3 optionnelle (Data / Overlay)
                if off2 > 0 and off2 < total_fw_len:
                    d_start = trx_offset + off2
                    d_end = trx_offset + total_fw_len
                    ent_d = GPTPartitionEntry()
                    ent_d.name = "Partition Données / Overlay"
                    ent_d.detected_fs = "Embedded Data"
                    ent_d.first_lba = d_start // self.sector_size
                    ent_d.last_lba = max(ent_d.first_lba, (d_end - 1) // self.sector_size)
                    ent_d.type_guid = "DATA-OVERLAY"
                    ent_d.byte_offset = d_start
                    ent_d.byte_size = d_end - d_start
                    partitions.append(ent_d)

                if partitions:
                    return partitions
            except Exception:
                pass

        # 2. Conteneur U-Boot uImage (ex: Caméras Dahua, Hikvision, Drones, IoT industriels, NAS)
        uimage_pos = buf.find(b"\x27\x05\x19\x56")
        if uimage_pos != -1 and uimage_pos + 64 <= len(buf):
            try:
                u_hdr = buf[uimage_pos : uimage_pos + 64]
                (ih_magic, ih_hcrc, ih_time, ih_size, ih_load, ih_ep,
                 ih_dcrc, ih_os, ih_arch, ih_type, ih_comp) = struct.unpack(">IIIIIIIBBBB", u_hdr[:32])
                ih_name = u_hdr[32:64].split(b"\x00")[0].decode("utf-8", errors="ignore").strip()

                comp_names = {0: "Non compressé", 1: "GZIP", 2: "BZIP2", 3: "LZMA", 4: "LZO", 5: "LZ4", 6: "ZSTD"}
                type_names = {1: "Standalone", 2: "Noyau Linux", 3: "RAMDisk", 4: "Multi-Fichier", 5: "Firmware", 6: "Script", 7: "Filesystem"}

                ent_u = GPTPartitionEntry()
                ent_u.name = f"U-Boot uImage : {ih_name or type_names.get(ih_type, 'Payload')}"
                ent_u.detected_fs = f"uImage ({comp_names.get(ih_comp, 'Raw')})"
                ent_u.first_lba = uimage_pos // self.sector_size
                u_end = uimage_pos + 64 + ih_size
                ent_u.last_lba = max(ent_u.first_lba, (u_end - 1) // self.sector_size)
                ent_u.type_guid = "UIMAGE-CONTAINER"
                partitions.append(ent_u)
            except Exception:
                pass

        # 3. Conteneur Android Boot Image
        android_pos = buf.find(b"ANDROID!")
        if android_pos != -1 and android_pos + 64 <= len(buf):
            try:
                (k_size, k_addr, r_size, r_addr, s_size, s_addr) = struct.unpack("<IIIIII", buf[android_pos + 8 : android_pos + 32])
                ent_a = GPTPartitionEntry()
                ent_a.name = "Android Boot / Recovery Image"
                ent_a.detected_fs = "Android Boot Image"
                ent_a.first_lba = android_pos // self.sector_size
                a_len = 2048 + k_size + r_size + s_size
                ent_a.last_lba = max(ent_a.first_lba, (android_pos + a_len - 1) // self.sector_size)
                ent_a.type_guid = "ANDROID-BOOT"
                partitions.append(ent_a)
            except Exception:
                pass

        # 4. Balayage multi-signatures des systèmes de fichiers embarqués dans l'image
        known_starts = {p.first_lba * self.sector_size for p in partitions}
        fs_signatures = [
            (b"hsqs", "SquashFS Filesystem", "Système de Fichiers SquashFS (v4 LE)"),
            (b"sqsh", "SquashFS Filesystem (Big-Endian)", "Système de Fichiers SquashFS (v4 BE)"),
            (b"shsq", "SquashFS Filesystem", "Système de Fichiers Racine (SquashFS v3 LE)"),
            (b"qshs", "SquashFS Filesystem (Big-Endian)", "Système de Fichiers Racine (SquashFS v3 BE)"),
            (b"\x28\xcd\x3d\x45", "CramFS Filesystem (LE)", "Système de Fichiers CramFS"),
            (b"\x45\x3d\xcd\x28", "CramFS Filesystem (BE)", "Système de Fichiers CramFS"),
            (b"-rom1fs-", "RomFS Filesystem", "Système de Fichiers RomFS"),
            (b"UBI#", "UBI Flash Container", "Conteneur Flash UBI"),
            (b"070701", "CPIO / Initramfs Archive", "Archive Initramfs CPIO"),
        ]

        for sig, fs_type, p_title in fs_signatures:
            pos = 0
            while pos < len(buf) - len(sig):
                found_pos = buf.find(sig, pos)
                if found_pos == -1:
                    break

                if found_pos not in known_starts:
                    est_size = 0
                    if sig in (b"hsqs", b"sqsh", b"shsq", b"qshs") and found_pos + 96 <= len(buf):
                        try:
                            if sig in (b"shsq", b"qshs"):
                                est_size = struct.unpack("<I" if sig == b"shsq" else ">I", buf[found_pos + 8 : found_pos + 12])[0]
                            else:
                                est_size = struct.unpack("<Q" if sig == b"hsqs" else ">Q", buf[found_pos + 40 : found_pos + 48])[0]
                        except Exception:
                            est_size = 0

                    if est_size <= 0 or found_pos + est_size > self.reader.total_size_bytes:
                        est_size = min(self.reader.total_size_bytes - found_pos, 8 * 1024 * 1024)

                    ent_fs = GPTPartitionEntry()
                    ent_fs.name = f"{p_title} (Offset 0x{found_pos:X})"
                    ent_fs.detected_fs = fs_type
                    ent_fs.first_lba = found_pos // self.sector_size
                    ent_fs.last_lba = max(ent_fs.first_lba, (found_pos + est_size - 1) // self.sector_size)
                    ent_fs.type_guid = "EMBEDDED-FS"
                    ent_fs.byte_offset = found_pos
                    ent_fs.byte_size = est_size
                    partitions.append(ent_fs)
                    known_starts.add(found_pos)

                pos = found_pos + len(sig)

        return partitions
