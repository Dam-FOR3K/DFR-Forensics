"""
DFR-Forensics - Synthétiseur GPT de zéro & Profiler d'Attaque (Wipers / Ransomwares)
Permet de ressusciter un disque même lorsque la table primaire ET la table de secours ont été anéanties.
Carve les superblocs (NTFS, EXT4, APFS, LUKS, FAT32) et synthétise une géométrie GPT neuve et valide.
"""

import struct
import uuid
import zlib
from typing import List, Optional, Tuple, Dict, Any

from core.image_reader import ForensicImageReader
from core.gpt_structures import (
    ProtectiveMBR,
    GPTHeader,
    GPTPartitionEntry,
    guid_to_bytes,
    compute_partition_array_crc32,
    KNOWN_GUIDS,
)


class CarvedPartition:
    """Représente une partition orpheline détectée par analyse heuristique de superblocs."""

    def __init__(self, first_lba: int, total_sectors: int, fs_type: str, type_guid: str, name: str = ""):
        self.first_lba = first_lba
        self.total_sectors = total_sectors
        self.last_lba = first_lba + total_sectors - 1
        self.fs_type = fs_type
        self.type_guid = type_guid
        self.name = name or f"Carved_{fs_type}"


class WiperProfiler:
    """Analyse les patterns de destruction pour identifier la signature du wiper ou du ransomware."""

    @staticmethod
    def profile_attack(
        total_sectors: int,
        sector_size: int,
        wipe_frontier: Optional[int],
        mbr_zero: bool,
        primary_zero: bool,
        backup_zero: bool,
    ) -> Dict[str, str]:
        if wipe_frontier is not None and wipe_frontier > 0:
            mb_wiped = (wipe_frontier * sector_size) / (1024 * 1024)
            if backup_zero:
                return {
                    "fr": f"Wiper chirurgical bilatéral (Début {mb_wiped:.1f} Mo et fin du disque rasés)",
                    "en": f"Bilateral Surgical Wiper (Start {mb_wiped:.1f} MB and disk tail destroyed)",
                    "class": "surgical",
                }
            else:
                return {
                    "fr": f"Wiper séquentiel interrompu (LBA 0 à {wipe_frontier - 1:,} - {mb_wiped:.1f} Mo effacés)",
                    "en": f"Interrupted Sequential Wipe (LBA 0 to {wipe_frontier - 1:,} - {mb_wiped:.1f} MB zeroed)",
                    "class": "sequential",
                }
        elif mbr_zero and primary_zero and not backup_zero:
            return {
                "fr": "Wiper chirurgical de métadonnées (Ciblage spécifique MBR et table GPT)",
                "en": "Surgical Metadata Wiper (Targeted destruction of MBR & Primary GPT)",
                "class": "targeted_mbr",
            }
        elif mbr_zero and primary_zero and backup_zero:
            return {
                "fr": "Effacement total des structures de partitionnement",
                "en": "Total Wipe of all partition structures",
                "class": "total_structure",
            }
        else:
            return {
                "fr": "Aucune trace d'effacement ou disque sain",
                "en": "No wipe detected or healthy disk",
                "class": "healthy",
            }


class GPTSynthesizer:
    """Moteur de reconstruction de table GPT à partir de zéro par carving heuristique."""

    def __init__(self, reader: ForensicImageReader):
        self.reader = reader
        self.sector_size = reader.sector_size
        self.total_sectors = reader.total_sectors

    def carve_partitions(self, max_sectors_scan: int = 500000) -> List[CarvedPartition]:
        """
        Scanne les secteurs du disque à la recherche de superblocs de systèmes de fichiers
        et extrait mathématiquement leur géométrie exacte.
        """
        partitions: List[CarvedPartition] = []
        step = 2048  # Aligné sur 1 Mo par défaut (standard de partitionnement moderne)
        tot = self.total_sectors

        # Scan des offsets alignés usuels (2048, 4096, 6144, etc.)
        scan_limit = min(tot, max_sectors_scan) if max_sectors_scan > 0 else tot

        lba = 2048
        while lba < scan_limit:
            try:
                sec_data = self.reader.read_sector(lba, count=8)
            except Exception:
                break

            carved = self._inspect_superblock(sec_data, lba)
            if carved:
                # Éviter les doublons
                if not any(p.first_lba == carved.first_lba for p in partitions):
                    partitions.append(carved)
                    # Sauter au-delà de la partition trouvée
                    lba = max(lba + step, carved.last_lba + 1)
                    continue

            lba += step

        return partitions

    def _inspect_superblock(self, data: bytes, lba: int) -> Optional[CarvedPartition]:
        if len(data) < 1024:
            return None

        # 1. NTFS VBR (Volume Boot Record)
        # Signature "NTFS    " à l'offset 3
        if data[3:11] == b"NTFS    ":
            bps = struct.unpack_from("<H", data, 11)[0]
            total_sec = struct.unpack_from("<Q", data, 40)[0]
            if bps in (512, 4096) and 2048 <= total_sec <= self.total_sectors:
                return CarvedPartition(
                    first_lba=lba,
                    total_sectors=total_sec,
                    fs_type="NTFS",
                    type_guid="ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
                    name="Recovered_NTFS",
                )

        # 2. Apple APFS Container Superblock (NXSB)
        if data[:4] == b"NXSB":
            block_size = struct.unpack_from("<I", data, 32)[0] if len(data) >= 36 else 4096
            block_count = struct.unpack_from("<Q", data, 36)[0] if len(data) >= 44 else 0
            if block_size in (4096, 8192) and block_count > 0:
                total_sec = (block_size * block_count) // self.sector_size
                return CarvedPartition(
                    first_lba=lba,
                    total_sectors=min(total_sec, self.total_sectors - lba),
                    fs_type="APFS",
                    type_guid="7c345030-0000-11aa-aa11-00306543ecac",
                    name="Recovered_APFS",
                )

        # 3. Linux EXT2 / EXT3 / EXT4 Superblock (offset 1024 du début de la partition)
        if len(data) >= 1024 + 512:
            sb = data[1024 : 1024 + 512]
            magic = struct.unpack_from("<H", sb, 0x38)[0]
            if magic == 0xEF53:
                blocks_count = struct.unpack_from("<I", sb, 0x04)[0]
                log_block_size = struct.unpack_from("<I", sb, 0x18)[0]
                block_size = 1024 << log_block_size
                total_sec = (blocks_count * block_size) // self.sector_size
                if 2048 <= total_sec <= self.total_sectors:
                    return CarvedPartition(
                        first_lba=lba,
                        total_sectors=total_sec,
                        fs_type="ext4",
                        type_guid="0fc63daf-8483-4772-8e79-3d69d8477de4",
                        name="Recovered_ext4",
                    )

        # 4. LUKS1 ou LUKS2 Encrypted Container
        if data[:6] == b"LUKS\xba\xbe":
            version = struct.unpack_from(">H", data, 6)[0]
            return CarvedPartition(
                first_lba=lba,
                total_sectors=self.total_sectors - lba - 34,
                fs_type=f"LUKS{version}",
                type_guid="ca7d7ccb-63ed-4c53-861c-1742536059cc",
                name=f"Recovered_LUKS{version}",
            )

        # 5. BitLocker Encrypted Volume (-FVE-FS-)
        if data[3:11] == b"-FVE-FS-":
            return CarvedPartition(
                first_lba=lba,
                total_sectors=self.total_sectors - lba - 34,
                fs_type="BitLocker",
                type_guid="ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
                name="Recovered_BitLocker",
            )

        return None

    def synthesize_gpt(self, carved_parts: List[CarvedPartition]) -> Tuple[ProtectiveMBR, GPTHeader, List[GPTPartitionEntry], GPTHeader]:
        """
        Génère une table GPT complète et valide à partir des partitions identifiées.
        Produit le Protective MBR, le Primary GPT Header, le tableau de 128 entrées et le Backup GPT Header.
        """
        tot = self.total_sectors
        disk_guid = str(uuid.uuid4())

        # Création des entrées
        entries: List[GPTPartitionEntry] = []
        for p in carved_parts:
            entry = GPTPartitionEntry()
            entry.type_guid = p.type_guid
            entry.type_guid_bytes = guid_to_bytes(p.type_guid)
            part_guid = str(uuid.uuid4())
            entry.unique_guid = part_guid
            entry.unique_guid_bytes = guid_to_bytes(part_guid)
            entry.first_lba = p.first_lba
            entry.last_lba = p.last_lba
            entry.name = p.name
            entry.detected_fs = p.fs_type
            entries.append(entry)

        while len(entries) < 128:
            entries.append(GPTPartitionEntry())

        # Calcul du CRC32 du tableau d'entrées
        part_array_crc = compute_partition_array_crc32(entries)

        # 1. Protective MBR (LBA 0)
        mbr = ProtectiveMBR(disk_sectors=tot)

        # 2. Primary GPT Header (LBA 1)
        p_hdr = GPTHeader()
        p_hdr.current_lba = 1
        p_hdr.backup_lba = tot - 1
        p_hdr.first_usable_lba = 34
        p_hdr.last_usable_lba = tot - 34
        p_hdr.disk_guid = disk_guid
        p_hdr.disk_guid_bytes = guid_to_bytes(disk_guid)
        p_hdr.partition_entries_lba = 2
        p_hdr.num_partition_entries = 128
        p_hdr.entry_size = 128
        p_hdr.partition_array_crc32 = part_array_crc
        p_hdr.pack_recalculated()

        # 3. Backup GPT Header (LBA -1)
        b_hdr = GPTHeader()
        b_hdr.current_lba = tot - 1
        b_hdr.backup_lba = 1
        b_hdr.first_usable_lba = 34
        b_hdr.last_usable_lba = tot - 34
        b_hdr.disk_guid = disk_guid
        b_hdr.disk_guid_bytes = guid_to_bytes(disk_guid)
        b_hdr.partition_entries_lba = tot - 33
        b_hdr.num_partition_entries = 128
        b_hdr.entry_size = 128
        b_hdr.partition_array_crc32 = part_array_crc
        b_hdr.pack_recalculated()

        return mbr, p_hdr, entries, b_hdr
