"""
WipeRescue-Forensics - Structures binaires UEFI MBR et GPT
Conforme aux spécifications UEFI 2.10.
Gère le packing, l'unpacking, le calcul et la validation des CRC32.
"""

import struct
import zlib
import uuid
from typing import List, Optional, Tuple


# GUIDs UEFI courants (format chaîne avec tirets)
KNOWN_GUIDS = {
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft Basic Data (NTFS/FAT/LUKS)",
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System Partition (ESP)",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux Filesystem Data",
    "ca7d7ccb-63ed-4c53-861c-1742536059cc": "Linux LUKS Partition",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux Swap",
    "7c345030-0000-11aa-aa11-00306543ecac": "Apple APFS Container",
    "cef5a9ad-73bc-4601-89f3-cdeeeee321a1": "QNX Power-Safe (QNX6) Filesystem",
    "e7d1a950-6142-44a4-8146-f9ac2e9adf54": "Linux LVM",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows Recovery Environment",
}


def bytes_to_guid(raw_bytes: bytes) -> str:
    """Convertit 16 octets GUID UEFI (Mixed-Endian) en chaîne standard."""
    if len(raw_bytes) != 16:
        return ""
    # Format UEFI : Data1 (uint32 LE), Data2 (uint16 LE), Data3 (uint16 LE), Data4 (8 bytes BE)
    d1, d2, d3 = struct.unpack("<IHH", raw_bytes[:8])
    d4 = raw_bytes[8:]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[:2].hex()}-{d4[2:].hex()}"


def guid_to_bytes(guid_str: str) -> bytes:
    """Convertit une chaîne GUID en 16 octets UEFI (Mixed-Endian)."""
    parts = guid_str.replace("-", "")
    if len(parts) != 32:
        return b"\x00" * 16
    d1 = int(parts[0:8], 16)
    d2 = int(parts[8:12], 16)
    d3 = int(parts[12:16], 16)
    d4 = bytes.fromhex(parts[16:32])
    return struct.pack("<IHH", d1, d2, d3) + d4


class ProtectiveMBR:
    """Représentation du Protective MBR (LBA 0)."""

    def __init__(self, disk_sectors: int = 0):
        self.bootcode = b"\x00" * 446
        self.partition_type = 0xEE
        self.starting_lba = 1
        # La taille dans le MBR est sur 32 bits (max 0xFFFFFFFF)
        self.size_in_sectors = min(0xFFFFFFFF, max(0, disk_sectors - 1)) if disk_sectors > 0 else 0xFFFFFFFF
        self.signature = 0xAA55

    @classmethod
    def parse(cls, data: bytes) -> Optional["ProtectiveMBR"]:
        if len(data) < 512:
            return None
        mbr = cls()
        mbr.bootcode = data[:446]
        sig = struct.unpack("<H", data[510:512])[0]
        mbr.signature = sig
        # Entrée de partition 1 (offset 446, 16 octets)
        part1 = data[446:462]
        boot_ind, s_chs, p_type, e_chs, start_lba, size_sectors = struct.unpack("<B3sB3sII", part1)
        mbr.partition_type = p_type
        mbr.starting_lba = start_lba
        mbr.size_in_sectors = size_sectors
        return mbr

    def is_valid(self) -> bool:
        return self.signature == 0xAA55 and self.partition_type == 0xEE

    def pack(self) -> bytes:
        mbr = bytearray(512)
        mbr[:446] = self.bootcode
        # Partition 1 : 0x00 (boot), 0x000200 (CHS), 0xEE (type), 0xFFFFFF (CHS), LBA 1, size
        part1 = struct.pack("<B3sB3sII", 0x00, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", self.starting_lba, self.size_in_sectors)
        mbr[446:462] = part1
        mbr[510:512] = struct.pack("<H", 0xAA55)
        return bytes(mbr)


class GPTPartitionEntry:
    """Représentation d'une entrée de partition GPT (128 octets)."""

    def __init__(self):
        self.type_guid: str = ""
        self.type_guid_bytes: bytes = b"\x00" * 16
        self.unique_guid: str = ""
        self.unique_guid_bytes: bytes = b"\x00" * 16
        self.first_lba: int = 0
        self.last_lba: int = 0
        self.attributes: int = 0
        self.name: str = ""
        self.detected_fs: Optional[str] = None
        self.coexisting_filesystems: List[str] = []
        self.multi_fs_warning: bool = False
        self.is_mbr: bool = False
        self.mbr_type: int = 0
        self.crypto_metadata: Dict[str, Any] = {}

    @classmethod
    def parse(cls, data: bytes) -> Optional["GPTPartitionEntry"]:
        if len(data) < 128:
            return None
        entry = cls()
        entry.type_guid_bytes = data[0:16]
        entry.type_guid = bytes_to_guid(entry.type_guid_bytes)
        entry.unique_guid_bytes = data[16:32]
        entry.unique_guid = bytes_to_guid(entry.unique_guid_bytes)
        entry.first_lba, entry.last_lba, entry.attributes = struct.unpack("<QQQ", data[32:56])
        name_raw = data[56:128]
        try:
            entry.name = name_raw.decode("utf-16le").rstrip("\x00")
        except Exception:
            entry.name = ""
        return entry

    def is_empty(self) -> bool:
        return self.type_guid_bytes == b"\x00" * 16 or self.first_lba == 0

    @property
    def total_sectors(self) -> int:
        if self.last_lba >= self.first_lba and self.first_lba >= 0:
            return (self.last_lba - self.first_lba) + 1
        return 0

    @property
    def type_name(self) -> str:
        return KNOWN_GUIDS.get(self.type_guid.lower(), "Unknown Type")

    def pack(self) -> bytes:
        data = bytearray(128)
        data[0:16] = self.type_guid_bytes
        data[16:32] = self.unique_guid_bytes
        struct.pack_into("<QQQ", data, 32, self.first_lba, self.last_lba, self.attributes)
        name_bytes = self.name.encode("utf-16le")[:72]
        data[56 : 56 + len(name_bytes)] = name_bytes
        return bytes(data)


class GPTHeader:
    """Représentation d'un en-tête GPT (92 octets)."""

    SIGNATURE = b"EFI PART"

    def __init__(self):
        self.signature = self.SIGNATURE
        self.revision = 0x00010000
        self.header_size = 92
        self.header_crc32 = 0
        self.reserved = 0
        self.current_lba = 1
        self.backup_lba = 0
        self.first_usable_lba = 34
        self.last_usable_lba = 0
        self.disk_guid_bytes = b"\x00" * 16
        self.disk_guid = ""
        self.partition_entries_lba = 2
        self.num_partition_entries = 128
        self.entry_size = 128
        self.partition_array_crc32 = 0

    @classmethod
    def parse(cls, data: bytes) -> Optional["GPTHeader"]:
        if len(data) < 92:
            return None
        sig = data[:8]
        if sig != cls.SIGNATURE:
            return None

        h = cls()
        h.signature = sig
        (
            h.revision,
            h.header_size,
            h.header_crc32,
            h.reserved,
            h.current_lba,
            h.backup_lba,
            h.first_usable_lba,
            h.last_usable_lba,
        ) = struct.unpack("<IIIIQQQQ", data[8:56])

        h.disk_guid_bytes = data[56:72]
        h.disk_guid = bytes_to_guid(h.disk_guid_bytes)

        (
            h.partition_entries_lba,
            h.num_partition_entries,
            h.entry_size,
            h.partition_array_crc32,
        ) = struct.unpack("<QIII", data[72:92])

        return h

    def compute_header_crc32(self) -> int:
        """Calcule le CRC32 de l'en-tête (champ CRC32 mis à 0)."""
        raw = bytearray(self.pack_without_crc())
        # Les 4 octets du CRC32 (offset 16 à 20) doivent être mis à 0
        raw[16:20] = b"\x00\x00\x00\x00"
        return zlib.crc32(raw[: self.header_size]) & 0xFFFFFFFF

    def is_crc_valid(self) -> bool:
        return self.compute_header_crc32() == self.header_crc32

    def pack_without_crc(self) -> bytes:
        raw = bytearray(512)
        raw[:8] = self.signature
        struct.pack_into(
            "<IIIIQQQQ",
            raw,
            8,
            self.revision,
            self.header_size,
            self.header_crc32,
            self.reserved,
            self.current_lba,
            self.backup_lba,
            self.first_usable_lba,
            self.last_usable_lba,
        )
        raw[56:72] = self.disk_guid_bytes
        struct.pack_into(
            "<QIII",
            raw,
            72,
            self.partition_entries_lba,
            self.num_partition_entries,
            self.entry_size,
            self.partition_array_crc32,
        )
        return bytes(raw)

    def pack_recalculated(self) -> bytes:
        """Produit le secteur de 512 octets avec le CRC32 correctement calculé."""
        raw = bytearray(self.pack_without_crc())
        raw[16:20] = b"\x00\x00\x00\x00"
        calculated_crc = zlib.crc32(raw[: self.header_size]) & 0xFFFFFFFF
        self.header_crc32 = calculated_crc
        struct.pack_into("<I", raw, 16, calculated_crc)
        return bytes(raw)


def compute_partition_array_crc32(entries: List[GPTPartitionEntry]) -> int:
    """Calcule le CRC32 de l'ensemble du tableau d'entrées de partition."""
    array_bytes = bytearray()
    for entry in entries:
        array_bytes.extend(entry.pack())
    return zlib.crc32(array_bytes) & 0xFFFFFFFF
