"""
WipeRescue-Forensics - Générateur d'image disque de test synthétique
Simule fidèlement le cas du PDF CIRCL :
 - Disque GPT avec 2 partitions (dont 1 conteneur chiffré LUKS2)
 - Backup GPT intact à la fin du disque
 - Effacement (wipe) des premiers secteurs (MBR, Primary GPT et début de partition détruits)
"""

import os
import sys

# Assure l'accès au package core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import struct
import zlib
import secrets
from core.gpt_structures import (
    ProtectiveMBR,
    GPTHeader,
    GPTPartitionEntry,
    guid_to_bytes,
    compute_partition_array_crc32,
)


def create_circl_simulation_disk(output_path: str, total_sectors: int = 40960, wipe_sectors: int = 15000):
    """
    Crée une image disque de test de 20 Mo (40 960 secteurs de 512 octets).
    """
    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    sector_size = 512
    total_bytes = total_sectors * sector_size

    # GUIDs
    disk_guid_str = "d4d2aac6-7159-422f-b5bc-520ac650ece1"
    part_type_basic_data = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
    part1_guid = "a2a0d0eb-e5b9-3344-87c0-68b6b72699c7"
    part2_guid = "83795b4f-1b77-5d43-bf13-a6461c013e88"

    # Création des entrées de partition
    entries = []

    # Partition 1 : Secteurs 2048 à 19999
    p1 = GPTPartitionEntry()
    p1.type_guid_bytes = guid_to_bytes(part_type_basic_data)
    p1.type_guid = part_type_basic_data
    p1.unique_guid_bytes = guid_to_bytes(part1_guid)
    p1.unique_guid = part1_guid
    p1.first_lba = 2048
    p1.last_lba = 19999
    p1.name = "disk1"
    entries.append(p1)

    # Partition 2 : Secteurs 20000 à (total_sectors - 35) (Conteneur LUKS)
    p2 = GPTPartitionEntry()
    p2.type_guid_bytes = guid_to_bytes(part_type_basic_data)
    p2.type_guid = part_type_basic_data
    p2.unique_guid_bytes = guid_to_bytes(part2_guid)
    p2.unique_guid = part2_guid
    p2.first_lba = 20000
    p2.last_lba = total_sectors - 35
    p2.name = "disk2"
    entries.append(p2)

    # Compléter jusqu'à 128 entrées vides
    while len(entries) < 128:
        entries.append(GPTPartitionEntry())

    # Calcul du CRC32 du tableau d'entrées
    partition_array_bytes = bytearray()
    for e in entries:
        partition_array_bytes.extend(e.pack())
    part_array_crc = zlib.crc32(partition_array_bytes) & 0xFFFFFFFF

    # 1. Protective MBR (LBA 0)
    mbr = ProtectiveMBR(disk_sectors=total_sectors)
    mbr_bytes = mbr.pack()

    # 2. Primary GPT Header (LBA 1)
    primary_hdr = GPTHeader()
    primary_hdr.current_lba = 1
    primary_hdr.backup_lba = total_sectors - 1
    primary_hdr.first_usable_lba = 34
    primary_hdr.last_usable_lba = total_sectors - 34
    primary_hdr.disk_guid_bytes = guid_to_bytes(disk_guid_str)
    primary_hdr.disk_guid = disk_guid_str
    primary_hdr.partition_entries_lba = 2
    primary_hdr.num_partition_entries = 128
    primary_hdr.entry_size = 128
    primary_hdr.partition_array_crc32 = part_array_crc
    primary_hdr_bytes = primary_hdr.pack_recalculated()

    # 3. Secondary GPT Header (LBA -1)
    backup_hdr = GPTHeader()
    backup_hdr.current_lba = total_sectors - 1
    backup_hdr.backup_lba = 1
    backup_hdr.first_usable_lba = 34
    backup_hdr.last_usable_lba = total_sectors - 34
    backup_hdr.disk_guid_bytes = guid_to_bytes(disk_guid_str)
    backup_hdr.disk_guid = disk_guid_str
    backup_hdr.partition_entries_lba = total_sectors - 33
    backup_hdr.num_partition_entries = 128
    backup_hdr.entry_size = 128
    backup_hdr.partition_array_crc32 = part_array_crc
    backup_hdr_bytes = backup_hdr.pack_recalculated()

    # Assemblage de l'image disque
    disk_data = bytearray(total_bytes)

    # Écriture MBR et Primary GPT
    disk_data[0 : 512] = mbr_bytes
    disk_data[512 : 1024] = primary_hdr_bytes
    disk_data[1024 : 1024 + len(partition_array_bytes)] = partition_array_bytes

    # Données simulées dans partition 1 (remplissage complet pour détecter la frontière du wipe)
    p1_offset = 2048 * 512
    p1_size = (19999 - 2048 + 1) * 512
    # Remplir partition 1 avec un motif reconnaissable
    pattern = b"OLD_FILE_DATA_PARTITION_1_" * 16  # 416 octets
    pattern_block = (pattern * ((p1_size // len(pattern)) + 1))[:p1_size]
    disk_data[p1_offset : p1_offset + p1_size] = pattern_block

    # Données LUKS2 dans partition 2 (Secteur 20000)
    p2_offset = 20000 * 512
    luks_header = bytearray(512)
    # Magic LUKS2 : 'LUKS\xba\xbe\x00\x02'
    luks_header[:8] = b"LUKS\xba\xbe\x00\x02"
    struct.pack_into(">H", luks_header, 8, 2)  # version 2
    disk_data[p2_offset : p2_offset + 512] = luks_header
    # Remplir le reste de la partition 2 avec des pseudo-données chiffrées à haute entropie
    p2_size = (p2.last_lba - p2.first_lba) * 512
    disk_data[p2_offset + 512 : p2_offset + min(p2_size, 1024 * 1024)] = secrets.token_bytes(min(p2_size - 512, 1024 * 1024 - 512))

    # Écriture Backup Partition Entries (LBA total_sectors - 33)
    backup_entries_offset = (total_sectors - 33) * 512
    disk_data[backup_entries_offset : backup_entries_offset + len(partition_array_bytes)] = partition_array_bytes

    # Écriture Backup GPT Header (LBA total_sectors - 1)
    backup_hdr_offset = (total_sectors - 1) * 512
    disk_data[backup_hdr_offset : backup_hdr_offset + 512] = backup_hdr_bytes

    # SIMULATION DU WIPE MALVEILLANT (Interrompu à wipe_sectors)
    # On écrase tout depuis le secteur 0 jusqu'au secteur wipe_sectors
    print(f"[*] Simulation de l'attaque : Effacement de LBA 0 à {wipe_sectors}...")
    disk_data[0 : wipe_sectors * 512] = b"\x00" * (wipe_sectors * 512)

    with open(output_path, "wb") as f:
        f.write(disk_data)

    print(f"[+] Disque de test généré avec succès : {output_path} ({len(disk_data)} octets)")
    return output_path


if __name__ == "__main__":
    test_path = os.path.join(os.path.dirname(__file__), "test_wiped_disk.raw")
    create_circl_simulation_disk(test_path)
