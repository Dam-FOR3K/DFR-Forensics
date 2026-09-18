"""
DFR-Forensics v2.6.0 - Tests unitaires des fonctionnalités de résilience
Couvre :
1. NTFS : Secours $MFTMirr (cluster 0x38) et Backup VBR (LBA N-1).
2. exFAT : Moteur pur-Python, Backup VBR (secteur 12), parsing 0x85/0xC0/0xC1, contiguous/FAT chains, undelete.
3. EXT4 : Arbre d'extents (magic 0xF30A), résolution des blocs et extraction de fichiers.
4. FAT32 : Bascule sur le Backup Boot Sector (LBA 6) quand LBA 0 est détruit.
"""

import os
import struct
import tempfile
import pytest
from core.image_reader import RawImageReader
from core.ntfs_reader import NTFSReader
from core.exfat_reader import ExFATReader, ExFATFileEntry
from core.ext_reader import ExtReader, ExtFileEntry
from core.fat_reader import FATReader
from core.scanner import DiskScanner, identify_fs_signature, detect_all_filesystems


@pytest.fixture
def temp_img():
    paths = []

    def _maker(size: int = 1024 * 1024) -> str:
        fd, path = tempfile.mkstemp(suffix=".raw")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(b"\x00" * size)
        paths.append(path)
        return path

    yield _maker
    for p in paths:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass


def test_ntfs_mftmirr_failover(temp_img):
    """Vérifie que NTFSReader bascule sur $MFTMirr si le Record 0 de la $MFT primaire est corrompu."""
    path = temp_img(size=2 * 1024 * 1024)
    with open(path, "r+b") as f:
        # 1. Écrire le VBR NTFS
        vbr = bytearray(512)
        vbr[3:11] = b"NTFS    "
        struct.pack_into("<H", vbr, 0x0B, 512)  # bytes_per_sector
        vbr[0x0D] = 8                          # sectors_per_cluster (4096 octets)
        struct.pack_into("<Q", vbr, 0x28, 4096) # total_sectors
        struct.pack_into("<q", vbr, 0x30, 4)   # mft_cluster = cluster 4
        struct.pack_into("<q", vbr, 0x38, 16)  # mftmirr_cluster = cluster 16
        struct.pack_into("<b", vbr, 0x40, -10) # 1024 bytes per record (2^10)
        vbr[510:512] = b"\x55\xaa"
        f.seek(0)
        f.write(vbr)

        # 2. Cluster 4 ($MFT primaire) : Corrompu / effacé
        f.seek(4 * 4096)
        f.write(b"CORRUPTED_RECORD_0_WIPED" + b"\x00" * 1000)

        # 3. Cluster 16 ($MFTMirr) : Record 0 valide avec Data Runs
        mirr_rec0 = bytearray(1024)
        mirr_rec0[:4] = b"FILE"
        struct.pack_into("<H", mirr_rec0, 0x14, 48)  # attr_off
        struct.pack_into("<H", mirr_rec0, 0x16, 0x01) # in_use
        struct.pack_into("<I", mirr_rec0, 0x2C, 0)    # rec_num 0

        # $FILE_NAME (0x30)
        fn_attr = bytearray(128)
        struct.pack_into("<II", fn_attr, 0, 0x30, 128)
        fn_attr[8] = 0  # resident
        struct.pack_into("<H", fn_attr, 0x14, 24) # content_off
        struct.pack_into("<Q", fn_attr, 24, 5)    # parent ref
        name_utf16 = "$MFT".encode("utf-16le")
        fn_attr[24 + 0x40] = len("$MFT")
        fn_attr[24 + 0x42 : 24 + 0x42 + len(name_utf16)] = name_utf16

        # $DATA (0x80) non-résident décrivant le run de la MFT (cluster 4, longueur 8)
        data_attr = bytearray(64)
        struct.pack_into("<II", data_attr, 0, 0x80, 64)
        data_attr[8] = 1 # non-resident
        struct.pack_into("<H", data_attr, 0x20, 32) # run offset
        struct.pack_into("<Q", data_attr, 0x30, 8 * 4096) # size
        # Run byte: len_size=1, off_size=1 -> 0x11, len=8, offset=4
        data_attr[32:35] = b"\x11\x08\x04"

        mirr_rec0[48 : 48 + len(fn_attr)] = fn_attr
        mirr_rec0[48 + len(fn_attr) : 48 + len(fn_attr) + len(data_attr)] = data_attr

        f.seek(16 * 4096)
        f.write(mirr_rec0)

    reader = RawImageReader(path)
    ntfs = NTFSReader(reader)
    assert ntfs.is_valid_ntfs is True
    assert ntfs.used_mft_mirror is True
    assert len(ntfs.all_entries) >= 1
    assert any(e.name == "$MFT" for e in ntfs.all_entries)
    reader.close()


def test_ntfs_backup_vbr_failover(temp_img):
    """Vérifie que NTFSReader récupère les paramètres depuis le Backup VBR (dernier secteur) si le LBA 0 est vierge."""
    total_size = 1024 * 1024
    path = temp_img(size=total_size)
    with open(path, "r+b") as f:
        # LBA 0 laissé à 0 (wipé)
        # Dernier secteur = total_size // 512 - 1 = 2047
        last_lba = total_size // 512 - 1
        b_vbr = bytearray(512)
        b_vbr[3:11] = b"NTFS    "
        struct.pack_into("<H", b_vbr, 0x0B, 512)
        b_vbr[0x0D] = 8
        struct.pack_into("<Q", b_vbr, 0x28, 2048)
        struct.pack_into("<q", b_vbr, 0x30, 10)
        struct.pack_into("<q", b_vbr, 0x38, 20)
        struct.pack_into("<b", b_vbr, 0x40, -10)
        b_vbr[510:512] = b"\x55\xaa"

        f.seek(last_lba * 512)
        f.write(b_vbr)

    reader = RawImageReader(path)
    ntfs = NTFSReader(reader, partition_offset_bytes=0, partition_size_bytes=total_size)
    assert ntfs.is_valid_ntfs is True
    assert ntfs.used_backup_vbr is True
    assert ntfs.mft_cluster == 10
    assert ntfs.mftmirr_cluster == 20
    reader.close()


def test_exfat_reader_main_and_backup_vbr(temp_img):
    """Vérifie le parsing exFAT, la bascule sur Backup VBR (secteur 12), le décodage d'arborescence et l'undelete."""
    path = temp_img(size=2 * 1024 * 1024)
    with open(path, "r+b") as f:
        # Créer un VBR exFAT de secours au secteur 12 (secteur 0 laissé vide pour tester la tolérance)
        vbr12 = bytearray(512)
        vbr12[3:11] = b"EXFAT   "
        vbr12[0x6C] = 9  # bytes_per_sector_shift = 9 (512 octets)
        vbr12[0x6D] = 3  # sectors_per_cluster_shift = 3 (8 secteurs = 4096 octets)
        struct.pack_into("<I", vbr12, 0x50, 24)   # fat_offset_sector = 24
        struct.pack_into("<I", vbr12, 0x54, 64)   # fat_length_sectors = 64
        struct.pack_into("<I", vbr12, 0x58, 128)  # cluster_heap_offset_sector = 128
        struct.pack_into("<I", vbr12, 0x5C, 256)  # cluster_count = 256
        struct.pack_into("<I", vbr12, 0x60, 2)    # root_dir_cluster = 2
        vbr12[0x6E] = 1 # num_fats
        vbr12[510:512] = b"\x55\xaa"

        f.seek(12 * 512)
        f.write(vbr12)

        # Créer le répertoire racine au cluster 2 (offset = 128 * 512 = 65536)
        # 1. Volume label (0x83)
        lbl_entry = bytearray(32)
        lbl_entry[0] = 0x83
        lbl_entry[1] = 8 # len("EVIDENCE")
        lbl_entry[2 : 2 + 16] = "EVIDENCE".encode("utf-16le")

        # 2. Fichier actif "case_report.txt" (0x85, 0xC0, 0xC1)
        fe1 = bytearray(32)
        fe1[0] = 0x85
        fe1[1] = 2 # 2 entrées secondaires (Stream + Nom)
        struct.pack_into("<H", fe1, 4, 0x20) # archive attribute
        struct.pack_into("<I", fe1, 8, 0x55005500) # created
        struct.pack_into("<I", fe1, 12, 0x55005500) # modified

        se1 = bytearray(32)
        se1[0] = 0xC0
        se1[1] = 0x03 # AllocationPossible | NoFatChain (contigu)
        struct.pack_into("<I", se1, 0x14, 3) # first_cluster = 3
        struct.pack_into("<Q", se1, 0x18, 38) # size = 38 octets

        ne1 = bytearray(32)
        ne1[0] = 0xC1
        fn1_bytes = "case_report.txt".encode("utf-16le")
        ne1[2 : 2 + len(fn1_bytes)] = fn1_bytes

        # 3. Fichier supprimé "deleted_log.dat" (0x05, 0x40, 0x41)
        fe2 = bytearray(32)
        fe2[0] = 0x05 # SUPPRIMÉ
        fe2[1] = 2
        struct.pack_into("<H", fe2, 4, 0x20)

        se2 = bytearray(32)
        se2[0] = 0x40 # Stream supprimé
        se2[1] = 0x03 # NoFatChain
        struct.pack_into("<I", se2, 0x14, 4) # cluster 4
        struct.pack_into("<Q", se2, 0x18, 25) # size = 25 octets

        ne2 = bytearray(32)
        ne2[0] = 0x41 # Nom supprimé
        fn2_bytes = "deleted_log.dat".encode("utf-16le")
        ne2[2 : 2 + len(fn2_bytes)] = fn2_bytes

        root_dir_data = lbl_entry + fe1 + se1 + ne1 + fe2 + se2 + ne2
        f.seek(128 * 512)
        f.write(root_dir_data)

        # Écrire les contenus des clusters 3 et 4
        # Cluster 3 = 128*512 + (3 - 2)*4096 = 65536 + 4096 = 69632
        f.seek(69632)
        f.write(b"CONFIDENTIAL FORENSIC REPORT - ACTIVE\x00")

        # Cluster 4 = 65536 + 2*4096 = 73728
        f.seek(73728)
        f.write(b"WIPED TRANSACTION HISTORY")

    reader = RawImageReader(path)
    exfat = ExFATReader(reader)
    assert exfat.is_valid_exfat is True
    assert exfat.used_backup_vbr is True
    assert exfat.volume_label == "EVIDENCE"

    # Vérification des entrées
    active = next((e for e in exfat.all_entries if e.name == "case_report.txt"), None)
    assert active is not None
    assert active.is_deleted is False
    assert active.size == 38
    assert exfat.extract_file_content(active) == b"CONFIDENTIAL FORENSIC REPORT - ACTIVE\x00"

    deleted = next((e for e in exfat.all_entries if e.name == "deleted_log.dat"), None)
    assert deleted is not None
    assert deleted.is_deleted is True
    assert deleted.size == 25
    assert exfat.extract_file_content(deleted) == b"WIPED TRANSACTION HISTORY"

    reader.close()


def test_ext4_extents_tree_parsing(temp_img):
    """Vérifie le parsing d'un arbre d'extents EXT4 (magic 0xF30A) pour fichiers volumineux / fragmentés."""
    path = temp_img(size=2 * 1024 * 1024)
    with open(path, "r+b") as f:
        # Superblock Ext4 à l'offset 1024
        sb = bytearray(1024)
        struct.pack_into("<I", sb, 0, 100)       # inodes_count
        struct.pack_into("<I", sb, 4, 2048)      # blocks_count
        struct.pack_into("<I", sb, 20, 1)        # first_data_block
        struct.pack_into("<I", sb, 24, 0)        # log_block_size = 0 (1024 octets)
        struct.pack_into("<I", sb, 32, 2048)     # blocks_per_group
        struct.pack_into("<I", sb, 40, 100)      # inodes_per_group
        struct.pack_into("<H", sb, 56, 0xEF53)   # magic
        struct.pack_into("<I", sb, 76, 1)        # rev_level = 1
        struct.pack_into("<H", sb, 88, 256)      # inode_size = 256
        f.seek(1024)
        f.write(sb)

        # Block Group Descriptor au bloc 2 (offset 2048)
        bgd = bytearray(32)
        struct.pack_into("<III", bgd, 0, 3, 4, 5) # inode_table = block 5 (offset 5120)
        f.seek(2048)
        f.write(bgd)

        # Inode 2 (Racine '/') au début de l'inode table (offset 5120 + (2-1)*256 = 5376)
        ino2 = bytearray(256)
        struct.pack_into("<H", ino2, 0, 0x41ED)   # mode: dir
        struct.pack_into("<I", ino2, 4, 1024)     # size: 1024
        struct.pack_into("<H", ino2, 26, 2)      # links: 2
        # Blocs directs standards pour la racine
        struct.pack_into("<15I", ino2, 40, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        f.seek(5376)
        f.write(ino2)

        # Inode 12 (Fichier utilisant EXT4 extents) à offset 5120 + (12-1)*256 = 7936
        ino12 = bytearray(256)
        struct.pack_into("<H", ino12, 0, 0x81A4)  # mode: regular file
        struct.pack_into("<I", ino12, 4, 3072)    # size: 3 blocs = 3072 octets
        struct.pack_into("<H", ino12, 26, 1)     # links: 1
        struct.pack_into("<I", ino12, 32, 0x00080000) # EXT4_EXTENTS_FL

        # Arbre d'extents dans ino12[40:100]
        # ext4_extent_header (12 octets)
        struct.pack_into("<HHHH", ino12, 40, 0xF30A, 2, 4, 0) # magic=0xF30A, entries=2, max=4, depth=0
        # Extent 1 : logical 0, len 2, phys block 50 (couvre blocs 50 et 51)
        struct.pack_into("<IHHI", ino12, 52, 0, 2, 0, 50)
        # Extent 2 : logical 2, len 1, phys block 60 (bloc 60)
        struct.pack_into("<IHHI", ino12, 64, 2, 1, 0, 60)
        f.seek(7936)
        f.write(ino12)

        # Contenu du répertoire racine au bloc 20 (offset 20480)
        # Contient '.' (inode 2) et 'large_extent.bin' (inode 12)
        dir_blk = bytearray(1024)
        # Entrée '.'
        struct.pack_into("<IHBB", dir_blk, 0, 2, 12, 1, 2)
        dir_blk[8:9] = b"."
        # Entrée 'large_extent.bin'
        fname = "large_extent.bin".encode("latin1")
        rec_len = 1024 - 12
        struct.pack_into("<IHBB", dir_blk, 12, 12, rec_len, len(fname), 1)
        dir_blk[20 : 20 + len(fname)] = fname
        f.seek(20 * 1024)
        f.write(dir_blk)

        # Écrire les blocs physiques de données de l'extent
        f.seek(50 * 1024)
        f.write(b"EXTENT_PART_1___" * 64) # 1024 octets
        f.seek(51 * 1024)
        f.write(b"EXTENT_PART_2___" * 64) # 1024 octets
        f.seek(60 * 1024)
        f.write(b"EXTENT_PART_3___" * 64) # 1024 octets

    reader = RawImageReader(path)
    ext = ExtReader(reader)
    assert ext.is_valid_ext is True
    file_entry = next((e for e in ext.all_entries if e.name == "large_extent.bin"), None)
    assert file_entry is not None
    assert file_entry.use_extents is True
    assert len(file_entry.extents) == 2

    # Extraction et intégrité des 3 blocs assemblés via extents
    content = ext.extract_file_content(file_entry)
    assert len(content) == 3072
    assert content[:16] == b"EXTENT_PART_1___"
    assert content[1024:1040] == b"EXTENT_PART_2___"
    assert content[2048:2064] == b"EXTENT_PART_3___"

    reader.close()


def test_fat32_backup_boot_sector_failover(temp_img):
    """Vérifie que FATReader et Scanner détectent un volume FAT32 via son Backup Boot Sector (LBA 6) si LBA 0 est vierge."""
    path = temp_img(size=1024 * 1024)
    with open(path, "r+b") as f:
        # LBA 0 = 0 (effacé)
        # LBA 6 = Backup Boot Sector FAT32 officiel
        s6 = bytearray(512)
        s6[3:11] = b"MSWIN4.1"
        struct.pack_into("<H", s6, 0x0B, 512)
        s6[0x0D] = 8 # spc
        struct.pack_into("<H", s6, 0x0E, 32) # reserved
        s6[0x10] = 2 # num_fats
        struct.pack_into("<H", s6, 0x16, 0)  # fat_size_16 = 0
        struct.pack_into("<I", s6, 0x20, 2048) # total_sectors_32
        struct.pack_into("<I", s6, 0x24, 64)   # fat_size_32
        struct.pack_into("<I", s6, 0x2C, 2)    # root_cluster = 2
        s6[0x47 : 0x47 + 11] = b"RESCUE_FAT "
        s6[82:90] = b"FAT32   "
        s6[510:512] = b"\x55\xaa"

        f.seek(6 * 512)
        f.write(s6)

    reader = RawImageReader(path)
    # Test Scanner
    sig = identify_fs_signature(reader.read_bytes(0, 8192))
    assert sig == "FAT32 Filesystem (Backup Boot Sector)"
    all_fs = detect_all_filesystems(reader.read_bytes(0, 8192))
    assert "FAT32" in all_fs

    # Test FATReader
    fat = FATReader(reader)
    assert fat.is_valid_fat is True
    assert fat.used_backup_boot_sector is True
    assert fat.fat_type == "FAT32"
    assert fat.bpb_label == "RESCUE_FAT"
    assert fat.root_cluster == 2

    reader.close()
