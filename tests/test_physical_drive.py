"""
Tests unitaires pour le support des disques physiques (PhysicalDiskReader & core/physical_disk).
"""

import os
import io
import pytest
from unittest.mock import patch, MagicMock

from core.physical_disk import (
    PhysicalDriveInfo,
    is_admin,
    enumerate_physical_drives,
)
from core.image_reader import (
    is_physical_drive_path,
    PhysicalDiskReader,
    open_forensic_image,
)


def test_is_physical_drive_path():
    """Vérifie la détection des chemins de périphériques physiques Windows et Linux."""
    # Windows
    assert is_physical_drive_path(r"\\.\PhysicalDrive0")
    assert is_physical_drive_path(r"\\.\PHYSICALDRIVE1")
    assert is_physical_drive_path(r"\\.\CdRom0")
    # Linux / Unix
    assert is_physical_drive_path("/dev/sda")
    assert is_physical_drive_path("/dev/nvme0n1")
    assert is_physical_drive_path("/dev/vda")
    assert is_physical_drive_path("/dev/rdisk2")

    # Fichiers standards (doivent renvoyer False)
    assert not is_physical_drive_path("image.raw")
    assert not is_physical_drive_path(r"C:\evidence\disk.e01")
    assert not is_physical_drive_path("/home/user/disk.img")
    assert not is_physical_drive_path("")
    assert not is_physical_drive_path(None)


def test_physical_drive_info_formatting():
    """Vérifie le formatage des métadonnées des disques physiques."""
    d1 = PhysicalDriveInfo(
        index=0,
        device_id=r"\\.\PhysicalDrive0",
        model="Crucial CT1000P3SSD8",
        size_bytes=1000204886016,  # ~1 To
        interface_type="NVMe",
        media_type="Fixed hard disk media",
        sector_size=512,
    )
    assert d1.index == 0
    assert "Disque 0" in d1.display_name
    assert "Crucial" in d1.display_name
    assert "To" in d1.display_name or "Go" in d1.display_name
    assert "NVMe" in d1.display_name

    d2 = PhysicalDriveInfo(
        index=2,
        device_id=r"\\.\PhysicalDrive2",
        model="SanDisk Ultra USB 3.0",
        size_bytes=32000000000,  # ~32 Go
        interface_type="USB",
        media_type="External hard disk media",
        sector_size=512,
    )
    assert "SanDisk" in d2.display_name
    assert "USB" in d2.display_name


def test_physical_disk_reader_sector_alignment(tmp_path):
    """Vérifie que PhysicalDiskReader aligne correctement les lectures arbitraires sur les secteurs."""
    # Création d'un fichier de test simulant un disque de 16 secteurs (8 192 octets)
    test_disk = tmp_path / "mock_physical_drive.bin"
    # Remplir avec un pattern identifiable (octets 0 à 255 répétés)
    data = bytes([i % 256 for i in range(8192)])
    test_disk.write_bytes(data)

    # Initialisation de PhysicalDiskReader sur ce fichier
    reader = PhysicalDiskReader(str(test_disk), sector_size=512, total_size_bytes=len(data))
    try:
        assert reader.total_sectors == 16
        assert reader.sector_size == 512

        # 1. Lecture alignée secteur 0
        sec0 = reader.read_sector(0, count=1)
        assert len(sec0) == 512
        assert sec0 == data[0:512]

        # 2. Lecture non alignée chevauchant 2 secteurs (offset=500, length=50 -> octets 500 à 550)
        unaligned_bytes = reader.read_bytes(500, 50)
        assert len(unaligned_bytes) == 50
        assert unaligned_bytes == data[500:550]

        # 3. Lecture non alignée de petite taille (offset=10, length=5)
        small_chunk = reader.read_bytes(10, 5)
        assert len(small_chunk) == 5
        assert small_chunk == data[10:15]

        # 4. Lecture en fin de disque
        end_bytes = reader.read_bytes(8190, 10)  # dépasse la fin
        assert len(end_bytes) == 2 or len(end_bytes) == 10  # retour tronqué ou paddé
    finally:
        reader.close()


def test_physical_disk_reader_bad_sector_resilience(tmp_path):
    """Vérifie que PhysicalDiskReader capture les erreurs I/O matérielles et renvoie des zéros sans crasher."""
    test_disk = tmp_path / "bad_sector_disk.bin"
    test_disk.write_bytes(b"\xAA" * 4096)

    reader = PhysicalDiskReader(str(test_disk), sector_size=512, total_size_bytes=4096)

    # Simuler une panne de secteur sur _file.read() en injectant une exception OSError(23, "CRC Error")
    original_read = reader._file.read

    def failing_read(size):
        # Si on lit le secteur LBA 2 (offset 1024)
        if reader._file.tell() == 1024:
            raise OSError(23, "Data error (cyclic redundancy check)")
        return original_read(size)

    reader._file.read = failing_read

    try:
        # LBA 0 fonctionne normalement
        s0 = reader.read_sector(0)
        assert s0 == b"\xAA" * 512

        # LBA 2 déclenche l'erreur matérielle simulée
        s2 = reader.read_sector(2)
        assert s2 == b"\x00" * 512, "Le secteur défectueux doit renvoyer des zéros"
        assert 2 in reader.bad_sectors, "Le LBA défectueux doit être consigné dans bad_sectors"

        # LBA 3 fonctionne à nouveau
        s3 = reader.read_sector(3)
        assert s3 == b"\xAA" * 512
    finally:
        reader.close()


def test_enumerate_physical_drives_system():
    """Vérifie que l'énumération système s'exécute sans lever d'exception."""
    drives = enumerate_physical_drives()
    assert isinstance(drives, list)
    # Sur la machine hôte actuelle, au moins un disque physique doit être présent
    if len(drives) > 0:
        d = drives[0]
        assert isinstance(d.index, int)
        assert isinstance(d.device_id, str)
        assert d.size_bytes >= 0


def test_bitlocker_modern_guid_detection(tmp_path):
    """Vérifie la détection de BitLocker avec le GUID moderne Windows 10/11/ToGo."""
    from core.crypto_engine import EncryptedVolumeHandler
    from core.image_reader import RawImageReader
    from core.scanner import identify_fs_signature, detect_all_filesystems

    # Créer un secteur 0 avec le GUID BitLocker et dummy FAT32 BPB
    sec0 = bytearray(512)
    # Dummy FAT32 OEM ID
    sec0[82:90] = b"FAT32   "
    # BitLocker information GUID à l'offset 0xA0
    bitlocker_guid = b";\xd6gI).\xd8J\x83\x99\xf6\xa39\xe3\xd0\x01"
    sec0[0xA0 : 0xA0 + 16] = bitlocker_guid
    sec0[510:512] = b"\x55\xaa"

    f = tmp_path / "bitlocker_test.bin"
    f.write_bytes(bytes(sec0))

    # Test scanner signature recognition
    detected = identify_fs_signature(bytes(sec0))
    assert detected == "BitLocker Encrypted Volume"

    all_fs = detect_all_filesystems(bytes(sec0))
    assert "BitLocker" in all_fs

    # Test EncryptedVolumeHandler detection
    reader = RawImageReader(str(f))
    try:
        handler = EncryptedVolumeHandler(reader, start_lba=0, total_sectors=1)
        assert handler.is_encrypted is True
        assert handler.crypto_type == "BitLocker"
        assert "BitLocker" in handler.metadata.get("version", "")
    finally:
        reader.close()


def test_encrypted_volume_handler_windows_unlock(tmp_path):
    """Vérifie le déverrouillage transparent via un lecteur Windows déchiffré."""
    from core.crypto_engine import EncryptedVolumeHandler
    from core.image_reader import RawImageReader

    # Simuler un disque physique chiffré
    sec0 = bytearray(512)
    sec0[0xA0 : 0xA0 + 16] = b";\xd6gI).\xd8J\x83\x99\xf6\xa39\xe3\xd0\x01"
    f_raw = tmp_path / "locked_disk.bin"
    f_raw.write_bytes(bytes(sec0))

    # Simuler le lecteur Windows déchiffré contenant un boot sector NTFS
    ntfs_boot = bytearray(512)
    ntfs_boot[3:11] = b"NTFS    "
    f_win = tmp_path / "decrypted_win.bin"
    f_win.write_bytes(bytes(ntfs_boot))

    reader = RawImageReader(str(f_raw))
    try:
        handler = EncryptedVolumeHandler(reader, start_lba=0, total_sectors=1)
        assert handler.is_encrypted is True

        # Mock PhysicalDiskReader pour renvoyer le flux f_win
        mock_win_reader = RawImageReader(str(f_win))
        with patch("core.image_reader.PhysicalDiskReader", return_value=mock_win_reader):
            ok, err = handler.unlock_with_windows_volume("D:")
            assert ok is True
            assert err is None
            assert handler.is_unlocked is True
            assert handler.decrypted_reader is not None
            # Vérifier qu'on lit bien le VBR NTFS
            hdr = handler.decrypted_reader.read_sector(0)
            assert hdr[3:11] == b"NTFS    "
    finally:
        reader.close()


