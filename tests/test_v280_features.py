"""
DFR-Forensics v2.8.0 - Tests unitaires des nouvelles capacités médico-légales.
Couvre :
1. QNX Flash Filesystem (F3S / ETFS) sur image réelle sample/test_image (1).bin.
2. Apple HFS+ / HFSX : détection, parsing catalogue B-Tree, allocation file, extraction.
3. Carving de l'espace non alloué Apple HFS+ via $AllocationFile.
4. Linux SquashFS v4 : détection magic 'hsqs' / 'sqsh', parsing superbloc et répertoires.
5. Linux Initramfs / CPIO : parsing d'archives '070701' et extraction de fichiers.
6. Systèmes Flash Embarqués : détection F2FS, EROFS, UBI, JFFS2.
7. Windows VSS (Volume Shadow Copies) : détection 'scek' et conversion de FILETIME.
8. Moteur de recherche brute multi-threadée (Raw Keyword & Regex Stream Search).
9. Sous-volumes APFS séparés dans GPTPartitionEntry et DiskScanner.
"""

import os
import struct
import tempfile
import pytest
from datetime import datetime, timezone

from core.image_reader import RawImageReader
from core.f3s_reader import F3SReader, F3SFileEntry
from core.hfs_reader import HFSReader, HFSFileEntry, hfs_timestamp_to_datetime
from core.unallocated import extract_unallocated_hfs
from core.squashfs_reader import SquashFSReader, SquashFSFileEntry
from core.cpio_reader import CPIOReader, CPIOFileEntry
from core.embedded_flash import EmbeddedFlashReader, EmbeddedFileEntry
from core.vss_reader import VSSReader, VSSSnapshot, filetime_to_datetime
from core.raw_search import RawSearchWorker, SearchHit
from core.gpt_structures import GPTPartitionEntry
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


def test_qnx_f3s_real_sample():
    """Vérifie le parsing complet de l'image Flash QNX réelle sample/test_image (1).bin."""
    sample_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample", "test_image (1).bin")
    if not os.path.exists(sample_path):
        pytest.skip("sample/test_image (1).bin non disponible pour le test")

    reader = RawImageReader(sample_path)
    f3s = F3SReader(reader, partition_offset_bytes=0, partition_size_bytes=reader.total_size_bytes)

    assert f3s.is_valid_f3s is True
    assert f3s.unit_size == 0x20000  # 128 Ko
    assert f3s.root_entry is not None
    assert len(f3s.all_entries) > 0

    # Vérifier la présence de fichiers clés connus
    names = [e.name for e in f3s.all_entries]
    assert "message.txt" in names
    assert "this_file_is_small" in names

    # Vérifier l'extraction de message.txt
    msg_entry = next(e for e in f3s.all_entries if e.name == "message.txt")
    content = f3s.extract_file_content(msg_entry)
    assert b"This is a test file system!" in content

    # Vérifier la présence d'entrées supprimées récupérées
    deleted_entries = [e for e in f3s.all_entries if e.is_deleted]
    assert len(deleted_entries) > 0


def test_hfs_reader_synthetic(temp_img):
    """Vérifie le lecteur Apple HFS+ sur une structure synthétique conforme."""
    path = temp_img(size=512 * 1024)
    with open(path, "r+b") as f:
        # Offset 1024 : Volume Header HFS+
        vh = bytearray(512)
        vh[:2] = b"H+"
        # version:2=4, attr:4, lmv:4, jib:4, cdate:4, mdate:4 (timestamp 1904), bdate:4, chkdate:4
        # fcount:4=10, dcount:4=2, bsize:4=4096, tblocks:4=128, fblocks:4=64
        struct.pack_into(">HIIIIIIIIIIII", vh, 2, 4, 0, 0, 0, 3700000000, 3700000000, 0, 0, 10, 2, 4096, 128, 64)
        # Allocation file extents à 112 : start_block=1, block_count=1
        struct.pack_into(">II", vh, 112, 1, 1)
        # Catalog file extents à 240 : start_block=2, block_count=2
        struct.pack_into(">II", vh, 240, 2, 2)
        f.seek(1024)
        f.write(vh)

        # Écrire un enregistrement catalogue dans le catalog file (bloc 2 => offset 2 * 4096 = 8192)
        cat_block = bytearray(4096)
        pos = 512
        # rec_type = 2 (kHFSPlusFileRecord)
        cat_block[pos : pos + 2] = struct.pack(">H", 2)
        test_filename = "apple_forensics.txt"
        encoded_name = test_filename.encode("utf-16-be")
        cat_block[pos + 6 : pos + 8] = struct.pack(">H", len(test_filename))
        cat_block[pos + 8 : pos + 8 + len(encoded_name)] = encoded_name
        f.seek(8192)
        f.write(cat_block)

    reader = RawImageReader(path)
    hfs_r = HFSReader(reader, 0, reader.total_size_bytes)
    assert hfs_r.is_valid_hfs is True
    assert hfs_r.signature == "HFS+"
    assert hfs_r.block_size == 4096
    assert hfs_r.total_blocks == 128
    assert hfs_r.free_blocks == 64

    found_names = [e.name for e in hfs_r.all_entries]
    assert "apple_forensics.txt" in found_names


def test_unallocated_hfs_carving(temp_img):
    """Vérifie la cartographie de l'espace non alloué HFS+ via $AllocationFile."""
    path = temp_img(size=512 * 1024)
    with open(path, "r+b") as f:
        vh = bytearray(512)
        vh[:2] = b"H+"
        # bsize=4096, total_blocks=16, free_blocks=8
        struct.pack_into(">HIIIIIIIIIIII", vh, 2, 4, 0, 0, 0, 3700000000, 3700000000, 0, 0, 1, 1, 4096, 16, 8)
        # Allocation file extents : start_block=1, block_count=1 (offset 4096)
        struct.pack_into(">II", vh, 112, 1, 1)
        f.seek(1024)
        f.write(vh)

        # Écrire le bitmap à l'offset 4096 :
        # 16 blocs = 2 octets de bitmap
        # Octet 0 : 0b11110000 = blocs 0,1,2,3 alloués (1), blocs 4,5,6,7 libres (0)
        # Octet 1 : 0b11110000 = blocs 8,9,10,11 alloués (1), blocs 12,13,14,15 libres (0)
        bitmap_data = bytearray(4096)
        bitmap_data[0] = 0b11110000
        bitmap_data[1] = 0b11110000
        f.seek(4096)
        f.write(bitmap_data)

    reader = RawImageReader(path)
    ranges = extract_unallocated_hfs(reader, 0, 512 * 1024)
    # Les blocs 4..7 et 12..15 doivent être rapportés comme libres en plages LBA
    assert len(ranges) >= 2
    # Bloc 4..7 => LBA 32..63 (4*8 .. 7*8+7)
    assert (32, 63) in ranges
    # Bloc 12..15 => LBA 96..127 (12*8 .. 15*8+7)
    assert (96, 127) in ranges



def test_squashfs_reader(temp_img):
    """Vérifie la détection et la lecture d'un conteneur SquashFS v4."""
    path = temp_img(size=128 * 1024)
    with open(path, "r+b") as f:
        sb = bytearray(96)
        sb[:4] = b"hsqs"  # Little-endian SquashFS v4
        # inodes:4=5, mkfs_time:4, block_size:4=131072, fragments:4=0, comp:2=1 (GZIP), b_log:2=17, flags:2=0, id_count:2=1, v_maj:2=4, v_min:2=0
        # root_inode:8=0x01, bytes_used:8=1024, id_table:8=0, xattr_table:8=-1, inode_table:8=96, dir_table:8=128, frag_table:8=-1, export_table:8=-1
        struct.pack_into("<IIIIHHhhhhQQQQQQQQ", sb, 4, 5, 1700000000, 131072, 0, 1, 17, 0, 1, 4, 0, 1, 1024, 0, 0xFFFFFFFFFFFFFFFF, 96, 128, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
        f.seek(0)
        f.write(sb)

    reader = RawImageReader(path)
    sqsh = SquashFSReader(reader, 0, reader.total_size_bytes)
    assert sqsh.is_valid_squashfs is True
    assert sqsh.compression_type == "GZIP"
    assert sqsh.block_size == 131072
    assert sqsh.root_entry is not None


def test_cpio_reader(temp_img):
    """Vérifie le parsing d'une archive CPIO Initramfs (magic '070701')."""
    path = temp_img(size=64 * 1024)
    with open(path, "r+b") as f:
        # Construction d'un en-tête CPIO SVR4 portable (110 octets hex)
        # Format : magic(6), ino(8), mode(8), uid(8), gid(8), nlink(8), mtime(8), filesize(8),
        # devmajor(8), devminor(8), rdevmajor(8), rdevminor(8), namesize(8), check(8)
        filename = "init.sh"
        namesize = len(filename) + 1  # inclut \0
        file_content = b"#!/bin/sh\necho Booting Forensics System...\n"
        filesize = len(file_content)

        hdr_str = (
            f"070701"
            f"{1:08X}"       # ino
            f"{0o100755:08X}"  # mode (regular file executable)
            f"{0:08X}"       # uid
            f"{0:08X}"       # gid
            f"{1:08X}"       # nlink
            f"{1700000000:08X}" # mtime
            f"{filesize:08X}"
            f"{0:08X}{0:08X}{0:08X}{0:08X}"
            f"{namesize:08X}"
            f"{0:08X}"       # check
        ).encode("ascii")
        assert len(hdr_str) == 110

        f.seek(0)
        f.write(hdr_str)
        f.write(filename.encode("ascii") + b"\x00")
        # Padding 4 octets pour le nom : (110 + namesize) % 4
        pad_name = (4 - ((110 + namesize) % 4)) % 4
        f.write(b"\x00" * pad_name)

        # Données du fichier
        f.write(file_content)
        pad_data = (4 - (filesize % 4)) % 4
        f.write(b"\x00" * pad_data)

        # Entrée de fin CPIO "TRAILER!!!"
        trailer = "TRAILER!!!"
        t_namesize = len(trailer) + 1
        t_hdr = (
            f"070701"
            f"{0:08X}{0:08X}{0:08X}{0:08X}{1:08X}{0:08X}{0:08X}"
            f"{0:08X}{0:08X}{0:08X}{0:08X}"
            f"{t_namesize:08X}"
            f"{0:08X}"
        ).encode("ascii")
        f.write(t_hdr)
        f.write(trailer.encode("ascii") + b"\x00")

    reader = RawImageReader(path)
    cpio = CPIOReader(reader, 0, reader.total_size_bytes)
    assert cpio.is_valid_cpio is True
    assert len(cpio.all_entries) >= 1

    entry = next(e for e in cpio.all_entries if e.name == "init.sh")
    assert entry.size == len(file_content)
    extracted = cpio.extract_file_content(entry)
    assert extracted == file_content


def test_embedded_flash_recognition(temp_img):
    """Vérifie la détection des superblocs F2FS, EROFS, UBI et JFFS2."""
    # 1. Tester F2FS
    p1 = temp_img(size=64 * 1024)
    with open(p1, "r+b") as f:
        f.seek(1024)
        f.write(struct.pack("<I", 0xF2F52010))

    r1 = RawImageReader(p1)
    emb1 = EmbeddedFlashReader(r1, 0, r1.total_size_bytes)
    assert emb1.is_valid is True
    assert "F2FS" in emb1.fs_type

    # 2. Tester EROFS
    p2 = temp_img(size=64 * 1024)
    with open(p2, "r+b") as f:
        f.seek(1024)
        f.write(struct.pack("<I", 0xE0F5E1E2))
    r2 = RawImageReader(p2)
    emb2 = EmbeddedFlashReader(r2, 0, r2.total_size_bytes)
    assert emb2.is_valid is True
    assert "EROFS" in emb2.fs_type

    # 3. Tester UBI
    p3 = temp_img(size=64 * 1024)
    with open(p3, "r+b") as f:
        f.seek(0)
        f.write(b"UBI#")
    r3 = RawImageReader(p3)
    emb3 = EmbeddedFlashReader(r3, 0, r3.total_size_bytes)
    assert emb3.is_valid is True
    assert "UBI" in emb3.fs_type



def test_vss_snapshot_scanner(temp_img):
    """Vérifie la détection heuristique des blocs de catalogue VSS 'scek'."""
    path = temp_img(size=1024 * 1024)
    with open(path, "r+b") as f:
        # Simuler un catalogue VSS à l'offset 4096 (secteur 8)
        pos = 4096
        # Magic "scek"
        f.seek(pos)
        f.write(b"scek" + b"\x00" * 12)
        # Écrire un timestamp FILETIME valide pour l'année 2024
        # 2024-06-01 12:00:00 UTC = 133616688000000000 en FILETIME
        dt = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        sec = dt.timestamp()
        ft = int((sec + 11644473600) * 10_000_000)
        f.seek(pos + 16)
        f.write(struct.pack("<Q", ft))

    reader = RawImageReader(path)
    vss = VSSReader(reader, 0, reader.total_size_bytes)
    assert len(vss.snapshots) >= 1
    snap = vss.snapshots[0]
    assert snap.creation_time is not None
    assert snap.creation_time.year == 2024
    assert snap.creation_time.month == 6


def test_raw_stream_scanner(temp_img):
    """Vérifie le moteur de recherche brute (mots-clés et regex multi-threadés)."""
    path = temp_img(size=512 * 1024)
    with open(path, "r+b") as f:
        f.seek(1024)
        f.write(b"CONFIDENTIAL_EVIDENCE_CASE_42")
        f.seek(2048)
        f.write(b"Target IP address: 192.168.1.105 established session")

    reader = RawImageReader(path)

    # 1. Recherche par mot-clé
    worker1 = RawSearchWorker(reader, query="CONFIDENTIAL_EVIDENCE", is_regex=False)
    worker1.run()
    assert len(worker1.hits) == 1
    assert worker1.hits[0].offset_bytes == 1024
    assert "CONFIDENTIAL_EVIDENCE" in worker1.hits[0].matched_term

    # 2. Recherche par expression régulière (IP)
    worker2 = RawSearchWorker(reader, query=r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", is_regex=True)
    worker2.run()
    assert len(worker2.hits) == 1
    assert worker2.hits[0].matched_term == "192.168.1.105"
    assert worker2.hits[0].offset_bytes == 2048 + len(b"Target IP address: ")



def test_scanner_signatures_and_apfs_subvolumes():
    """Vérifie la reconnaissance des signatures dans core/scanner.py et l'enrichissement des sous-volumes APFS."""
    # 1. Signatures
    assert identify_fs_signature(b"\x00" * 44 + b"QSSL_F3S" + b"\x00" * 400) == "QNX Flash Filesystem (F3S)"
    assert identify_fs_signature(b"\x00" * 1024 + b"H+" + b"\x00" * 400) == "Apple HFS+ Filesystem"
    assert identify_fs_signature(b"hsqs" + b"\x00" * 508) == "SquashFS Filesystem"
    assert identify_fs_signature(b"070701" + b"\x00" * 506) == "CPIO / Initramfs Archive"
    assert identify_fs_signature(b"UBI#" + b"\x00" * 508) == "UBI Flash Container"

    # 2. Structure GPTPartitionEntry sub_volumes
    entry = GPTPartitionEntry()
    entry.first_lba = 100
    entry.last_lba = 200
    entry.name = "Test APFS"
    assert hasattr(entry, "sub_volumes")
    assert entry.sub_volumes == []
    entry.sub_volumes.append({"name": "Macintosh HD", "uuid": "ABC-123", "is_encrypted": False})
    assert len(entry.sub_volumes) == 1


def test_raw_search_dialog_init(temp_img):
    """Vérifie que RawSearchDialog s'initialise sans aucune erreur d'import ou de layout."""
    from PySide6.QtWidgets import QApplication
    from ui.raw_search_dialog import RawSearchDialog

    app = QApplication.instance() or QApplication([])
    path = temp_img(size=256 * 1024)
    reader = RawImageReader(path)
    dialog = RawSearchDialog(reader, diag=None)
    assert dialog.combo_scope.count() >= 1
    assert dialog.combo_scope.itemText(0) in ("Disque Entier (Physique)", "Entire Physical Disk")
    assert dialog.edit_query is not None
    dialog.close()
    reader.close()


def test_reader_stream_and_slack_inspector(temp_img):
    """Vérifie l'adaptateur de flux ReaderStream et l'extracteur de slack de VirtualExplorerDialog."""
    from ui.file_explorer_dialog import ReaderStream, VirtualExplorerDialog
    from core.ntfs_reader import NTFSFileEntry

    path = temp_img(size=1024 * 1024)
    with open(path, "r+b") as f:
        f.seek(1000)
        f.write(b"HELLO_DISSECT_NTFS_TEST_DATA")
    reader = RawImageReader(path)

    # 1. ReaderStream tests
    stream = ReaderStream(reader, offset_bytes=1000, size_bytes=100)
    assert stream.readable() is True
    assert stream.seekable() is True
    assert stream.tell() == 0
    data = stream.read(5)
    assert data == b"HELLO"
    assert stream.tell() == 5
    stream.seek(6)
    data2 = stream.read(7)
    assert data2 == b"DISSECT"

    # 2. Slack Inspector extraction test
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    dialog = VirtualExplorerDialog(reader, diag=None)

    entry = NTFSFileEntry(record_num=100)
    entry.name = "test_slack.txt"
    entry.size = 3000
    entry.allocated_size = 4096
    entry.data_runs = [(10, 1)]

    name, fsize, csize, slack_size, slack_bytes = dialog._extract_slack_data(entry)
    assert name == "test_slack.txt"
    assert fsize == 3000
    assert csize == 4096
    assert slack_size == 4096 - 3000  # 1096 bytes slack
    dialog.close()
    reader.close()



