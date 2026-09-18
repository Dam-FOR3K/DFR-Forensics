# -*- coding: utf-8 -*-
"""
Tests unitaires pour le moteur QNX étendu (QNX4 & QNX6 Power-Safe)
Inspiré des spécifications qnxmount (NFI) et qnxprobe (Alexis Brignoni).
"""

import os
import struct
import io
import pytest

from core.qnx_reader import (
    QNX6_MAGIC,
    QNX6_BOOTBLOCK_MAGIC,
    parse_qnx6_sb,
    find_qnx6_superblocks,
    NativeQnx6Walker,
    QNXReader,
)
from core.image_reader import RawImageReader


def test_qnx6_superblock_parsing():
    """Vérifie la robustesse du parseur de superblocks QNX6 (Little-Endian et Big-Endian)."""
    buf = bytearray(512)
    # Magic
    struct.pack_into("<I", buf, 0, QNX6_MAGIC)
    # Serial
    struct.pack_into("<Q", buf, 8, 42)
    # Blocksize = 4096
    struct.pack_into("<I", buf, 48, 4096)
    # num_inodes = 100, free_inodes = 80
    struct.pack_into("<I", buf, 52, 100)
    struct.pack_into("<I", buf, 56, 80)
    # num_blocks = 1000, free_blocks = 900
    struct.pack_into("<I", buf, 60, 1000)
    struct.pack_into("<I", buf, 64, 900)

    sb, bad = parse_qnx6_sb(bytes(buf), "little")
    assert sb is not None, "Le superblock doit être reconnu"
    assert not bad, f"Le superblock doit être sain : {bad}"
    assert sb["serial"] == 42
    assert sb["blocksize"] == 4096
    assert sb["free_blocks"] == 900


def test_qnx6_bootblock_pointers():
    """Vérifie la découverte de superblocks via les pointeurs du bootblock automobile."""
    # Créer un flux en mémoire simulant une partition QNX6 avec bootblock
    stream_data = bytearray(65536)
    
    # 1. Bootblock à l'offset 0 avec pointeurs vers sblk0 (secteur 16) et sblk1 (secteur 24)
    struct.pack_into("<4s", stream_data, 0, QNX6_BOOTBLOCK_MAGIC)
    struct.pack_into("<II", stream_data, 8, 16, 24)

    # 2. Superblock valide au secteur 16 (offset 8192)
    sb0_off = 16 * 512
    struct.pack_into("<I", stream_data, sb0_off + 0, QNX6_MAGIC)
    struct.pack_into("<Q", stream_data, sb0_off + 8, 100)  # serial 100 (plus récent)
    struct.pack_into("<I", stream_data, sb0_off + 48, 4096) # 4K
    struct.pack_into("<I", stream_data, sb0_off + 52, 50)
    struct.pack_into("<I", stream_data, sb0_off + 56, 40)
    struct.pack_into("<I", stream_data, sb0_off + 60, 500)
    struct.pack_into("<I", stream_data, sb0_off + 64, 450)

    # 3. Superblock valide au secteur 24 (offset 12288) avec génération antérieure
    sb1_off = 24 * 512
    struct.pack_into("<I", stream_data, sb1_off + 0, QNX6_MAGIC)
    struct.pack_into("<Q", stream_data, sb1_off + 8, 99)   # serial 99 (ancien)
    struct.pack_into("<I", stream_data, sb1_off + 48, 4096)
    struct.pack_into("<I", stream_data, sb1_off + 52, 50)
    struct.pack_into("<I", stream_data, sb1_off + 56, 41)
    struct.pack_into("<I", stream_data, sb1_off + 60, 500)
    struct.pack_into("<I", stream_data, sb1_off + 64, 451)

    bio = io.BytesIO(bytes(stream_data))
    found = find_qnx6_superblocks(bio, len(stream_data))

    assert len(found) >= 2, "Les deux générations de superblocks doivent être découvertes"
    # Le premier doit être le serial le plus récent (100)
    assert found[0][1]["serial"] == 100
    assert found[0][0] == sb0_off
    assert found[1][1]["serial"] == 99
    assert found[1][0] == sb1_off
