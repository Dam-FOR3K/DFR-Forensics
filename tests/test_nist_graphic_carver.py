"""
Tests unitaires médico-légaux pour la suite NIST CFTT Graphic Carving.
Valide le carveur TIFF (II* / MM*), la résilience PNG, les en-têtes BMP v1-v5,
ainsi que le dé-tressage mathématique (BraidResolver).
"""

import io
import os
import sys
import struct
import zlib
import pytest
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.carver import (
    SmartCarver,
    CarvedArtefact,
    validate_tiff,
    validate_png,
    validate_bmp,
)
from core.defragmenter import BraidResolver, extract_stream_data, is_filler_sector
from core.image_reader import ForensicImageReader, RawImageReader


class MockBytesReader(ForensicImageReader):
    """Lecteur forensique en mémoire pour les tests unitaires."""

    def __init__(self, data: bytes, sector_size: int = 512):
        self._data = bytearray(data)
        self.sector_size = sector_size
        self._total_sectors = max(1, (len(self._data) + sector_size - 1) // sector_size)
        pad = (self._total_sectors * sector_size) - len(self._data)
        if pad > 0:
            self._data += b"\x00" * pad

    def open(self):
        pass

    def close(self):
        pass

    def read_sector(self, lba: int) -> bytes:
        offset = lba * self.sector_size
        if offset >= len(self._data):
            return b"\x00" * self.sector_size
        return bytes(self._data[offset : offset + self.sector_size])

    def read_bytes(self, offset: int, length: int) -> bytes:
        if offset >= len(self._data):
            return b""
        return bytes(self._data[offset : offset + length])

    @property
    def total_sectors(self) -> int:
        return self._total_sectors

    @property
    def total_size_bytes(self) -> int:
        return len(self._data)


def create_minimal_tiff(width=100, height=80, endian="<") -> bytes:
    """Génère un flux binaire TIFF 6.0 minimal et valide."""
    order = "<" if endian == "<" else ">"
    sig = b"II*\x00" if endian == "<" else b"MM\x00*"
    
    # Image data: 1 strip uncompressed RGB or Grayscale
    strip_bytes = width * height
    raw_pixels = b"\x80" * strip_bytes
    strip_offset = 8  # Immédiatement après l'en-tête de 8 octets
    ifd_offset = 8 + strip_bytes
    
    buf = bytearray()
    buf.extend(sig)
    buf.extend(struct.pack(f"{order}I", ifd_offset))
    buf.extend(raw_pixels)
    
    # IFD: 10 entrées standard
    entries = [
        (0x0100, 3, 1, width if order == "<" else (width << 16)),       # ImageWidth
        (0x0101, 3, 1, height if order == "<" else (height << 16)),     # ImageLength
        (0x0102, 3, 1, 8 if order == "<" else (8 << 16)),               # BitsPerSample
        (0x0103, 3, 1, 1 if order == "<" else (1 << 16)),               # Compression (None)
        (0x0106, 3, 1, 1 if order == "<" else (1 << 16)),               # Photometric (BlackIsZero)
        (0x0111, 4, 1, strip_offset),                                   # StripOffsets
        (0x0115, 3, 1, 1 if order == "<" else (1 << 16)),               # SamplesPerPixel
        (0x0116, 3, 1, height if order == "<" else (height << 16)),     # RowsPerStrip
        (0x0117, 4, 1, strip_bytes),                                    # StripByteCounts
    ]
    
    buf.extend(struct.pack(f"{order}H", len(entries)))
    for tag, typ, cnt, val in entries:
        buf.extend(struct.pack(f"{order}HHII", tag, typ, cnt, val))
    buf.extend(struct.pack(f"{order}I", 0))  # Next IFD = 0
    return bytes(buf)


def test_validate_tiff_little_endian():
    raw_tiff = create_minimal_tiff(width=64, height=32, endian="<")
    reader = MockBytesReader(raw_tiff)
    res = validate_tiff(reader, 0)
    assert res is not None
    length, meta, is_frag = res
    assert length == len(raw_tiff)
    assert meta["file_type"] == "TIFF"
    assert meta["width"] == 64
    assert meta["height"] == 32
    assert meta["endianness"] == "Little"
    assert not is_frag


def test_validate_tiff_big_endian():
    raw_tiff = create_minimal_tiff(width=120, height=90, endian=">")
    reader = MockBytesReader(raw_tiff)
    res = validate_tiff(reader, 0)
    assert res is not None
    length, meta, is_frag = res
    assert length == len(raw_tiff)
    assert meta["file_type"] == "TIFF"
    assert meta["width"] == 120
    assert meta["height"] == 90
    assert meta["endianness"] == "Big"
    assert not is_frag


def test_validate_tiff_rejects_embedded_exif():
    """Vérifie que les segments EXIF intégrés dans les JPEG ne sont pas carvers comme TIFF."""
    raw_tiff = create_minimal_tiff(width=64, height=32, endian="<")
    # Simuler un segment JPEG APP1 contenant Exif\x00\x00 suivi du header TIFF
    jpeg_exif_prefix = b"\xFF\xE1\x00\x40Exif\x00\x00"
    data = jpeg_exif_prefix + raw_tiff
    reader = MockBytesReader(data)
    # L'offset du header TIFF est len(jpeg_exif_prefix) = 10
    res = validate_tiff(reader, len(jpeg_exif_prefix))
    assert res is None, "Le validator TIFF doit rejeter un IFD précédé de Exif\\x00\\x00"


def test_validate_tiff_rejects_no_strips():
    """Vérifie qu'un en-tête TIFF sans StripOffsets ni TileOffsets est rejeté."""
    buf = bytearray()
    buf.extend(b"II*\x00\x08\x00\x00\x00")  # Header TIFF Little Endian pointant à offset 8
    # 2 entries: ImageWidth (0x100) et ImageLength (0x101) sans StripOffsets
    buf.extend(struct.pack("<H", 2))
    buf.extend(struct.pack("<HHII", 0x0100, 3, 1, 100))  # Width = 100
    buf.extend(struct.pack("<HHII", 0x0101, 3, 1, 80))   # Height = 80
    buf.extend(struct.pack("<I", 0))
    reader = MockBytesReader(bytes(buf))
    res = validate_tiff(reader, 0)
    assert res is None, "Le validator TIFF doit rejeter un IFD sans strips/tiles"


def test_validate_bmp_v3_header():
    """Valide les bitmaps Windows avec en-tête BITMAPV3INFOHEADER (56 octets)."""
    # Header: BM (2) + size (4) + reserved (4) + offset (4) = 14 bytes
    # DIB: 56 bytes (0x38), width=320, height=240, bpp=16, comp=3 (bitfields)
    width, height = 320, 240
    pixel_data_len = width * height * 2
    total_size = 14 + 56 + pixel_data_len
    hdr = bytearray(total_size)
    hdr[0:2] = b"BM"
    struct.pack_into("<I", hdr, 2, total_size)
    struct.pack_into("<I", hdr, 10, 70)  # Pixel data offset
    struct.pack_into("<I", hdr, 14, 56)  # DIB header size = 56
    struct.pack_into("<I", hdr, 18, width)
    struct.pack_into("<i", hdr, 22, height)
    struct.pack_into("<H", hdr, 26, 1)   # Planes
    struct.pack_into("<H", hdr, 28, 16)  # BPP = 16
    struct.pack_into("<I", hdr, 30, 3)   # BI_BITFIELDS

    reader = MockBytesReader(hdr)
    res = validate_bmp(reader, 0)
    assert res is not None
    length, meta, is_frag = res
    assert length == total_size
    assert meta["file_type"] == "BMP"
    assert meta["width"] == 320
    assert meta["height"] == 240
    assert meta["bit_depth"] == 16


def test_validate_png_resilient():
    """Vérifie qu'un PNG dont un chunk IDAT intermédiaire est corrompu ou fragmenté est sauvé."""
    # Créer un PNG valide avec Pillow
    img = Image.new("RGB", (64, 64), color="blue")
    out = io.BytesIO()
    img.save(out, format="PNG")
    png_bytes = out.getvalue()

    # Altérer le CRC d'un chunk au milieu
    corrupted = bytearray(png_bytes)
    # Trouver le premier IDAT
    idat_pos = corrupted.find(b"IDAT")
    if idat_pos != -1:
        # Corrompre un octet dans les données IDAT
        corrupted[idat_pos + 10] ^= 0xFF

    reader = MockBytesReader(corrupted)
    res = validate_png(reader, 0)
    assert res is not None
    length, meta, is_frag = res
    assert meta["width"] == 64
    assert meta["height"] == 64
    assert is_frag is True  # Sauvetage médico-légal réussi


def test_debraid_in_memory_simulation():
    """Simule mathématiquement un entrelacement 1A-1B-2A-2B de deux images BMP."""
    # Créer Image A (100x100) et Image B (120x80)
    imgA = Image.new("RGB", (100, 100), color="red")
    outA = io.BytesIO()
    imgA.save(outA, format="BMP")
    dataA = outA.getvalue()

    imgB = Image.new("RGB", (120, 80), color="green")
    outB = io.BytesIO()
    imgB.save(outB, format="BMP")
    dataB = outB.getvalue()

    # Découper en tiers (alignés sur 512 octets)
    def to_sectors(b):
        pad = (512 - len(b) % 512) % 512
        return b + b"\x00" * pad

    padA = to_sectors(dataA)
    padB = to_sectors(dataB)
    secA = len(padA) // 512
    secB = len(padB) // 512

    p1A = max(1, secA // 3)
    p2A = secA - p1A

    p1B = max(1, secB // 3)
    p2B = secB - p1B

    # Assembler le disque tressé : 1A + 1B + 2A + 2B
    braided_disk = bytearray()
    braided_disk.extend(padA[: p1A * 512])
    braided_disk.extend(padB[: p1B * 512])
    braided_disk.extend(padA[p1A * 512 :])
    braided_disk.extend(padB[p1B * 512 :])

    reader = MockBytesReader(braided_disk)
    resolver = BraidResolver(reader)

    artA = CarvedArtefact(1, "Images", "BMP", ".bmp", 0, 0, len(dataA), secA - 1)
    artB = CarvedArtefact(2, "Images", "BMP", ".bmp", p1A, p1A * 512, len(dataB), p1A + secB - 1)

    resolver.resolve([artA, artB])

    assert artA.is_fragmented is True
    assert artB.is_fragmented is True
    assert artA.metadata.get("is_braided") is True

    # Vérifier que les flux extraits s'ouvrent avec PIL sans erreur
    streamA = extract_stream_data(reader, artA)
    res_imgA = Image.open(io.BytesIO(streamA))
    assert res_imgA.size == (100, 100)

    streamB = extract_stream_data(reader, artB)
    res_imgB = Image.open(io.BytesIO(streamB))
    assert res_imgB.size == (120, 80)


def test_is_filler_sector():
    """Vérifie la détection de secteurs de remplissage parasite."""
    zero_sec = b"\x00" * 512
    assert is_filler_sector(zero_sec) is True

    bom_utf16 = b"\xff\xfe" + b"A\x00" * 255
    assert is_filler_sector(bom_utf16) is True

    noise = os.urandom(512)
    assert is_filler_sector(noise) is False


def test_smart_carver_auto_unaligned_fallback():
    """Vérifie que SmartCarver bascule automatiquement sur un pas de 1 octet si les fichiers sont décalés."""
    # Créer un BMP déplacé à l'offset 17 (non aligné sur 512)
    img = Image.new("RGB", (64, 64), color="red")
    out = io.BytesIO()
    img.save(out, format="BMP")
    bmp_data = out.getvalue()

    shifted_disk = b"\x00" * 17 + bmp_data + b"\x00" * 500
    reader = MockBytesReader(shifted_disk)

    # Initialisation standard avec sector_alignment=512 et auto_unaligned_fallback=True
    carver = SmartCarver(reader, sector_alignment=512, auto_unaligned_fallback=True)
    arts = carver.scan()

    assert len(arts) >= 1
    art = arts[0]
    assert art.start_offset == 17
    assert art.file_type == "BMP"


def test_validate_gif_exact_block_parsing():
    """Vérifie que validate_gif parse exactement les blocs GIF jusqu'au trailer 0x3B sans déborder."""
    # Créer un vrai GIF avec Pillow
    img = Image.new("P", (128, 64), color=1)
    out = io.BytesIO()
    img.save(out, format="GIF")
    gif_bytes = out.getvalue()

    # Entourer le GIF de texte parasite contenant des points-virgules
    noise_after = b"Some; dummy; text; with; semicolons; " + b"X" * 1024
    disk_data = gif_bytes + noise_after
    reader = MockBytesReader(disk_data)

    from core.carver import validate_gif
    res = validate_gif(reader, 0)
    assert res is not None
    length, meta, is_frag = res
    assert length == len(gif_bytes), f"Attendu {len(gif_bytes)}, obtenu {length}"
    assert meta["width"] == 128
    assert meta["height"] == 64
    assert meta["file_type"] == "GIF"
    assert is_frag is False


def test_smart_carver_debraid_disabled_by_default():
    """Vérifie que le dé-tressage est bien désactivé par défaut pour préserver l'intégrité des fichiers."""
    reader = MockBytesReader(b"\x00" * 1024)
    carver = SmartCarver(reader)
    assert carver.enable_debraid is False

