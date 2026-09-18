"""
Tests unitaires et forensiques approfondis pour le moteur de carving médico-légal SmartCarver.
Vérifie la validation structurelle sémantique, la prévention de fausse troncature (vignette EXIF),
la détection multi-formats (PNG, JPEG, SQLite, DOCX/ZIP, EVTX, Reg, PDF),
ainsi que l'accélération zero-skipping sur blocs vierges.
"""

import io
import os
import struct
import zlib
import zipfile
import pytest

from core.carver import (
    SmartCarver,
    CarvedArtefact,
    validate_jpeg,
    validate_png,
    validate_sqlite,
    validate_zip_office,
    validate_evtx,
    validate_registry,
    validate_pdf,
)
from core.image_reader import ForensicImageReader


class MockBytesReader(ForensicImageReader):
    """Lecteur forensique en mémoire pour les tests unitaires."""

    def __init__(self, data: bytes, sector_size: int = 512):
        self._data = bytearray(data)
        self.sector_size = sector_size
        self._total_sectors = (len(self._data) + sector_size - 1) // sector_size
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
        chunk = self._data[offset : offset + self.sector_size]
        if len(chunk) < self.sector_size:
            chunk = chunk.ljust(self.sector_size, b"\x00")
        return bytes(chunk)

    def read_bytes(self, offset: int, length: int) -> bytes:
        if offset >= len(self._data):
            return b""
        return bytes(self._data[offset : offset + length])

    @property
    def total_sectors(self) -> int:
        return self._total_sectors


# =========================================================================
# 1. Tests Sémantiques Validateurs (In-Memory Validation)
# =========================================================================

def test_png_validation_crc_and_dimensions():
    """Vérifie la conformité PNG avec calculs CRC et parsing IHDR."""
    png_sig = b"\x89PNG\r\n\x1a\n"

    # Chunk IHDR (13 octets de data) : width=320, height=240, bit_depth=8, color_type=2, comp=0, filter=0, interlace=0
    ihdr_data = struct.pack(">IIBBBBB", 320, 240, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

    # Chunk IDAT
    idat_data = b"compressed_pixel_stream"
    idat_crc = zlib.crc32(b"IDAT" + idat_data)
    idat_chunk = struct.pack(">I", len(idat_data)) + b"IDAT" + idat_data + struct.pack(">I", idat_crc)

    # Chunk IEND
    iend_crc = zlib.crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    valid_png_stream = png_sig + ihdr_chunk + idat_chunk + iend_chunk
    trailing_garbage = b"JUNK_GARBAGE_AFTER_FILE" * 5

    reader = MockBytesReader(valid_png_stream + trailing_garbage)
    res = validate_png(reader, 0, len(valid_png_stream) + 1000)
    assert res is not None
    size, meta, is_trunc = res
    assert size == len(valid_png_stream)
    assert meta["resolution"] == "320x240"
    assert not is_trunc


def test_png_corrupted_crc_rejected():
    """Un PNG avec un CRC corrompu ne doit pas valider comme 'Valid'."""
    png_sig = b"\x89PNG\r\n\x1a\n"
    bad_ihdr = struct.pack(">I", 13) + b"IHDR" + (b"\x00" * 13) + struct.pack(">I", 0xDEADBEEF)
    iend_crc = zlib.crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    reader = MockBytesReader(png_sig + bad_ihdr + iend_chunk)
    res = validate_png(reader, 0, 1000)
    assert res is None


def test_jpeg_nested_exif_thumbnail_no_truncation():
    """
    TEST FORENSIQUE CRUCIAL :
    Une image JPEG contient souvent une vignette miniature dans le segment APP1 (EXIF).
    Cette vignette commence par FF D8 et se termine par FF D9.
    SmartCarver doit sauter le segment APP1 et trouver le vrai EOI final après le SOS.
    """
    soi = b"\xff\xd8"

    # Segment APP1 contenant un faux EOI interne (vignette EXIF miniature)
    app1_payload = b"Exif\x00\x00" + b"THUMBNAIL_DATA" + b"\xff\xd9" + b"TRAILING_EXIF"
    app1_len = len(app1_payload) + 2
    app1_marker = b"\xff\xe1" + struct.pack(">H", app1_len) + app1_payload

    # Segment SOF0 (Baseline DCT) : precision=8, lines(height)=600, samples(width)=800, components=3
    sof0_payload = struct.pack(">BHHB", 8, 600, 800, 3) + b"\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    sof0_len = len(sof0_payload) + 2
    sof0_marker = b"\xff\xc0" + struct.pack(">H", sof0_len) + sof0_payload

    # Segment SOS (Start of Scan)
    sos_payload = b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    sos_len = len(sos_payload) + 2
    sos_marker = b"\xff\xda" + struct.pack(">H", sos_len) + sos_payload

    # Flux d'entropie compressé (avec byte-stuffing \xff\x00 qui ne doit pas être confondu avec un marker)
    entropy_data = b"ENTROPY_PIXELS\xff\x00STUFFED_BYTE_DATA_MORE_IMAGE"
    real_eoi = b"\xff\xd9"

    full_jpeg = soi + app1_marker + sof0_marker + sos_marker + entropy_data + real_eoi
    trailing_padding = b"\x00" * 512

    reader = MockBytesReader(full_jpeg + trailing_padding)
    res = validate_jpeg(reader, 0, len(full_jpeg) + 500)
    assert res is not None, "Le JPEG doit être détecté avec succès"
    size, meta, is_trunc = res
    assert size == len(full_jpeg), f"Taille exacte attendue {len(full_jpeg)}, obtenu {size}"
    assert meta["resolution"] == "800x600"
    assert not is_trunc


def test_sqlite_validation_and_table_extraction():
    """Vérifie le parsing d'en-tête SQLite et l'extraction des tables."""
    header = b"SQLite format 3\x00"  # 16 bytes
    page_size = 4096
    page_count = 10
    reserved = 0

    sqlite_hdr = bytearray(100)
    sqlite_hdr[0:16] = header
    struct.pack_into(">H", sqlite_hdr, 16, page_size)
    sqlite_hdr[18] = 1  # write version
    sqlite_hdr[19] = 1  # read version
    sqlite_hdr[20] = reserved
    struct.pack_into(">I", sqlite_hdr, 28, page_count)

    db_data = bytearray(page_size * page_count)
    db_data[0:100] = sqlite_hdr

    table_snippet = b"CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, pass_hash TEXT);"
    db_data[200 : 200 + len(table_snippet)] = table_snippet

    reader = MockBytesReader(bytes(db_data))
    res = validate_sqlite(reader, 0, len(db_data) + 1000)
    assert res is not None
    size, meta, is_trunc = res
    assert size == page_size * page_count
    assert meta["page_size"] == 4096
    assert meta["page_count"] == 10
    assert "users" in meta.get("tables", [])


def test_zip_and_docx_classification():
    """Vérifie la détection exacte ZIP et la spécialisation sémantique Office (DOCX)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types></Types>")
        zf.writestr("word/document.xml", b"<w:document><w:body><w:p><w:t>Investigation Forensique</w:t></w:p></w:body></w:document>")
        zf.writestr("word/_rels/document.xml.rels", b"<Relationships></Relationships>")
    
    docx_bytes = buf.getvalue()
    reader = MockBytesReader(docx_bytes)
    res = validate_zip_office(reader, 0, len(docx_bytes) + 1000)
    assert res is not None
    size, meta, is_trunc = res
    assert size == len(docx_bytes)
    assert meta.get("file_type") == "DOCX"
    assert meta.get("extension") == ".docx"


def test_evtx_validation():
    """Vérifie la détection d'un journal d'événements Windows EVTX."""
    header = bytearray(4096)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<Q", header, 8, 1)    # oldest chunk
    struct.pack_into("<Q", header, 16, 1)   # current chunk (chunk_count)
    struct.pack_into("<Q", header, 24, 100) # next record id
    struct.pack_into("<I", header, 32, 128) # header size
    struct.pack_into("<H", header, 36, 1)   # minor
    struct.pack_into("<H", header, 38, 3)   # major
    struct.pack_into("<H", header, 40, 4096)# chunk header size
    struct.pack_into("<H", header, 42, 1)   # chunk count

    # Ajouter le premier chunk avec ElfChnk\x00
    chunk1 = bytearray(65536)
    chunk1[0:8] = b"ElfChnk\x00"

    full_evtx = bytes(header) + bytes(chunk1)
    reader = MockBytesReader(full_evtx)
    res = validate_evtx(reader, 0, 10 * 1024 * 1024)
    assert res is not None
    size, meta, is_trunc = res
    assert meta.get("file_type") == "EVTX"
    assert size == 4096 + 65536


def test_registry_validation():
    """Vérifie la validation d'une ruche de registre Windows (regf)."""
    hive = bytearray(8192)
    hive[0:4] = b"regf"
    struct.pack_into("<I", hive, 4, 1)   # seq1
    struct.pack_into("<I", hive, 8, 1)   # seq2
    struct.pack_into("<I", hive, 40, 8192) # hive length

    xor = 0
    for i in range(0, 508, 4):
        val = struct.unpack_from("<I", hive, i)[0]
        xor ^= val
    struct.pack_into("<I", hive, 508, xor)

    reader = MockBytesReader(bytes(hive))
    res = validate_registry(reader, 0, 1024 * 1024)
    assert res is not None
    size, meta, is_trunc = res
    assert size == 8192
    assert meta.get("file_type") == "Registry"
    assert meta.get("extension") == ".hiv"


def test_pdf_validation():
    """Vérifie la validation de document PDF avec recherche %%EOF."""
    pdf_content = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000010 00000 n \n"
        b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n70\n%%EOF\n"
    )
    padding = b"\x00" * 1024
    reader = MockBytesReader(pdf_content + padding)
    res = validate_pdf(reader, 0, len(pdf_content) + 500)
    assert res is not None
    size, meta, is_trunc = res
    assert size == len(pdf_content)
    assert meta.get("file_type") == "PDF"
    assert meta.get("pdf_version") == "1.7"


# =========================================================================
# 2. Test d'Intégration SmartCarver & Zero-Skipping
# =========================================================================

def test_smart_carver_zero_skipping_and_extraction():
    """
    Crée un disque virtuel synthétique contenant :
    - 50 secteurs à zéro (0 à 49)
    - Une image PNG valide au secteur 50
    - 100 secteurs à zéro (au bus speed zero-skipping)
    - Une base SQLite au secteur 155
    - 20 secteurs de remplissage
    Vérifie que le scan s'exécute, ignore les zéros, et extrait fidèlement les données.
    """
    sector_size = 512

    # Construire PNG
    png_sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 100, 100, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)
    iend_crc = zlib.crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)
    png_bytes = png_sig + ihdr_chunk + iend_chunk

    # Construire SQLite
    page_size = 1024
    page_count = 4
    sqlite_hdr = bytearray(100)
    sqlite_hdr[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", sqlite_hdr, 16, page_size)
    sqlite_hdr[18] = 1
    sqlite_hdr[19] = 1
    struct.pack_into(">I", sqlite_hdr, 28, page_count)
    sqlite_bytes = bytes(sqlite_hdr) + (b"\x00" * (page_size * page_count - 100))

    # Assembler le disque
    total_sectors = 200
    disk_data = bytearray(total_sectors * sector_size)

    # Placer PNG à LBA 50
    offset_png = 50 * sector_size
    disk_data[offset_png : offset_png + len(png_bytes)] = png_bytes

    # Placer SQLite à LBA 155
    offset_sqlite = 155 * sector_size
    disk_data[offset_sqlite : offset_sqlite + len(sqlite_bytes)] = sqlite_bytes

    reader = MockBytesReader(bytes(disk_data), sector_size=sector_size)

    carver = SmartCarver(
        reader=reader,
        start_lba=0,
        end_lba=total_sectors - 1,
        sector_alignment=512,
        enabled_categories=["Images", "Databases"],
    )

    discovered = []
    def on_art(art):
        discovered.append(art)

    carver.scan(artefact_callback=on_art)

    assert len(discovered) == 2, f"2 artefacts attendus, trouvé {len(discovered)}"
    
    art_png = next(a for a in discovered if a.file_type == "PNG")
    assert art_png.start_lba == 50
    assert art_png.length_bytes == len(png_bytes)

    art_sql = next(a for a in discovered if a.file_type == "SQLite3")
    assert art_sql.start_lba == 155
    assert art_sql.length_bytes == len(sqlite_bytes)

    extracted_png = carver.extract_stream(art_png)
    assert extracted_png == png_bytes, "Les octets extraits du PNG doivent correspondre exactement au flux source"


def test_bmp_validation():
    """Vérifie la validation BMP avec calcul exact de la taille d'en-tête."""
    from core.carver import validate_bmp
    # Construire en-tête BMP valide
    file_size = 54 + 100 * 100 * 3
    bmp_hdr = bytearray(54)
    bmp_hdr[0:2] = b"BM"
    struct.pack_into("<I", bmp_hdr, 2, file_size)
    struct.pack_into("<I", bmp_hdr, 10, 54) # pixel offset
    struct.pack_into("<I", bmp_hdr, 14, 40) # DIB header size
    struct.pack_into("<I", bmp_hdr, 18, 100) # width
    struct.pack_into("<i", bmp_hdr, 22, 100) # height
    struct.pack_into("<H", bmp_hdr, 26, 1) # planes
    struct.pack_into("<H", bmp_hdr, 28, 24) # bpp
    bmp_data = bytes(bmp_hdr) + (b"\xFF" * (file_size - 54))

    reader = MockBytesReader(bmp_data + b"\x00" * 512)
    res = validate_bmp(reader, 0)
    assert res is not None
    size, meta, is_frag = res
    assert size == file_size
    assert meta["width"] == 100
    assert meta["height"] == 100
    assert meta["bit_depth"] == 24


def test_gif_validation():
    """Vérifie la validation GIF avec recherche du trailer 0x3B."""
    from core.carver import validate_gif
    gif_data = b"GIF89a" + struct.pack("<HH", 64, 64) + b"\x80\x00\x00" + b"\xFF\xFF\xFF" + b"\x00\x00\x00" + b";"
    reader = MockBytesReader(gif_data + b"\x00" * 512)
    res = validate_gif(reader, 0)
    assert res is not None
    size, meta, is_frag = res
    assert size == len(gif_data)
    assert meta["width"] == 64
    assert meta["height"] == 64
    assert meta["file_type"] == "GIF"


def test_ole_validation():
    """Vérifie la validation OLE/CFBF (DOC/XLS/PPT) avec table FAT."""
    from core.carver import validate_ole
    ole_hdr = bytearray(512)
    ole_hdr[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    struct.pack_into("<H", ole_hdr, 30, 9) # sector shift 9 -> 512 bytes
    struct.pack_into("<I", ole_hdr, 44, 1) # num FAT sectors = 1
    struct.pack_into("<I", ole_hdr, 76, 0) # first FAT sector at sector 0

    # Sector 0 is at offset 512 (first sector after header)
    fat_sec = bytearray(512)
    # Mark 5 sectors as allocated (not 0xFFFFFFFF)
    for i in range(5):
        struct.pack_into("<I", fat_sec, i * 4, i + 1)
    for i in range(5, 128):
        struct.pack_into("<I", fat_sec, i * 4, 0xFFFFFFFF)

    ole_file = bytes(ole_hdr) + bytes(fat_sec) + (b"\x00" * (4 * 512))
    # Inject marker for DOC
    ole_file_doc = bytearray(ole_file)
    ole_file_doc[100:112] = b"WordDocument"

    reader = MockBytesReader(bytes(ole_file_doc) + b"\x00" * 1024)
    res = validate_ole(reader, 0)
    assert res is not None
    size, meta, is_frag = res
    assert size == (4 + 2) * 512 # max allocated 4 + 2 = 6 sectors * 512 = 3072 bytes
    assert meta["file_type"] == "DOC"
    assert meta["extension"] == ".doc"


def test_jpeg_fault_tolerance_and_auto_close():
    """Vérifie la tolérance aux en-têtes altérés (FF DB 00 00) et l'auto-fermeture des fichiers tronqués."""
    from core.carver import validate_jpeg
    # Construire un JPEG minimal avec marqueur DQT corrompu (longueur 00 00 comme haxor2)
    # SOI (FF D8) + DQT (FF DB 00 00 + 65 bytes de data) + SOF0 (FF C0 00 11 08 01 00 01 00 03 ...) + SOS (FF DA 00 08 01 01 00 00 3F 00) + entropy + EOI
    soi = b"\xFF\xD8"
    dqt = b"\xFF\xDB\x00\x00" + (b"\x05" * 65)
    sof0 = b"\xFF\xC0\x00\x11\x08" + struct.pack(">HH", 200, 300) + b"\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    sos = b"\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00"
    entropy = b"\x12\x34\x56\x78" * 200
    eoi = b"\xFF\xD9"

    full_jpeg = soi + dqt + sof0 + sos + entropy + eoi
    reader = MockBytesReader(full_jpeg + b"\x00" * 512)
    res = validate_jpeg(reader, 0)
    assert res is not None, "Le carver doit tolérer l'en-tête altéré FF DB 00 00"
    size, meta, is_frag = res
    assert meta["width"] == 300
    assert meta["height"] == 200

    # Test auto-fermeture sur JPEG tronqué (sans EOI)
    truncated_jpeg = soi + dqt + sof0 + sos + entropy
    reader_trunc = MockBytesReader(truncated_jpeg + b"\x00" * 512)
    res_trunc = validate_jpeg(reader_trunc, 0)
    assert res_trunc is not None, "Le carver doit sauver le JPEG tronqué en auto-fermeture"
    size_t, meta_t, is_frag_t = res_trunc
    assert meta_t["is_truncated"] is True
    assert is_frag_t is True


def test_resilient_pixmap_loading():
    """Vérifie le décodage d'image résilient avec auto-fermeture FF D9 et patch DQT."""
    from ui.carver_dialog import load_resilient_pixmap
    from PySide6.QtWidgets import QApplication
    import sys
    app = QApplication.instance() or QApplication(sys.argv)

    # Image altérée style haxor2 (DQT FF DB 00 00) et tronquée sans EOI
    corrupted_truncated = (
        b"\xFF\xD8\xFF\xDB\x00\x00"
        + b"\x05" * 65
        + b"\xFF\xC0\x00\x11\x08\x00\x32\x00\x32\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01"
        + b"\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00"
        + b"\x12" * 100
    )

    pix, notes = load_resilient_pixmap(corrupted_truncated, "JPEG")
    assert pix is not None and not pix.isNull(), "L'aperçu doit réussir même sur image altérée et tronquée"
    assert any("DQT" in n for n in notes), "Le patch DQT doit être appliqué"
    assert any("Auto-fermeture" in n for n in notes), "L'auto-fermeture FF D9 doit être appliquée"

