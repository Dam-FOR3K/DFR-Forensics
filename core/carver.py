"""
DFR-Forensics - Moteur de Carving Médico-Légal Sémantique (In-Memory)
Permet la reconstruction chirurgicale d'artefacts sur partitions détruites ou espaces non alloués.
Calcule la taille mathématique exacte des fichiers via leurs métadonnées internes,
éliminant les faux footers (ex: miniatures EXIF imbriquées dans les JPEG) et les troncatures.
"""

import io
import os
import struct
import zlib
import hashlib
import sqlite3
import zipfile
from typing import List, Dict, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field

from core.image_reader import ForensicImageReader


@dataclass
class CarvedArtefact:
    """Représente un artefact médico-légal découvert et validé en mémoire."""
    artefact_id: int
    category: str               # "Images", "Databases", "Documents", "Logs", "Registry", "Archives"
    file_type: str              # "JPEG", "PNG", "SQLite3", "PDF", "DOCX", "XLSX", "PPTX", "ZIP", "EVTX", "Registry"
    extension: str              # ".jpg", ".png", ".sqlite", ".pdf", ".docx", etc.
    start_lba: int
    start_offset: int
    length_bytes: int
    end_lba: int
    filename: str = ""
    is_valid: bool = True
    is_fragmented: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    block_list: Optional[List[int]] = None
    md5: str = ""
    sha256: str = ""

    @property
    def display_size(self) -> str:
        s = self.length_bytes
        if s < 1024:
            return f"{s} B"
        elif s < 1024 * 1024:
            return f"{s / 1024:.2f} KB"
        elif s < 1024 * 1024 * 1024:
            return f"{s / (1024 * 1024):.2f} MB"
        else:
            return f"{s / (1024**3):.2f} GB"


# -----------------------------------------------------------------------------
# VALIDATEURS SÉMANTIQUES STRUCTURELS (Zero False-Footer)
# -----------------------------------------------------------------------------

def validate_jpeg(reader: ForensicImageReader, start_offset: int, max_bytes: int = 50 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide un flux JPEG en parcourant ses marqueurs JFIF/EXIF.
    Évite absolument le piège des miniatures imbriquées dans les segments APP1/EXIF.
    Retourne (taille_octets, métadonnées, est_fragmenté) ou None.
    """
    head = reader.read_bytes(start_offset, 4)
    if len(head) < 4 or head[0:2] != b"\xFF\xD8" or head[2] != 0xFF:
        return None

    pos = 2
    width = 0
    height = 0
    has_exif = False
    in_sos = False
    buffer_chunk_size = 64 * 1024

    # Parcourir les segments d'en-tête (APPn, DQT, DHT, SOF0, etc.)
    while pos < max_bytes:
        marker_data = reader.read_bytes(start_offset + pos, 4)
        if len(marker_data) < 4 or marker_data[0] != 0xFF:
            break

        marker = marker_data[1]

        # Marqueurs autonomes sans longueur
        if marker in (0xD8, 0xD9, 0x00) or (0xD0 <= marker <= 0xD7):
            pos += 2
            continue

        length = struct.unpack(">H", marker_data[2:4])[0]
        if length < 2:
            # Tolérance médico-légale aux en-têtes altérés (ex: DQT FF DB avec longueur 0x0000 écrasée)
            if marker == 0xDB:
                length = 67  # Longueur standard d'une table DQT 8-bit (2 + 1 + 64)
            else:
                probe = reader.read_bytes(start_offset + pos + 2, 256)
                next_ff = probe.find(b"\xFF")
                if next_ff > 0:
                    length = 2 + next_ff
                else:
                    break

        # APP1 (EXIF / XMP)
        if marker == 0xE1:
            has_exif = True

        # SOF0 (Baseline) ou SOF2 (Progressive) -> Récupérer dimensions réelles
        if marker in (0xC0, 0xC1, 0xC2):
            sof_data = reader.read_bytes(start_offset + pos + 4, 5)
            if len(sof_data) >= 5:
                height, width = struct.unpack(">HH", sof_data[1:5])

        # Start of Scan (SOS) -> Fin des en-têtes, début des données entropiques
        if marker == 0xDA:
            pos += 2 + length
            in_sos = True
            break

        pos += 2 + length

    if not in_sos or width <= 0 or height <= 0:
        return None

    # Parcourir les données compressées jusqu'au véritable marqueur de fin EOI (FF D9)
    # Les octets FF00 correspondent à des échappements (byte stuffing) et ne sont pas des marqueurs
    file_end_pos = -1
    scan_offset = pos
    while scan_offset < max_bytes:
        chunk = reader.read_bytes(start_offset + scan_offset, buffer_chunk_size)
        if not chunk:
            break

        idx = 0
        while idx < len(chunk) - 1:
            ff_idx = chunk.find(b"\xFF", idx)
            if ff_idx == -1 or ff_idx >= len(chunk) - 1:
                break

            nxt = chunk[ff_idx + 1]
            if nxt == 0xD9:  # EOI final !
                file_end_pos = scan_offset + ff_idx + 2
                break
            elif nxt == 0x00:
                # Byte stuffing normal
                idx = ff_idx + 2
            elif 0xD0 <= nxt <= 0xD7:
                # Restart marker
                idx = ff_idx + 2
            else:
                idx = ff_idx + 2

        if file_end_pos != -1:
            break
        if len(chunk) < buffer_chunk_size:
            scan_offset += len(chunk)
            break
        scan_offset += max(1, len(chunk) - 1)  # Chevauchement d'un octet pour ne pas rater FF D9 à cheval

    if file_end_pos <= 0:
        # Fichier JPEG tronqué sans EOI final (Sauvetage médico-légal)
        if in_sos and scan_offset > pos + 512:
            meta = {
                "width": width,
                "height": height,
                "resolution": f"{width}x{height}",
                "has_exif": has_exif,
                "is_truncated": True,
            }
            return scan_offset, meta, True
        return None

    meta = {
        "width": width,
        "height": height,
        "resolution": f"{width}x{height}",
        "has_exif": has_exif,
    }
    return file_end_pos, meta, False


def validate_png(reader: ForensicImageReader, start_offset: int, max_bytes: int = 100 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide un flux PNG chunk par chunk avec contrôle CRC32 et tolérance médico-légale
    pour les flux entrelacés ou fragmentés.
    """
    sig = reader.read_bytes(start_offset, 8)
    if sig != b"\x89PNG\r\n\x1a\n":
        return None

    pos = 8
    width = 0
    height = 0
    bit_depth = 0
    color_type = 0
    chunks_seen = 0

    while pos < max_bytes:
        chunk_hdr = reader.read_bytes(start_offset + pos, 8)
        if len(chunk_hdr) < 8:
            break

        length = struct.unpack(">I", chunk_hdr[0:4])[0]
        chunk_type = chunk_hdr[4:8]

        # Protection contre longueurs invalides ou aberrantes
        if length > 32 * 1024 * 1024:
            break

        chunk_full = reader.read_bytes(start_offset + pos + 4, length + 4)  # type + data
        crc_bytes = reader.read_bytes(start_offset + pos + 8 + length, 4)
        if len(chunk_full) < length + 4 or len(crc_bytes) < 4:
            break

        expected_crc = struct.unpack(">I", crc_bytes)[0]
        actual_crc = zlib.crc32(chunk_full)

        # Chunk IHDR (Dimensions obligatoires)
        if chunk_type == b"IHDR" and length >= 13:
            ihdr_data = chunk_full[4:17]
            width, height, bit_depth, color_type = struct.unpack(">IIBB", ihdr_data[0:10])

        if actual_crc != expected_crc:
            # Flux fragmenté ou entrelacé (Braid) : sauvetage si IHDR valide
            if width > 0 and height > 0:
                scan_buf = reader.read_bytes(start_offset + pos, min(30 * 1024 * 1024, max_bytes - pos))
                iend_idx = scan_buf.find(b"IEND")
                end_pos = (pos + iend_idx + 8) if iend_idx != -1 else (pos + 12 + length)
                meta = {
                    "width": width,
                    "height": height,
                    "resolution": f"{width}x{height}",
                    "bit_depth": bit_depth,
                    "color_type": color_type,
                    "chunks_count": chunks_seen,
                    "is_fragmented": True,
                }
                return end_pos, meta, True
            return None

        pos += 12 + length  # 4B length + 4B type + length + 4B crc
        chunks_seen += 1

        # Chunk IEND (Fin obligatoire)
        if chunk_type == b"IEND":
            meta = {
                "width": width,
                "height": height,
                "resolution": f"{width}x{height}",
                "bit_depth": bit_depth,
                "color_type": color_type,
                "chunks_count": chunks_seen,
            }
            return pos, meta, False

    if width > 0 and height > 0:
        meta = {
            "width": width,
            "height": height,
            "resolution": f"{width}x{height}",
            "is_truncated": True,
        }
        return pos, meta, True

    return None


def validate_tiff(reader: ForensicImageReader, start_offset: int, max_bytes: int = 150 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide une image TIFF (Tagged Image File Format) selon la spécification TIFF 6.0.
    Prend en charge Little-Endian (II*\x00) et Big-Endian (MM\x00*).
    Parcourt l'IFD (Image File Directory) et calcule la taille exacte via les bandes/tuiles et balises.
    """
    hdr = reader.read_bytes(start_offset, 8)
    if len(hdr) < 8:
        return None

    if hdr[:4] == b"II*\x00":
        endian = "<"
    elif hdr[:4] == b"MM\x00*":
        endian = ">"
    else:
        return None

    first_ifd_offset = struct.unpack(endian + "I", hdr[4:8])[0]
    if first_ifd_offset < 8 or first_ifd_offset > max_bytes:
        return None

    # Lire l'IFD
    ifd_hdr = reader.read_bytes(start_offset + first_ifd_offset, 2)
    if len(ifd_hdr) < 2:
        meta = {
            "file_type": "TIFF",
            "extension": ".tiff",
            "endianness": "Little" if endian == "<" else "Big",
            "is_fragmented": True,
        }
        return first_ifd_offset + 512, meta, True

    num_entries = struct.unpack(endian + "H", ifd_hdr)[0]
    if num_entries == 0 or num_entries > 4096:
        meta = {
            "file_type": "TIFF",
            "extension": ".tiff",
            "endianness": "Little" if endian == "<" else "Big",
            "is_fragmented": True,
        }
        return first_ifd_offset + 512, meta, True

    entries_data = reader.read_bytes(start_offset + first_ifd_offset + 2, num_entries * 12)
    if len(entries_data) < num_entries * 12:
        meta = {
            "file_type": "TIFF",
            "extension": ".tiff",
            "endianness": "Little" if endian == "<" else "Big",
            "is_fragmented": True,
        }
        return first_ifd_offset + 512, meta, True

    def type_size(t: int) -> int:
        return {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}.get(t, 1)

    max_offset = first_ifd_offset + 2 + num_entries * 12 + 4
    width = 0
    height = 0
    strip_offsets_info = None
    strip_counts_info = None
    tile_offsets_info = None
    tile_counts_info = None

    for i in range(num_entries):
        entry = entries_data[i * 12 : (i + 1) * 12]
        tag, typ, cnt, val = struct.unpack(endian + "HHII", entry)
        item_sz = type_size(typ) * cnt
        if item_sz > 4:
            max_offset = max(max_offset, val + item_sz)

        if tag == 0x0100:  # ImageWidth
            width = val if typ == 4 else (val >> 16 if endian == ">" else val & 0xFFFF)
        elif tag == 0x0101:  # ImageLength
            height = val if typ == 4 else (val >> 16 if endian == ">" else val & 0xFFFF)
        elif tag == 0x0111:  # StripOffsets
            strip_offsets_info = (cnt, typ, val)
        elif tag == 0x0117:  # StripByteCounts
            strip_counts_info = (cnt, typ, val)
        elif tag == 0x0144:  # TileOffsets
            tile_offsets_info = (cnt, typ, val)
        elif tag == 0x0145:  # TileByteCounts
            tile_counts_info = (cnt, typ, val)

    def read_offsets(info):
        if not info:
            return []
        cnt, typ, val = info
        if cnt == 1:
            return [val if typ == 4 else (val >> 16 if endian == ">" else val & 0xFFFF)]
        sz = type_size(typ)
        if sz not in (2, 4) or cnt > 100000:
            return []
        raw = reader.read_bytes(start_offset + val, cnt * sz)
        if len(raw) < cnt * sz:
            return []
        char_fmt = "I" if sz == 4 else "H"
        fmt = f"{endian}{cnt}{char_fmt}"
        return list(struct.unpack(fmt, raw))

    for s_off, s_cnt in zip(read_offsets(strip_offsets_info), read_offsets(strip_counts_info)):
        max_offset = max(max_offset, s_off + s_cnt)

    for t_off, t_cnt in zip(read_offsets(tile_offsets_info), read_offsets(tile_counts_info)):
        max_offset = max(max_offset, t_off + t_cnt)

    if max_offset <= 8 or max_offset > max_bytes:
        return None

    meta = {
        "width": width,
        "height": height,
        "resolution": f"{width}x{height}" if width and height else "Unknown",
        "file_type": "TIFF",
        "extension": ".tiff",
        "endianness": "Little" if endian == "<" else "Big",
        "is_fragmented": False,
    }
    return max_offset, meta, False


def validate_bmp(reader: ForensicImageReader, start_offset: int, max_bytes: int = 50 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide une image Bitmap (BMP) et extrait sa taille mathématique exacte depuis l'en-tête (offset 0x02).
    Prend en charge les en-têtes DIB v1 à v5 (12, 40, 52, 56, 64, 108, 124 octets).
    """
    hdr = reader.read_bytes(start_offset, 54)
    if len(hdr) < 54 or hdr[0:2] != b"BM":
        return None

    file_size = struct.unpack("<I", hdr[2:6])[0]
    res1, res2 = struct.unpack("<HH", hdr[6:10])
    pixel_offset = struct.unpack("<I", hdr[10:14])[0]

    # Contrôles médico-légaux stricts
    if res1 != 0 or res2 != 0 or pixel_offset < 54 or file_size < pixel_offset or file_size > max_bytes:
        return None

    dib_size = struct.unpack("<I", hdr[14:18])[0]
    if dib_size not in (12, 40, 52, 56, 64, 108, 124):
        return None

    width = struct.unpack("<I", hdr[18:22])[0]
    height = struct.unpack("<i", hdr[22:26])[0]
    bpp = struct.unpack("<H", hdr[28:30])[0]

    meta = {
        "width": width,
        "height": abs(height),
        "resolution": f"{width}x{abs(height)}",
        "bit_depth": bpp,
        "file_type": "BMP",
        "extension": ".bmp",
    }
    return file_size, meta, False


def validate_gif(reader: ForensicImageReader, start_offset: int, max_bytes: int = 50 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide une image GIF (GIF87a / GIF89a) et localise le trailer final 0x3B.
    """
    hdr = reader.read_bytes(start_offset, 13)
    if len(hdr) < 13 or hdr[0:6] not in (b"GIF87a", b"GIF89a"):
        return None

    width, height = struct.unpack("<HH", hdr[6:10])
    if width <= 0 or height <= 0:
        return None

    scan_limit = min(max_bytes, 16 * 1024 * 1024)
    data = reader.read_bytes(start_offset, scan_limit)
    trailer_pos = -1
    pos = 13
    while pos < len(data):
        found = data.find(b";", pos)
        if found == -1:
            break
        trailer_pos = found + 1
        pos = found + 1

    if trailer_pos <= 0:
        return None

    meta = {
        "width": width,
        "height": height,
        "resolution": f"{width}x{height}",
        "version": hdr[0:6].decode("ascii", errors="ignore"),
        "file_type": "GIF",
        "extension": ".gif",
    }
    return trailer_pos, meta, False


def validate_sqlite(reader: ForensicImageReader, start_offset: int, max_bytes: int = 500 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide une base de données SQLite 3 et calcule sa taille exacte : page_size * page_count.
    Extrait les noms des tables directement depuis la mémoire.
    """
    hdr = reader.read_bytes(start_offset, 100)
    if len(hdr) < 100 or hdr[0:16] != b"SQLite format 3\x00":
        return None

    page_size = struct.unpack(">H", hdr[16:18])[0]
    if page_size == 1:
        page_size = 65536
    elif page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768):
        return None

    page_count = struct.unpack(">I", hdr[28:32])[0]
    if page_count <= 0 or page_count * page_size > max_bytes:
        return None

    exact_size = page_size * page_count

    # Vérification de cohérence de l'en-tête (freelist page count <= page_count)
    freelist_count = struct.unpack(">I", hdr[36:40])[0]
    if freelist_count > page_count:
        return None

    # Extraction des tables via analyse textuelle rapide du schéma dans la première page
    tables = []
    try:
        sample_len = min(exact_size, 256 * 1024)
        sample = reader.read_bytes(start_offset, sample_len)
        idx = 0
        while True:
            tbl_match = sample.find(b"CREATE TABLE ", idx)
            if tbl_match == -1:
                break
            end_name = sample.find(b"(", tbl_match)
            if end_name != -1 and end_name - tbl_match < 80:
                tbl_name = sample[tbl_match + 13 : end_name].decode("utf-8", errors="ignore").strip().strip('"[]`')
                if tbl_name and tbl_name not in tables and not tbl_name.startswith("sqlite_"):
                    tables.append(tbl_name)
            idx = tbl_match + 13
    except Exception:
        pass

    meta = {
        "page_size": page_size,
        "page_count": page_count,
        "tables": tables,
        "tables_summary": ", ".join(tables[:6]) + ("..." if len(tables) > 6 else "") if tables else "Schéma vide / Aucune table",
    }
    return exact_size, meta, False


def validate_zip_office(reader: ForensicImageReader, start_offset: int, max_bytes: int = 200 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide une archive ZIP et détecte les documents Office (Word, Excel, PowerPoint).
    Localise le bloc End of Central Directory (EOCD PK\\x05\\x06) pour certifier la taille exacte.
    """
    head = reader.read_bytes(start_offset, 30)
    if len(head) < 30 or head[0:4] != b"PK\x03\x04":
        return None

    scan_size = min(max_bytes, 32 * 1024 * 1024)
    data = reader.read_bytes(start_offset, scan_size)
    if len(data) < 22:
        return None

    eocd_sig = b"PK\x05\x06"
    eocd_pos = data.rfind(eocd_sig)
    if eocd_pos == -1:
        return None

    if len(data) < eocd_pos + 22:
        return None

    eocd = data[eocd_pos : eocd_pos + 22]
    cd_size = struct.unpack("<I", eocd[12:16])[0]
    cd_offset = struct.unpack("<I", eocd[16:20])[0]
    comment_len = struct.unpack("<H", eocd[20:22])[0]

    expected_eocd = cd_offset + cd_size
    if expected_eocd != eocd_pos:
        return None

    exact_size = eocd_pos + 22 + comment_len

    # Classification automatique du type d'archive (DOCX, XLSX, PPTX, APK, ZIP standard)
    file_type = "ZIP"
    extension = ".zip"
    internal_files = []

    try:
        zf_stream = io.BytesIO(data[:exact_size])
        with zipfile.ZipFile(zf_stream, "r") as zf:
            internal_files = zf.namelist()

        if any(f.startswith("word/") for f in internal_files):
            file_type = "DOCX"
            extension = ".docx"
        elif any(f.startswith("xl/") for f in internal_files):
            file_type = "XLSX"
            extension = ".xlsx"
        elif any(f.startswith("ppt/") for f in internal_files):
            file_type = "PPTX"
            extension = ".pptx"
        elif "AndroidManifest.xml" in internal_files:
            file_type = "APK"
            extension = ".apk"
    except Exception:
        pass

    meta = {
        "file_type": file_type,
        "extension": extension,
        "internal_files_count": len(internal_files),
        "files_sample": internal_files[:5],
    }
    return exact_size, meta, False


def validate_ole(reader: ForensicImageReader, start_offset: int, max_bytes: int = 100 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide un document Microsoft Compound File (OLE CFBF : DOC, XLS, PPT).
    Calcule la taille mathématique exacte via la table d'allocation de secteurs (FAT).
    """
    hdr = reader.read_bytes(start_offset, 512)
    if len(hdr) < 512 or hdr[0:8] != b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        return None

    sec_shift = struct.unpack("<H", hdr[30:32])[0]
    if sec_shift not in (9, 12):  # 512 ou 4096 octets
        return None
    sec_size = 1 << sec_shift

    num_fat_secs = struct.unpack("<I", hdr[44:48])[0]
    first_fat_sec = struct.unpack("<I", hdr[76:80])[0]

    fat_offset = (first_fat_sec + 1) * sec_size
    fat_data = reader.read_bytes(start_offset + fat_offset, sec_size)
    if not fat_data:
        return None

    entries = struct.unpack(f"<{len(fat_data) // 4}I", fat_data)
    allocated = [i for i, val in enumerate(entries) if val != 0xFFFFFFFF]
    if not allocated:
        exact_size = (num_fat_secs + 1) * sec_size
    else:
        exact_size = (max(allocated) + 2) * sec_size

    if exact_size <= 0 or exact_size > max_bytes:
        return None

    probe_sample = reader.read_bytes(start_offset, min(exact_size, 32768))
    doc_type = "DOC"
    ext = ".doc"
    if b"WordDocument" in probe_sample:
        doc_type = "DOC"
        ext = ".doc"
    elif b"Workbook" in probe_sample or b"Book" in probe_sample:
        doc_type = "XLS"
        ext = ".xls"
    elif b"PowerPoint Document" in probe_sample or b"Current User" in probe_sample:
        doc_type = "PPT"
        ext = ".ppt"

    meta = {
        "file_type": doc_type,
        "extension": ext,
        "ole_sector_size": sec_size,
    }
    return exact_size, meta, False


def validate_evtx(reader: ForensicImageReader, start_offset: int, max_bytes: int = 100 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide un journal d'événements Windows EVTX (ElfFile\\x00).
    Taille = 4096 (header) + chunk_count * 65536.
    """
    hdr = reader.read_bytes(start_offset, 512)
    if len(hdr) < 512 or hdr[0:8] != b"ElfFile\x00":
        return None

    chunk_count = struct.unpack("<Q", hdr[16:24])[0]
    if chunk_count <= 0 or chunk_count > 5000:
        return None

    exact_size = 4096 + chunk_count * 65536
    if exact_size > max_bytes:
        return None

    first_chunk_magic = reader.read_bytes(start_offset + 4096, 8)
    if first_chunk_magic != b"ElfChnk\x00":
        return None

    meta = {
        "chunk_count": chunk_count,
        "file_type": "EVTX",
        "extension": ".evtx",
    }
    return exact_size, meta, False


def validate_registry(reader: ForensicImageReader, start_offset: int, max_bytes: int = 500 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide une ruche de registre Windows (regf).
    Taille exacte lue à l'offset 0x28 avec contrôle de cohérence.
    """
    hdr = reader.read_bytes(start_offset, 512)
    if len(hdr) < 512 or hdr[0:4] != b"regf":
        return None

    hive_size = struct.unpack("<I", hdr[0x28:0x2C])[0]
    if hive_size <= 4096 or hive_size > max_bytes:
        return None

    chk = 0
    for i in range(0, 508, 4):
        chk ^= struct.unpack("<I", hdr[i : i + 4])[0]
    expected_chk = struct.unpack("<I", hdr[508:512])[0]
    if chk != expected_chk:
        return None

    hive_name = hdr[0x30:0x50].decode("utf-16le", errors="ignore").split("\x00")[0].strip()

    meta = {
        "hive_name": hive_name or "Ruche Windows",
        "file_type": "Registry",
        "extension": ".hiv",
    }
    return hive_size, meta, False


def validate_pdf(reader: ForensicImageReader, start_offset: int, max_bytes: int = 150 * 1024 * 1024) -> Optional[Tuple[int, Dict[str, Any], bool]]:
    """
    Valide un document PDF (%PDF-) et repère son marqueur %%EOF propre,
    sans déborder sur les PDF ou fichiers consécutifs.
    """
    hdr = reader.read_bytes(start_offset, 16)
    if len(hdr) < 8 or not hdr.startswith(b"%PDF-"):
        return None

    scan_size = min(max_bytes, 16 * 1024 * 1024)
    data = reader.read_bytes(start_offset, scan_size)
    eof_sig = b"%%EOF"

    pos = 0
    matched_eof = -1
    KNOWN_NEXT_SIGS = [b"%PDF-", b"\xFF\xD8\xFF", b"\x89PNG", b"BM", b"GIF8", b"\xD0\xCF\x11\xE0", b"PK\x03\x04"]

    while pos < len(data):
        found = data.find(eof_sig, pos)
        if found == -1:
            break

        cand_end = found + len(eof_sig)
        while cand_end < len(data) and data[cand_end : cand_end + 1] in (b"\r", b"\n"):
            cand_end += 1

        matched_eof = cand_end

        # Si suivi d'un en-tête connu, d'une frontière de secteur ou de zéros continus
        peek = data[cand_end : cand_end + 16]
        if any(peek.startswith(s) for s in KNOWN_NEXT_SIGS) or cand_end % 512 == 0 or peek.startswith(b"\x00\x00\x00\x00"):
            break

        pos = found + len(eof_sig)

    if matched_eof == -1:
        return None

    version = hdr[5:8].decode("ascii", errors="ignore")
    meta = {
        "pdf_version": version,
        "file_type": "PDF",
        "extension": ".pdf",
    }
    return matched_eof, meta, False


# -----------------------------------------------------------------------------
# DISPATCHEUR DE SIGNATURES & MOTEUR SMART CARVER
# -----------------------------------------------------------------------------

SIGNATURE_DISPATCH = [
    (b"\xFF\xD8\xFF", "Images", "JPEG", ".jpg", validate_jpeg),
    (b"\x89PNG\r\n\x1a\n", "Images", "PNG", ".png", validate_png),
    (b"II*\x00", "Images", "TIFF", ".tiff", validate_tiff),
    (b"MM\x00*", "Images", "TIFF", ".tiff", validate_tiff),
    (b"BM", "Images", "BMP", ".bmp", validate_bmp),
    (b"GIF87a", "Images", "GIF", ".gif", validate_gif),
    (b"GIF89a", "Images", "GIF", ".gif", validate_gif),
    (b"SQLite format 3\x00", "Databases", "SQLite3", ".sqlite", validate_sqlite),
    (b"PK\x03\x04", "Documents", "ZIP/Office", ".zip", validate_zip_office),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "Documents", "OLE/Office", ".doc", validate_ole),
    (b"ElfFile\x00", "Logs", "EVTX", ".evtx", validate_evtx),
    (b"regf", "Registry", "Registry", ".hiv", validate_registry),
    (b"%PDF-", "Documents", "PDF", ".pdf", validate_pdf),
]


class SmartCarver:
    """
    Moteur de Carving Asynchrone Haute Performance.
    Balaye l'espace disque avec saut instantané des zones effacées et alignement strict.
    """

    def __init__(
        self,
        reader: ForensicImageReader,
        start_lba: int = 0,
        end_lba: Optional[int] = None,
        sector_alignment: int = 512,
        enabled_categories: Optional[List[str]] = None,
    ):
        self.reader = reader
        self.sector_size = reader.sector_size
        self.start_lba = max(0, start_lba)
        self.end_lba = min(reader.total_sectors - 1, end_lba) if end_lba is not None else reader.total_sectors - 1
        self.sector_alignment = sector_alignment
        self.enabled_categories = enabled_categories or ["Images", "Databases", "Documents", "Logs", "Registry", "Archives"]

        self.carved_artefacts: List[CarvedArtefact] = []
        self._is_cancelled = False
        self._is_paused = False

        from core.correlator import MetadataCorrelator
        self.correlator = MetadataCorrelator(reader)

    def cancel(self):
        self._is_cancelled = True

    def pause(self):
        self._is_paused = True

    def resume(self):
        self._is_paused = False

    def scan(self, progress_callback: Optional[Callable[[int, int, float, int], None]] = None, artefact_callback: Optional[Callable[[CarvedArtefact], None]] = None) -> List[CarvedArtefact]:
        """
        Exécute le balayage intelligent de la plage LBA définie.
        progress_callback: (processed_lba, total_lba, speed_mbs, total_found)
        artefact_callback: (artefact)
        """
        total_lbas = max(1, self.end_lba - self.start_lba + 1)
        current_lba = self.start_lba
        chunk_lbas = 4096  # 2 Mo par itération (à 512 o/secteur)
        artefact_counter = 0

        active_dispatch = [
            d for d in SIGNATURE_DISPATCH
            if d[1] in self.enabled_categories or ("ZIP/Office" in d[2] and ("Documents" in self.enabled_categories or "Archives" in self.enabled_categories))
        ]

        import time
        t_start = time.time()
        bytes_scanned = 0
        seen_offsets = set()

        while current_lba <= self.end_lba and not self._is_cancelled:
            while self._is_paused and not self._is_cancelled:
                time.sleep(0.1)

            step_lba = min(chunk_lbas, self.end_lba - current_lba + 1)
            chunk_bytes_len = step_lba * self.sector_size
            chunk_offset = current_lba * self.sector_size

            raw_chunk = self.reader.read_bytes(chunk_offset, chunk_bytes_len)
            if not raw_chunk:
                break

            bytes_scanned += len(raw_chunk)

            # ACCÉLÉRATION TRIAGE SPATIAL : Si le bloc est 100% zéros, sauter instantanément !
            if raw_chunk == b"\x00" * len(raw_chunk):
                current_lba += step_lba
                if progress_callback:
                    elapsed = max(0.001, time.time() - t_start)
                    speed = (bytes_scanned / (1024 * 1024)) / elapsed
                    progress_callback(current_lba - self.start_lba, total_lbas, speed, artefact_counter)
                continue

            # Recherche des signatures magiques au sein du bloc
            for sig, cat, ftype, ext, validator in active_dispatch:
                search_pos = 0
                while search_pos < len(raw_chunk):
                    match_pos = raw_chunk.find(sig, search_pos)
                    if match_pos == -1:
                        break

                    # Vérification d'alignement sectoriel (512 ou 4096 octets)
                    global_offset = chunk_offset + match_pos
                    if global_offset % self.sector_alignment != 0:
                        search_pos = match_pos + 1
                        continue

                    if global_offset in seen_offsets:
                        search_pos = match_pos + self.sector_alignment
                        continue

                    # Validation sémantique du candidat
                    try:
                        res = validator(self.reader, global_offset)
                    except Exception:
                        res = None

                    if res:
                        length, meta, is_frag = res
                        if length > 0:
                            seen_offsets.add(global_offset)
                            artefact_counter += 1
                            art_lba = global_offset // self.sector_size
                            end_lba = (global_offset + length - 1) // self.sector_size

                            final_type = meta.get("file_type", ftype)
                            final_ext = meta.get("extension", ext)
                            final_cat = "Documents" if final_type in ("DOCX", "XLSX", "PPTX") else cat

                            art = CarvedArtefact(
                                artefact_id=artefact_counter,
                                category=final_cat,
                                file_type=final_type,
                                extension=final_ext,
                                start_lba=art_lba,
                                start_offset=global_offset,
                                length_bytes=length,
                                end_lba=end_lba,
                                filename=f"artefact_{artefact_counter:04d}{final_ext}",
                                is_valid=True,
                                is_fragmented=is_frag,
                                metadata=meta,
                            )
                            self.carved_artefacts.append(art)
                            if artefact_callback:
                                artefact_callback(art)

                    search_pos = match_pos + self.sector_alignment

            current_lba += step_lba

            if progress_callback:
                elapsed = max(0.001, time.time() - t_start)
                speed = (bytes_scanned / (1024 * 1024)) / elapsed
                progress_callback(current_lba - self.start_lba, total_lbas, speed, artefact_counter)

        # Dé-tressage médico-légal automatique des flux entrelacés (BraidResolver)
        try:
            from core.defragmenter import BraidResolver
            resolver = BraidResolver(self.reader)
            resolver.resolve(self.carved_artefacts)
        except Exception:
            pass

        # Corrélation sémantique avec les répertoires orphelins (FAT / NTFS)
        try:
            self.correlator.correlate(self.carved_artefacts)
            # Carving assisté par métadonnées pour les fichiers sans signature directe
            additional = self.correlator.recover_orphan_entries(
                self.carved_artefacts,
                current_max_id=len(self.carved_artefacts),
            )
            for extra_art in additional:
                self.carved_artefacts.append(extra_art)
                if artefact_callback:
                    artefact_callback(extra_art)
        except Exception:
            pass

        return self.carved_artefacts

    def extract_stream(self, artefact: CarvedArtefact) -> bytes:
        """Extrait le flux binaire de l'artefact en mémoire vive sans écriture disque."""
        from core.defragmenter import extract_stream_data
        return extract_stream_data(self.reader, artefact)
