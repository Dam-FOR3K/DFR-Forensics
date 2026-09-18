"""
WipeRescue-Forensics - Couche d'accès aux images disques
Supporte :
 - Images brutes : .raw, .dd, .img, .bin, .iso
 - Images brutes segmentées : .001, .002, ...
 - Expert Witness Format (EnCase) : .E01, .E02, ... (via dissect.evidence.ewf)
Garantit une sécurité forensique stricte en lecture seule.
"""

import os
import sys
import glob
import re
from typing import List, Optional, BinaryIO, Dict, Any
from abc import ABC, abstractmethod

# Augmenter la limite de descripteurs de fichiers sous Windows (indispensable pour les images à plus de 50 segments)
try:
    import msvcrt
    msvcrt.setmaxstdio(2048)
except Exception:
    pass


class ForensicImageReader(ABC):
    """Interface abstraite pour un lecteur d'image disque médico-légale en lecture seule."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.sector_size: int = 512
        self.total_size_bytes: int = 0
        self.total_sectors: int = 0

    @abstractmethod
    def read_bytes(self, offset: int, length: int) -> bytes:
        """Lit un nombre d'octets à partir d'un offset précis."""
        pass

    def read_sector(self, lba: int, count: int = 1) -> bytes:
        """Lit un ou plusieurs secteurs à partir du numéro de secteur LBA."""
        if lba < 0:
            lba = self.total_sectors + lba
        if lba < 0 or lba + count > self.total_sectors:
            raise IndexError(f"LBA hors limites : {lba} (total : {self.total_sectors})")
        offset = lba * self.sector_size
        return self.read_bytes(offset, count * self.sector_size)

    @abstractmethod
    def close(self):
        """Ferme les descripteurs de fichiers ouverts."""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class RawImageReader(ForensicImageReader):
    """Lecteur pour images brutes (RAW, DD, IMG, BIN)."""

    def __init__(self, path: str, sector_size: int = 512):
        super().__init__(path)
        self.sector_size = sector_size
        self._file: BinaryIO = open(self.path, "rb")
        self._file.seek(0, os.SEEK_END)
        self.total_size_bytes = self._file.tell()
        self.total_sectors = self.total_size_bytes // self.sector_size

    def read_bytes(self, offset: int, length: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(length)

    def close(self):
        if self._file and not self._file.closed:
            self._file.close()


class SplitRawReader(ForensicImageReader):
    """Lecteur pour images brutes segmentées (.001, .002, .003 ...)."""

    def __init__(self, first_part_path: str, sector_size: int = 512):
        super().__init__(first_part_path)
        self.sector_size = sector_size
        self.segments: List[str] = self._discover_segments(first_part_path)
        self.segment_sizes: List[int] = [os.path.getsize(s) for s in self.segments]
        self.total_size_bytes = sum(self.segment_sizes)
        self.total_sectors = self.total_size_bytes // self.sector_size
        self._open_handles: List[Optional[BinaryIO]] = [None] * len(self.segments)

    def _discover_segments(self, first_part: str) -> List[str]:
        base_dir = os.path.dirname(first_part)
        filename = os.path.basename(first_part)
        # Match .001, .raw.001, etc.
        match = re.search(r"^(.*?)(?:\.(\d{3,}))$$", filename, re.IGNORECASE)
        if not match:
            return [first_part]

        prefix = match.group(1)
        pattern = os.path.join(base_dir, f"{prefix}.*")
        found = []
        for path in glob.glob(pattern):
            ext_match = re.search(r"\.(\d{3,})$$", path)
            if ext_match:
                found.append((int(ext_match.group(1)), path))

        found.sort(key=lambda x: x[0])
        return [path for _, path in found] if found else [first_part]

    def _get_handle(self, index: int) -> BinaryIO:
        if self._open_handles[index] is None:
            self._open_handles[index] = open(self.segments[index], "rb")
        return self._open_handles[index]

    def read_bytes(self, offset: int, length: int) -> bytes:
        if offset >= self.total_size_bytes:
            return b""

        result = bytearray()
        bytes_to_read = min(length, self.total_size_bytes - offset)
        current_offset = offset

        while bytes_to_read > 0:
            seg_start = 0
            seg_idx = 0
            for idx, size in enumerate(self.segment_sizes):
                if seg_start <= current_offset < seg_start + size:
                    seg_idx = idx
                    break
                seg_start += size
            else:
                break

            handle = self._get_handle(seg_idx)
            offset_in_seg = current_offset - seg_start
            available = self.segment_sizes[seg_idx] - offset_in_seg
            chunk_size = min(bytes_to_read, available)

            handle.seek(offset_in_seg)
            data = handle.read(chunk_size)
            result.extend(data)

            current_offset += len(data)
            bytes_to_read -= len(data)
            if not data:
                break

        return bytes(result)

    def close(self):
        for h in self._open_handles:
            if h and not h.closed:
                h.close()


class E01ImageReader(ForensicImageReader):
    """Lecteur pour images Expert Witness Format (E01/EnCase) via dissect.evidence.ewf."""

    def __init__(self, path: str, sector_size: int = 512):
        super().__init__(path)
        self.sector_size = sector_size
        import re
        from pathlib import Path
        try:
            from dissect.evidence.ewf import EWF
            p = Path(self.path)
            ext = p.suffix.lower()
            segments = [p]
            if re.match(r"^\.e01$", ext):
                stem = p.name[: -len(ext)]
                sibling_files = []

                def ewf_sort_key(suffix: str) -> int:
                    m_num = re.match(r"^\.e(\d+)$", suffix)
                    if m_num:
                        return int(m_num.group(1))
                    m_alpha = re.match(r"^\.e([a-z]{2})$", suffix)
                    if m_alpha:
                        letters = m_alpha.group(1)
                        return 100 + (ord(letters[0]) - ord('a')) * 26 + (ord(letters[1]) - ord('a'))
                    return 999999

                for f in p.parent.iterdir():
                    if f.name.lower().startswith(stem.lower()):
                        s_low = f.suffix.lower()
                        if re.match(r"^\.e(?:\d+|[a-z]{2})$", s_low):
                            sibling_files.append((ewf_sort_key(s_low), f))
                if sibling_files:
                    sibling_files.sort(key=lambda x: x[0])
                    segments = [f for _, f in sibling_files]

            self._ewf_obj = EWF(segments if len(segments) > 1 else p)
            self._stream = self._ewf_obj.open()
            self.total_size_bytes = self._ewf_obj.size
            if hasattr(self._ewf_obj, "volume") and self._ewf_obj.volume:
                self.sector_size = getattr(self._ewf_obj.volume, "sector_size", sector_size)
            self.total_sectors = self.total_size_bytes // self.sector_size
        except Exception as e:
            raise RuntimeError(f"Échec de l'ouverture de l'image E01 ({path}): {e}")

    def read_bytes(self, offset: int, length: int) -> bytes:
        self._stream.seek(offset)
        return self._stream.read(length)

    def close(self):
        if hasattr(self, "_stream") and self._stream:
            try:
                self._stream.close()
            except Exception:
                pass


class AFF4ImageReader(ForensicImageReader):
    """
    Lecteur pour images médico-légales au format AFF4 (Advanced Forensics File Format 4).
    Basé sur conteneur ZIP64, streams de segments (bevies) et tables d'index (.idx).
    """

    def __init__(self, path: str, sector_size: int = 512):
        super().__init__(path)
        self.sector_size = sector_size
        import zipfile

        try:
            self._zip = zipfile.ZipFile(self.path, "r")
        except Exception as e:
            raise RuntimeError(f"Fichier AFF4 non valide ou archive ZIP corrompue ({path}) : {e}")

        self.chunk_size = 32768  # 32 Ko par défaut dans la spécification AFF4
        self.stream_size = 0
        self.bevies: List[Dict[str, Any]] = []
        self._cache_chunk_idx: int = -1
        self._cache_chunk_data: bytes = b""

        self._init_aff4_stream()

    def _init_aff4_stream(self):
        import re
        import struct

        namelist = self._zip.namelist()

        # 1. Inspection des métadonnées information.turtle
        turtle_content = ""
        for name in namelist:
            if name.endswith("information.turtle"):
                try:
                    turtle_content = self._zip.read(name).decode("utf-8", errors="ignore")
                    break
                except Exception:
                    pass

        if turtle_content:
            # Recherche de aff4:size
            size_match = re.search(r'aff4:size\s+["\']?(\d+)["\']?', turtle_content)
            if size_match:
                self.stream_size = int(size_match.group(1))

            # Recherche de aff4:chunkSize
            chunk_match = re.search(r'aff4:chunkSize\s+["\']?(\d+)["\']?', turtle_content)
            if chunk_match:
                self.chunk_size = int(chunk_match.group(1))

        # 2. Recherche des fichiers index (.idx) et des segments de données
        idx_files = [n for n in namelist if n.endswith(".idx")]

        if idx_files:
            # Trier les index
            idx_files.sort()
            for idx_name in idx_files:
                data_name = idx_name[:-4]  # Enlever .idx
                if data_name in namelist:
                    idx_raw = self._zip.read(idx_name)
                    # L'index AFF4 contient une suite d'offsets uint32 (<I) ou uint64 (<Q)
                    # Déterminer la taille des entrées d'index
                    data_info = self._zip.getinfo(data_name)
                    data_size = data_info.file_size
                    entry_format = "<I" if data_size < 0xFFFFFFFF and len(idx_raw) % 4 == 0 else "<Q"
                    entry_sz = 4 if entry_format == "<I" else 8
                    count = len(idx_raw) // entry_sz

                    offsets = [struct.unpack_from(entry_format, idx_raw, i * entry_sz)[0] for i in range(count)]
                    # S'assurer que le dernier offset correspond à la taille du fichier si non présent
                    if offsets and offsets[-1] < data_size:
                        offsets.append(data_size)

                    self.bevies.append({
                        "data_name": data_name,
                        "idx_name": idx_name,
                        "offsets": offsets,
                        "chunks_count": max(0, len(offsets) - 1),
                    })

            total_chunks = sum(b["chunks_count"] for b in self.bevies)
            calculated_size = total_chunks * self.chunk_size
            if self.stream_size == 0 or self.stream_size > calculated_size:
                self.stream_size = calculated_size

        else:
            # Cas d'un stream direct stocké dans le ZIP (ex: disk.raw ou stream)
            candidates = [n for n in namelist if not n.endswith(".turtle") and not n.endswith(".version")]
            if candidates:
                # Prendre le plus volumineux
                largest = max(candidates, key=lambda n: self._zip.getinfo(n).file_size)
                self.direct_member = largest
                self.stream_size = self._zip.getinfo(largest).file_size
                self.bevies = []
            else:
                raise RuntimeError("Aucun flux de données de disque valide trouvé dans le conteneur AFF4.")

        self.total_size_bytes = self.stream_size
        self.total_sectors = self.total_size_bytes // self.sector_size

    def _read_chunk(self, chunk_index: int) -> bytes:
        if chunk_index == self._cache_chunk_idx:
            return self._cache_chunk_data

        import zlib

        # Trouver dans quel bevy se trouve le chunk
        accum = 0
        for bevy in self.bevies:
            count = bevy["chunks_count"]
            if accum <= chunk_index < accum + count:
                local_idx = chunk_index - accum
                offsets = bevy["offsets"]
                start_off = offsets[local_idx]
                end_off = offsets[local_idx + 1] if local_idx + 1 < len(offsets) else start_off

                # Lire les octets compressés du chunk
                with self._zip.open(bevy["data_name"]) as f:
                    f.seek(start_off)
                    raw_chunk = f.read(end_off - start_off)

                # Décompression (Deflate ou Stored)
                decompressed = b""
                if len(raw_chunk) == self.chunk_size:
                    decompressed = raw_chunk
                else:
                    try:
                        decompressed = zlib.decompress(raw_chunk)
                    except Exception:
                        try:
                            # Tenter deflate brut (sans zlib wrapper)
                            decompressed = zlib.decompress(raw_chunk, -15)
                        except Exception:
                            # Si non compressé ou autre algo
                            decompressed = raw_chunk.ljust(self.chunk_size, b"\x00")

                self._cache_chunk_idx = chunk_index
                self._cache_chunk_data = decompressed
                return decompressed

            accum += count

        return b"\x00" * self.chunk_size

    def read_bytes(self, offset: int, length: int) -> bytes:
        if offset >= self.total_size_bytes:
            return b""

        # Cas du stream direct
        if hasattr(self, "direct_member") and self.direct_member:
            with self._zip.open(self.direct_member) as f:
                f.seek(offset)
                return f.read(length)

        # Cas du stream par chunks
        result = bytearray()
        bytes_to_read = min(length, self.total_size_bytes - offset)
        curr_offset = offset

        while bytes_to_read > 0:
            chunk_idx = curr_offset // self.chunk_size
            offset_in_chunk = curr_offset % self.chunk_size
            available = self.chunk_size - offset_in_chunk
            read_len = min(bytes_to_read, available)

            chunk_data = self._read_chunk(chunk_idx)
            result.extend(chunk_data[offset_in_chunk : offset_in_chunk + read_len])

            curr_offset += read_len
            bytes_to_read -= read_len

        return bytes(result)

    def close(self):
        if hasattr(self, "_zip") and self._zip:
            try:
                self._zip.close()
            except Exception:
                pass


class AD1ImageReader(ForensicImageReader):
    """Lecteur médico-légal pour images logiques AccessData FTK Imager (.ad1, .ad2, ...)."""

    def __init__(self, path: str, sector_size: int = 512):
        super().__init__(path)
        self.sector_size = sector_size

        from pathlib import Path
        from dissect.evidence.ad1 import AD1

        path_obj = Path(self.path)
        stem = path_obj.stem
        parent = path_obj.parent
        # Recherche des segments multiples (.ad1, .ad2, ..., .ad10, etc.) avec tri naturel numérique
        matched_segments = []
        for p in parent.iterdir():
            if p.stem.lower() == stem.lower():
                m = re.match(r"^\.ad(\d+)$", p.suffix.lower())
                if m:
                    matched_segments.append((int(m.group(1)), p))

        if matched_segments:
            matched_segments.sort(key=lambda x: x[0])
            self.segment_paths = [p for _, p in matched_segments]
        else:
            self.segment_paths = [path_obj]

        self._fhs = [open(str(p), "rb") for p in self.segment_paths]
        self.ad1 = AD1(self._fhs)

        disk_size = sum(os.path.getsize(str(p)) for p in self.segment_paths)
        self.total_size_bytes = self.ad1.size if getattr(self.ad1, "size", 0) > 0 else disk_size
        self.total_sectors = max(1, (self.total_size_bytes + self.sector_size - 1) // self.sector_size)

    def read_bytes(self, offset: int, length: int) -> bytes:
        if offset >= self.total_size_bytes:
            return b""
        actual_len = min(length, self.total_size_bytes - offset)
        try:
            return self.ad1.stream.readoffset(offset, actual_len)
        except Exception:
            return b"\x00" * actual_len

    def close(self):
        for fh in getattr(self, "_fhs", []):
            try:
                if not fh.closed:
                    fh.close()
            except Exception:
                pass


def is_physical_drive_path(path: str) -> bool:
    """Détermine si le chemin correspond à un périphérique de stockage physique direct."""
    if not path or not isinstance(path, str):
        return False
    p = path.strip().lower()
    return (
        p.startswith(r"\\.\physicaldrive")
        or p.startswith(r"\\.\cdrom")
        or p.startswith(r"\\.\tape")
        or p.startswith("/dev/sd")
        or p.startswith("/dev/nvme")
        or p.startswith("/dev/hd")
        or p.startswith("/dev/vd")
        or p.startswith("/dev/rdisk")
        or p.startswith("/dev/disk")
    )


class PhysicalDiskReader(ForensicImageReader):
    """
    Lecteur médico-légal bas niveau pour disques physiques connectés (RAW Physical Drive).
    Supporte :
     - Windows : \\\\.\\PhysicalDrive0, \\\\.\\PhysicalDrive1 ...
     - Linux : /dev/sda, /dev/nvme0n1 ...
     - macOS : /dev/rdisk2 ...
    Caractéristiques :
     - Lecture seule stricte (Read-Only).
     - Alignement matériel automatique des lectures sur les frontières de secteur (requis sous Windows).
     - Tolérance de panne aux secteurs défectueux (Bad Sectors) sans interruption du scan.
    """

    def __init__(self, path: str, sector_size: int = 512, total_size_bytes: Optional[int] = None):
        super().__init__(path)
        self.sector_size = sector_size
        self.bad_sectors: List[int] = []
        self._file: Optional[BinaryIO] = None

        # 1. Ouverture bas niveau en lecture seule stricte
        try:
            self._file = open(self.path, "rb", buffering=0)
        except PermissionError as pe:
            raise PermissionError(
                f"Accès refusé au disque physique '{self.path}'. "
                "L'exécution avec les privilèges Administrateur est requise pour l'accès direct aux disques physiques."
            ) from pe
        except Exception as e:
            raise IOError(f"Impossible d'ouvrir le disque physique '{self.path}': {e}") from e

        # 2. Détermination de la taille totale du disque
        if total_size_bytes and total_size_bytes > 0:
            self.total_size_bytes = total_size_bytes
        else:
            self.total_size_bytes = self._detect_total_size()

        self.total_sectors = max(1, self.total_size_bytes // self.sector_size)

    def _detect_total_size(self) -> int:
        """Détecte la taille totale du disque physique selon l'OS."""
        # A. Sous Windows via DeviceIoControl IOCTL_DISK_GET_LENGTH_INFO
        if sys.platform == "win32":
            try:
                import msvcrt
                import ctypes
                from ctypes import wintypes

                IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C

                class GET_LENGTH_INFORMATION(ctypes.Structure):
                    _fields_ = [("Length", ctypes.c_int64)]

                handle = msvcrt.get_osfhandle(self._file.fileno())
                out_buf = GET_LENGTH_INFORMATION()
                bytes_returned = wintypes.DWORD()

                res = ctypes.windll.kernel32.DeviceIoControl(
                    handle,
                    IOCTL_DISK_GET_LENGTH_INFO,
                    None,
                    0,
                    ctypes.byref(out_buf),
                    ctypes.sizeof(out_buf),
                    ctypes.byref(bytes_returned),
                    None
                )
                if res and out_buf.Length > 0:
                    return int(out_buf.Length)
            except Exception:
                pass

            # Fallback Windows : interrogation de l'énumération WMI/CimInstance
            try:
                from core.physical_disk import enumerate_physical_drives
                drives = enumerate_physical_drives()
                for d in drives:
                    if d.device_id.lower() == self.path.lower():
                        if d.size_bytes > 0:
                            return d.size_bytes
            except Exception:
                pass

        # B. Sous Linux / Unix via ioctl BLKGETSIZE64
        elif sys.platform.startswith("linux"):
            try:
                import fcntl
                import struct
                BLKGETSIZE64 = 0x80081272
                buf = struct.pack("L", 0)
                res = fcntl.ioctl(self._file.fileno(), BLKGETSIZE64, buf)
                size = struct.unpack("L", res)[0]
                if size > 0:
                    return size
            except Exception:
                pass

        # C. Tentative générique via seek(0, SEEK_END)
        try:
            self._file.seek(0, os.SEEK_END)
            size = self._file.tell()
            self._file.seek(0)
            if size > 0:
                return size
        except Exception:
            pass

        return 0

    def read_bytes(self, offset: int, length: int) -> bytes:
        if length <= 0 or (self.total_size_bytes > 0 and offset >= self.total_size_bytes):
            return b""

        # Windows requiert des lectures alignées sur la taille de secteur physique
        sector_sz = self.sector_size
        aligned_start = (offset // sector_sz) * sector_sz
        end_offset = offset + length
        if self.total_size_bytes > 0:
            end_offset = min(end_offset, self.total_size_bytes)
        aligned_end = ((end_offset + sector_sz - 1) // sector_sz) * sector_sz
        to_read = max(sector_sz, aligned_end - aligned_start)

        try:
            self._file.seek(aligned_start)
            raw_chunk = self._file.read(to_read)
        except (OSError, IOError) as io_err:
            # Gestion résiliente des secteurs physiques défectueux (Bad Sectors)
            bad_lba = aligned_start // sector_sz
            if bad_lba not in self.bad_sectors:
                self.bad_sectors.append(bad_lba)
            # Renvoyer des zéros pour ne pas corrompre le parsing
            return b"\x00" * length

        slice_start = offset - aligned_start
        slice_end = slice_start + length
        result = raw_chunk[slice_start:slice_end]
        if len(result) < length:
            result = result + b"\x00" * (length - len(result))
        return result

    def close(self):
        if self._file and not self._file.closed:
            try:
                self._file.close()
            except Exception:
                pass


def open_forensic_image(path: str, sector_size: int = 512) -> ForensicImageReader:
    """Détecte automatiquement le format de l'image et instancie le lecteur adéquat."""
    # 1. Détection des périphériques disques physiques directs
    if is_physical_drive_path(path):
        return PhysicalDiskReader(path, sector_size=sector_size)

    if not os.path.exists(path):
        raise FileNotFoundError(f"Fichier image introuvable : {path}")

    lower_path = path.lower()

    # Détection AD1 (AccessData FTK Imager)
    if lower_path.endswith(".ad1") or re.search(r"\.ad\d+$", lower_path):
        return AD1ImageReader(path, sector_size=sector_size)

    # Détection AFF4
    if lower_path.endswith(".aff4"):
        return AFF4ImageReader(path, sector_size=sector_size)

    # Détection E01 / EWF
    if re.search(r"\.e\d{2}$", lower_path) or lower_path.endswith(".ewf"):
        return E01ImageReader(path, sector_size=sector_size)

    # Détection image segmentée .001
    if re.search(r"\.001$", lower_path):
        return SplitRawReader(path, sector_size=sector_size)

    # Vérification magique en cas d'extension générique (.raw, .bin, .img)
    try:
        with open(path, "rb") as f_chk:
            header_16 = f_chk.read(16)
            if header_16.startswith(b"ADSEGMENTEDFILE") or header_16.startswith(b"ADLOGICALIMAGE"):
                return AD1ImageReader(path, sector_size=sector_size)
    except Exception:
        pass

    # Image RAW standard (.raw, .dd, .img, .bin, etc.)
    return RawImageReader(path, sector_size=sector_size)
