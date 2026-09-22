"""
DFR-Forensics - Moteur de Lecture Linux SquashFS (v4)
Permet d'explorer l'arborescence et d'extraire les fichiers des firmwares
embarqués (dashcams, boîtiers IoT, routeurs, autoradios).
"""

import struct
import zlib
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timezone

from core.image_reader import ForensicImageReader

try:
    import lzma
    LZMA_AVAILABLE = True
except ImportError:
    lzma = None
    LZMA_AVAILABLE = False


class SquashFSFileEntry:
    """Représentation d'une entrée de fichier ou dossier SquashFS."""

    def __init__(
        self,
        name: str,
        path: str,
        is_dir: bool,
        size: int = 0,
        inode: int = 0,
        mtime: Optional[datetime] = None,
        data_offset: int = 0,
        data_length: int = 0,
        raw_data: Optional[bytes] = None,
    ):
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.size = size
        self.inode = inode
        self.mtime = mtime
        self.data_offset = data_offset
        self.data_length = data_length
        self.raw_data = raw_data
        self.children: List["SquashFSFileEntry"] = []

    def get_formatted_mtime(self) -> str:
        if self.mtime:
            return self.mtime.strftime("%Y-%m-%d %H:%M:%S")
        return ""


class SquashFSReader:
    """Lecteur forensic autonome pour images Linux SquashFS."""

    COMP_NAMES = {
        1: "GZIP",
        2: "LZMA",
        3: "LZO",
        4: "XZ",
        5: "LZ4",
        6: "ZSTD",
    }

    def __init__(
        self,
        reader: ForensicImageReader,
        partition_offset_bytes: int = 0,
        partition_size_bytes: Optional[int] = None,
    ):
        self.reader = reader
        self.offset = partition_offset_bytes
        self.size = partition_size_bytes or (reader.total_size_bytes - partition_offset_bytes)
        self.is_valid_squashfs: bool = False
        self.compression_type: str = "GZIP"
        self.block_size: int = 131072
        self.root_entry: Optional[SquashFSFileEntry] = None
        self.all_entries: List[SquashFSFileEntry] = []

        self._parse()

    def _parse(self):
        hdr = self.reader.read_bytes(self.offset, 4096)
        if len(hdr) < 96:
            return

        # Auto-alignement si le SquashFS ne commence pas exactement à la frontière de secteur
        shift = 0
        if hdr[:4] not in (b"hsqs", b"sqsh", b"shsq", b"qshs"):
            for candidate in (b"hsqs", b"sqsh", b"shsq", b"qshs"):
                p_cand = hdr.find(candidate)
                if p_cand != -1:
                    shift = p_cand
                    break
        if shift > 0:
            self.offset += shift
            if self.size and self.size > shift:
                self.size -= shift
            hdr = hdr[shift:]

        magic = hdr[:4]
        endian = "<"
        if magic in (b"hsqs", b"shsq"):
            endian = "<"
        elif magic in (b"sqsh", b"qshs"):
            endian = ">"
        else:
            return

        self.is_valid_squashfs = True

        if magic in (b"shsq", b"qshs"):
            # SquashFS v3 (courant sur routeurs MIPS / OpenWrt / Broadcom)
            inodes = struct.unpack(endian + "I", hdr[4:8])[0] if len(hdr) >= 8 else 0
            mkfs_time = 0
            bsize = 65536
            dir_table_start = 0
            bytes_used = self.size
            self.compression_type = "LZMA (Broadcom)"
            try:
                s_major, s_minor = struct.unpack(endian + "HH", hdr[28:32])
                self.version = f"v{s_major}.{s_minor}"
            except Exception:
                self.version = "v3.0"
        else:
            # SquashFS v4 standard
            (
                inodes,
                mkfs_time,
                bsize,
                fragments,
                comp_id,
                block_log,
                flags,
                no_ids,
                s_maj,
                s_min,
                root_ref,
                bytes_used,
                id_table_start,
                xattr_start,
                inode_table_start,
                dir_table_start,
                frag_table_start,
                export_table_start,
            ) = struct.unpack(endian + "IIIIHHHHHHQQQQQQQQ", hdr[4:96])
            self.compression_type = self.COMP_NAMES.get(comp_id, f"Code {comp_id}")

        self.block_size = bsize if bsize > 0 else 131072
        mtime_obj = datetime.fromtimestamp(mkfs_time, tz=timezone.utc) if mkfs_time > 0 else None

        # Création de la racine
        self.root_entry = SquashFSFileEntry(
            name=f"/ [SquashFS {self.compression_type} RootFS]",
            path="/",
            is_dir=True,
            inode=1,
            mtime=mtime_obj,
        )
        self.all_entries.append(self.root_entry)

        # Extraction des entrées depuis la table des répertoires
        if dir_table_start > 0 and dir_table_start < bytes_used:
            self._scan_directory_table(endian, dir_table_start, bytes_used)

        # Si aucune entrée n'a pu être extraite (flux propriétaire LZMA Broadcom 'shsq')
        if len(self.root_entry.children) == 0:
            clean_comp = self.compression_type.lower().replace(" ", "_").replace("(", "").replace(")", "")
            img_name = f"rootfs_{clean_comp}.squashfs"
            img_entry = SquashFSFileEntry(
                name=img_name,
                path=f"/{img_name}",
                is_dir=False,
                size=self.size,
                inode=100,
                mtime=mtime_obj,
                data_offset=self.offset,
                data_length=self.size,
            )
            self.root_entry.children.append(img_entry)
            self.all_entries.append(img_entry)

    def _decompress_chunk(self, data: bytes) -> bytes:
        """Tente de décompresser un bloc de métadonnées selon l'algorithme détecté."""
        try:
            return zlib.decompress(data)
        except Exception:
            pass
        if LZMA_AVAILABLE and lzma:
            try:
                return lzma.decompress(data)
            except Exception:
                pass
        return data

    def _scan_directory_table(self, endian: str, dir_table_start: int, bytes_used: int):
        """Scanne les métadonnées de répertoires décompressées pour extraire l'arborescence."""
        if dir_table_start >= bytes_used or dir_table_start == 0:
            return

        table_len = min(bytes_used - dir_table_start, 2 * 1024 * 1024)
        raw_meta = self.reader.read_bytes(self.offset + dir_table_start, table_len)

        # Décompression et découpage des blocs de répertoires (blocs de 8 Ko)
        decompressed_chunks = []
        pos = 0
        while pos < len(raw_meta) - 2:
            hdr_val = struct.unpack(endian + "H", raw_meta[pos : pos + 2])[0]
            is_uncompressed = (hdr_val & 0x8000) != 0
            chunk_size = hdr_val & 0x7FFF
            pos += 2
            if chunk_size == 0 or pos + chunk_size > len(raw_meta):
                break
            raw_chunk = raw_meta[pos : pos + chunk_size]
            pos += chunk_size
            if is_uncompressed:
                decompressed_chunks.append(raw_chunk)
            else:
                decompressed_chunks.append(self._decompress_chunk(raw_chunk))

        all_dir_data = b"".join(decompressed_chunks)
        if not all_dir_data:
            return

        # Parcours des en-têtes de répertoire SquashFS :
        # count:4, start_block:4, inode_number:4
        # Suivis de count entrées : offset:2, inode_offset:2, type:2, size:2, name
        d_pos = 0
        while d_pos < len(all_dir_data) - 12:
            try:
                count, start_block, inode_num = struct.unpack(endian + "III", all_dir_data[d_pos : d_pos + 12])
                count = (count & 0xFFFF) + 1  # SquashFS stocke count - 1
                if count > 512:
                    d_pos += 4
                    continue

                d_pos += 12
                for _ in range(count):
                    if d_pos + 8 > len(all_dir_data):
                        break
                    offset, ino_off, f_type, name_size = struct.unpack(endian + "HHHH", all_dir_data[d_pos : d_pos + 8])
                    name_len = name_size + 1
                    d_pos += 8
                    if d_pos + name_len > len(all_dir_data):
                        break
                    raw_name = all_dir_data[d_pos : d_pos + name_len]
                    d_pos += name_len

                    name = raw_name.decode("utf-8", errors="ignore").rstrip("\x00")
                    if name and name.isprintable() and name not in (".", ".."):
                        is_dir = (f_type == 1)
                        entry = SquashFSFileEntry(
                            name=name,
                            path=f"/{name}",
                            is_dir=is_dir,
                            inode=inode_num + ino_off,
                        )
                        self.root_entry.children.append(entry)
                        self.all_entries.append(entry)
            except Exception:
                d_pos += 4

    def read_file_data(self, entry: SquashFSFileEntry) -> bytes:
        if entry.raw_data is not None:
            return entry.raw_data
        if entry.data_length > 0:
            return self.reader.read_bytes(entry.data_offset, entry.data_length)
        return b""

    extract_file_content = read_file_data

