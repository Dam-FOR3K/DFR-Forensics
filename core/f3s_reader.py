"""
DFR-Forensics - Lecteur QNX Flash Filesystem (F3S / ETFS)
Permet d'explorer l'arborescence, de visualiser et d'extraire les fichiers
des puces mémoires Flash automobiles et embarquées QNX.
"""

import os
import struct
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime

from core.image_reader import ForensicImageReader


class F3SFileEntry:
    """Représente un fichier ou dossier dans un système de fichiers QNX F3S."""

    def __init__(
        self,
        name: str,
        path: str,
        is_dir: bool,
        size: int = 0,
        inode: int = 0,
        parent_inode: int = 0,
        mtime: Optional[datetime] = None,
        is_deleted: bool = False,
        data_offset: int = 0,
        data_length: int = 0,
        raw_data: Optional[bytes] = None,
    ):
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.size = size
        self.inode = inode
        self.parent_inode = parent_inode
        self.mtime = mtime
        self.is_deleted = is_deleted
        self.data_offset = data_offset
        self.data_length = data_length
        self.raw_data = raw_data
        self.children: List["F3SFileEntry"] = []

    def get_formatted_mtime(self) -> str:
        if self.mtime:
            return self.mtime.strftime("%Y-%m-%d %H:%M:%S")
        return ""


class F3SReader:
    """Lecteur forensic autonome pour images Flash QNX F3S (Flash File System v3)."""

    def __init__(
        self,
        reader: ForensicImageReader,
        partition_offset_bytes: int = 0,
        partition_size_bytes: Optional[int] = None,
    ):
        self.reader = reader
        self.offset = partition_offset_bytes
        self.size = partition_size_bytes or (reader.total_size_bytes - partition_offset_bytes)
        self.is_valid_f3s: bool = False
        self.mount_point: str = "/"
        self.unit_size: int = 0x20000  # 128 Ko par défaut pour flash NOR/NAND
        self.root_entry: Optional[F3SFileEntry] = None
        self.all_entries: List[F3SFileEntry] = []

        self._parse()

    def _parse(self):
        # Vérification du superbloc au secteur 0
        hdr = self.reader.read_bytes(self.offset, 4096)
        if len(hdr) < 64:
            return

        f3s_pos = hdr.find(b"QSSL_F3S")
        if f3s_pos == -1:
            return

        self.is_valid_f3s = True

        # Recherche du point de montage d'origine (ex: /mnt/test123)
        mount_start = hdr.find(b"/", f3s_pos)
        if mount_start != -1:
            mount_end = hdr.find(b"\x00", mount_start)
            if mount_end != -1 and (mount_end - mount_start) < 256:
                try:
                    self.mount_point = hdr[mount_start:mount_end].decode("utf-8", errors="ignore")
                except Exception:
                    self.mount_point = "/"

        # Détection de la taille d'unité (Erase Block) : chercher répétition du header 0x10 0x00 0x4C 0xFF
        sig_unit = b"\x10\x00\x4c\xff\x11\x00\xff\xff"
        for candidate_unit in [0x10000, 0x20000, 0x40000, 0x80000]:
            if candidate_unit < self.size:
                sample = self.reader.read_bytes(self.offset + candidate_unit, 16)
                if sample.startswith(sig_unit[:4]):
                    self.unit_size = candidate_unit
                    break

        # Création de la racine
        root_name = f"/ [{self.mount_point.strip('/') or 'f3s_root'}]"
        self.root_entry = F3SFileEntry(name=root_name, path="/", is_dir=True, inode=1, parent_inode=0)
        self.all_entries.append(self.root_entry)

        # Balayage des unités logiques et extraction des enregistrements
        raw_entries = self._scan_records()

        # Dictionnaire des répertoires par inode
        dir_nodes_by_inode: Dict[int, F3SFileEntry] = {1: self.root_entry, 2: self.root_entry}
        for rec in raw_entries:
            if rec.is_dir:
                dir_nodes_by_inode[rec.inode] = rec

        seen_entries: Dict[Tuple[int, str], F3SFileEntry] = {}
        for rec in raw_entries:
            parent = dir_nodes_by_inode.get(rec.parent_inode, self.root_entry)
            key = (id(parent), rec.name.lower())
            if key in seen_entries:
                # Ancienne version ou version effacée
                rec.is_deleted = True
                rec.name = f"{rec.name} (v{rec.inode})"
            seen_entries[key] = rec

            parent.children.append(rec)
            rec.path = (parent.path.rstrip("/") + "/" + rec.name).replace("//", "/")
            self.all_entries.append(rec)

    def _scan_records(self) -> List[F3SFileEntry]:
        """Scanne les enregistrements TLV de type fichier/répertoire dans la flash."""
        entries: List[F3SFileEntry] = []
        chunk_size = min(self.size, 8 * 1024 * 1024)  # Scan par blocs de 8 Mo max
        data = self.reader.read_bytes(self.offset, chunk_size)

        pos = 0
        while True:
            # En-tête de nom de fichier F3S : 0x08 0x00 0x00 <namelen> <parent_inode:2> <inode:2>
            pos = data.find(b"\x08\x00\x00", pos)
            if pos == -1 or pos >= len(data) - 24:
                break

            try:
                namelen = data[pos + 3]
                if 1 < namelen < 128 and pos + 8 + namelen < len(data):
                    parent_ino, ino = struct.unpack("<HH", data[pos + 4 : pos + 8])
                    name_raw = data[pos + 8 : pos + 8 + namelen]
                    if b"\x00" in name_raw:
                        name = name_raw.split(b"\x00")[0].decode("utf-8", errors="ignore")
                        if name.isprintable() and len(name) > 0 and name != self.mount_point:
                            # Métadonnées immédiatement après le nom aligné sur 2 ou 4 octets
                            meta_pos = pos + 8 + namelen
                            if meta_pos % 2 != 0:
                                meta_pos += 1
                            if meta_pos % 4 != 0:
                                meta_pos += 2

                            mode = 0x81A4  # Default regular file -rw-r--r--
                            file_size = 0
                            mtime = None
                            data_offset = meta_pos
                            data_length = 0
                            raw_file_data = None

                            if meta_pos + 16 <= len(data):
                                # Struct metadata: [struct_len:2] [mode:2] [uid:2] [gid:2] [ctime:4] [mtime:4]
                                s_len, s_mode = struct.unpack("<HH", data[meta_pos : meta_pos + 4])
                                if s_mode != 0xFFFF and s_mode != 0:
                                    mode = s_mode
                                if meta_pos + 16 <= len(data):
                                    ts = struct.unpack("<I", data[meta_pos + 12 : meta_pos + 16])[0]
                                    if 1000000000 < ts < 2100000000:
                                        try:
                                            mtime = datetime.fromtimestamp(ts)
                                        except Exception:
                                            pass

                                is_directory = (mode & 0xF000) == 0x4000 or "directory" in name.lower() or name.startswith("dir_")

                                # Données du fichier : situées après les métadonnées (20 octets)
                                payload_start = meta_pos + 20
                                if not is_directory:
                                    # Chercher la fin du payload (prochain header 0x08 0x00 0x00 ou 0xFF 0xFF 0xFF 0xFF)
                                    next_sig = data.find(b"\x08\x00\x00", payload_start)
                                    next_ff = data.find(b"\xff\xff\xff\xff", payload_start)
                                    end_candidates = [pos for pos in [next_sig, next_ff] if pos != -1 and pos > payload_start]
                                    if end_candidates:
                                        payload_end = min(end_candidates)
                                    else:
                                        payload_end = min(len(data), payload_start + 65536)

                                    payload = data[payload_start:payload_end]
                                    # Nettoyer les padding 0xFF de fin
                                    payload = payload.rstrip(b"\xff")
                                    file_size = len(payload)
                                    data_offset = self.offset + payload_start
                                    data_length = file_size
                                    raw_file_data = payload

                                entry = F3SFileEntry(
                                    name=name,
                                    path=f"/{name}",
                                    is_dir=is_directory,
                                    size=file_size,
                                    inode=ino,
                                    parent_inode=parent_ino,
                                    mtime=mtime,
                                    data_offset=data_offset,
                                    data_length=data_length,
                                    raw_data=raw_file_data,
                                )
                                entries.append(entry)
            except Exception:
                pass

            pos += 4

        return entries

    def read_file_data(self, entry: F3SFileEntry) -> bytes:
        """Extrait les données d'un fichier F3S."""
        if entry.raw_data is not None:
            return entry.raw_data
        if entry.data_length > 0:
            return self.reader.read_bytes(entry.data_offset, entry.data_length)
        return b""

    extract_file_content = read_file_data

