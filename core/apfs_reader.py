"""
CorruptDisk-Analyzer - Moteur de Lecture Apple APFS
Permet d'explorer l'arborescence des conteneurs NXSB et des volumes APFS,
de prévisualiser les métadonnées et d'extraire les fichiers.
"""

from typing import List, Optional, Any, Dict
from datetime import datetime
import io

from core.image_reader import ForensicImageReader
from core.crypto_engine import PartitionStream

try:
    import dissect.apfs as apfs
    APFS_AVAILABLE = True
except ImportError:
    apfs = None
    APFS_AVAILABLE = False


class APFSFileEntry:
    """Représentation d'une entrée de fichier ou dossier APFS."""

    def __init__(self, name: str, path: str, is_dir: bool, size: int = 0, mtime: Optional[datetime] = None, node: Any = None):
        self.name = name
        self.path = path
        self._is_dir = is_dir
        self.size = size
        self.mtime = mtime
        self.node = node
        self.children: List["APFSFileEntry"] = []

    def is_dir(self) -> bool:
        return self._is_dir


class APFSVolumeInfo:
    """Représentation d'un volume au sein du conteneur APFS."""

    def __init__(self, name: str, uuid: str, is_encrypted: bool, vol_obj: Any):
        self.name = name
        self.uuid = uuid
        self.is_encrypted = is_encrypted
        self.vol_obj = vol_obj
        self.root_entry: Optional[APFSFileEntry] = None
        self.all_entries: List[APFSFileEntry] = []


class APFSReader:
    """Lecteur médico-légal pour conteneurs et volumes Apple APFS."""

    def __init__(self, reader: ForensicImageReader, partition_offset_bytes: int = 0, partition_size_bytes: Optional[int] = None):
        self.reader = reader
        self.offset = partition_offset_bytes
        self.size = partition_size_bytes or (reader.total_size_bytes - partition_offset_bytes)
        self.stream = PartitionStream(reader, self.offset, self.size)
        self.is_valid_apfs: bool = False
        self.container = None
        self.volumes: List[APFSVolumeInfo] = []

        self._parse()

    def _parse(self):
        if not APFS_AVAILABLE:
            return

        try:
            self.stream.seek(0)
            # Vérification magic NXSB à l'offset 32 du bloc ou au début
            hdr_sample = self.reader.read_bytes(self.offset, 4096)
            if b"NXSB" not in hdr_sample[:64]:
                return

            self.stream.seek(0)
            self.container = apfs.APFS(self.stream)
            self.is_valid_apfs = True

            for vol in self.container.volumes:
                try:
                    vol_name = getattr(vol, "name", "Sans Titre") or "Volume APFS"
                    vol_uuid = str(getattr(vol, "uuid", ""))
                    is_enc = getattr(vol, "is_encrypted", False)
                    v_info = APFSVolumeInfo(name=vol_name, uuid=vol_uuid, is_encrypted=is_enc, vol_obj=vol)

                    if not is_enc:
                        try:
                            root_node = vol.get("/")
                            v_info.root_entry = APFSFileEntry(name=f"/ [{vol_name}]", path="/", is_dir=True, node=root_node)
                            v_info.all_entries.append(v_info.root_entry)
                            self._traverse(root_node, v_info.root_entry, "/", v_info)
                        except Exception:
                            pass

                    self.volumes.append(v_info)
                except Exception:
                    continue
        except Exception:
            pass

    def _traverse(self, node: Any, parent_entry: APFSFileEntry, current_path: str, v_info: APFSVolumeInfo, max_depth: int = 15):
        if max_depth <= 0:
            return

        try:
            entries = []
            if hasattr(node, "iterdir"):
                entries = list(node.iterdir())
            elif hasattr(node, "listdir"):
                for name in node.listdir():
                    try:
                        entries.append(node.get(name))
                    except Exception:
                        pass

            for child in entries:
                try:
                    c_name = getattr(child, "name", str(child))
                    c_is_dir = child.is_dir() if callable(getattr(child, "is_dir", None)) else False
                    c_size = getattr(child, "size", 0) if not c_is_dir else 0
                    c_mtime = getattr(child, "mtime", None)
                    c_path = f"{current_path.rstrip('/')}/{c_name}"

                    file_entry = APFSFileEntry(name=c_name, path=c_path, is_dir=c_is_dir, size=c_size, mtime=c_mtime, node=child)
                    parent_entry.children.append(file_entry)
                    v_info.all_entries.append(file_entry)

                    if c_is_dir:
                        self._traverse(child, file_entry, c_path, v_info, max_depth - 1)
                except Exception:
                    continue
        except Exception:
            pass

    def extract_file_content(self, entry: APFSFileEntry) -> bytes:
        if not entry.node or entry.is_dir():
            return b""
        try:
            if hasattr(entry.node, "open"):
                with entry.node.open() as f:
                    return f.read()
            elif hasattr(entry.node, "read"):
                return entry.node.read()
        except Exception:
            return b""
        return b""
