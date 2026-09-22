"""
DFR-Forensics - Moteur de Lecture QNX Avancé (QNX4 & QNX6 Power-Safe)
Inspiré des recherches forensiques automobiles du NFI (qnxmount) et d'Alexis Brignoni (qnxprobe).
Prend en charge :
 - Superblocks QNX6 multi-générations (primaire 0x2000, secondaire 0x2E00, bootblock 0xeb109000, fin de volume)
 - Tailles de blocs exotiques (> 4 Ko, jusqu'à 64 Ko)
 - Arborescence complète d'inodes, noms longs (.longfilenode) et gestion des trous (sparse blocks)
 - Fallback natif autonome pur Python sans dépendance externe
"""

import os
import struct
import datetime
from typing import List, Optional, Any, Tuple, Dict
from datetime import timezone

from core.image_reader import ForensicImageReader
from core.crypto_engine import PartitionStream

try:
    import dissect.qnxfs as qnxfs
    QNX_DISSECT_AVAILABLE = True
except ImportError:
    qnxfs = None
    QNX_DISSECT_AVAILABLE = False


QNX6_MAGIC = 0x68191122
QNX6_BOOTBLOCK_MAGIC = b"\xeb\x10\x90\x00"
QNX6_BOOTBLOCK_SIZE = 0x2000  # 8192 octets
QNX6_INODE_SIZE = 0x80        # 128 octets
QNX6_DIRENT_SIZE = 0x20       # 32 octets
QNX6_ROOT_INO = 1
QNX6_ROOTNODE = dict(Inode=72, Longfile=232)

QNX4_SUPER_MAGIC = 0x002F
QNX4_BLOCK_SIZE = 512
QNX4_DIRENT_SIZE = 64
QNX4_ROOT_NODE = 8
QNX4_XBLK_SIG = b"IamXblk"

# Offsets des champs dans struct qnx6_super_block
F_QNX6 = dict(
    magic=0, checksum=4, serial=8, ctime=16, atime=20, flags=24,
    version1=28, version2=30, volumeid=32, blocksize=48,
    num_inodes=52, free_inodes=56, num_blocks=60, free_blocks=64,
    allocgroup=68
)


class QNXFileEntry:
    """Représentation unifiée d'une entrée de fichier ou dossier QNX."""

    def __init__(self, name: str, path: str, is_dir: bool, size: int = 0, mtime: Optional[datetime.datetime] = None, node: Any = None):
        self.name = name
        self.path = path
        self._is_dir = is_dir
        self.size = size
        self.mtime = mtime
        self.node = node
        self.children: List["QNXFileEntry"] = []

    def is_dir(self) -> bool:
        return self._is_dir


def parse_qnx6_sb(buf: bytes, endian: str = "little") -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Parse un en-tête superblock QNX6 avec validation rigoureuse des champs."""
    if len(buf) < 512:
        return None, ["Buffer inférieur à 512 octets"]

    e = "<" if endian == "little" else ">"
    try:
        magic = struct.unpack_from(e + "I", buf, F_QNX6["magic"])[0]
        if magic != QNX6_MAGIC:
            return None, [f"Magic invalide : 0x{magic:08x}"]

        g32 = lambda k: struct.unpack_from(e + "I", buf, F_QNX6[k])[0]
        g16 = lambda k: struct.unpack_from(e + "H", buf, F_QNX6[k])[0]

        sb = dict(
            magic=magic,
            checksum=g32("checksum"),
            serial=struct.unpack_from(e + "Q", buf, F_QNX6["serial"])[0],
            ctime=g32("ctime"),
            atime=g32("atime"),
            flags=g32("flags"),
            version1=g16("version1"),
            version2=g16("version2"),
            volumeid=buf[F_QNX6["volumeid"]:F_QNX6["volumeid"] + 16],
            blocksize=g32("blocksize"),
            num_inodes=g32("num_inodes"),
            free_inodes=g32("free_inodes"),
            num_blocks=g32("num_blocks"),
            free_blocks=g32("free_blocks"),
            allocgroup=g32("allocgroup"),
            raw=buf,
            endian=endian,
        )

        bad = []
        bs = sb["blocksize"]
        if not (512 <= bs <= 65536 and (bs & (bs - 1)) == 0):
            bad.append(f"Taille de bloc {bs} non puissance de 2 dans [512..65536]")
        if sb["free_blocks"] > sb["num_blocks"]:
            bad.append("free_blocks > num_blocks")
        if sb["free_inodes"] > sb["num_inodes"]:
            bad.append("free_inodes > num_inodes")
        if sb["num_blocks"] == 0:
            bad.append("num_blocks == 0")

        return sb, bad
    except Exception as exc:
        return None, [str(exc)]


def find_qnx6_superblocks(stream: Any, total_size: int) -> List[Tuple[int, Dict[str, Any], str]]:
    """
    Recherche exhaustive des superblocks QNX6 à travers tous les emplacements connus :
    - Pointeurs du bootblock à l'offset 0 (sblk0, sblk1)
    - Offsets standards : 0x2000 (8192), 0x2E00 (11776), 0, 0xE00 (3584)
    - Offsets de fin de volume : total_size - 0x1000, total_size - 0x200
    """
    candidates_offsets = []

    # 1. Vérification du bootblock
    stream.seek(0)
    boot = stream.read(512)
    if len(boot) >= 16 and boot[:4] == QNX6_BOOTBLOCK_MAGIC:
        s0, s1 = struct.unpack_from("<II", boot, 8)
        if s0 > 0:
            candidates_offsets.append(s0 * 512)
        if s1 > 0:
            candidates_offsets.append(s1 * 512)

    # 2. Emplacements standards
    candidates_offsets.extend([
        QNX6_BOOTBLOCK_SIZE,          # 0x2000 = 8192
        QNX6_BOOTBLOCK_SIZE + 0xE00,  # 0x2E00 = 11776 (génération précédente)
        0,                            # Début direct
        0xE00,                        # 3584
    ])

    # 3. Fin de partition / volume
    if total_size >= 0x1000:
        candidates_offsets.extend([
            total_size - 0x1000,
            total_size - 0x200,
        ])

    seen = set()
    valid_superblocks = []

    for off in candidates_offsets:
        if off < 0 or off + 512 > total_size or off in seen:
            continue
        seen.add(off)

        stream.seek(off)
        buf = stream.read(512)
        if len(buf) < 512:
            continue

        for endian in ("little", "big"):
            sb, bad = parse_qnx6_sb(buf, endian)
            if sb and not bad:
                valid_superblocks.append((off, sb, endian))
                break

    # Trier par numéro de série décroissant (la génération active la plus récente d'abord)
    valid_superblocks.sort(key=lambda item: item[1]["serial"], reverse=True)
    return valid_superblocks


class NativeQnx6Walker:
    """
    Parcours d'arborescence et extraction QNX6 Power-Safe purement en Python standard.
    Gère n'importe quelle taille de bloc (512 à 65536 o), résout les B-Trees et les noms longs.
    """

    def __init__(self, stream: Any, sb_offset: int, sb: Dict[str, Any], endian: str = "little"):
        self.stream = stream
        self.sb_offset = sb_offset
        self.sb = sb
        self.endian = endian
        self.e = "<" if endian == "little" else ">"

        self.bs = sb["blocksize"]
        bits = self.bs.bit_length() - 1
        self.ptrbits = (self.bs // 4).bit_length() - 1
        self.blks_off = (0x2000 >> bits) + (0x1000 >> bits)

        raw_sb = sb["raw"]
        self.inode_rn = self._rn(raw_sb, QNX6_ROOTNODE["Inode"])
        self.long_rn = self._rn(raw_sb, QNX6_ROOTNODE["Longfile"])

    def _rn(self, sb_raw: bytes, offset: int) -> Dict[str, Any]:
        ptrs = list(struct.unpack_from(self.e + "16I", sb_raw, offset + 8))
        levels = sb_raw[offset + 72]
        return dict(ptr=ptrs, levels=levels)

    def _read_blk(self, blk_idx: int) -> bytes:
        pos = blk_idx * self.bs
        self.stream.seek(pos)
        data = self.stream.read(self.bs)
        if len(data) < self.bs:
            data = data + b"\x00" * (self.bs - len(data))
        return data

    def _map(self, ptrs: List[int], levels: int, logical_blk: int) -> Optional[int]:
        bitdelta = self.ptrbits * levels
        mask = (1 << self.ptrbits) - 1
        lp = logical_blk >> bitdelta
        if lp > 15:
            return None

        blk = ptrs[lp] + self.blks_off
        for _ in range(levels):
            buf = self._read_blk(blk)
            if len(buf) < self.bs:
                return None
            bitdelta -= self.ptrbits
            idx = ((logical_blk >> bitdelta) & mask) * 4
            ptr = struct.unpack_from(self.e + "I", buf, idx)[0]
            if ptr in (0, 0xFFFFFFFF):
                return None
            blk = ptr + self.blks_off
        return blk

    def _tree(self, rootnode: Dict[str, Any], logical_blk: int) -> Optional[bytes]:
        b = self._map(rootnode["ptr"], rootnode["levels"], logical_blk)
        return self._read_blk(b) if b is not None else None

    def get_inode(self, inode_num: int) -> Optional[Dict[str, Any]]:
        byte_off = (inode_num - 1) * QNX6_INODE_SIZE
        buf = self._tree(self.inode_rn, byte_off // self.bs)
        if not buf:
            return None
        raw = buf[byte_off % self.bs : byte_off % self.bs + QNX6_INODE_SIZE]
        if len(raw) < QNX6_INODE_SIZE:
            return None

        size = struct.unpack_from(self.e + "Q", raw, 0)[0]
        mtime = struct.unpack_from(self.e + "I", raw, 20)[0]
        mode = struct.unpack_from(self.e + "H", raw, 32)[0]
        ptrs = list(struct.unpack_from(self.e + "16I", raw, 36))
        levels = raw[100]

        return dict(size=size, mtime=mtime, mode=mode, ptr=ptrs, levels=levels)

    def _read_longname(self, blk_idx: int) -> str:
        buf = self._tree(self.long_rn, blk_idx)
        if not buf:
            return "nom_inconnu"
        length = struct.unpack_from(self.e + "H", buf, 0)[0]
        return buf[2 : 2 + min(length, 510)].decode("utf-8", errors="replace")

    def listdir(self, inode_num: int) -> List[Tuple[str, int]]:
        ino = self.get_inode(inode_num)
        if not ino or not (ino["mode"] & 0o040000):
            return []

        out = []
        num_blocks = (ino["size"] + self.bs - 1) // self.bs
        for lb in range(num_blocks):
            b = self._map(ino["ptr"], ino["levels"], lb)
            if b is None:
                continue
            buf = self._read_blk(b)
            for p in range(0, len(buf) - QNX6_DIRENT_SIZE + 1, QNX6_DIRENT_SIZE):
                de_ino = struct.unpack_from(self.e + "I", buf, p)[0]
                de_size = buf[p + 4]
                if not de_ino or not de_size:
                    continue
                if de_size == 0xFF:
                    long_blk = struct.unpack_from(self.e + "I", buf, p + 8)[0]
                    name = self._read_longname(long_blk)
                else:
                    name = buf[p + 5 : p + 5 + min(de_size, 27)].decode("utf-8", errors="replace")
                if name not in (".", ".."):
                    out.append((name, de_ino))
        return sorted(out, key=lambda x: x[0])

    def read_file_bytes(self, inode_num: int, max_bytes: Optional[int] = None) -> bytes:
        ino = self.get_inode(inode_num)
        if not ino:
            return b""
        total_size = ino["size"]
        if max_bytes is not None:
            total_size = min(total_size, max_bytes)

        out = bytearray()
        left = total_size
        num_blocks = (total_size + self.bs - 1) // self.bs

        for lb in range(num_blocks):
            b = self._map(ino["ptr"], ino["levels"], lb)
            buf = self._read_blk(b) if b is not None else b"\x00" * self.bs
            take = min(self.bs, left)
            out.extend(buf[:take])
            left -= take
            if left <= 0:
                break
        return bytes(out)


class QNXReader:
    """Lecteur unifié forensique pour systèmes de fichiers QNX4 et QNX6 Power-Safe."""

    def __init__(self, reader: ForensicImageReader, partition_offset_bytes: int = 0, partition_size_bytes: Optional[int] = None):
        self.reader = reader
        self.offset = partition_offset_bytes
        self.size = partition_size_bytes or (reader.total_size_bytes - partition_offset_bytes)
        self.stream = PartitionStream(reader, self.offset, self.size)
        self.is_valid_qnx: bool = False
        self.version: str = "Inconnu"
        self.root_entry: Optional[QNXFileEntry] = None
        self.all_entries: List[QNXFileEntry] = []
        self.native_walker: Optional[NativeQnx6Walker] = None
        self.dissect_fs = None

        self._parse()

    def _parse(self):
        # 1. Tentative avec dissect.qnxfs si disponible
        if QNX_DISSECT_AVAILABLE:
            try:
                self.stream.seek(0)
                if qnxfs.is_qnxfs(self.stream):
                    self.stream.seek(0)
                    self.dissect_fs = qnxfs.QNXFS(self.stream)
                    self.is_valid_qnx = True
                    self.version = "QNX6 Power-Safe (dissect)" if isinstance(self.dissect_fs, qnxfs.QNX6) else "QNX4 (dissect)"
                    root_node = self.dissect_fs.get("/")
                    self.root_entry = QNXFileEntry(name=f"/ [{self.version}]", path="/", is_dir=True, node=root_node)
                    self.all_entries.append(self.root_entry)
                    self._traverse_dissect(root_node, self.root_entry, "/")
                    return
            except Exception:
                pass

        # 2. Moteur natif haute tolérance QNX6 (Support blocs > 4K et géométries automobiles)
        candidates = find_qnx6_superblocks(self.stream, self.size)
        if candidates:
            best_off, best_sb, endian = candidates[0]
            self.native_walker = NativeQnx6Walker(self.stream, best_off, best_sb, endian)
            self.is_valid_qnx = True
            bs_kb = best_sb["blocksize"] // 1024
            self.version = f"QNX6 Power-Safe (Natif {bs_kb}K, serial {best_sb['serial']})"
            root_ino = self.native_walker.get_inode(QNX6_ROOT_INO)
            mtime_dt = None
            if root_ino and root_ino["mtime"] > 0:
                try:
                    mtime_dt = datetime.datetime.fromtimestamp(root_ino["mtime"], tz=timezone.utc)
                except Exception:
                    pass

            self.root_entry = QNXFileEntry(
                name=f"/ [{self.version}]",
                path="/",
                is_dir=True,
                size=root_ino["size"] if root_ino else 0,
                mtime=mtime_dt,
                node=QNX6_ROOT_INO
            )
            self.all_entries.append(self.root_entry)
            self._traverse_native(QNX6_ROOT_INO, self.root_entry, "/")
            return

        # 3. Vérification QNX4 native (blocs de 512 octets)
        self.stream.seek(QNX4_BLOCK_SIZE)
        sb4_buf = self.stream.read(QNX4_DIRENT_SIZE)
        if len(sb4_buf) >= 64 and sb4_buf[:2] == b"/\x00":
            mode = struct.unpack_from("<H", sb4_buf, 50)[0]
            if (mode & 0o170000) == 0o040000:
                self.is_valid_qnx = True
                self.version = "QNX4 Filesystem (Natif)"
                self.root_entry = QNXFileEntry(name=f"/ [{self.version}]", path="/", is_dir=True, node=QNX4_ROOT_NODE)
                self.all_entries.append(self.root_entry)
                return

    def _traverse_dissect(self, node: Any, parent_entry: QNXFileEntry, current_path: str, max_depth: int = 15):
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
                    if isinstance(child, tuple) and len(child) == 2:
                        c_name, c_node = child
                    else:
                        c_name = getattr(child, "name", str(child))
                        c_node = child

                    if c_name in (".", ".."):
                        continue

                    c_is_dir = c_node.is_dir() if callable(getattr(c_node, "is_dir", None)) else False
                    c_size = getattr(c_node, "size", 0) if not c_is_dir else 0
                    c_mtime = getattr(c_node, "mtime", None)
                    c_path = f"{current_path.rstrip('/')}/{c_name}"

                    file_entry = QNXFileEntry(name=c_name, path=c_path, is_dir=c_is_dir, size=c_size, mtime=c_mtime, node=c_node)
                    parent_entry.children.append(file_entry)
                    self.all_entries.append(file_entry)

                    if c_is_dir:
                        self._traverse_dissect(c_node, file_entry, c_path, max_depth - 1)
                except Exception:
                    continue
        except Exception:
            pass

    def _traverse_native(self, inode_num: int, parent_entry: QNXFileEntry, current_path: str, max_depth: int = 15):
        if max_depth <= 0 or not self.native_walker:
            return

        try:
            children = self.native_walker.listdir(inode_num)
            for c_name, c_ino in children:
                try:
                    ino_data = self.native_walker.get_inode(c_ino)
                    if not ino_data:
                        continue

                    c_is_dir = bool(ino_data["mode"] & 0o040000)
                    c_size = ino_data["size"] if not c_is_dir else 0
                    c_mtime = None
                    if ino_data["mtime"] > 0:
                        try:
                            c_mtime = datetime.datetime.fromtimestamp(ino_data["mtime"], tz=timezone.utc)
                        except Exception:
                            pass
                    c_path = f"{current_path.rstrip('/')}/{c_name}"

                    file_entry = QNXFileEntry(
                        name=c_name,
                        path=c_path,
                        is_dir=c_is_dir,
                        size=c_size,
                        mtime=c_mtime,
                        node=c_ino
                    )
                    parent_entry.children.append(file_entry)
                    self.all_entries.append(file_entry)

                    if c_is_dir:
                        self._traverse_native(c_ino, file_entry, c_path, max_depth - 1)
                except Exception:
                    continue
        except Exception:
            pass

    def extract_file_content(self, entry: QNXFileEntry) -> bytes:
        if not entry.node or entry.is_dir():
            return b""

        # Mode natif
        if self.native_walker and isinstance(entry.node, int):
            return self.native_walker.read_file_bytes(entry.node)

        # Mode dissect
        try:
            if hasattr(entry.node, "open"):
                with entry.node.open() as f:
                    return f.read()
            elif hasattr(entry.node, "read"):
                return entry.node.read()
        except Exception:
            return b""
        return b""
