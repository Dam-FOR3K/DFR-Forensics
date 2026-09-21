"""
DFR-Forensics - Test unitaire pour image AFF4 contenant un conteneur Apple APFS
"""

import os
import sys
import zipfile
import struct
import zlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.image_reader import open_forensic_image, AFF4ImageReader
from core.scanner import DiskScanner


def create_mock_aff4_apfs_image(output_path: str):
    """Crée une image AFF4 synthétique avec conteneur APFS (NXSB)."""
    # 64 Ko d'image = 2 chunks de 32 Ko = 128 secteurs de 512 octets
    chunk_size = 32768
    total_size = 65536

    # Chunk 0 : commence par le Superblock APFS (NXSB)
    chunk0 = bytearray(chunk_size)
    chunk0[0:4] = b"NXSB"  # Signature APFS
    struct.pack_into("<I", chunk0, 4, 4096)  # Block size 4096
    struct.pack_into("<Q", chunk0, 8, total_size // 4096)  # Block count

    # Chunk 1 : données quelconques
    chunk1 = bytearray(b"\xaa" * chunk_size)

    # Compression des chunks
    comp_chunk0 = zlib.compress(bytes(chunk0))
    comp_chunk1 = zlib.compress(bytes(chunk1))

    # Assemblage du segment bevy
    bevy_data = comp_chunk0 + comp_chunk1

    # Table d'index (.idx) : offsets uint32
    # offset 0, offset du chunk 1, offset de fin
    idx_data = struct.pack("<III", 0, len(comp_chunk0), len(bevy_data))

    # Turtle metadata
    turtle = f"""
    @prefix aff4: <http://aff4.org/Schema#> .
    <aff4://test_apfs_disk> a aff4:ImageStream ;
        aff4:size "{total_size}" ;
        aff4:chunkSize "{chunk_size}" .
    """

    with zipfile.ZipFile(output_path, "w") as zf:
        zf.writestr("information.turtle", turtle.strip())
        zf.writestr("test_apfs/00000000.idx", idx_data)
        zf.writestr("test_apfs/00000000", bevy_data)

    print(f"[+] Image AFF4 de test créée : {output_path}")


def test_aff4_apfs_pipeline():
    test_aff4 = os.path.join(os.path.dirname(__file__), "test_apfs.aff4")
    create_mock_aff4_apfs_image(test_aff4)

    try:
        reader = open_forensic_image(test_aff4)
        print(f"Reader class : {type(reader).__name__}")
        assert isinstance(reader, AFF4ImageReader), "Le lecteur doit être AFF4ImageReader"
        assert reader.total_size_bytes == 65536
        assert reader.total_sectors == 128

        # Lecture du secteur 0
        sec0 = reader.read_sector(0)
        assert sec0.startswith(b"NXSB"), f"Le secteur 0 doit commencer par NXSB (obtenu {sec0[:4]})"

        # Test avec DiskScanner
        scanner = DiskScanner(reader)
        diag = scanner.run_full_scan()

        print(f"Standalone volume : {getattr(diag, 'is_standalone_volume', False)}")
        print(f"Partitions : {len(diag.partitions)}")
        if diag.partitions:
            print(f"Detected FS : {diag.partitions[0].detected_fs}")

        assert diag.is_standalone_volume, "L'image doit être détectée comme volume autonome"
        assert len(diag.partitions) == 1
        assert "APFS" in (diag.partitions[0].detected_fs or "")

        reader.close()
        print("[SUCCESS] Test AFF4 + APFS validé avec succès !")
    finally:
        if os.path.exists(test_aff4):
            os.remove(test_aff4)


def test_apfs_reader_inode_traversal():
    """Vérifie que APFSReader résout les DirectoryEntry vers leur INode pour descendre dans les sous-dossiers."""
    from datetime import datetime
    from core.apfs_reader import APFSReader, APFSFileEntry, APFSVolumeInfo

    # Mock de structure dissect.apfs avec DirectoryEntry encapsulant un INode
    class MockFileINode:
        def __init__(self, name: str, size: int = 1234):
            self.name = name
            self.size = size
            self.mtime = datetime.now()

        def is_dir(self):
            return False

        def open(self):
            import io
            return io.BytesIO(b"HELLO APFS FORENSICS")

    class MockDirINode:
        def __init__(self, name: str, children: list):
            self.name = name
            self._children = children
            self.mtime = datetime.now()

        def is_dir(self):
            return True

        def iterdir(self):
            return iter(self._children)

    class MockDirectoryEntry:
        """Simule un DirectoryEntry renvoyé par iterdir(), qui pointe vers son inode."""
        def __init__(self, name: str, inode_obj):
            self.name = name
            self.file_id = 999
            self.inode = inode_obj

        def is_dir(self):
            return self.inode.is_dir()

    # Arborescence : / -> Documents (Dir) -> secret.txt (File)
    sub_file_inode = MockFileINode("secret.txt", 42)
    dir_entry_subfile = MockDirectoryEntry("secret.txt", sub_file_inode)

    sub_dir_inode = MockDirINode("Documents", [dir_entry_subfile])
    dir_entry_docs = MockDirectoryEntry("Documents", sub_dir_inode)

    root_inode = MockDirINode("/", [dir_entry_docs])

    reader = MockAPFSImageReader(b"\x00" * 4096)
    apfs_reader = APFSReader(reader)
    v_info = APFSVolumeInfo("Macintosh HD", "uuid-123", False, None)
    v_info.root_entry = APFSFileEntry("/ [Macintosh HD]", "/", is_dir=True, node=root_inode)

    # Lancement du parcours récursif
    apfs_reader._traverse(root_inode, v_info.root_entry, "/", v_info, max_depth=5)

    # 1. Vérification niveau 1 (Documents)
    assert len(v_info.root_entry.children) == 1
    docs_entry = v_info.root_entry.children[0]
    assert docs_entry.name == "Documents"
    assert docs_entry.is_dir() is True

    # 2. Vérification niveau 2 (secret.txt accessible dans Documents)
    assert len(docs_entry.children) == 1, "Le sous-dossier Documents doit contenir secret.txt"
    secret_entry = docs_entry.children[0]
    assert secret_entry.name == "secret.txt"
    assert secret_entry.is_dir() is False
    assert secret_entry.size == 42

    # 3. Vérification extraction du fichier
    content = apfs_reader.extract_file_content(secret_entry)
    assert content == b"HELLO APFS FORENSICS"
    print("[SUCCESS] Test APFSReader INode traversal validé !")


class MockAPFSImageReader:
    def __init__(self, data: bytes):
        self._data = data
        self.sector_size = 512

    @property
    def total_size_bytes(self) -> int:
        return len(self._data)

    @property
    def total_sectors(self) -> int:
        return len(self._data) // 512

    def read_bytes(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + size]


if __name__ == "__main__":
    test_aff4_apfs_pipeline()
    test_apfs_reader_inode_traversal()
