"""
WipeRescue-Forensics - Test unitaire pour image AFF4 contenant un conteneur Apple APFS
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


if __name__ == "__main__":
    test_aff4_apfs_pipeline()
