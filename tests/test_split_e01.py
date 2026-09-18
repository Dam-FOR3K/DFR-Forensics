"""
WipeRescue-Forensics - Test de prise en charge des images segmentées .001, .002
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.image_reader import open_forensic_image, SplitRawReader


def test_split_image():
    base_dir = os.path.dirname(__file__)
    part1_path = os.path.join(base_dir, "test_split.001")
    part2_path = os.path.join(base_dir, "test_split.002")

    # Créer deux segments de 1024 octets (2 secteurs chacun)
    data1 = b"A" * 1024
    data2 = b"B" * 1024
    with open(part1_path, "wb") as f1:
        f1.write(data1)
    with open(part2_path, "wb") as f2:
        f2.write(data2)

    try:
        reader = open_forensic_image(part1_path)
        assert isinstance(reader, SplitRawReader), f"Attendu SplitRawReader, obtenu {type(reader)}"
        assert reader.total_size_bytes == 2048
        assert reader.total_sectors == 4

        # Lecture chevauchant les deux fichiers
        combined = reader.read_bytes(512, 1024)
        assert combined == (b"A" * 512) + (b"B" * 512), "La lecture multi-fichiers doit être continue"

        # Lecture du dernier secteur
        last_sec = reader.read_sector(3)
        assert last_sec == b"B" * 512

        reader.close()
        print("[SUCCESS] Test SplitRawReader (.001, .002) validé avec succès !")
    finally:
        if os.path.exists(part1_path):
            os.remove(part1_path)
        if os.path.exists(part2_path):
            os.remove(part2_path)


if __name__ == "__main__":
    test_split_image()
