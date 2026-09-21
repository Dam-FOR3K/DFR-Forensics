import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PIL import Image
from core.image_reader import ForensicImageReader
from core.unallocated import merge_lba_ranges, get_unallocated_ranges_for_disk
from core.carver import SmartCarver


class MockReader(ForensicImageReader):
    def __init__(self, data: bytes, sector_size: int = 512):
        self._data = data
        self._sector_size = sector_size

    @property
    def total_size_bytes(self) -> int:
        return len(self._data)

    @property
    def sector_size(self) -> int:
        return self._sector_size

    @property
    def total_sectors(self) -> int:
        return len(self._data) // self._sector_size

    def read_bytes(self, offset: int, size: int) -> bytes:
        if offset < 0 or offset >= len(self._data):
            return b""
        return self._data[offset : offset + size]

    def read_sector(self, sector_lba: int, count: int = 1) -> bytes:
        return self.read_bytes(sector_lba * self._sector_size, count * self._sector_size)

    def close(self):
        pass


def test_merge_lba_ranges():
    """Vérifie la fusion des plages LBA adjacentes ou chevauchantes."""
    ranges = [(10, 20), (21, 30), (50, 60), (55, 70), (100, 110)]
    merged = merge_lba_ranges(ranges)
    assert merged == [(10, 30), (50, 70), (100, 110)]

    empty = merge_lba_ranges([])
    assert empty == []

    invalid = merge_lba_ranges([(50, 10)])
    assert invalid == []


def test_smart_carver_with_lba_ranges():
    """Vérifie que SmartCarver respecte strictement les plages LBA non allouées fournies."""
    # Créer deux images BMP distinctes
    imgA = Image.new("RGB", (32, 32), color="red")
    outA = io.BytesIO()
    imgA.save(outA, format="BMP")
    dataA = outA.getvalue()

    imgB = Image.new("RGB", (32, 32), color="blue")
    outB = io.BytesIO()
    imgB.save(outB, format="BMP")
    dataB = outB.getvalue()

    # Disque simulé de 100 secteurs (51 200 octets)
    disk = bytearray(100 * 512)

    # Placer Image A au secteur 10 (Zone active / occupée)
    disk[10 * 512 : 10 * 512 + len(dataA)] = dataA

    # Placer Image B au secteur 50 (Zone effacée / non allouée)
    disk[50 * 512 : 50 * 512 + len(dataB)] = dataB

    reader = MockReader(bytes(disk))

    # Cas 1 : Carving global sans lba_ranges -> doit trouver les deux images (secteurs 10 et 50)
    carver_all = SmartCarver(reader, start_lba=0, end_lba=99)
    arts_all = carver_all.scan()
    assert len(arts_all) == 2
    lbas = [a.start_lba for a in arts_all]
    assert 10 in lbas
    assert 50 in lbas

    # Cas 2 : Carving ciblé sur l'espace non alloué uniquement : plages [(40, 60), (80, 90)]
    # L'image A (secteur 10) est dans la zone active et DOIT être ignorée !
    # Seule l'image B (secteur 50) doit être sculptée !
    unallocated_ranges = [(40, 60), (80, 90)]
    carver_unalloc = SmartCarver(reader, lba_ranges=unallocated_ranges)
    arts_unalloc = carver_unalloc.scan()
    assert len(arts_unalloc) == 1
    assert arts_unalloc[0].start_lba == 50
    assert arts_unalloc[0].file_type == "BMP"


def test_get_unallocated_ranges_for_disk_no_diag():
    """Vérifie le repli sur l'ensemble du disque si aucun diagnostic n'est disponible."""
    reader = MockReader(b"\x00" * (1000 * 512))
    ranges = get_unallocated_ranges_for_disk(reader, diag=None)
    assert ranges == [(0, 999)]
