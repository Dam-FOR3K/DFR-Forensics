"""
DFR-Forensics - Calcul d'entropie et cartographie des blocs
Mesure l'entropie de Shannon et la densité de zéros pour cartographier le disque.
"""

import math
from typing import List, Dict, Any
from core.image_reader import ForensicImageReader


def shannon_entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon (de 0.0 à 8.0) pour un bloc de données."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def zero_ratio(data: bytes) -> float:
    """Calcule la proportion d'octets nuls (0x00) dans le bloc."""
    if not data:
        return 1.0
    return data.count(b"\x00") / len(data)


class DiskMapSegment:
    """Représente une tranche du disque pour la visualisation."""

    def __init__(self, start_lba: int, end_lba: int, entropy: float, zeros: float, category: str = "unknown"):
        self.start_lba = start_lba
        self.end_lba = end_lba
        self.entropy = entropy
        self.zeros = zeros
        self.category = category  # 'wiped', 'encrypted', 'filesystem', 'sparse', 'metadata'

    @property
    def total_sectors(self) -> int:
        return (self.end_lba - self.start_lba) + 1


def profile_disk_map(
    reader: ForensicImageReader,
    num_samples: int = 500,
    sample_bytes: int = 65536,
) -> List[DiskMapSegment]:
    """
    Génère un profil échantillonné du disque pour la cartographie visuelle.
    num_samples : nombre de points de mesure répartis sur toute la surface.
    sample_bytes : nombre d'octets lus par point de mesure.
    """
    total_sectors = reader.total_sectors
    if total_sectors == 0:
        return []

    sectors_per_sample = max(1, total_sectors // num_samples)
    segments = []

    for i in range(num_samples):
        start_lba = i * sectors_per_sample
        end_lba = min(total_sectors - 1, (i + 1) * sectors_per_sample - 1)
        if start_lba >= total_sectors:
            break

        # Lecture d'un échantillon représentatif au début du bloc
        count_sectors = min(sample_bytes // reader.sector_size, (end_lba - start_lba) + 1)
        try:
            data = reader.read_sector(start_lba, count=max(1, count_sectors))
            ent = shannon_entropy(data)
            zeros = zero_ratio(data)
        except Exception:
            ent = 0.0
            zeros = 1.0

        # Classification heuristique
        if zeros > 0.98:
            cat = "wiped"
        elif ent > 7.5:
            cat = "encrypted"  # Haute entropie (LUKS, BitLocker, compressé)
        elif ent > 3.0:
            cat = "filesystem"  # Données structurées / FS standard
        else:
            cat = "sparse"

        segments.append(DiskMapSegment(start_lba, end_lba, ent, zeros, cat))

    return segments
