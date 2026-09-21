"""
DFR-Forensics - Moteur de Défragmentation Médico-Légale et Dé-tressage (De-Braiding)
Reconstitue les fichiers morcelés, entrelacés (braided) et élimine les secteurs de remplissage (fillers).
Conforme aux standards NIST CFTT Graphic Carving.
"""

from __future__ import annotations
import io
import struct
from typing import List, Tuple, Optional, Dict, Any
from core.image_reader import ForensicImageReader

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


def is_filler_sector(data: bytes) -> bool:
    """
    Détecte si un secteur de 512 octets correspond à une zone de remplissage parasite
    (zéros stricts, texte multilingue UTF-16/UTF-8/GB2312, motifs répétitifs).
    """
    if len(data) < 512:
        return False
    # 1. 100% zéros ou motif identique
    if data == b"\x00" * len(data) or data == data[:1] * len(data):
        return True

    # 2. En-tête texte UTF-16LE / UTF-16BE (BOM ou caractères espacés \x00)
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return True
    
    # 3. Test forte proportion de texte (fillers NIST: arabic.txt, chinese.txt, farsi.txt, etc.)
    # Si plus de 80% des octets sont des caractères textuels ASCII/Latin/UTF-8/UTF-16
    printable_count = sum(1 for b in data if (32 <= b <= 126) or b in (9, 10, 13) or b == 0)
    if printable_count > 480 and (data.count(b"\x00") > 180 or data.count(b" ") > 30):
        return True

    return False


def extract_stream_data(reader: ForensicImageReader, art: Any) -> bytes:
    """
    Extrait le flux de données d'un artefact.
    Si l'artefact possède une block_list défragmentée / dé-tressée [(start_lba, count_lba), ...],
    recolle les fragments en mémoire sans écriture disque.
    Sinon, lit de manière séquentielle standard.
    """
    block_list = getattr(art, "block_list", None)
    total_length = getattr(art, "length_bytes", 0)

    if not block_list:
        start_offset = getattr(art, "start_offset", 0)
        return reader.read_bytes(start_offset, total_length)

    buf = bytearray()
    for item in block_list:
        if isinstance(item, tuple) and len(item) == 2:
            lba_start, lba_count = item
            chunk = reader.read_bytes(lba_start * reader.sector_size, lba_count * reader.sector_size)
            buf.extend(chunk)
        elif isinstance(item, int):
            # Single LBA
            chunk = reader.read_sector(item)
            buf.extend(chunk)

    if total_length > 0 and len(buf) > total_length:
        return bytes(buf[:total_length])
    return bytes(buf)


class BraidResolver:
    """
    Moteur de dé-tressage (De-braiding) automatique pour flux entrelacés par paires.
    Détecte l'entrelacement [Part 1A, Part 1B, Part 2A, Part 2B] et reconstitue les deux images.
    """

    def __init__(self, reader: ForensicImageReader):
        self.reader = reader

    def resolve(self, artefacts: List[Any]) -> None:
        """
        Analyse les artefacts détectés, repère les paires entrelacées et résout leurs block_lists.
        Modifie les artefacts in-place.
        """
        if len(artefacts) < 2:
            return

        # Trier les artefacts par LBA de début
        arts_sorted = sorted(artefacts, key=lambda a: a.start_lba)
        n = len(arts_sorted)

        i = 0
        while i < n - 1:
            artA = arts_sorted[i]
            artB = arts_sorted[i + 1]

            # Condition de chevauchement d'en-tête (Fichier A interrompu par Fichier B)
            # artA.start_lba < artB.start_lba < artA.end_lba
            if artA.start_lba < artB.start_lba < artA.end_lba:
                # Trouver la frontière de fin du groupe tressé (le début du fichier suivant i+2 ou la fin du volume)
                lba_next = arts_sorted[i + 2].start_lba if (i + 2 < n) else (self.reader.total_sectors)
                
                # Tentative de résolution de la tresse
                resolved = self._try_debraid_pair(artA, artB, lba_next)
                if resolved:
                    i += 2
                    continue

            i += 1

    def _try_debraid_pair(self, artA: Any, artB: Any, lba_next: int) -> bool:
        """
        Tente de résoudre mathématiquement le découpage entre artA et artB.
        """
        lbaA = artA.start_lba
        lbaB = artB.start_lba
        p1A = lbaB - lbaA
        total_sectors = lba_next - lbaA

        if p1A <= 0 or total_sectors <= p1A:
            return False

        # 1. Estimation des tailles nominales
        # artA.length_bytes est souvent la taille déclarée dans l'en-tête (BMP, TIFF, etc.)
        nom_sec_A = (artA.length_bytes + 511) // 512
        nom_sec_B = (artB.length_bytes + 511) // 512 if artB.length_bytes > 0 else 0

        # Si ratio 1/3 typique NIST
        candidate_splits = []

        # Candidat A: basé sur nom_sec_A si valide
        if nom_sec_A > p1A and (nom_sec_A < total_sectors):
            p2A = nom_sec_A - p1A
            p1B_cand = (total_sectors - nom_sec_A) // 3
            candidate_splits.append((p1B_cand, p2A))

        # Candidat B: ratio 1/3 pur (p1A = 1/3 de S_A -> p2A = 2 * p1A)
        p2A_ratio = 2 * p1A
        p1B_ratio = max(1, (total_sectors - 3 * p1A) // 3)
        candidate_splits.append((p1B_ratio, p2A_ratio))

        # Variations fines spirales (priorité aux deltas les plus proches)
        test_queue = []
        deltas = sorted(
            [(d1, d2) for d1 in range(-15, 16) for d2 in range(-15, 16)],
            key=lambda x: abs(x[0]) + abs(x[1])
        )
        for base_p1B, base_p2A in candidate_splits:
            for d_p1B, d_p2A in deltas:
                p2A_val = base_p2A + d_p2A
                p1B_val = base_p1B + d_p1B
                if p2A_val <= 0 or p1B_val <= 0:
                    continue
                p2B_val = total_sectors - p1A - p1B_val - p2A_val
                if p2B_val <= 0:
                    continue
                test_queue.append((p1B_val, p2A_val, p2B_val))

        # Éliminer doublons en préservant l'ordre
        seen = set()
        unique_queue = []
        for q in test_queue:
            if q not in seen:
                seen.add(q)
                unique_queue.append(q)

        # Test des combinaisons avec validation d'image PIL
        for p1B, p2A, p2B in unique_queue:
            lba_2A = lbaB + p1B
            lba_2B = lba_2A + p2A

            if not HAS_PIL:
                # Mode sans PIL : accepter le premier ratio compatible
                self._apply_blocks(artA, artB, lbaA, p1A, lbaB, p1B, lba_2A, p2A, lba_2B, p2B)
                return True

            dataA = self.reader.read_bytes(lbaA * 512, p1A * 512) + self.reader.read_bytes(lba_2A * 512, p2A * 512)
            try:
                imgA = Image.open(io.BytesIO(dataA))
                imgA.load()
                # Vérifier Fichier B
                dataB = self.reader.read_bytes(lbaB * 512, p1B * 512) + self.reader.read_bytes(lba_2B * 512, p2B * 512)
                imgB = Image.open(io.BytesIO(dataB))
                imgB.load()

                # Les deux images se décompressent intégralement sans erreur !
                self._apply_blocks(artA, artB, lbaA, p1A, lbaB, p1B, lba_2A, p2A, lba_2B, p2B)
                
                # Mise à jour des métadonnées
                artA.metadata["width"], artA.metadata["height"] = imgA.size
                artA.metadata["resolution"] = f"{imgA.size[0]}x{imgA.size[1]}"
                artB.metadata["width"], artB.metadata["height"] = imgB.size
                artB.metadata["resolution"] = f"{imgB.size[0]}x{imgB.size[1]}"
                return True
            except Exception:
                pass

        return False

    def _apply_blocks(
        self,
        artA: Any,
        artB: Any,
        lbaA: int,
        p1A: int,
        lbaB: int,
        p1B: int,
        lba_2A: int,
        p2A: int,
        lba_2B: int,
        p2B: int,
    ) -> None:
        """Applique les listes de blocs dé-tressées aux artefacts."""
        artA.block_list = [(lbaA, p1A), (lba_2A, p2A)]
        artA.is_fragmented = True
        artA.metadata["is_braided"] = True
        artA.metadata["fragments_count"] = 2
        artA.end_lba = lba_2A + p2A - 1
        artA.length_bytes = (p1A + p2A) * 512

        artB.block_list = [(lbaB, p1B), (lba_2B, p2B)]
        artB.is_fragmented = True
        artB.metadata["is_braided"] = True
        artB.metadata["fragments_count"] = 2
        artB.end_lba = lba_2B + p2B - 1
        artB.length_bytes = (p1B + p2B) * 512
