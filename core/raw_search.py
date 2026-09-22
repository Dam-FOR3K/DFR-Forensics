"""
DFR-Forensics - Moteur de Recherche Brute de Mots-Clés & Regex (Multi-Threadé)
Permet de rechercher des chaînes (numéros de série, VIN, emails, clés, mots de passe)
sur le disque physique entier ou exclusivement sur l'espace non alloué.
"""

import re
import threading
from typing import List, Optional, Tuple, Callable, Any
from dataclasses import dataclass

from core.image_reader import ForensicImageReader
from core.scanner import ScanDiagnostic, GPTPartitionEntry
from core.unallocated import get_unallocated_ranges_for_disk


@dataclass
class SearchHit:
    """Représente une occurrence trouvée lors de la recherche brute."""
    hit_id: int
    lba: int
    offset_bytes: int
    matched_term: str
    preview_ascii: str
    preview_hex: str


class RawSearchWorker(threading.Thread):
    """Thread de recherche médico-légale haute performance par streaming de blocs."""

    def __init__(
        self,
        reader: ForensicImageReader,
        query: str,
        is_regex: bool = False,
        case_sensitive: bool = False,
        search_unallocated_only: bool = False,
        diag: Optional[ScanDiagnostic] = None,
        target_partition: Optional[GPTPartitionEntry] = None,
        progress_callback: Optional[Callable[[int, int, int, int], None]] = None,
        hit_callback: Optional[Callable[[SearchHit], None]] = None,
        finished_callback: Optional[Callable[[List[SearchHit]], None]] = None,
    ):
        super().__init__(daemon=True)
        self.reader = reader
        self.query = query
        self.is_regex = is_regex
        self.case_sensitive = case_sensitive
        self.search_unallocated_only = search_unallocated_only
        self.diag = diag
        self.target_partition = target_partition
        self.progress_callback = progress_callback
        self.hit_callback = hit_callback
        self.finished_callback = finished_callback

        self._is_cancelled = False
        self.hits: List[SearchHit] = []

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        # Préparation du pattern
        flags = 0 if self.case_sensitive else re.IGNORECASE
        try:
            if self.is_regex:
                pattern = re.compile(self.query.encode("utf-8", errors="ignore"), flags)
            else:
                escaped = re.escape(self.query)
                pattern = re.compile(escaped.encode("utf-8", errors="ignore"), flags)
        except Exception:
            if self.finished_callback:
                self.finished_callback([])
            return

        # Détermination des plages LBA à balayer
        if self.search_unallocated_only:
            lba_ranges = get_unallocated_ranges_for_disk(self.reader, self.diag, self.target_partition)
        elif self.target_partition:
            lba_ranges = [(self.target_partition.first_lba, self.target_partition.last_lba)]
        else:
            lba_ranges = [(0, self.reader.total_sectors - 1)]

        total_sectors_to_scan = sum(e - s + 1 for s, e in lba_ranges)
        if total_sectors_to_scan <= 0:
            if self.finished_callback:
                self.finished_callback([])
            return

        scanned_sectors = 0
        hit_counter = 0
        chunk_sectors = 8192  # 4 Mo par chunk de lecture (8192 secteurs de 512)
        overlap_bytes = 256   # 256 octets de recouvrement pour ne rater aucun mot en bordure de bloc

        for start_lba, end_lba in lba_ranges:
            if self._is_cancelled:
                break

            cur_lba = start_lba
            while cur_lba <= end_lba:
                if self._is_cancelled:
                    break

                count = min(chunk_sectors, end_lba - cur_lba + 1)
                offset = cur_lba * self.reader.sector_size
                chunk_bytes = count * self.reader.sector_size

                # Lire avec recouvrement
                read_len = min(chunk_bytes + overlap_bytes, self.reader.total_size_bytes - offset)
                if read_len <= 0:
                    break

                data = self.reader.read_bytes(offset, read_len)
                if not data:
                    break

                # Recherche dans le bloc
                for m in pattern.finditer(data):
                    if self._is_cancelled:
                        break

                    rel_pos = m.start()
                    # Si l'occurrence est dans la zone de recouvrement mais pas à la fin de la plage, elle sera traitée au bloc suivant
                    if rel_pos >= chunk_bytes and cur_lba + count <= end_lba:
                        continue

                    abs_offset = offset + rel_pos
                    hit_lba = abs_offset // self.reader.sector_size
                    hit_counter += 1

                    # Générer un aperçu ASCII et HEX autour de l'occurrence
                    ctx_start = max(0, rel_pos - 32)
                    ctx_end = min(len(data), rel_pos + len(m.group()) + 32)
                    ctx_bytes = data[ctx_start:ctx_end]

                    ascii_ctx = "".join(chr(b) if 32 <= b <= 126 else "." for b in ctx_bytes)
                    hex_ctx = " ".join(f"{b:02X}" for b in ctx_bytes[:32])

                    matched_str = m.group().decode("utf-8", errors="replace")
                    hit = SearchHit(
                        hit_id=hit_counter,
                        lba=hit_lba,
                        offset_bytes=abs_offset,
                        matched_term=matched_str,
                        preview_ascii=ascii_ctx,
                        preview_hex=hex_ctx,
                    )
                    self.hits.append(hit)

                    if self.hit_callback:
                        self.hit_callback(hit)

                scanned_sectors += count
                cur_lba += count

                if self.progress_callback:
                    pct = int((scanned_sectors / total_sectors_to_scan) * 100)
                    self.progress_callback(min(pct, 100), cur_lba, total_sectors_to_scan, hit_counter)

        if self.finished_callback:
            self.finished_callback(self.hits)
