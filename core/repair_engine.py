"""
WipeRescue-Forensics - Moteur de reconstruction et restauration GPT
Méthode forensique conforme au scénario CIRCL :
 1. Génération du Protective MBR à LBA 0
 2. Inversion des rôles du Header GPT de secours -> Header primaire à LBA 1
 3. Recalcul conforme du CRC32 UEFI
 4. Copie du tableau de partitions à LBA 2..33
 5. Exportation sécurisée (image miroir, patch binaire, script dd)
"""

import os
import copy
from typing import Dict, List, Optional, Callable, Tuple
from core.image_reader import ForensicImageReader
from core.gpt_structures import ProtectiveMBR, GPTHeader, GPTPartitionEntry
from core.scanner import ScanDiagnostic


class SectorPatch:
    """Représente un secteur modifié pour le diff et l'application."""

    def __init__(self, lba: int, description: str, old_data: bytes, new_data: bytes):
        self.lba = lba
        self.description = description
        self.old_data = old_data
        self.new_data = new_data

    @property
    def is_changed(self) -> bool:
        return self.old_data != self.new_data


class RepairEngine:
    """Moteur de préparation et d'application de la restauration."""

    def __init__(self, reader: ForensicImageReader, diagnostic: ScanDiagnostic):
        self.reader = reader
        self.diag = diagnostic
        self.sector_size = reader.sector_size
        self.total_sectors = reader.total_sectors

    def prepare_restoration_plan(self) -> List[SectorPatch]:
        """
        Prépare tous les secteurs modifiés (LBA 0 à 33) et génère le plan de restauration.
        """
        if not self.diag.backup_gpt_present or not self.diag.backup_gpt_header:
            raise ValueError("Impossible de préparer la restauration : En-tête GPT de secours absent ou invalide.")

        patches: List[SectorPatch] = []
        b_header = self.diag.backup_gpt_header

        # 1. LBA 0 : Protective MBR
        old_mbr_bytes = self.reader.read_sector(0)
        new_mbr = ProtectiveMBR(disk_sectors=self.total_sectors)
        new_mbr_bytes = new_mbr.pack()
        patches.append(SectorPatch(0, "Protective MBR (LBA 0)", old_mbr_bytes, new_mbr_bytes))

        # 2. LBA 1 : Primary GPT Header (inversion de Backup GPT)
        old_primary_bytes = self.reader.read_sector(1)
        p_header = copy.deepcopy(b_header)
        p_header.current_lba = 1
        p_header.backup_lba = b_header.current_lba
        p_header.partition_entries_lba = 2
        # Recalculer le CRC32 avec le nouveau current_lba et partition_entries_lba
        new_primary_bytes = p_header.pack_recalculated()
        patches.append(SectorPatch(1, "Primary GPT Header (LBA 1)", old_primary_bytes, new_primary_bytes))

        # 3. LBA 2..33 : Partition Table Entries
        total_entries_bytes = b_header.num_partition_entries * b_header.entry_size
        sectors_count = (total_entries_bytes + self.sector_size - 1) // self.sector_size

        # Lecture du tableau d'origine depuis la position de secours
        raw_entries = self.reader.read_sector(b_header.partition_entries_lba, count=sectors_count)

        for s_idx in range(sectors_count):
            target_lba = 2 + s_idx
            old_sec = self.reader.read_sector(target_lba)
            new_sec = raw_entries[s_idx * self.sector_size : (s_idx + 1) * self.sector_size]
            patches.append(
                SectorPatch(
                    target_lba,
                    f"Partition Array Sector {s_idx + 1}/{sectors_count} (LBA {target_lba})",
                    old_sec,
                    new_sec,
                )
            )

        return patches

    def export_repaired_image(
        self,
        output_path: str,
        patches: List[SectorPatch],
        progress_cb: Optional[Callable[[float, str], None]] = None,
        chunk_size: int = 4 * 1024 * 1024,
    ) -> str:
        """
        Crée une copie miroir complète du disque avec les secteurs corrigés.
        Garantit que la preuve d'origine reste vierge de toute modification.
        """
        output_path = os.path.abspath(output_path)

        # Création d'une map des secteurs patchés par LBA
        patch_map: Dict[int, bytes] = {p.lba: p.new_data for p in patches}
        max_patched_lba = max(patch_map.keys()) if patch_map else 0

        total_bytes = self.reader.total_size_bytes
        bytes_written = 0

        with open(output_path, "wb") as out_f:
            # 1. Écriture des premiers secteurs patchés
            for lba in range(max_patched_lba + 1):
                if lba in patch_map:
                    out_f.write(patch_map[lba])
                else:
                    out_f.write(self.reader.read_sector(lba))
                bytes_written += self.sector_size

            if progress_cb:
                progress_cb(bytes_written / total_bytes, "En-têtes GPT restaurés, copie du reste des données...")

            # 2. Copie du reste des données par blocs optimisés
            current_offset = bytes_written
            while current_offset < total_bytes:
                to_read = min(chunk_size, total_bytes - current_offset)
                chunk = self.reader.read_bytes(current_offset, to_read)
                if not chunk:
                    break
                out_f.write(chunk)
                current_offset += len(chunk)
                if progress_cb:
                    progress_cb(current_offset / total_bytes, f"Copie des données ({current_offset // (1024*1024)} Mo / {total_bytes // (1024*1024)} Mo)...")

        return output_path

    def export_patch_binary(self, output_path: str, patches: List[SectorPatch]) -> str:
        """Exporte un fichier binaire contenant uniquement les 34 premiers secteurs corrigés (17 408 octets)."""
        output_path = os.path.abspath(output_path)
        with open(output_path, "wb") as f:
            for p in sorted(patches, key=lambda x: x.lba):
                f.write(p.new_data)
        return output_path

    def generate_dd_script(self, patches: List[SectorPatch], disk_dev: str = "/dev/sdb") -> str:
        """
        Génère les commandes de réplication manuelle dd (conformément aux slides CIRCL).
        """
        last_lba = self.total_sectors - 1
        sec_table_lba = self.diag.backup_gpt_header.partition_entries_lba if self.diag.backup_gpt_header else (last_lba - 32)

        script = f"""#!/bin/bash
# ==============================================================================
# WipeRescue-Forensics - Procédure de restauration manuelle (Table GPT secondaire)
# Cible : {disk_dev} (Taille : {self.total_sectors} secteurs de {self.sector_size} octets)
# ==============================================================================

set -e

echo "[*] Étape 1 : Sauvegarde de sécurité des 34 premiers secteurs actuels..."
dd if={disk_dev} of=backup_first34.bin count=34 status=progress

echo "[*] Étape 2 : Écriture du patch binaire reconstruit (LBA 0 à 33)..."
# Vous pouvez appliquer le fichier patch.bin généré :
dd if=patch_gpt.bin of={disk_dev} seek=0 conv=notrunc

echo "[*] Étape 3 : Relecture de la table des partitions par le noyau Linux..."
partx -u {disk_dev} || blockdev --rereadpt {disk_dev}

echo "[*] Étape 4 : Vérification de la géométrie restaurée..."
fdisk -l {disk_dev}

echo "[+] Restauration terminée avec succès !"
"""
        return script
