"""
DFR-Forensics - Tests unitaires et d'intégration complets
Vérifie le cycle de vie :
 1. Lecture de l'image disque
 2. Détection du wipe et diagnostic
 3. Réparation via le moteur de restauration
 4. Validation de l'image réparée
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.image_reader import open_forensic_image
from core.scanner import DiskScanner
from core.repair_engine import RepairEngine
from tests.generate_test_disk import create_circl_simulation_disk


def test_full_rescue_lifecycle(tmp_path):
    test_raw = str(tmp_path / "test_wiped_disk.raw")
    repaired_raw = str(tmp_path / "test_repaired_disk.raw")

    # Si l'image n'existe pas, la créer
    if not os.path.exists(test_raw):
        create_circl_simulation_disk(test_raw)

    print("=== ÉTAPE 1 : SCAN DE L'IMAGE ENDOMMAGÉE ===")
    with open_forensic_image(test_raw) as reader:
        scanner = DiskScanner(reader)
        diag = scanner.run_full_scan()

        print(f"Total secteurs : {diag.total_sectors}")
        print(f"MBR présent : {diag.mbr_present} (all zeros : {diag.mbr_is_all_zero})")
        print(f"GPT Primaire présent : {diag.primary_gpt_present}")
        print(f"GPT Secondaire présent : {diag.backup_gpt_present} (CRC valide : {diag.backup_gpt_valid_crc})")
        print(f"Frontière de wipe détectée : LBA {diag.wipe_frontier_lba}")
        print(f"Nombre de partitions récupérables : {len(diag.partitions)}")
        for idx, p in enumerate(diag.partitions, 1):
            print(f" - Partition {idx} : LBA {p.first_lba} -> {p.last_lba} | Nom: '{p.name}' | FS: {p.detected_fs}")

        # Assertions
        assert diag.mbr_is_all_zero, "Le MBR devrait être à zéro (wipé)"
        assert not diag.primary_gpt_present, "La GPT primaire devrait être absente/wipée"
        assert diag.backup_gpt_present, "La GPT de backup doit être présente"
        assert diag.backup_gpt_valid_crc, "Le CRC de la GPT de backup doit être valide"
        assert diag.wipe_frontier_lba == 15000, f"Le wipe doit s'arrêter à 15000 (trouvé {diag.wipe_frontier_lba})"
        assert len(diag.partitions) == 2, "2 partitions doivent être trouvées dans le backup"
        assert diag.partitions[1].detected_fs == "LUKS2 Encrypted Container", f"LUKS2 attendu, trouvé {diag.partitions[1].detected_fs}"
        assert diag.can_restore_from_backup, "La restauration depuis le backup doit être possible"

        print("\n=== ÉTAPE 2 : EXÉCUTION DE LA RESTAURATION ===")
        engine = RepairEngine(reader, diag)
        patches = engine.prepare_restoration_plan()
        print(f"Nombre de secteurs à patcher : {len(patches)}")

        def progress(p, msg):
            pass

        repaired_path = engine.export_repaired_image(repaired_raw, patches, progress_cb=progress)
        assert os.path.exists(repaired_path), "L'image réparée doit exister"

    print("\n=== ÉTAPE 3 : CONTRÔLE FORENSIQUE DE L'IMAGE RÉPARÉE ===")
    with open_forensic_image(repaired_raw) as rep_reader:
        rep_scanner = DiskScanner(rep_reader)
        rep_diag = rep_scanner.run_full_scan()

        print(f"MBR réparé présent et valide : {rep_diag.mbr_valid}")
        print(f"GPT Primaire réparée présente : {rep_diag.primary_gpt_present}")
        print(f"GPT Primaire CRC valide : {rep_diag.primary_gpt_valid_crc}")
        print(f"Summary : {rep_diag.status_summary}")

        assert rep_diag.mbr_valid, "Le Protective MBR réparé doit être valide"
        assert rep_diag.primary_gpt_present, "La GPT primaire doit être restaurée"
        assert rep_diag.primary_gpt_valid_crc, "Le CRC de la GPT primaire restaurée doit être valide"
        assert not rep_diag.can_restore_from_backup, "Le disque réparé doit être déclaré sain"

    print("\n[SUCCESS] TOUS LES TESTS SONT PASSÉS AVEC SUCCÈS !")


if __name__ == "__main__":
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_full_rescue_lifecycle(Path(tmp_dir))
