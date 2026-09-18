"""
WipeRescue-Forensics - Moteur d'Exportation Forensique de Partition
Permet d'exporter n'importe quelle partition (brute ou déchiffrée) vers une image autonome (.dd / .raw)
avec calcul simultané des sommes de contrôle MD5 et SHA-256 et fiche d'expertise légale.
"""

import os
import time
import hashlib
from datetime import datetime, timezone
from typing import Optional, Callable, Dict, Any

from core.image_reader import ForensicImageReader
from core.gpt_structures import GPTPartitionEntry


def export_partition(
    reader: ForensicImageReader,
    partition: GPTPartitionEntry,
    output_path: str,
    decrypted_reader: Optional[ForensicImageReader] = None,
    progress_callback: Optional[Callable[[int, int, float, float], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    chunk_size: int = 2 * 1024 * 1024,  # 2 Mio
) -> Dict[str, Any]:
    """
    Exporte une partition vers un fichier image brut (.dd ou .raw).

    :param reader: Lecteur forensique source de l'image disque complète.
    :param partition: Métadonnées de la partition à exporter.
    :param output_path: Chemin du fichier de destination.
    :param decrypted_reader: Lecteur optionnel fournissant le flux déchiffré (pour volume LUKS/BitLocker).
    :param progress_callback: Callback fn(bytes_written, total_bytes, percentage, mb_per_sec).
    :param cancel_callback: Callback renvoyant True si l'utilisateur a annulé.
    :param chunk_size: Taille des blocs d'écriture en octets.
    :return: Dictionnaire contenant le résumé forensique de l'export.
    """
    # Déterminer la source et la taille
    is_decrypted = decrypted_reader is not None
    active_reader = decrypted_reader if is_decrypted else reader

    if is_decrypted:
        source_offset = 0
        total_bytes = decrypted_reader.total_size_bytes
    else:
        source_offset = partition.first_lba * reader.sector_size
        total_bytes = partition.total_sectors * reader.sector_size

    # S'assurer du répertoire parent
    parent_dir = os.path.dirname(os.path.abspath(output_path))
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    bytes_written = 0
    t_start = time.time()
    last_ui_update = 0.0

    try:
        with open(output_path, "wb") as f_out:
            while bytes_written < total_bytes:
                # Vérification annulation
                if cancel_callback and cancel_callback():
                    f_out.close()
                    try:
                        if os.path.exists(output_path):
                            os.remove(output_path)
                    except Exception:
                        pass
                    return {"success": False, "cancelled": True, "error": "Export annulé par l'utilisateur."}

                to_read = min(chunk_size, total_bytes - bytes_written)
                current_offset = source_offset + bytes_written
                chunk = active_reader.read_bytes(current_offset, to_read)

                if not chunk:
                    # Remplissage de sécurité si fin de flux imprévue
                    chunk = b"\x00" * to_read

                f_out.write(chunk)
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
                bytes_written += len(chunk)

                # Callback progression (limité à ~20 Hz pour la fluidité de l'UI)
                now = time.time()
                if now - last_ui_update >= 0.05 or bytes_written >= total_bytes:
                    elapsed = max(0.001, now - t_start)
                    speed_mb = (bytes_written / (1024 * 1024)) / elapsed
                    pct = (bytes_written / total_bytes * 100.0) if total_bytes > 0 else 100.0
                    if progress_callback:
                        progress_callback(bytes_written, total_bytes, pct, speed_mb)
                    last_ui_update = now

    except Exception as e:
        try:
            if os.path.exists(output_path):
                os.remove(output_path)
        except Exception:
            pass
        return {"success": False, "cancelled": False, "error": str(e)}

    elapsed_total = max(0.001, time.time() - t_start)
    res_md5 = md5_hash.hexdigest()
    res_sha256 = sha256_hash.hexdigest()
    avg_speed_mb = (bytes_written / (1024 * 1024)) / elapsed_total

    # Génération de la fiche d'expertise compagnon (.info.txt)
    receipt_path = f"{output_path}.info.txt"
    try:
        utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        local_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report_lines = [
            "================================================================================",
            "        WipeRescue-Forensics - Fiche d'Expertise d'Export de Partition",
            "================================================================================",
            f"Date d'export (UTC)       : {utc_now}",
            f"Date locale               : {local_now}",
            f"Fichier exporté           : {os.path.basename(output_path)}",
            f"Chemin complet            : {os.path.abspath(output_path)}",
            f"Image source              : {getattr(reader, 'path', 'N/A')}",
            "--------------------------------------------------------------------------------",
            "MÉTADONNÉES DE LA PARTITION :",
            f"  Nom de partition        : {partition.name or 'Volume'}",
            f"  Système détecté         : {partition.detected_fs or 'Non identifié'}",
            f"  Mode d'exportation      : {'Volume Déchiffré' if is_decrypted else 'Secteurs Bruts Physiques'}",
            f"  Premier secteur (LBA)   : {partition.first_lba:,}",
            f"  Dernier secteur (LBA)   : {partition.last_lba:,}",
            f"  Nombre de secteurs      : {partition.total_sectors:,}",
            f"  Taille totale           : {bytes_written:,} octets ({bytes_written / (1024 * 1024):.2f} Mio / {bytes_written / (1024**3):.3f} Gio)",
            f"  Durée du transfert      : {elapsed_total:.2f} secondes (Vitesse moyenne : {avg_speed_mb:.2f} Mio/s)",
            "--------------------------------------------------------------------------------",
            "EMPREINTES NUMÉRIQUES D'INTÉGRITÉ FORENSIQUE (HASHES) :",
            f"  MD5    : {res_md5}",
            f"  SHA256 : {res_sha256}",
            "================================================================================",
            "Conforme aux principes de reproductibilité et d'intégrité de la norme ISO/CEI 27037.",
            "================================================================================\n",
        ]
        with open(receipt_path, "w", encoding="utf-8") as f_rec:
            f_rec.write("\n".join(report_lines))
    except Exception:
        receipt_path = None

    return {
        "success": True,
        "cancelled": False,
        "output_path": output_path,
        "receipt_path": receipt_path,
        "bytes_written": bytes_written,
        "md5": res_md5,
        "sha256": res_sha256,
        "elapsed_seconds": elapsed_total,
        "speed_mb_s": avg_speed_mb,
        "is_decrypted": is_decrypted,
    }
