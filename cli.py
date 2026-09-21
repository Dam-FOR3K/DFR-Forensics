"""
DFR-Forensics - Interface Ligne de Commande (CLI avec Rich)
Permet d'effectuer le triage, l'analyse d'intégrité et la restauration sans interface graphique.
"""

import sys
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, base_dir)

vendor_dir = os.path.join(base_dir, "vendor")
if os.path.exists(vendor_dir):
    sys.path.insert(0, vendor_dir)

from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from core.image_reader import open_forensic_image, is_physical_drive_path
from core.scanner import DiskScanner
from core.repair_engine import RepairEngine

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(highlight=False)


def cmd_scan(image_path: str):
    """Analyse complète d'une image médico-légale ou d'un disque physique et affichage du diagnostic."""
    if not is_physical_drive_path(image_path) and not os.path.exists(image_path):
        console.print(f"[bold red]Erreur :[/bold red] Fichier ou disque physique introuvable : {image_path}")
        sys.exit(1)

    with open_forensic_image(image_path) as reader:
        scanner = DiskScanner(reader)
        with console.status("[bold cyan]Analyse géométrique et recherche de signatures en cours..."):
            diag = scanner.run_full_scan()

        # 1. En-tête
        console.print()
        target_name = image_path if is_physical_drive_path(image_path) else os.path.basename(image_path)
        console.print(
            Panel(
                f"[bold white]Cible :[/bold white] [yellow]{target_name}[/yellow]\n"
                f"[bold white]Taille :[/bold white] {diag.total_size_bytes / (1024**3):.2f} Gio ({diag.total_size_bytes:,} octets)\n"
                f"[bold white]Total Secteurs :[/bold white] {diag.total_sectors:,} (Secteur de {diag.sector_size} octets)",
                title="🔍 Diagnostic Forensique DFR-Forensics (Disk & File Resurrection)",
                border_style="cyan",
            )
        )

        # 2. Table de Triage
        triage_table = Table(title="Statut d'Intégrité des Métadonnées", border_style="blue")
        triage_table.add_column("Structure", style="bold")
        triage_table.add_column("LBA", justify="center")
        triage_table.add_column("État", justify="center")
        triage_table.add_column("Détails")

        # MBR
        mbr_status = "[green]✔️ VALIDE (0xEE)[/green]" if diag.mbr_valid else ("[red]❌ DÉTRUIT (100% ZÉROS)[/red]" if diag.mbr_is_all_zero else "[yellow]⚠️ INVALIDE[/yellow]")
        triage_table.add_row("Protective MBR", "0", mbr_status, "Protection pour BIOS/GPT")

        # Primary GPT
        p_status = "[green]✔️ INTACT (CRC OK)[/green]" if diag.primary_gpt_valid_crc else ("[red]❌ ÉCRASÉ / ABSENT[/red]" if not diag.primary_gpt_present else "[yellow]⚠️ CRC CORROMPU[/yellow]")
        triage_table.add_row("Primary GPT Header", "1", p_status, "Table de partition primaire")

        # Backup GPT
        b_status = "[green]✔️ INTACT (CRC OK)[/green]" if diag.backup_gpt_valid_crc else "[red]❌ INVALIDE[/red]"
        last_lba = diag.total_sectors - 1
        triage_table.add_row("Backup GPT Header", str(last_lba), b_status, "Table de secours à la fin du disque")

        # Wipe frontier
        if diag.wipe_frontier_lba and diag.wipe_frontier_lba > 0:
            mb = diag.wiped_bytes / (1024 * 1024)
            wipe_info = f"[red]Zone écrasée : LBA 0 à {diag.wipe_frontier_lba - 1:,} ({mb:.2f} Mo de zéros)[/red]"
        else:
            wipe_info = "[green]Aucun effacement initial détecté[/green]"
        triage_table.add_row("Frontière Wipe", str(diag.wipe_frontier_lba or 0), wipe_info, "Transition zéros -> données")

        console.print(triage_table)

        # 3. Tableau des Partitions Détectées
        part_table = Table(title=f"Partitions Détectées dans la Table de Secours ({len(diag.partitions)})", border_style="magenta")
        part_table.add_column("#", justify="center")
        part_table.add_column("Nom")
        part_table.add_column("Système / Signature", style="cyan")
        part_table.add_column("LBA Début", justify="right")
        part_table.add_column("LBA Fin", justify="right")
        part_table.add_column("Taille", justify="right")
        part_table.add_column("GUID Type")

        for idx, p in enumerate(diag.partitions, 1):
            size_mb = (p.total_sectors * diag.sector_size) / (1024 * 1024)
            size_str = f"{size_mb / 1024:.2f} Gio" if size_mb >= 1024 else f"{size_mb:.2f} Mio"
            part_table.add_row(
                str(idx),
                p.name or "N/A",
                p.detected_fs or p.type_name,
                f"{p.first_lba:,}",
                f"{p.last_lba:,}",
                size_str,
                p.type_guid,
            )

        console.print(part_table)

        # 4. Diagnostic de Restauration
        if diag.can_restore_from_backup:
            console.print(
                Panel(
                    "[bold green]✔️ RESTAURATION POSSIBLE (Méthode CIRCL)[/bold green]\n"
                    "La table de secours à la fin du disque est 100% saine. "
                    "Le MBR et la table primaire peuvent être reconstruits sans risque d'altération de la preuve.",
                    border_style="green",
                )
            )
        else:
            console.print(Panel(f"[yellow]{diag.status_summary}[/yellow]", border_style="yellow"))


def cmd_repair(image_path: str, output_image: Optional[str] = None, patch_path: Optional[str] = None):
    """Exécute la réparation et l'exportation d'une image ou d'un disque physique."""
    if not is_physical_drive_path(image_path) and not os.path.exists(image_path):
        console.print(f"[bold red]Erreur :[/bold red] Fichier ou disque physique introuvable : {image_path}")
        sys.exit(1)

    with open_forensic_image(image_path) as reader:
        scanner = DiskScanner(reader)
        diag = scanner.run_full_scan()

        if not diag.can_restore_from_backup:
            console.print(f"[bold red]Erreur :[/bold red] Impossible de restaurer : {diag.status_summary}")
            sys.exit(1)

        engine = RepairEngine(reader, diag)
        patches = engine.prepare_restoration_plan()

        console.print(f"[bold green][*][/bold green] {len(patches)} secteurs préparés pour la reconstruction (LBA 0 à 33).")

        if patch_path:
            p_out = engine.export_patch_binary(patch_path, patches)
            console.print(f"[bold cyan][+][/bold cyan] Patch binaire exporté : {p_out}")

        if output_image:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("[cyan]Création de l'image miroir réparée...", total=100)

                def update_cb(pct, msg):
                    progress.update(task, completed=int(pct * 100), description=f"[cyan]{msg}")

                out_path = engine.export_repaired_image(output_image, patches, progress_cb=update_cb)
                console.print(f"[bold green][+][/bold green] Image réparée créée avec succès : {out_path}")


def cmd_list_drives():
    """Énumère et affiche tous les disques physiques connectés avec leurs caractéristiques."""
    from core.physical_disk import enumerate_physical_drives, is_admin

    console.print()
    if is_admin():
        admin_txt = "[bold green]🛡️ Administrateur Actif (Accès brut direct autorisé)[/bold green]"
    else:
        admin_txt = "[bold yellow]⚠️ Utilisateur Standard (Exécutez en Administrateur pour la lecture brute sous Windows)[/bold yellow]"

    console.print(Panel(f"Statut Privilèges : {admin_txt}", title="🔌 Disques Physiques Détectés", border_style="cyan"))

    with console.status("[bold cyan]Recherche des périphériques de stockage en cours..."):
        drives = enumerate_physical_drives()

    if not drives:
        console.print("[yellow]Aucun périphérique physique détecté.[/yellow]")
        return

    table = Table(title="Liste des Disques Physiques Connectés", border_style="blue")
    table.add_column("Index", justify="center", style="bold cyan")
    table.add_column("Périphérique (ID)", style="yellow")
    table.add_column("Modèle / Fabricant", style="bold white")
    table.add_column("Capacité", justify="right", style="green")
    table.add_column("Interface", justify="center")
    table.add_column("Type Média")
    table.add_column("Secteur", justify="center")

    for d in drives:
        size_gb = d.size_bytes / (1024 ** 3)
        if size_gb >= 1000:
            size_str = f"{size_gb / 1024:.2f} To"
        else:
            size_str = f"{size_gb:.1f} Go"
        table.add_row(
            str(d.index),
            d.device_id,
            d.model,
            size_str,
            d.interface_type,
            d.media_type,
            f"{d.sector_size} o"
        )

    console.print(table)
    console.print("[dim]Pour scanner un disque physique directement :[/dim]")
    if sys.platform == "win32":
        console.print("  [bold cyan]python cli.py scan \"\\\\.\\PhysicalDrive1\"[/bold cyan]\n")
    else:
        console.print("  [bold cyan]python cli.py scan /dev/sdb[/bold cyan]\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[bold cyan]DFR-Forensics CLI - Disk & File Resurrection (v2.7.1)[/bold cyan]")
        console.print("Usage:")
        console.print("  python cli.py --list-drives                                     (Lister les disques physiques connectés)")
        console.print("  python cli.py scan <image_ou_disque>                            (Analyser une image ou \\\\.\\PhysicalDriveX)")
        console.print("  python cli.py repair <cible> --output <repaired.raw>            (Créer une copie réparée)")
        sys.exit(0)

    arg1 = sys.argv[1].lower()

    if arg1 in ("--list-drives", "-l", "list-drives", "list", "drives"):
        cmd_list_drives()
    elif arg1 == "scan" and len(sys.argv) >= 3:
        cmd_scan(sys.argv[2])
    elif arg1 == "repair" and len(sys.argv) >= 3:
        target = sys.argv[2]
        out_img = None
        out_patch = None
        if "--output" in sys.argv:
            idx = sys.argv.index("--output")
            if idx + 1 < len(sys.argv):
                out_img = sys.argv[idx + 1]
        if "--patch" in sys.argv:
            idx = sys.argv.index("--patch")
            if idx + 1 < len(sys.argv):
                out_patch = sys.argv[idx + 1]
        cmd_repair(target, output_image=out_img, patch_path=out_patch)
    else:
        console.print(f"[red]Commande inconnue : {arg1}[/red]")
        console.print("Utilisez [bold cyan]python cli.py --list-drives[/bold cyan] ou [bold cyan]python cli.py scan <path>[/bold cyan]")
