"""
CorruptDisk-Analyzer - Point d'entrée principal
Lance l'interface graphique (PySide6) par défaut,
ou bascule en mode CLI si des arguments de commande sont passés.
"""

import sys
import os

# Assure l'import des modules locaux et du dossier vendor autonome
base_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, base_dir)

vendor_dir = os.path.join(base_dir, "vendor")
if os.path.exists(vendor_dir):
    sys.path.insert(0, vendor_dir)


def main():
    # Détection si l'utilisateur appelle des sous-commandes CLI
    cli_commands = {"scan", "repair", "--cli", "-h", "--help"}
    if len(sys.argv) > 1 and any(arg in cli_commands for arg in sys.argv[1:]):
        from cli import cmd_scan, cmd_repair, console
        # Exécution CLI
        if "scan" in sys.argv:
            idx = sys.argv.index("scan")
            if idx + 1 < len(sys.argv):
                cmd_scan(sys.argv[idx + 1])
                return
        elif "repair" in sys.argv:
            idx = sys.argv.index("repair")
            if idx + 1 < len(sys.argv):
                target = sys.argv[idx + 1]
                out_img = None
                out_patch = None
                if "--output" in sys.argv:
                    o_idx = sys.argv.index("--output")
                    if o_idx + 1 < len(sys.argv):
                        out_img = sys.argv[o_idx + 1]
                if "--patch" in sys.argv:
                    p_idx = sys.argv.index("--patch")
                    if p_idx + 1 < len(sys.argv):
                        out_patch = sys.argv[p_idx + 1]
                cmd_repair(target, output_image=out_img, patch_path=out_patch)
                return
        console.print("[bold cyan]DFR-Forensics CLI - Disk & File Resurrection[/bold cyan]")
        console.print("Usage :")
        console.print("  python main.py scan <image_path>")
        console.print("  python main.py repair <image_path> --output <repaired.raw>")
        return

    # Intégration de l'ID d'application Windows pour la barre des tâches
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("damfor3k.dfrforensics.v250")
    except Exception:
        pass

    # Lancement de l'interface graphique PySide6
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QIcon
    from ui.app_gui import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("DFR-Forensics")
    app.setOrganizationName("Dam-FOR3K")

    icon_path = os.path.join(base_dir, "icon.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    initial_image = sys.argv[1] if len(sys.argv) > 1 and os.path.exists(sys.argv[1]) else None
    window = MainWindow(initial_image=initial_image)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
