"""
Tests de non-régression pour la fluidité de l'interface graphique :
1. DiskCanvas : Zoom et Pan instantanés à 60 FPS sans I/O synchrone bloquante.
2. VirtualExplorerDialog : Lazy-loading à la demande sans récursion intégrale initiale.
"""

import sys
from pathlib import Path
import pytest
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from core.image_reader import RawImageReader, open_forensic_image
from core.gpt_structures import GPTPartitionEntry
from core.scanner import ScanDiagnostic
from ui.disk_canvas import DiskCanvas
from ui.file_explorer_dialog import VirtualExplorerDialog


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_disk_canvas_fluid_zoom_no_blocking_io(qapp, tmp_path):
    """Vérifie que le zoom avant, arrière et le pan ne bloquent pas le canvas et utilisent le debounce."""
    dummy_disk = tmp_path / "dummy.raw"
    dummy_disk.write_bytes(b"\x00" * 65536)

    reader = RawImageReader(str(dummy_disk), sector_size=512)
    p = GPTPartitionEntry()
    p.name = "TestPart"
    p.first_lba = 34
    p.last_lba = 100
    p.detected_fs = "NTFS"

    diag = ScanDiagnostic()
    diag.total_sectors = 128
    diag.sector_size = 512
    diag.primary_gpt_present = True
    diag.backup_gpt_present = True
    diag.partitions = [p]

    canvas = DiskCanvas()
    canvas.set_source(reader, diag)

    # 1. État initial
    assert canvas.zoom_factor == 1.0
    assert canvas.view_start_lba == 0
    assert canvas.view_end_lba == 127
    assert canvas._density_timer.isSingleShot()

    # 2. Zoom avant instantané (O(1))
    canvas.zoom_in(center_ratio=0.5, factor=2.0)
    assert canvas.zoom_factor == 2.0
    assert canvas.view_end_lba - canvas.view_start_lba < 127
    assert canvas._density_timer.isActive(), "Le timer de debounce doit être activé sans I/O synchrone"

    # 3. Pan instantané
    start_before = canvas.view_start_lba
    canvas.pan_lba(5)
    assert canvas.view_start_lba == start_before + 5
    assert canvas._density_timer.isActive()

    # 4. Zoom reset
    canvas.reset_zoom()
    assert canvas.zoom_factor == 1.0
    assert canvas.view_start_lba == 0
    assert canvas.view_end_lba == 127

    reader.close()


def test_virtual_explorer_lazy_loading(qapp, tmp_path):
    """Vérifie que l'explorateur n'explore pas les sous-répertoires récursivement au chargement."""
    sample_ad1 = Path("tests/sample.ad1")
    if not sample_ad1.exists():
        pytest.skip("sample.ad1 non présent")

    try:
        reader = open_forensic_image(str(sample_ad1))
    except Exception as e:
        pytest.skip(f"sample.ad1 non lisible : {e}")

    p = GPTPartitionEntry()
    p.name = "Logical AD1"
    p.first_lba = 0
    p.last_lba = reader.total_sectors - 1
    p.detected_fs = "AD1"

    diag = ScanDiagnostic()
    diag.total_sectors = reader.total_sectors
    diag.sector_size = 512
    diag.partitions = [p]

    explorer = VirtualExplorerDialog(reader, diag)
    assert explorer.tree.topLevelItemCount() >= 1

    root_item = explorer.tree.topLevelItem(0)
    assert root_item is not None
    # L'élément racine doit être marqué comme chargé (UserRole + 1 = True)
    assert root_item.data(0, Qt.UserRole + 1) is True

    # Si la racine contient des enfants, les dossiers doivent avoir un placeholder factice et UserRole + 1 == False
    for i in range(root_item.childCount()):
        ch = root_item.child(i)
        entry = ch.data(0, Qt.UserRole)
        if entry and callable(getattr(entry, "is_dir", None)) and entry.is_dir():
            assert ch.data(0, Qt.UserRole + 1) is False, "Le sous-dossier doit être non-chargé (lazy loading actif)"
            assert ch.childCount() == 1, "Le sous-dossier doit contenir l'élément placeholder factice"

    reader.close()


def test_hex_viewer_i18n_toggle(qapp, tmp_path):
    """Vérifie que le basculement FR <-> EN met à jour HexViewer et les textes de l'interface."""
    from core.i18n import set_lang, get_lang
    from ui.hex_viewer import HexViewer

    dummy_disk = tmp_path / "dummy_i18n.raw"
    dummy_disk.write_bytes(b"\x00" * 4096)
    reader = RawImageReader(str(dummy_disk), sector_size=512)

    diag = ScanDiagnostic()
    diag.total_sectors = 8
    diag.sector_size = 512

    try:
        set_lang("fr")
        viewer = HexViewer()
        viewer.set_reader_and_diag(reader, diag)

        # Vérification en Français
        assert viewer.lbl_lba.text() == "Secteur LBA :"
        assert "Précédent" in viewer.btn_prev.text()
        assert "Suivant" in viewer.btn_next.text()
        assert "Saut Rapide" in viewer.lbl_jump.text()
        assert "Protective MBR (Secteur 0)" in viewer.combo_jump.itemText(1)
        assert "SECTEUR LBA 0" in viewer.text_hex.toPlainText()
        assert "Secteur 100% à zéro" in viewer.text_hex.toPlainText()

        # Basculement en Anglais
        set_lang("en")
        viewer.retranslate_ui()

        # Vérification en Anglais
        assert viewer.lbl_lba.text() == "LBA Sector:"
        assert "Previous" in viewer.btn_prev.text()
        assert "Next" in viewer.btn_next.text()
        assert "Quick Jump" in viewer.lbl_jump.text()
        assert "Protective MBR (Sector 0)" in viewer.combo_jump.itemText(1)
        assert "LBA SECTOR 0" in viewer.text_hex.toPlainText()
        assert "Sector 100% zero-filled" in viewer.text_hex.toPlainText()

    finally:
        set_lang("fr")  # Remise par défaut
        reader.close()

