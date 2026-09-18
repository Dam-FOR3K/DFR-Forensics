"""
DFR-Forensics - Interface Graphique Principale (PySide6 / Qt6)
Bilingue Français / Anglais avec basculement dynamique en 1-clic.
Cartographie spatiale, Inspecteur Hex synchronisé, Profiler de Wipers,
Explorateur COW In-Memory, Générateur de Rapports Judiciaires et Restauration GPT.
"""

import os
from typing import Optional
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFileDialog,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QSplitter,
    QFrame,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QFont, QColor, QIcon

from core.image_reader import open_forensic_image, ForensicImageReader, is_physical_drive_path
from core.scanner import DiskScanner, ScanDiagnostic
from core.repair_engine import RepairEngine
from core.report_generator import ForensicReportGenerator
from core.i18n import t, get_lang, toggle_lang, set_lang
from ui.disk_canvas import DiskCanvas
from ui.hex_viewer import HexViewer
from ui.repair_dialog import RepairDialog
from ui.file_explorer_dialog import VirtualExplorerDialog


FORENSIC_DARK_QSS = """
QMainWindow {
    background-color: #0d0f14;
    color: #e0e6ed;
}

QFrame#HeaderCard, QFrame#TriageCard, QFrame#TableCard {
    background-color: #151822;
    border: 1px solid #282c3c;
    border-radius: 6px;
}

QLabel {
    color: #e0e6ed;
    font-family: 'Segoe UI', Arial, sans-serif;
}

QPushButton {
    background-color: #242838;
    color: #ffffff;
    border: 1px solid #363b50;
    border-radius: 4px;
    padding: 6px 14px;
    font-weight: 500;
}

QPushButton:hover {
    background-color: #33394e;
    border-color: #00d2ff;
}

QPushButton#BtnLang {
    background-color: #2c3e50;
    border: 1px solid #00d2ff;
    font-weight: bold;
}

QPushButton#BtnAction {
    background-color: #0088cc;
    border: 1px solid #00d2ff;
    font-weight: bold;
}

QPushButton#BtnRepair {
    background-color: #1e824c;
    border: 1px solid #27ae60;
    font-weight: bold;
    font-size: 13px;
    padding: 8px 16px;
    color: #ffffff;
}

QPushButton#BtnRepair:hover {
    background-color: #27ae60;
}

QPushButton#BtnExplorer {
    background-color: #6c5ce7;
    border: 1px solid #a29bfe;
    font-weight: bold;
    padding: 8px 14px;
}

QPushButton#BtnReport {
    background-color: #d35400;
    border: 1px solid #e67e22;
    font-weight: bold;
    padding: 8px 14px;
}

QPushButton#BtnPhysical {
    background-color: #1a365d;
    border: 1px solid #3182ce;
    font-weight: bold;
    color: #90cdf4;
}

QPushButton#BtnPhysical:hover {
    background-color: #2b6cb0;
    color: #ffffff;
}

QMenuBar {
    background-color: #10121a;
    color: #e0e6ed;
    border-bottom: 1px solid #282c3c;
    font-size: 13px;
    padding: 2px 4px;
}

QMenuBar::item:selected {
    background-color: #242838;
    border-radius: 4px;
}

QMenu {
    background-color: #171b26;
    color: #e0e6ed;
    border: 1px solid #363b50;
    padding: 4px;
}

QMenu::item {
    padding: 6px 20px 6px 12px;
    border-radius: 3px;
}

QMenu::item:selected {
    background-color: #0088cc;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background-color: #282c3c;
    margin: 4px 8px;
}

QTableWidget {
    background-color: #10121a;
    color: #ffffff;
    border: 1px solid #282c3c;
    gridline-color: #1e2230;
    selection-background-color: #0088cc;
}

QHeaderView::section {
    background-color: #171b26;
    color: #00d2ff;
    padding: 6px;
    border: 1px solid #222636;
    font-weight: bold;
}
"""


class MainWindow(QMainWindow):
    """Fenêtre principale de l'outil forensique DFR-Forensics."""

    def __init__(self, initial_image: Optional[str] = None):
        super().__init__()
        self.reader: Optional[ForensicImageReader] = None
        self.diagnostic: Optional[ScanDiagnostic] = None
        self.current_image_path: Optional[str] = None

        self.setup_ui()
        self.setStyleSheet(FORENSIC_DARK_QSS)
        self.retranslate_ui()

        if initial_image and (os.path.exists(initial_image) or is_physical_drive_path(initial_image)):
            self.load_image(initial_image)

    def setup_ui(self):
        self.resize(1260, 890)
        self.setAcceptDrops(True)

        # Menu Bar
        menubar = self.menuBar()
        self.menu_file = menubar.addMenu("Fichier")

        self.action_open_image = self.menu_file.addAction("Ouvrir une image disque...")
        self.action_open_image.setShortcut("Ctrl+O")
        self.action_open_image.triggered.connect(self.on_browse_file)

        self.action_open_physical = self.menu_file.addAction("Ouvrir un disque physique...")
        self.action_open_physical.setShortcut("Ctrl+Shift+D")
        self.action_open_physical.triggered.connect(self.on_open_physical_drive)

        self.menu_file.addSeparator()

        self.action_quit = self.menu_file.addAction("Quitter")
        self.action_quit.setShortcut("Ctrl+Q")
        self.action_quit.triggered.connect(self.close)

        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if not os.path.exists(icon_path):
            icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # 1. Barre d'en-tête (Sélection de fichier, Métadonnées et Bouton Langue)
        header_frame = QFrame()
        header_frame.setObjectName("HeaderCard")
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(12, 10, 12, 10)

        self.lbl_file_path = QLabel("")
        self.lbl_file_path.setStyleSheet("font-size: 13px;")
        header_layout.addWidget(self.lbl_file_path, 1)

        self.btn_browse = QPushButton("")
        self.btn_browse.clicked.connect(self.on_browse_file)
        header_layout.addWidget(self.btn_browse)

        self.btn_open_physical = QPushButton("")
        self.btn_open_physical.setObjectName("BtnPhysical")
        self.btn_open_physical.clicked.connect(self.on_open_physical_drive)
        header_layout.addWidget(self.btn_open_physical)

        self.btn_rescan = QPushButton("")
        self.btn_rescan.setEnabled(False)
        self.btn_rescan.clicked.connect(self.run_scan)
        header_layout.addWidget(self.btn_rescan)

        # Bouton Toggle Langue (Français <-> English)
        self.btn_lang = QPushButton("🌐 English")
        self.btn_lang.setObjectName("BtnLang")
        self.btn_lang.clicked.connect(self.on_toggle_language)
        header_layout.addWidget(self.btn_lang)

        main_layout.addWidget(header_frame)

        # 2. Cartes de Triage & Diagnostic de santé + Profiler
        triage_frame = QFrame()
        triage_frame.setObjectName("TriageCard")
        triage_layout = QHBoxLayout(triage_frame)
        triage_layout.setContentsMargins(12, 8, 12, 8)
        triage_layout.setSpacing(8)

        # Badge MBR
        self.lbl_badge_mbr = QLabel("MBR : --")
        self.lbl_badge_mbr.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #222; font-weight: bold;")
        triage_layout.addWidget(self.lbl_badge_mbr)

        # Badge Primary GPT
        self.lbl_badge_primary = QLabel("GPT Primaire : --")
        self.lbl_badge_primary.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #222; font-weight: bold;")
        triage_layout.addWidget(self.lbl_badge_primary)

        # Badge Backup GPT
        self.lbl_badge_backup = QLabel("GPT Secours : --")
        self.lbl_badge_backup.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #222; font-weight: bold;")
        triage_layout.addWidget(self.lbl_badge_backup)

        # Badge Frontière Wipe
        self.lbl_badge_wipe = QLabel("Wipe Détecté : --")
        self.lbl_badge_wipe.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #222; font-weight: bold; color: #ffaa00;")
        triage_layout.addWidget(self.lbl_badge_wipe)

        # Badge Profiler Attaque
        self.lbl_badge_wiper = QLabel("Attaque : --")
        self.lbl_badge_wiper.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #1c2833; font-weight: bold; color: #5dade2;")
        triage_layout.addWidget(self.lbl_badge_wiper)

        triage_layout.addStretch()

        # Bouton Explorateur COW
        self.btn_explorer = QPushButton("")
        self.btn_explorer.setObjectName("BtnExplorer")
        self.btn_explorer.setEnabled(False)
        self.btn_explorer.clicked.connect(self.open_file_explorer)
        triage_layout.addWidget(self.btn_explorer)

        # Bouton Carving Sémantique
        self.btn_carver = QPushButton("")
        self.btn_carver.setObjectName("BtnCarver")
        self.btn_carver.setEnabled(False)
        self.btn_carver.clicked.connect(lambda: self.open_carver_dialog())
        triage_layout.addWidget(self.btn_carver)

        # Bouton Rapport Forensique
        self.btn_report = QPushButton("")
        self.btn_report.setObjectName("BtnReport")
        self.btn_report.setEnabled(False)
        self.btn_report.clicked.connect(self.export_forensic_report)
        triage_layout.addWidget(self.btn_report)

        # Bouton d'action principale : Restauration
        self.btn_repair = QPushButton("")
        self.btn_repair.setObjectName("BtnRepair")
        self.btn_repair.setEnabled(False)
        self.btn_repair.clicked.connect(self.open_repair_dialog)
        triage_layout.addWidget(self.btn_repair)

        main_layout.addWidget(triage_frame)

        # 3. Cartographie spatiale du disque (Canvas interactif avec Zoom & Présence des Données)
        canvas_header_layout = QHBoxLayout()
        canvas_header_layout.setContentsMargins(0, 4, 0, 2)
        canvas_header_layout.setSpacing(6)

        self.lbl_canvas_title = QLabel("")
        self.lbl_canvas_title.setStyleSheet("color: #00d2ff; font-size: 12px; font-weight: bold;")
        canvas_header_layout.addWidget(self.lbl_canvas_title)

        self.disk_canvas = DiskCanvas()
        self.disk_canvas.sector_selected.connect(self.on_canvas_sector_clicked)
        self.disk_canvas.viewport_changed.connect(self.on_canvas_viewport_changed)

        # Contrôles de Zoom placés directement à côté du titre
        self.btn_zoom_out = QPushButton("🔍 -")
        self.btn_zoom_out.setToolTip("Zoom arrière (Molette vers le bas)")
        self.btn_zoom_out.setFixedWidth(52)
        self.btn_zoom_out.setStyleSheet("padding: 3px 8px; font-size: 11px; background: #1e293b; color: #00d2ff; font-weight: bold; border: 1px solid #0284c7; border-radius: 4px;")
        self.btn_zoom_out.clicked.connect(self.disk_canvas.zoom_out)
        canvas_header_layout.addWidget(self.btn_zoom_out)

        self.btn_zoom_in = QPushButton("🔍 +")
        self.btn_zoom_in.setToolTip("Zoom avant (Molette vers le haut)")
        self.btn_zoom_in.setFixedWidth(52)
        self.btn_zoom_in.setStyleSheet("padding: 3px 8px; font-size: 11px; background: #1e293b; color: #00d2ff; font-weight: bold; border: 1px solid #0284c7; border-radius: 4px;")
        self.btn_zoom_in.clicked.connect(self.disk_canvas.zoom_in)
        canvas_header_layout.addWidget(self.btn_zoom_in)

        self.btn_zoom_reset = QPushButton("🔄 100%")
        self.btn_zoom_reset.setToolTip("Réinitialiser la vue à 100% (Double-clic sur la barre)")
        self.btn_zoom_reset.setFixedWidth(68)
        self.btn_zoom_reset.setStyleSheet("padding: 3px 8px; font-size: 11px; background: #1e293b; color: #38bdf8; font-weight: bold; border: 1px solid #0284c7; border-radius: 4px;")
        self.btn_zoom_reset.clicked.connect(self.disk_canvas.reset_zoom)
        canvas_header_layout.addWidget(self.btn_zoom_reset)

        self.lbl_zoom_status = QLabel("")
        self.lbl_zoom_status.setStyleSheet("color: #94a3b8; font-size: 11px; margin-left: 10px;")
        canvas_header_layout.addWidget(self.lbl_zoom_status)

        canvas_header_layout.addStretch()

        main_layout.addLayout(canvas_header_layout)
        main_layout.addWidget(self.disk_canvas)

        # 4. Splitter vertical : Tableau des partitions en haut, Inspecteur Hex en bas
        splitter = QSplitter(Qt.Vertical)

        # Tableau des partitions
        table_frame = QFrame()
        table_frame.setObjectName("TableCard")
        table_layout = QVBoxLayout(table_frame)
        table_layout.setContentsMargins(8, 8, 8, 8)

        self.lbl_parts = QLabel("")
        self.lbl_parts.setStyleSheet("color: #00d2ff;")
        table_layout.addWidget(self.lbl_parts)

        self.table_partitions = QTableWidget()
        self.table_partitions.setColumnCount(8)
        self.table_partitions.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table_partitions.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_partitions.cellClicked.connect(self.on_partition_row_clicked)
        self.table_partitions.cellDoubleClicked.connect(self.on_partition_double_clicked)
        self.table_partitions.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table_partitions.customContextMenuRequested.connect(self.on_table_context_menu)
        table_layout.addWidget(self.table_partitions)
        splitter.addWidget(table_frame)

        # Inspecteur Hexadécimal
        self.hex_viewer = HexViewer()
        self.hex_viewer.lba_navigated.connect(self.disk_canvas.set_cursor_lba)
        splitter.addWidget(self.hex_viewer)

        splitter.setSizes([260, 380])
        main_layout.addWidget(splitter, 1)

    def retranslate_ui(self):
        """Met à jour instantanément tous les textes de l'interface dans la langue active."""
        self.setWindowTitle(t("app_title"))
        self.btn_browse.setText(t("btn_browse"))
        self.btn_open_physical.setText(t("btn_open_physical"))
        self.btn_rescan.setText(t("btn_rescan"))
        self.btn_lang.setText(t("btn_lang_toggle"))
        self.btn_repair.setText(t("btn_repair"))
        self.btn_explorer.setText(t("btn_explorer"))
        self.btn_carver.setText(t("btn_carver"))
        self.btn_report.setText(t("btn_report"))
        self.lbl_canvas_title.setText(t("canvas_title"))
        self.lbl_parts.setText(t("table_title"))

        self.btn_zoom_out.setToolTip(t("zoom_out_tip"))
        self.btn_zoom_in.setToolTip(t("zoom_in_tip"))
        self.btn_zoom_reset.setToolTip(t("zoom_reset_tip"))

        self.menu_file.setTitle("Fichier" if get_lang() == "fr" else "File")
        self.action_open_image.setText(t("btn_browse"))
        self.action_open_physical.setText(t("menu_open_physical"))
        self.action_quit.setText("Quitter" if get_lang() == "fr" else "Quit")

        cols = t("table_cols")
        self.table_partitions.setHorizontalHeaderLabels(cols)

        if not self.reader:
            self.lbl_file_path.setText(t("header_no_image"))
        else:
            size_gib = self.reader.total_size_bytes / (1024**3)
            if is_physical_drive_path(self.current_image_path or ""):
                self.lbl_file_path.setText(
                    t("header_physical_loaded", path=self.current_image_path, size=size_gib, bytes=self.reader.total_size_bytes, sectors=self.reader.total_sectors)
                )
            else:
                self.lbl_file_path.setText(
                    t("header_image_loaded", name=os.path.basename(self.current_image_path or ""), size=size_gib, bytes=self.reader.total_size_bytes, sectors=self.reader.total_sectors)
                )

        if self.diagnostic:
            self.update_badges()
            self._update_table_partitions()

        self.hex_viewer.retranslate_ui()
        self.disk_canvas.update()

    def on_toggle_language(self):
        toggle_lang()
        self.retranslate_ui()

    # --- Gestion Glisser-Déposer ---
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            if os.path.isfile(file_path):
                self.load_image(file_path)

    def on_browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Sélectionner une image médico-légale",
            "",
            "Toutes Images Médico-Légales (*.raw *.dd *.img *.bin *.001 *.e01 *.aff4 *.ad1);;Images AccessData FTK (*.ad1 *.ad2);;Images AFF4 (*.aff4);;Images E01 (*.e01);;Images Brutes (*.raw *.dd *.img *.bin);;Tous les fichiers (*.*)",
        )
        if path:
            self.load_image(path)

    def on_open_physical_drive(self):
        from ui.physical_drive_dialog import PhysicalDriveDialog
        dialog = PhysicalDriveDialog(self)
        if dialog.exec():
            drive_path = dialog.selected_drive_path
            if drive_path:
                self.load_image(drive_path)

    def load_image(self, path: str):
        try:
            if self.reader:
                self.reader.close()

            self.current_image_path = path
            self.reader = open_forensic_image(path)

            size_gib = self.reader.total_size_bytes / (1024**3)
            if is_physical_drive_path(path):
                self.lbl_file_path.setText(
                    t("header_physical_loaded", path=path, size=size_gib, bytes=self.reader.total_size_bytes, sectors=self.reader.total_sectors)
                )
            else:
                self.lbl_file_path.setText(
                    t("header_image_loaded", name=os.path.basename(path), size=size_gib, bytes=self.reader.total_size_bytes, sectors=self.reader.total_sectors)
                )
            self.btn_rescan.setEnabled(True)
            self.btn_repair.setEnabled(True)
            self.btn_explorer.setEnabled(True)
            self.btn_carver.setEnabled(True)
            self.btn_report.setEnabled(True)
            self.run_scan()

        except Exception as e:
            display_name = path if is_physical_drive_path(path) else os.path.basename(path)
            QMessageBox.critical(self, "Erreur d'ouverture", f"Impossible d'ouvrir ({display_name}) :\n\n{e}")

    def update_badges(self):
        if not self.diagnostic:
            return

        lang = get_lang()

        # Profiler Wiper
        if hasattr(self.diagnostic, "wiper_profile"):
            prof = self.diagnostic.wiper_profile.get(lang, "N/A")
            self.lbl_badge_wiper.setText(t("badge_wiper_profile", profile=prof))

        if getattr(self.diagnostic, "is_logical_image", False):
            self.lbl_badge_mbr.setText(t("badge_mbr_logical"))
            self.lbl_badge_mbr.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #2c3e50; color: #bdc3c7; font-weight: bold;")
            self.lbl_badge_primary.setText(t("badge_primary_logical_ad1"))
            self.lbl_badge_primary.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #16a085; color: #ffffff; font-weight: bold;")
            self.lbl_badge_backup.setText(t("badge_backup_logical"))
            self.lbl_badge_backup.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #2c3e50; color: #bdc3c7; font-weight: bold;")
            self.lbl_badge_wipe.setText(t("badge_wipe_logical"))
            self.lbl_badge_wipe.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #1e4620; color: #2ecc71; font-weight: bold;")
        elif getattr(self.diagnostic, "is_standalone_volume", False):
            fs_name = self.diagnostic.partitions[0].detected_fs if self.diagnostic.partitions else "Volume Brut"
            self.lbl_badge_mbr.setText(t("badge_mbr_standalone"))
            self.lbl_badge_mbr.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #2c3e50; color: #bdc3c7; font-weight: bold;")
            self.lbl_badge_primary.setText(f"Conteneur : {fs_name}")
            self.lbl_badge_primary.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #d35400; color: #ffffff; font-weight: bold;")
            self.lbl_badge_backup.setText("GPT Secours : N/A")
            self.lbl_badge_backup.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #2c3e50; color: #bdc3c7; font-weight: bold;")
            self.lbl_badge_wipe.setText(t("badge_wipe_none"))
            self.lbl_badge_wipe.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #1e4620; color: #2ecc71; font-weight: bold;")
        else:
            if self.diagnostic.mbr_valid:
                mbr_desc = f"MBR Valide ({len(self.diagnostic.partitions)} part.)" if self.diagnostic.partitions else t("badge_mbr_valid")
                self.lbl_badge_mbr.setText(mbr_desc)
                self.lbl_badge_mbr.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #1e4620; color: #2ecc71; font-weight: bold;")
            elif self.diagnostic.mbr_is_all_zero:
                self.lbl_badge_mbr.setText(t("badge_mbr_destroyed"))
                self.lbl_badge_mbr.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #4a1c1c; color: #e74c3c; font-weight: bold;")
            else:
                self.lbl_badge_mbr.setText(t("badge_mbr_invalid"))
                self.lbl_badge_mbr.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #553e1e; color: #f39c12; font-weight: bold;")

            if self.diagnostic.primary_gpt_valid_crc:
                self.lbl_badge_primary.setText(t("badge_primary_intact"))
                self.lbl_badge_primary.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #1e4620; color: #2ecc71; font-weight: bold;")
            elif self.diagnostic.primary_gpt_present:
                self.lbl_badge_primary.setText(t("badge_primary_bad_crc"))
                self.lbl_badge_primary.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #553e1e; color: #f39c12; font-weight: bold;")
            elif self.diagnostic.mbr_valid and self.diagnostic.partitions:
                self.lbl_badge_primary.setText(f"Partitions MBR : {len(self.diagnostic.partitions)}")
                self.lbl_badge_primary.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #2c3e50; color: #00d2ff; font-weight: bold;")
            else:
                self.lbl_badge_primary.setText(t("badge_primary_destroyed"))
                self.lbl_badge_primary.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #4a1c1c; color: #e74c3c; font-weight: bold;")

            if self.diagnostic.backup_gpt_valid_crc:
                self.lbl_badge_backup.setText(t("badge_backup_intact"))
                self.lbl_badge_backup.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #1e4620; color: #2ecc71; font-weight: bold;")
            elif self.diagnostic.mbr_valid and self.diagnostic.partitions:
                self.lbl_badge_backup.setText("GPT Secours : N/A (MBR)")
                self.lbl_badge_backup.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #2c3e50; color: #bdc3c7; font-weight: bold;")
            else:
                self.lbl_badge_backup.setText(t("badge_backup_destroyed"))
                self.lbl_badge_backup.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #4a1c1c; color: #e74c3c; font-weight: bold;")

            if self.diagnostic.wipe_frontier_lba and self.diagnostic.wipe_frontier_lba > 0:
                mb = self.diagnostic.wiped_bytes / (1024 * 1024)
                self.lbl_badge_wipe.setText(t("badge_wipe_detected", lba=self.diagnostic.wipe_frontier_lba - 1, mb=mb))
                self.lbl_badge_wipe.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #4a1c1c; color: #e74c3c; font-weight: bold;")
            else:
                self.lbl_badge_wipe.setText(t("badge_wipe_none"))
                self.lbl_badge_wipe.setStyleSheet("padding: 5px 8px; border-radius: 4px; background: #1e4620; color: #2ecc71; font-weight: bold;")

    def run_scan(self):
        if not self.reader:
            return

        scanner = DiskScanner(self.reader)
        self.diagnostic = scanner.run_full_scan()

        self.update_badges()
        self.disk_canvas.set_source(self.reader, self.diagnostic)
        self.hex_viewer.set_reader_and_diag(self.reader, self.diagnostic)

        # Remplir le tableau des partitions
        self._update_table_partitions()

        if self.diagnostic.partitions:
            p = self.diagnostic.partitions[0]
            self.hex_viewer.spin_lba.setValue(p.first_lba)
            self.hex_viewer.load_sector(p.first_lba)
            self.disk_canvas.set_cursor_lba(p.first_lba)

    def _update_table_partitions(self):
        if not self.diagnostic:
            return
        is_fr = get_lang() == "fr"
        self.table_partitions.setRowCount(0)
        for idx, p in enumerate(self.diagnostic.partitions, 1):
            row = self.table_partitions.rowCount()
            self.table_partitions.insertRow(row)

            fs_display = p.detected_fs or p.type_name
            if getattr(p, "multi_fs_warning", False) and p.coexisting_filesystems:
                coex_txt = "Coexistence" if is_fr else "Coexisting"
                fs_display = f"⚠️ {coex_txt} ({', '.join(p.coexisting_filesystems)})"
            size_mb = (p.total_sectors * self.diagnostic.sector_size) / (1024 * 1024)
            unit_gib = "Gio" if is_fr else "GiB"
            unit_mib = "Mio" if is_fr else "MiB"
            size_str = f"{size_mb / 1024:.2f} {unit_gib}" if size_mb >= 1024 else f"{size_mb:.2f} {unit_mib}"

            self.table_partitions.setItem(row, 0, QTableWidgetItem(str(idx)))
            self.table_partitions.setItem(row, 1, QTableWidgetItem(p.name or f"Partition #{idx}"))
            self.table_partitions.setItem(row, 2, QTableWidgetItem(fs_display))
            self.table_partitions.setItem(row, 3, QTableWidgetItem(f"{p.first_lba:,}"))
            self.table_partitions.setItem(row, 4, QTableWidgetItem(f"{p.last_lba:,}"))
            self.table_partitions.setItem(row, 5, QTableWidgetItem(f"{p.total_sectors:,}"))
            self.table_partitions.setItem(row, 6, QTableWidgetItem(size_str))

            status_str = t("status_intact") if not getattr(p, "is_wiped", False) else t("status_wiped")
            self.table_partitions.setItem(row, 7, QTableWidgetItem(status_str))

    def on_partition_row_clicked(self, row: int, col: int = 0):
        if self.diagnostic and 0 <= row < len(self.diagnostic.partitions):
            p = self.diagnostic.partitions[row]
            self.hex_viewer.spin_lba.setValue(p.first_lba)
            self.hex_viewer.load_sector(p.first_lba)
            self.disk_canvas.set_cursor_lba(p.first_lba)

    def on_canvas_sector_clicked(self, lba: int):
        self.hex_viewer.spin_lba.blockSignals(True)
        self.hex_viewer.spin_lba.setValue(lba)
        self.hex_viewer.spin_lba.blockSignals(False)
        self.hex_viewer.load_sector(lba)
        self.disk_canvas.set_cursor_lba(lba)

    def on_canvas_viewport_changed(self, start_lba: int, end_lba: int, zoom: float):
        """Met à jour le badge d'information sur la fenêtre visible et la résolution de zoom."""
        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            self.lbl_zoom_status.setText("")
            return
        tot = self.diagnostic.total_sectors
        pct = ((end_lba - start_lba + 1) / tot) * 100
        zoom_text = t("zoom_status_label", start=start_lba, end=end_lba, pct=pct, zoom=zoom)
        self.lbl_zoom_status.setText(zoom_text)

    def on_partition_double_clicked(self, row: int, col: int = 0):
        self.on_partition_row_clicked(row, col)
        self.open_file_explorer()

    def on_table_context_menu(self, pos):
        if not self.diagnostic or not self.diagnostic.partitions:
            return
        row = self.table_partitions.rowAt(pos.y())
        if row < 0 or row >= len(self.diagnostic.partitions):
            return
        p = self.diagnostic.partitions[row]

        from PySide6.QtWidgets import QMenu
        is_fr = get_lang() == "fr"
        menu = QMenu(self)
        explore_txt = f"📁 Explorer / Déverrouiller ({p.name or 'Partition'})..." if is_fr else f"📁 Explore / Unlock ({p.name or 'Partition'})..."
        carve_txt = f"🔬 Carving de cette partition ({p.name or 'Partition'})..." if is_fr else f"🔬 Carve this partition ({p.name or 'Partition'})..."
        export_txt = "💾 Exporter cette partition (.dd / .raw)..." if is_fr else "💾 Export this partition (.dd / .raw)..."
        act_explore = menu.addAction(explore_txt)
        act_carve = menu.addAction(carve_txt)
        act_export = menu.addAction(export_txt)

        action = menu.exec(self.table_partitions.viewport().mapToGlobal(pos))
        if action == act_explore:
            self.open_file_explorer()
        elif action == act_carve:
            self.open_carver_dialog((p.first_lba, p.last_lba))
        elif action == act_export:
            self.export_partition_row(p)

    def open_carver_dialog(self, lba_range: Optional[Tuple[int, int]] = None):
        if not self.reader or not self.diagnostic:
            return
        from ui.carver_dialog import CarverDialog
        dialog = CarverDialog(self.reader, self.diagnostic, parent=self, initial_lba_range=lba_range)
        dialog.exec()

    def export_partition_row(self, p):
        if not self.reader:
            return
        from PySide6.QtWidgets import QFileDialog, QProgressDialog, QApplication
        from core.partition_exporter import export_partition

        clean_name = "".join(c for c in (p.name or "partition") if c.isalnum() or c in "_-")
        default_name = f"partition_{clean_name}_{p.first_lba}.dd"
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Exporter la partition médico-légale",
            default_name,
            "Images brutes DD (*.dd);;Images brutes RAW (*.raw);;Tous les fichiers (*.*)",
        )
        if not save_path:
            return

        progress = QProgressDialog("Préparation de l'exportation forensique...", "Annuler", 0, 100, self)
        progress.setWindowTitle("Exportation de Partition")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.setValue(0)

        def cancel_chk():
            return progress.wasCanceled()

        def prog_cb(written, total, pct, speed_mb):
            progress.setValue(int(pct))
            progress.setLabelText(
                f"Exportation en cours : {pct:.1f}%\n"
                f"Transféré : {written / (1024*1024):.1f} / {total / (1024*1024):.1f} Mio\n"
                f"Vitesse : {speed_mb:.1f} Mio/s"
            )
            QApplication.processEvents()

        res = export_partition(
            reader=self.reader,
            partition=p,
            output_path=save_path,
            progress_callback=prog_cb,
            cancel_callback=cancel_chk,
        )

        progress.close()

        if res.get("cancelled"):
            QMessageBox.information(self, "Exportation", "L'exportation a été annulée par l'utilisateur.")
        elif res.get("success"):
            info_msg = (
                f"<b>Exportation forensique de la partition réussie avec succès !</b><br><br>"
                f"<b>Fichier image :</b> <code>{os.path.basename(res['output_path'])}</code><br>"
                f"<b>Taille :</b> {res['bytes_written'] / (1024*1024):.2f} Mio ({res['bytes_written']:,} octets)<br>"
                f"<b>Durée :</b> {res['elapsed_seconds']:.2f} s ({res['speed_mb_s']:.1f} Mio/s)<br><br>"
                f"<b>Empreintes numériques d'intégrité (Hashes) :</b><br>"
                f"• <b>MD5 :</b> <code>{res['md5']}</code><br>"
                f"• <b>SHA256 :</b> <code>{res['sha256']}</code><br><br>"
                f"Une fiche d'expertise légale <b>.info.txt</b> conforme ISO/CEI 27037 a été générée aux côtés du fichier."
            )
            box = QMessageBox(QMessageBox.Information, "Exportation Réussie", info_msg, QMessageBox.Ok, self)
            box.setTextFormat(Qt.RichText)
            box.exec()
        else:
            QMessageBox.critical(self, "Erreur d'exportation", f"L'exportation a échoué :\n\n{res.get('error')}")

    def open_file_explorer(self):
        if not self.reader or not self.diagnostic:
            return
        dlg = VirtualExplorerDialog(self.reader, self.diagnostic, self)
        dlg.exec()

    def export_forensic_report(self):
        if not self.reader or not self.diagnostic:
            return
        gen = ForensicReportGenerator(self.reader, self.diagnostic)
        lang = get_lang()
        md_content = gen.generate_markdown_report(lang=lang)

        default_name = f"Forensic_Report_{os.path.splitext(os.path.basename(self.reader.path))[0]}.md"
        out_path, _ = QFileDialog.getSaveFileName(self, "Exporter le rapport d'expertise", default_name, "Rapport Markdown (*.md);;Tous les fichiers (*.*)")
        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(md_content)
            QMessageBox.information(self, "Rapport Exporté", f"Rapport d'expertise judiciaire exporté avec succès :\n\n{out_path}")

    def open_repair_dialog(self):
        if not self.reader or not self.diagnostic:
            QMessageBox.warning(self, t("dlg_no_image_title"), t("dlg_no_image_msg"))
            return

        if getattr(self.diagnostic, "is_logical_image", False):
            QMessageBox.information(self, t("dlg_logical_ad1_title"), t("dlg_logical_ad1_msg"))
            return

        if getattr(self.diagnostic, "is_standalone_volume", False):
            QMessageBox.information(self, t("dlg_standalone_title"), t("dlg_standalone_msg"))
            return

        if self.diagnostic.can_restore_from_backup:
            engine = RepairEngine(self.reader, self.diagnostic)
            dlg = RepairDialog(engine, self)
            dlg.exec()
            return

        if self.diagnostic.primary_gpt_present and self.diagnostic.primary_gpt_valid_crc:
            reply = QMessageBox.question(self, t("dlg_already_healthy_title"), t("dlg_already_healthy_msg"), QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                engine = RepairEngine(self.reader, self.diagnostic)
                dlg = RepairDialog(engine, self)
                dlg.exec()
            return

        # Cas sévère : Proposer la reconstruction synthétique de zéro !
        reply = QMessageBox.question(self, t("dlg_severe_corruption_title"), t("dlg_severe_corruption_msg", summary=self.diagnostic.status_summary), QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            from core.synthesizer import GPTSynthesizer
            synth = GPTSynthesizer(self.reader)
            carved = synth.carve_partitions()
            if carved:
                mbr, p_hdr, entries, b_hdr = synth.synthesize_gpt(carved)
                self.diagnostic.backup_gpt_present = True
                self.diagnostic.backup_gpt_valid_crc = True
                self.diagnostic.backup_gpt_header = b_hdr
                self.diagnostic.partitions = entries
                self.diagnostic.can_restore_from_backup = True
                QMessageBox.information(self, "Partitions Retrouvées", f"{len(carved)} partitions orphelines ont été détectées et une table GPT neuve a été synthétisée !")
                engine = RepairEngine(self.reader, self.diagnostic)
                dlg = RepairDialog(engine, self)
                dlg.exec()
            else:
                QMessageBox.warning(self, "Aucun Superblock", "Aucun superblock ou début de partition n'a pu être identifié par analyse heuristique.")

    def closeEvent(self, event):
        if self.reader:
            self.reader.close()
        event.accept()
