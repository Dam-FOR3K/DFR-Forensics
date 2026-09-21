"""
DFR-Forensics - Interface Graphique de Carving Médico-Légal (In-Memory)
Aperçu direct des artefacts découverts en mémoire vive sans aucune écriture disque,
galerie interactive, extraction chirurgicale à la demande et journal d'audit.
"""

import os
import io
import csv
import json
import hashlib
from typing import Optional, List, Dict, Any, Tuple

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QSplitter,
    QTextEdit,
    QHeaderView,
    QComboBox,
    QCheckBox,
    QLineEdit,
    QFileDialog,
    QMessageBox,
    QFrame,
    QAbstractItemView,
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor, QPixmap, QImage, QBrush, QIcon

from core.image_reader import ForensicImageReader
from core.scanner import ScanDiagnostic, GPTPartitionEntry
from core.carver import SmartCarver, CarvedArtefact
from core.i18n import t, get_lang


class CarverWorker(QThread):
    """Thread de balayage non-bloquant pour maintenir une interface 60 FPS."""
    progress_signal = Signal(int, int, float, int)   # processed_lba, total_lba, speed_mbs, total_found
    artefact_signal = Signal(object)                 # CarvedArtefact
    finished_signal = Signal(list)                   # List[CarvedArtefact]

    def __init__(self, carver: SmartCarver):
        super().__init__()
        self.carver = carver

    def run(self):
        def on_prog(processed, total, speed, count):
            self.progress_signal.emit(processed, total, speed, count)

        def on_art(art):
            self.artefact_signal.emit(art)

        results = self.carver.scan(progress_callback=on_prog, artefact_callback=on_art)
        self.finished_signal.emit(results)

    def pause(self):
        self.carver.pause()

    def resume(self):
        self.carver.resume()

    def stop(self):
        self.carver.cancel()


def load_resilient_pixmap(data: bytes, file_type: str = "") -> Tuple[Optional[QPixmap], List[str]]:
    """
    Décodeur d'image résilient et permissif :
    1. Chargement direct haute vitesse (Qt).
    2. Réparation dynamique en mémoire des en-têtes altérés (ex: DQT FF DB 00 00 -> 00 43).
    3. Auto-fermeture des flux tronqués (ajout FF D9).
    4. Décodage permissif (Pillow avec ImageFile.LOAD_TRUNCATED_IMAGES = True).
    """
    notes = []
    pix = QPixmap()
    if pix.loadFromData(data):
        return pix, notes

    repaired = bytearray(data)
    # Réparation en-tête léger (ex: haxor2.jpg)
    db_idx = repaired.find(b"\xFF\xDB\x00\x00")
    if db_idx != -1 and db_idx < 256:
        repaired[db_idx + 2 : db_idx + 4] = b"\x00\x43"
        notes.append("En-tête DQT réparé en mémoire")

    # Auto-fermeture JPEG si marqueur EOI manquant
    if (repaired.startswith(b"\xFF\xD8") or file_type == "JPEG") and not repaired.endswith(b"\xFF\xD9"):
        repaired.extend(b"\xFF\xD9")
        notes.append("Auto-fermeture FF D9")

    # Décodage permissif via Pillow
    try:
        from PIL import Image, ImageFile
        ImageFile.LOAD_TRUNCATED_IMAGES = True
        im = Image.open(io.BytesIO(repaired))
        im.load()
        if im.mode != "RGBA":
            im = im.convert("RGBA")
        qim = QImage(im.tobytes("raw", "RGBA"), im.width, im.height, QImage.Format_RGBA8888)
        res_pix = QPixmap.fromImage(qim)
        if not notes:
            notes.append("Aperçu permissif tolérant")
        return res_pix, notes
    except Exception as e:
        return None, [f"Décodage impossible ({e})"]


class CarverDialog(QDialog):
    """Dialogue principal de Carving interactif avec prévisualisation directe."""

    def __init__(self, reader: ForensicImageReader, diag: ScanDiagnostic, parent=None, initial_lba_range: Optional[Tuple[int, int]] = None):
        super().__init__(parent)
        self.reader = reader
        self.diag = diag
        self.initial_lba_range = initial_lba_range
        self.all_artefacts: List[CarvedArtefact] = []
        self.worker: Optional[CarverWorker] = None
        self.carver: Optional[SmartCarver] = None
        self.current_selected_artefact: Optional[CarvedArtefact] = None

        self.setWindowTitle(t("carver_dialog_title"))
        self.resize(1180, 740)

        self.setup_ui()
        self.init_ranges()

    def setup_ui(self):
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if not os.path.exists(icon_path):
            icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(8)

        # 1. Barre de configuration supérieure
        cfg_frame = QFrame()
        cfg_frame.setStyleSheet("background: #141926; border: 1px solid #1e293b; border-radius: 6px; padding: 6px;")
        cfg_layout = QVBoxLayout(cfg_frame)
        cfg_layout.setSpacing(6)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel(f"<b>{t('carver_range_label')}</b>"))

        self.combo_scope = QComboBox()
        self.combo_scope.setMinimumWidth(320)
        self.combo_scope.setStyleSheet("background: #222530; color: #fff; padding: 4px; border: 1px solid #444; border-radius: 3px;")
        self.combo_scope.currentIndexChanged.connect(self.on_scope_changed)
        row1.addWidget(self.combo_scope)

        row1.addSpacing(15)
        row1.addWidget(QLabel(f"<b>{t('carver_alignment_label')}</b>"))
        self.combo_align = QComboBox()
        is_fr = get_lang() == "fr"
        self.combo_align.addItem("512 octets (Secteurs standard - Recommandé)" if is_fr else "512 bytes (Standard sectors - Recommended)", 512)
        self.combo_align.addItem("1 octet (Exhaustif / Tout décalage - Fichiers décalés)" if is_fr else "1 byte (Exhaustive / Any offset - Shifted files)", 1)
        self.combo_align.addItem("4 096 octets (Clusters standard)" if is_fr else "4,096 bytes (Standard clusters)", 4096)
        self.combo_align.setStyleSheet("background: #222530; color: #fff; padding: 4px; border: 1px solid #444; border-radius: 3px;")
        row1.addWidget(self.combo_align)

        row1.addStretch()

        # Boutons d'action scan
        self.btn_start = QPushButton(t("carver_btn_start"))
        self.btn_start.setStyleSheet("background: #27ae60; color: #fff; font-weight: bold; padding: 6px 16px; border-radius: 4px;")
        self.btn_start.clicked.connect(self.toggle_scan)
        row1.addWidget(self.btn_start)

        self.btn_pause = QPushButton(t("carver_btn_pause"))
        self.btn_pause.setEnabled(False)
        self.btn_pause.setStyleSheet("background: #d97706; color: #fff; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        self.btn_pause.clicked.connect(self.toggle_pause)
        row1.addWidget(self.btn_pause)

        self.btn_stop = QPushButton(t("carver_btn_stop"))
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("background: #dc2626; color: #fff; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        self.btn_stop.clicked.connect(self.stop_scan)
        row1.addWidget(self.btn_stop)

        cfg_layout.addLayout(row1)

        # Ligne 2 : Filtres de catégories
        row2 = QHBoxLayout()
        row2.addWidget(QLabel(f"<b>{t('carver_targets_label')}</b>"))

        self.chk_images = QCheckBox(f"🖼️ {t('cat_images')}")
        self.chk_images.setChecked(True)
        self.chk_images.setStyleSheet("color: #38bdf8; font-weight: bold;")
        row2.addWidget(self.chk_images)

        self.chk_databases = QCheckBox(f"🗄️ {t('cat_databases')}")
        self.chk_databases.setChecked(True)
        self.chk_databases.setStyleSheet("color: #4ade80; font-weight: bold;")
        row2.addWidget(self.chk_databases)

        self.chk_documents = QCheckBox(f"📄 {t('cat_documents')}")
        self.chk_documents.setChecked(True)
        self.chk_documents.setStyleSheet("color: #facc15; font-weight: bold;")
        row2.addWidget(self.chk_documents)

        self.chk_logs = QCheckBox(f"📋 {t('cat_logs')}")
        self.chk_logs.setChecked(True)
        self.chk_logs.setStyleSheet("color: #fb923c; font-weight: bold;")
        row2.addWidget(self.chk_logs)

        self.chk_registry = QCheckBox(f"🛡️ {t('cat_registry')}")
        self.chk_registry.setChecked(True)
        self.chk_registry.setStyleSheet("color: #c084fc; font-weight: bold;")
        row2.addWidget(self.chk_registry)

        row2.addSpacing(25)
        is_fr = get_lang() == "fr"
        self.chk_debraid = QCheckBox("🧩 " + ("Dé-tressage avancé (flux entrelacés)" if is_fr else "Advanced De-Braiding (interleaved streams)"))
        self.chk_debraid.setChecked(False)
        self.chk_debraid.setToolTip(
            "Active l'algorithme heuristique de séparation pour les fichiers fragmentés et entrelacés (BraidResolver).\n"
            "Désactivé par défaut pour préserver l'intégrité brute des fichiers sur les systèmes standards."
            if is_fr else
            "Enables heuristic separation for interleaved fragmented files (BraidResolver).\n"
            "Disabled by default to preserve raw file integrity on standard filesystems."
        )
        self.chk_debraid.setStyleSheet("color: #e879f9; font-weight: bold;")
        row2.addWidget(self.chk_debraid)

        row2.addStretch()
        cfg_layout.addLayout(row2)

        main_layout.addWidget(cfg_frame)

        # 2. Barre de progression & métriques en temps réel
        prog_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet(
            """
            QProgressBar {
                background: #11141e;
                color: #ffffff;
                border: 1px solid #1e293b;
                border-radius: 4px;
                text-align: center;
                height: 20px;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8);
                border-radius: 3px;
            }
            """
        )
        prog_layout.addWidget(self.progress_bar, 1)

        self.lbl_stats = QLabel(t("carver_status_idle"))
        self.lbl_stats.setStyleSheet("color: #94a3b8; font-family: 'Consolas', monospace; font-size: 11px;")
        prog_layout.addWidget(self.lbl_stats)

        main_layout.addLayout(prog_layout)

        # 3. Splitter central : Tableau des artefacts (gauche) & Panneau d'aperçu direct (droite)
        splitter = QSplitter(Qt.Horizontal)

        # Côté gauche : Recherche + Tableau
        left_frame = QFrame()
        left_layout = QVBoxLayout(left_frame)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        # Filtre texte
        filter_bar = QHBoxLayout()
        self.edit_filter = QLineEdit()
        self.edit_filter.setPlaceholderText(t("carver_filter_placeholder"))
        self.edit_filter.setStyleSheet("background: #1e222d; color: #fff; padding: 5px 8px; border: 1px solid #3b4252; border-radius: 4px;")
        self.edit_filter.textChanged.connect(self.apply_filter)
        filter_bar.addWidget(self.edit_filter)

        self.btn_select_all = QPushButton(t("carver_btn_select_all"))
        self.btn_select_all.setStyleSheet("background: #1e293b; color: #38bdf8; font-size: 11px; padding: 4px 8px; border: 1px solid #0284c7; border-radius: 3px;")
        self.btn_select_all.clicked.connect(self.select_all_items)
        filter_bar.addWidget(self.btn_select_all)

        self.btn_unselect_all = QPushButton(t("carver_btn_unselect_all"))
        self.btn_unselect_all.setStyleSheet("background: #1e293b; color: #94a3b8; font-size: 11px; padding: 4px 8px; border: 1px solid #444; border-radius: 3px;")
        self.btn_unselect_all.clicked.connect(self.unselect_all_items)
        filter_bar.addWidget(self.btn_unselect_all)

        left_layout.addLayout(filter_bar)

        # Tableau des artefacts
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "☑",
            "#",
            t("col_filename"),
            t("col_cat"),
            t("col_type"),
            t("col_lba"),
            t("col_size"),
            t("col_details"),
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self.table.setStyleSheet(
            """
            QTableWidget {
                background-color: #10121a;
                color: #e0e6ed;
                border: 1px solid #282c3c;
                font-size: 12px;
                gridline-color: #1a1e2b;
            }
            QTableWidget::item:selected {
                background-color: #0088cc;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #1a1e2b;
                color: #00d2ff;
                padding: 4px;
                border: 1px solid #282c3c;
                font-weight: bold;
            }
            """
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.cellClicked.connect(lambda row, col: self.on_cell_clicked(row))
        left_layout.addWidget(self.table)

        splitter.addWidget(left_frame)

        # Côté droit : Panneau d'aperçu direct en mémoire
        right_frame = QFrame()
        right_layout = QVBoxLayout(right_frame)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)

        # Zone d'image (Aperçu direct QPixmap sans disque)
        self.lbl_image_preview = QLabel()
        self.lbl_image_preview.setAlignment(Qt.AlignCenter)
        self.lbl_image_preview.setMinimumHeight(240)
        self.lbl_image_preview.setStyleSheet("background: #090a0f; border: 1px solid #1e293b; border-radius: 4px;")
        self.lbl_image_preview.setVisible(False)
        right_layout.addWidget(self.lbl_image_preview)

        # Zone de texte / métadonnées / hexadécimal
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setFont(QFont("Consolas", 10))
        self.preview_text.setStyleSheet("background-color: #0d0f14; color: #00ffcc; border: 1px solid #282c3c; padding: 8px; line-height: 1.4;")
        self.preview_text.setPlainText(t("carver_preview_placeholder"))
        right_layout.addWidget(self.preview_text)

        splitter.addWidget(right_frame)
        splitter.setSizes([680, 500])

        main_layout.addWidget(splitter, 1)

        # 4. Barre d'export & actions inférieures
        btn_bar = QHBoxLayout()

        self.btn_export_single = QPushButton(t("carver_btn_export_single"))
        self.btn_export_single.setEnabled(False)
        self.btn_export_single.setStyleSheet("background-color: #27ae60; color: #fff; font-weight: bold; padding: 7px 16px; border-radius: 4px;")
        self.btn_export_single.clicked.connect(self.export_single_artefact)
        btn_bar.addWidget(self.btn_export_single)

        self.btn_export_selected = QPushButton(t("carver_btn_export_checked"))
        self.btn_export_selected.setStyleSheet("background-color: #0284c7; color: #fff; font-weight: bold; padding: 7px 16px; border-radius: 4px;")
        self.btn_export_selected.clicked.connect(self.export_checked_artefacts)
        btn_bar.addWidget(self.btn_export_selected)

        self.btn_export_audit = QPushButton(t("carver_btn_export_audit"))
        self.btn_export_audit.setStyleSheet("background-color: #475569; color: #fff; font-weight: bold; padding: 7px 16px; border-radius: 4px;")
        self.btn_export_audit.clicked.connect(self.export_audit_log)
        btn_bar.addWidget(self.btn_export_audit)

        btn_bar.addStretch()

        btn_close = QPushButton(t("carver_btn_close"))
        btn_close.setStyleSheet("background-color: #334155; color: #fff; padding: 7px 18px; border-radius: 4px;")
        btn_close.clicked.connect(self.close)
        btn_bar.addWidget(btn_close)

        main_layout.addLayout(btn_bar)

    def init_ranges(self):
        """Remplit le menu déroulant des zones à carver."""
        self.combo_scope.clear()
        tot = self.reader.total_sectors
        is_fr = get_lang() == "fr"
        to_word = "à" if is_fr else "to"

        entire_lbl = f"💿 Disque entier (LBA 0 {to_word} {tot - 1:,})" if is_fr else f"💿 Entire Disk (LBA 0 {to_word} {tot - 1:,})"
        self.combo_scope.addItem(entire_lbl, (0, tot - 1))

        if self.initial_lba_range:
            s, e = self.initial_lba_range
            lbl_sel = "🎯 Zone Sélectionnée / Ciblée" if is_fr else "🎯 Targeted Range"
            self.combo_scope.addItem(f"{lbl_sel} (LBA {s:,} {to_word} {e:,})", (s, e))
            self.combo_scope.setCurrentIndex(1)

        if self.diag and self.diag.partitions:
            for idx, p in enumerate(self.diag.partitions, 1):
                name = p.name or f"Partition #{idx}"
                fs = p.detected_fs or p.type_name or "Partition"
                self.combo_scope.addItem(f"📁 Part {idx} : {name} [{fs}] (LBA {p.first_lba:,} {to_word} {p.last_lba:,})", (p.first_lba, p.last_lba))

    def on_scope_changed(self, index: int):
        pass

    def get_enabled_categories(self) -> List[str]:
        cats = []
        if self.chk_images.isChecked():
            cats.append("Images")
        if self.chk_databases.isChecked():
            cats.append("Databases")
        if self.chk_documents.isChecked():
            cats.append("Documents")
        if self.chk_logs.isChecked():
            cats.append("Logs")
        if self.chk_registry.isChecked():
            cats.append("Registry")
        return cats

    def toggle_scan(self):
        if self.worker and self.worker.isRunning():
            return

        scope_data = self.combo_scope.currentData()
        start_lba, end_lba = scope_data if scope_data else (0, self.reader.total_sectors - 1)
        alignment = self.combo_align.currentData() or 512
        categories = self.get_enabled_categories()

        if not categories:
            QMessageBox.warning(self, "Attention", "Veuillez cocher au moins une catégorie d'artefacts à carver.")
            return

        self.all_artefacts.clear()
        self.table.setRowCount(0)
        self.lbl_image_preview.setVisible(False)
        self.preview_text.setPlainText("Scan de carving en cours...")

        self.carver = SmartCarver(
            reader=self.reader,
            start_lba=start_lba,
            end_lba=end_lba,
            sector_alignment=alignment,
            enabled_categories=categories,
            auto_unaligned_fallback=False,
            enable_debraid=self.chk_debraid.isChecked(),
        )

        self.worker = CarverWorker(self.carver)
        self.worker.progress_signal.connect(self.on_worker_progress)
        self.worker.artefact_signal.connect(self.on_artefact_discovered)
        self.worker.finished_signal.connect(self.on_worker_finished)

        self.btn_start.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_pause.setText(t("carver_btn_pause"))
        self.btn_stop.setEnabled(True)
        self.combo_scope.setEnabled(False)

        self.worker.start()

    def toggle_pause(self):
        if not self.worker or not self.worker.isRunning():
            return
        if self.carver._is_paused:
            self.carver.resume()
            self.btn_pause.setText(t("carver_btn_pause"))
        else:
            self.carver.pause()
            self.btn_pause.setText(t("carver_btn_resume"))

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.btn_stop.setEnabled(False)

    def on_worker_progress(self, processed: int, total: int, speed: float, count: int):
        pct = int((processed / max(1, total)) * 100)
        self.progress_bar.setValue(min(100, pct))
        self.lbl_stats.setText(f"Vitesse : {speed:.1f} Mo/s | LBA : {processed:,}/{total:,} | Artefacts trouvés : {count:,}")

    def on_artefact_discovered(self, art: CarvedArtefact):
        self.all_artefacts.append(art)
        self.add_artefact_row(art)

    def add_artefact_row(self, art: CarvedArtefact):
        row = self.table.rowCount()
        self.table.insertRow(row)

        chk_item = QTableWidgetItem()
        chk_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
        chk_item.setCheckState(Qt.Checked)
        chk_item.setData(Qt.UserRole, art)
        self.table.setItem(row, 0, chk_item)

        self.table.setItem(row, 1, QTableWidgetItem(str(art.artefact_id)))

        # Col 2: Nom de fichier (avec badge vert si corrélé)
        is_corr = "correlation_source" in art.metadata
        display_name = f"🏷️ {art.filename}" if is_corr else art.filename
        name_item = QTableWidgetItem(display_name)
        if is_corr:
            name_item.setForeground(QBrush(QColor("#4ade80")))
            name_item.setToolTip(f"Origine : {art.metadata.get('correlation_source')}\nConfiance : {art.metadata.get('correlation_confidence', '100%')}")
        self.table.setItem(row, 2, name_item)

        self.table.setItem(row, 3, QTableWidgetItem(art.category))
        self.table.setItem(row, 4, QTableWidgetItem(art.file_type))
        self.table.setItem(row, 5, QTableWidgetItem(f"{art.start_lba:,}"))
        self.table.setItem(row, 6, QTableWidgetItem(art.display_size))

        detail_str = ""
        if art.file_type in ("JPEG", "PNG", "TIFF", "BMP", "GIF"):
            detail_str = art.metadata.get("resolution", "")
        elif art.file_type == "SQLite3":
            detail_str = art.metadata.get("tables_summary", "")
        elif art.file_type in ("DOCX", "XLSX", "PPTX", "ZIP"):
            detail_str = f"{art.metadata.get('internal_files_count', 0)} fichiers internes"
        elif art.file_type == "EVTX":
            detail_str = f"{art.metadata.get('chunk_count', 0)} chunks d'événements"
        elif art.file_type == "Registry":
            detail_str = art.metadata.get("hive_name", "")
        elif art.file_type == "PDF":
            detail_str = f"PDF v{art.metadata.get('pdf_version', '1.x')}"

        if is_corr:
            detail_str = f"[{art.metadata.get('correlation_source')}] {detail_str}".strip()

        self.table.setItem(row, 7, QTableWidgetItem(detail_str))

    def on_worker_finished(self, results: List[CarvedArtefact]):
        self.progress_bar.setValue(100)
        self.btn_start.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_stop.setEnabled(False)
        self.combo_scope.setEnabled(True)

        # Mettre à jour l'affichage complet du tableau avec les corrélations finales
        self.table.setRowCount(0)
        for art in results:
            self.add_artefact_row(art)

        corr_count = sum(1 for a in results if "correlation_source" in a.metadata)
        stat_msg = f"Scan terminé avec succès ! {len(results):,} artefacts découverts."
        if corr_count > 0:
            stat_msg += f" (🏷️ {corr_count} noms réels restaurés par corrélation)"
        self.lbl_stats.setText(stat_msg)

        if results:
            self.table.selectRow(0)
            self.on_cell_clicked(0)
        else:
            msg = "Scan terminé. Aucun artefact valide découvert dans la plage sélectionnée."
            if self.carver and self.carver.sector_alignment > 1:
                msg += "\n\n💡 Astuce médico-légale : Si l'image disque brute présente un décalage d'octets (fichiers non alignés sur les frontières de secteur), relancez le scan avec l'alignement '1 octet (Exhaustif / Tout décalage - Fichiers décalés)'."
            self.preview_text.setPlainText(msg)

    def select_all_items(self):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                item.setCheckState(Qt.Checked)

    def unselect_all_items(self):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                item.setCheckState(Qt.Unchecked)

    def apply_filter(self, text: str):
        query = text.lower().strip()
        for row in range(self.table.rowCount()):
            match = False
            for col in range(1, 7):
                it = self.table.item(row, col)
                if it and query in it.text().lower():
                    match = True
                    break
            self.table.setRowHidden(row, not match if query else False)

    def on_cell_clicked(self, row: int):
        if row < 0 or row >= self.table.rowCount():
            return
        chk_item = self.table.item(row, 0)
        if not chk_item:
            return

        art: CarvedArtefact = chk_item.data(Qt.UserRole)
        if art:
            self.current_selected_artefact = art
            self.btn_export_single.setEnabled(True)
            self.render_artefact_preview(art)

    def on_selection_changed(self):
        row = self.table.currentRow()
        if row < 0:
            selected_items = self.table.selectedItems()
            if selected_items:
                row = selected_items[0].row()
        if row >= 0:
            self.on_cell_clicked(row)
        else:
            self.btn_export_single.setEnabled(False)

    def render_artefact_preview(self, art: CarvedArtefact):
        """Affiche l'aperçu direct en mémoire vive (zéro écriture disque)."""
        raw_bytes = self.carver.extract_stream(art) if self.carver else self.reader.read_bytes(art.start_offset, min(art.length_bytes, 10 * 1024 * 1024))
        if not art.md5:
            full_bytes = self.carver.extract_stream(art) if self.carver else self.reader.read_bytes(art.start_offset, art.length_bytes)
            art.md5 = hashlib.md5(full_bytes).hexdigest()
            art.sha256 = hashlib.sha256(full_bytes).hexdigest()

        # 1. Aperçu Image Direct & Permissif (JPEG, PNG, BMP, GIF, TIFF)
        repair_notes = []
        if art.category == "Images" or art.file_type in ("JPEG", "PNG", "BMP", "GIF", "TIFF"):
            self.lbl_image_preview.setVisible(True)
            pix, repair_notes = load_resilient_pixmap(raw_bytes, art.file_type)
            if pix and not pix.isNull():
                scaled_pix = pix.scaled(
                    self.lbl_image_preview.width() - 20,
                    self.lbl_image_preview.height() - 20,
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation,
                )
                self.lbl_image_preview.setPixmap(scaled_pix)
            else:
                err_msg = repair_notes[0] if repair_notes else "Erreur de décodage visuel"
                self.lbl_image_preview.setText(f"[{err_msg}]")
        else:
            self.lbl_image_preview.setVisible(False)

        # 2. Panneau de métadonnées et contenu textuel
        lines = [
            f"=== ARTEFACT MÉDICO-LÉGAL CARVÉ #{art.artefact_id} ===",
            "",
            f"Fichier (Nom)   : {art.filename}",
            f"Origine du Nom  : {art.metadata.get('correlation_source', 'Carving brut par signature')}",
            f"Indice Confiance: {art.metadata.get('correlation_confidence', 'N/A')}",
            f"Catégorie       : {art.category}",
            f"Format détecté  : {art.file_type} ({art.extension})",
            f"Emplacement LBA : LBA {art.start_lba:,} à LBA {art.end_lba:,}",
            f"Offset Physique : 0x{art.start_offset:012X} ({art.start_offset:,} octets)",
            f"Taille exacte   : {art.length_bytes:,} octets ({art.display_size})",
            f"Validation      : {'✔️ Structure 100% Intègre' if art.is_valid and not art.is_fragmented else '⚠️ Fragmenté / Reconstruit'}",
            f"Empreinte MD5   : {art.md5}",
            f"Empreinte SHA256: {art.sha256}",
        ]
        if repair_notes:
            lines.append(f"Résilience Visuel: 🟢 {' | '.join(repair_notes)}")

        lines.append("")
        lines.append("--- Métadonnées Internes ---")
        for k, v in art.metadata.items():
            if k not in ("original_filename", "correlation_source", "correlation_confidence"):
                lines.append(f"  • {k} : {v}")

        # Aperçu textuel / Hexadécimal des premiers octets
        lines.append("\n--- Hex Dump (Premiers 512 octets) ---")
        sample_hex = raw_bytes[:512]
        for i in range(0, len(sample_hex), 16):
            chunk = sample_hex[i : i + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:08X}  {hex_part:<48}  |{ascii_part}|")

        self.preview_text.setPlainText("\n".join(lines))

    def export_single_artefact(self):
        art = self.current_selected_artefact
        if not art:
            return

        default_name = art.filename or f"carved_{art.file_type.lower()}_lba_{art.start_lba}{art.extension}"
        out_path, _ = QFileDialog.getSaveFileName(self, "Exporter l'artefact", default_name)
        if not out_path:
            return

        try:
            data = self.carver.extract_stream(art) if self.carver else self.reader.read_bytes(art.start_offset, art.length_bytes)
            with open(out_path, "wb") as f_out:
                f_out.write(data)
            QMessageBox.information(self, "Export Réussi", f"Artefact extrait avec succès :\n\n{out_path}\nTaille : {len(data):,} octets\nMD5 : {art.md5}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur d'export", f"Impossible d'exporter l'artefact :\n{e}")

    def get_checked_artefacts(self) -> List[CarvedArtefact]:
        checked = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.checkState() == Qt.Checked:
                art = item.data(Qt.UserRole)
                if art:
                    checked.append(art)
        return checked

    def export_checked_artefacts(self):
        checked = self.get_checked_artefacts()
        if not checked:
            QMessageBox.warning(self, "Attention", "Aucun artefact n'est coché dans la liste.")
            return

        dest_dir = QFileDialog.getExistingDirectory(self, f"Sélectionner le dossier d'export ({len(checked)} fichiers)")
        if not dest_dir:
            return

        success_count = 0
        for art in checked:
            fname = art.filename or f"carved_{art.file_type.lower()}_lba_{art.start_lba}{art.extension}"
            out_file = os.path.join(dest_dir, fname)
            try:
                data = self.carver.extract_stream(art) if self.carver else self.reader.read_bytes(art.start_offset, art.length_bytes)
                with open(out_file, "wb") as f_out:
                    f_out.write(data)
                success_count += 1
            except Exception:
                pass

        QMessageBox.information(
            self,
            "Export en Masse Terminé",
            f"{success_count} / {len(checked)} artefacts ont été exportés avec succès dans :\n{dest_dir}",
        )

    def export_audit_log(self):
        if not self.all_artefacts:
            QMessageBox.warning(self, "Attention", "Aucun artefact à consigner dans le journal d'audit.")
            return

        out_csv, _ = QFileDialog.getSaveFileName(self, "Exporter le journal d'audit de carving", "carving_audit_report.csv", "Fichiers CSV (*.csv)")
        if not out_csv:
            return

        try:
            with open(out_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Category", "FileType", "StartLBA", "EndLBA", "StartOffsetBytes", "LengthBytes", "MD5", "SHA256", "Metadata"])
                for art in self.all_artefacts:
                    writer.writerow([
                        art.artefact_id,
                        art.category,
                        art.file_type,
                        art.start_lba,
                        art.end_lba,
                        art.start_offset,
                        art.length_bytes,
                        art.md5 or hashlib.md5(self.reader.read_bytes(art.start_offset, art.length_bytes)).hexdigest(),
                        art.sha256 or hashlib.sha256(self.reader.read_bytes(art.start_offset, art.length_bytes)).hexdigest(),
                        json.dumps(art.metadata, ensure_ascii=False),
                    ])
            QMessageBox.information(self, "Audit Exporté", f"Journal médico-légal exporté avec succès :\n{out_csv}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Échec de l'export du journal d'audit :\n{e}")

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(2000)
        event.accept()
