"""
DFR-Forensics - Dialogue de Recherche Brute de Mots-Clés & Regex (Raw Keyword Search)
Permet de rechercher des chaînes (numéros de série, VIN, emails, clés, mots de passe)
sur le disque physique entier ou exclusivement sur l'espace non alloué.
"""

import os
from typing import Optional, List
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QCheckBox,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QProgressBar,
    QHeaderView,
    QFileDialog,
    QMessageBox,
    QSplitter,
    QTextEdit,
    QFrame,
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QColor, QBrush, QIcon

from core.i18n import t, get_lang
from core.image_reader import ForensicImageReader
from core.scanner import ScanDiagnostic, GPTPartitionEntry
from core.raw_search import RawSearchWorker, SearchHit


class RawSearchDialog(QDialog):
    """Fenêtre interactive de recherche médico-légale de chaînes et motifs regex."""

    def __init__(
        self,
        reader: ForensicImageReader,
        diag: Optional[ScanDiagnostic] = None,
        parent=None,
    ):
        super().__init__(parent)
        self.reader = reader
        self.diag = diag
        self.worker: Optional[RawSearchWorker] = None
        self.all_hits: List[SearchHit] = []
        self._new_hits_queue: List[SearchHit] = []

        is_fr = get_lang() == "fr"
        self.setWindowTitle("🔍 Recherche Brute de Mots-Clés & Regex (Raw Disk Search)" if is_fr else "🔍 Raw Disk Keyword & Regex Search")
        self.resize(1150, 720)

        self.setup_ui()

        # Timer pour insérer les résultats par lots sans geler l'interface graphique
        self.ui_timer = QTimer(self)
        self.ui_timer.timeout.connect(self._flush_hits_to_table)
        self.ui_timer.start(100)

    def setup_ui(self):
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # 1. Cadre supérieur de configuration
        cfg_frame = QFrame()
        cfg_frame.setStyleSheet("background: #141926; border: 1px solid #1e293b; border-radius: 6px; padding: 8px;")
        cfg_layout = QVBoxLayout(cfg_frame)
        cfg_layout.setSpacing(6)

        is_fr = get_lang() == "fr"

        # Ligne 1 : Requête + Boutons
        row1 = QHBoxLayout()
        row1.addWidget(QLabel(f"<b>{'Terme ou Motif Regex :' if is_fr else 'Search Term or Regex :'}</b>"))
        self.edit_query = QLineEdit()
        self.edit_query.setPlaceholderText("Ex: password, admin, VIN, [A-Z0-9]{17}, email..." if is_fr else "Ex: password, admin, VIN, [A-Z0-9]{17}, email...")
        self.edit_query.setStyleSheet("background: #222530; color: #00ffcc; font-family: Consolas; font-size: 13px; padding: 6px; border: 1px solid #444; border-radius: 4px;")
        self.edit_query.returnPressed.connect(self.start_search)
        row1.addWidget(self.edit_query)

        self.btn_search = QPushButton("🚀 " + ("Lancer la Recherche" if is_fr else "Start Search"))
        self.btn_search.setStyleSheet("background: #0284c7; color: #fff; font-weight: bold; padding: 6px 18px; border-radius: 4px; font-size: 13px;")
        self.btn_search.clicked.connect(self.start_search)
        row1.addWidget(self.btn_search)

        self.btn_stop = QPushButton("⏹️ " + ("Arrêter" if is_fr else "Stop"))
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("background: #dc2626; color: #fff; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        self.btn_stop.clicked.connect(self.stop_search)
        row1.addWidget(self.btn_stop)

        cfg_layout.addLayout(row1)

        # Ligne 2 : Options
        row2 = QHBoxLayout()
        row2.addWidget(QLabel(f"<b>{'Périmètre :' if is_fr else 'Scope :'}</b>"))
        self.combo_scope = QComboBox()
        self.combo_scope.addItem("Disque Entier (Physique)" if is_fr else "Entire Physical Disk", None)
        partitions = self.diag.partitions if (self.diag and hasattr(self.diag, "partitions")) else []
        for idx, p in enumerate(partitions, 1):
            p_name = p.name or f"Partition {idx}"
            self.combo_scope.addItem(f"Partition {idx} : {p_name} (LBA {p.first_lba:,})", p)
        self.combo_scope.setStyleSheet("background: #222530; color: #fff; padding: 4px; border: 1px solid #444; border-radius: 3px;")
        row2.addWidget(self.combo_scope)

        row2.addSpacing(15)
        self.chk_regex = QCheckBox("🔤 " + ("Expression Régulière (Regex)" if is_fr else "Regular Expression (Regex)"))
        self.chk_regex.setStyleSheet("color: #e0e6ed;")
        row2.addWidget(self.chk_regex)

        self.chk_case = QCheckBox("Aa " + ("Sensible à la casse" if is_fr else "Case Sensitive"))
        self.chk_case.setStyleSheet("color: #e0e6ed;")
        row2.addWidget(self.chk_case)

        self.chk_unallocated = QCheckBox("🗑️ " + ("Espace non alloué uniquement (fichiers effacés)" if is_fr else "Unallocated space only (deleted files)"))
        self.chk_unallocated.setChecked(False)
        self.chk_unallocated.setStyleSheet("color: #34d399; font-weight: bold;")
        row2.addWidget(self.chk_unallocated)

        row2.addStretch()
        cfg_layout.addLayout(row2)

        layout.addWidget(cfg_frame)

        # 2. Progression
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet(
            """
            QProgressBar {
                border: 1px solid #282c3c;
                border-radius: 4px;
                text-align: center;
                color: #ffffff;
                background-color: #10121a;
                font-weight: bold;
                height: 18px;
            }
            QProgressBar::chunk {
                background-color: #00d2ff;
                border-radius: 3px;
            }
            """
        )
        layout.addWidget(self.progress_bar)

        self.lbl_status = QLabel("Prêt pour la recherche brute." if is_fr else "Ready for raw keyword search.")
        self.lbl_status.setStyleSheet("color: #94a3b8; font-size: 11px;")
        layout.addWidget(self.lbl_status)

        # 3. Tableau des résultats
        splitter = QSplitter(Qt.Vertical)

        self.table_hits = QTableWidget()
        self.table_hits.setColumnCount(5)
        self.table_hits.setHorizontalHeaderLabels([
            "#" if is_fr else "#",
            "Secteur LBA" if is_fr else "LBA Sector",
            "Offset Physique (Hex)" if is_fr else "Physical Offset (Hex)",
            "Terme Trouvé" if is_fr else "Matched String",
            "Contexte ASCII" if is_fr else "ASCII Context",
        ])
        self.table_hits.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_hits.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_hits.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_hits.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_hits.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table_hits.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_hits.setSelectionMode(QTableWidget.SingleSelection)
        self.table_hits.setStyleSheet(
            """
            QTableWidget {
                background-color: #10121a;
                color: #e0e6ed;
                gridline-color: #1e293b;
                border: 1px solid #282c3c;
                font-family: Consolas;
                font-size: 12px;
            }
            QTableWidget::item:selected {
                background-color: #0284c7;
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
        self.table_hits.itemDoubleClicked.connect(self.on_row_double_clicked)
        splitter.addWidget(self.table_hits)

        # Panneau d'aperçu hexadécimal étendu
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setFont(QFont("Consolas", 10))
        self.preview_text.setMaximumHeight(140)
        self.preview_text.setStyleSheet("background-color: #0d0f14; color: #00ffcc; border: 1px solid #282c3c; padding: 6px;")
        splitter.addWidget(self.preview_text)

        layout.addWidget(splitter)

        # 4. Boutons d'action inférieurs
        bottom_layout = QHBoxLayout()

        btn_export = QPushButton("💾 " + ("Exporter les résultats (CSV)..." if is_fr else "Export Results (CSV)..."))
        btn_export.setStyleSheet("background: #334155; color: #fff; padding: 6px 14px; border-radius: 4px;")
        btn_export.clicked.connect(self.export_results)
        bottom_layout.addWidget(btn_export)

        bottom_layout.addStretch()

        btn_close = QPushButton("Fermer" if is_fr else "Close")
        btn_close.setStyleSheet("background: #444b5d; color: #fff; padding: 6px 18px; border-radius: 4px;")
        btn_close.clicked.connect(self.reject)
        bottom_layout.addWidget(btn_close)

        layout.addLayout(bottom_layout)

    def start_search(self):
        query = self.edit_query.text().strip()
        if not query:
            return

        self.all_hits.clear()
        self._new_hits_queue.clear()
        self.table_hits.setRowCount(0)
        self.preview_text.clear()

        self.btn_search.setEnabled(False)
        self.btn_stop.setEnabled(True)

        target_part = self.combo_scope.currentData()

        self.worker = RawSearchWorker(
            reader=self.reader,
            query=query,
            is_regex=self.chk_regex.isChecked(),
            case_sensitive=self.chk_case.isChecked(),
            search_unallocated_only=self.chk_unallocated.isChecked(),
            diag=self.diag,
            target_partition=target_part,
            progress_callback=self.on_search_progress,
            hit_callback=self.on_search_hit,
            finished_callback=self.on_search_finished,
        )
        self.worker.start()

    def stop_search(self):
        if self.worker:
            self.worker.cancel()
        self.btn_search.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def on_search_progress(self, pct: int, cur_lba: int, total_lba: int, hits_count: int):
        self.progress_bar.setValue(pct)
        is_fr = get_lang() == "fr"
        self.lbl_status.setText(
            f"{'Scan en cours...' if is_fr else 'Scanning...'} LBA {cur_lba:,} / {total_lba:,} — {hits_count} {'occurrences trouvées' if is_fr else 'hits found'}"
        )

    def on_search_hit(self, hit: SearchHit):
        self._new_hits_queue.append(hit)

    def _flush_hits_to_table(self):
        if not self._new_hits_queue:
            return

        batch = self._new_hits_queue[:]
        self._new_hits_queue.clear()

        start_row = self.table_hits.rowCount()
        self.table_hits.setRowCount(start_row + len(batch))

        for idx, hit in enumerate(batch, start=start_row):
            self.all_hits.append(hit)
            item_id = QTableWidgetItem(str(hit.hit_id))
            item_lba = QTableWidgetItem(f"{hit.lba:,}")
            item_off = QTableWidgetItem(f"0x{hit.offset_bytes:010X}")
            item_match = QTableWidgetItem(hit.matched_term)
            item_match.setForeground(QBrush(QColor("#00ffcc")))
            item_ctx = QTableWidgetItem(hit.preview_ascii)

            self.table_hits.setItem(idx, 0, item_id)
            self.table_hits.setItem(idx, 1, item_lba)
            self.table_hits.setItem(idx, 2, item_off)
            self.table_hits.setItem(idx, 3, item_match)
            self.table_hits.setItem(idx, 4, item_ctx)

    def on_search_finished(self, hits: List[SearchHit]):
        self._flush_hits_to_table()
        self.btn_search.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress_bar.setValue(100)
        is_fr = get_lang() == "fr"
        self.lbl_status.setText(f"{'Recherche terminée.' if is_fr else 'Search completed.'} {len(self.all_hits)} {'résultats.' if is_fr else 'hits.'}")

    def on_row_double_clicked(self, item: QTableWidgetItem):
        row = item.row()
        if 0 <= row < len(self.all_hits):
            hit = self.all_hits[row]
            # Aperçu dans le visualiseur hexadécimal
            hex_dialog = HexViewerDialog(self.reader, initial_lba=hit.lba, parent=self)
            hex_dialog.exec()

    def export_results(self):
        if not self.all_hits:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter les résultats", "search_results.csv", "Fichiers CSV (*.csv)")
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "LBA", "Offset_Hex", "Matched_Term", "Context_ASCII"])
                for h in self.all_hits:
                    writer.writerow([h.hit_id, h.lba, f"0x{h.offset_bytes:010X}", h.matched_term, h.preview_ascii])
            is_fr = get_lang() == "fr"
            QMessageBox.information(self, "Exportation réussie", f"Les {len(self.all_hits)} résultats ont été exportés avec succès dans {path}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur d'exportation", str(e))
