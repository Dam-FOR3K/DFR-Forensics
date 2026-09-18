"""
WipeRescue-Forensics - Dialogue de restauration et prévisualisation Diff
Permet de visualiser les modifications avant écriture et d'exporter en toute sécurité.
"""

import os
from typing import List
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QTextEdit,
    QPushButton,
    QFileDialog,
    QMessageBox,
    QProgressBar,
    QSplitter,
    QApplication,
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QIcon
from core.repair_engine import RepairEngine, SectorPatch
from core.image_reader import ForensicImageReader
from core.scanner import ScanDiagnostic


class ExportThread(QThread):
    progress = Signal(float, str)
    finished_export = Signal(str)
    error = Signal(str)

    def __init__(self, engine: RepairEngine, out_path: str, patches: List[SectorPatch]):
        super().__init__()
        self.engine = engine
        self.out_path = out_path
        self.patches = patches

    def run(self):
        try:
            res = self.engine.export_repaired_image(
                self.out_path,
                self.patches,
                progress_cb=lambda p, msg: self.progress.emit(p, msg),
            )
            self.finished_export.emit(res)
        except Exception as e:
            self.error.emit(str(e))


class RepairDialog(QDialog):
    """Fenêtre modale de prévisualisation Diff et de restauration."""

    def __init__(self, engine: RepairEngine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.setWindowTitle("WipeRescue-Forensics - Assistant de Restauration")
        self.resize(950, 650)
        self.patches: List[SectorPatch] = self.engine.prepare_restoration_plan()

        self.setup_ui()
        self.populate_patches()

    def setup_ui(self):
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if not os.path.exists(icon_path):
            icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # En-tête informatif
        header = QLabel(
            "<b>Plan de Restauration Forensic</b> : "
            "Les secteurs suivants seront reconstruits à partir de la table de secours GPT et des spécifications UEFI."
        )
        header.setStyleSheet("color: #00d2ff; font-size: 13px;")
        layout.addWidget(header)

        # Zone centrale en splitter (Liste des secteurs à gauche, Diff à droite)
        splitter = QSplitter(Qt.Horizontal)

        # Liste des secteurs modifiés
        self.patch_list = QListWidget()
        self.patch_list.setFixedWidth(280)
        self.patch_list.setStyleSheet(
            """
            QListWidget {
                background-color: #1e2029;
                color: #ecf0f1;
                border: 1px solid #34495e;
                font-family: 'Segoe UI', sans-serif;
            }
            QListWidget::item:selected {
                background-color: #0088cc;
            }
            """
        )
        self.patch_list.currentRowChanged.connect(self.display_diff)
        splitter.addWidget(self.patch_list)

        # Comparatif Diff
        self.diff_view = QTextEdit()
        self.diff_view.setReadOnly(True)
        self.diff_view.setFont(QFont("Consolas", 9))
        self.diff_view.setStyleSheet(
            """
            QTextEdit {
                background-color: #12131a;
                color: #ecf0f1;
                border: 1px solid #34495e;
            }
            """
        )
        splitter.addWidget(self.diff_view)

        layout.addWidget(splitter, 1)

        # Barre de progression (pour l'export)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(
            """
            QProgressBar {
                border: 1px solid #444;
                border-radius: 3px;
                text-align: center;
                background: #111;
                color: #fff;
            }
            QProgressBar::chunk {
                background-color: #00d2ff;
            }
            """
        )
        layout.addWidget(self.progress_bar)

        self.lbl_progress_status = QLabel("")
        self.lbl_progress_status.setVisible(False)
        layout.addWidget(self.lbl_progress_status)

        # Boutons d'action
        btn_layout = QHBoxLayout()

        self.btn_export_image = QPushButton("💾 Exporter Nouvelle Image Réparée (.raw)")
        self.btn_export_image.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold; padding: 8px 14px;")
        self.btn_export_image.clicked.connect(self.on_export_image)
        btn_layout.addWidget(self.btn_export_image)

        self.btn_export_patch = QPushButton("📦 Exporter Patch Binaire (.bin)")
        self.btn_export_patch.setStyleSheet("background-color: #2980b9; color: white; padding: 8px 14px;")
        self.btn_export_patch.clicked.connect(self.on_export_patch)
        btn_layout.addWidget(self.btn_export_patch)

        self.btn_copy_dd = QPushButton("📋 Générer Script Shell 'dd'")
        self.btn_copy_dd.setStyleSheet("background-color: #8e44ad; color: white; padding: 8px 14px;")
        self.btn_copy_dd.clicked.connect(self.on_generate_dd_script)
        btn_layout.addWidget(self.btn_copy_dd)

        btn_close = QPushButton("Fermer")
        btn_close.setStyleSheet("background-color: #7f8c8d; color: white; padding: 8px 14px;")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)

    def populate_patches(self):
        for p in self.patches:
            self.patch_list.addItem(f"LBA {p.lba:02d} : {p.description}")
        if self.patches:
            self.patch_list.setCurrentRow(0)

    def display_diff(self, row: int):
        if row < 0 or row >= len(self.patches):
            return
        p = self.patches[row]

        lines = []
        lines.append(f"=== COMPARAISON AVANT / APRÈS : {p.description} ===")
        lines.append(f"Statut : {'MODIFIÉ' if p.is_changed else 'IDENTIQUE'}\n")

        # Format hex side-by-side
        lines.append(f"{'OFFSET':<8}  {'--- ÉTAT ACTUEL (ENDOMMAGÉ) ---':<40}    {'+++ NOUVEL ÉTAT (RECONSTRUIT) +++'}")
        lines.append("-" * 90)

        for off in range(0, 512, 16):
            chunk_old = p.old_data[off : off + 16]
            chunk_new = p.new_data[off : off + 16]

            hex_old = " ".join(f"{b:02x}" for b in chunk_old)
            hex_new = " ".join(f"{b:02x}" for b in chunk_new)

            indicator = " " if chunk_old == chunk_new else "*"
            lines.append(f"{off:04x} {indicator}   {hex_old:<40}  |  {hex_new}")

        self.diff_view.setPlainText("\n".join(lines))

    def on_export_image(self):
        default_name = os.path.splitext(self.engine.reader.path)[0] + ".repaired.raw"
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Enregistrer l'image disque réparée",
            default_name,
            "Images brutes (*.raw *.img *.dd);;Tous les fichiers (*.*)",
        )
        if not out_path:
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.lbl_progress_status.setVisible(True)
        self.btn_export_image.setEnabled(False)

        self.thread = ExportThread(self.engine, out_path, self.patches)
        self.thread.progress.connect(self.on_progress)
        self.thread.finished_export.connect(self.on_export_finished)
        self.thread.error.connect(self.on_export_error)
        self.thread.start()

    def on_progress(self, percent: float, msg: str):
        self.progress_bar.setValue(int(percent * 100))
        self.lbl_progress_status.setText(msg)

    def on_export_finished(self, path: str):
        self.progress_bar.setValue(100)
        self.lbl_progress_status.setText("Export terminé avec succès !")
        self.btn_export_image.setEnabled(True)
        QMessageBox.information(
            self,
            "Restauration Réussie",
            f"L'image réparée a été créée avec succès :\n\n{path}\n\nLa preuve d'origine est restée intacte.",
        )

    def on_export_error(self, err: str):
        self.btn_export_image.setEnabled(True)
        QMessageBox.critical(self, "Erreur d'exportation", f"Une erreur est survenue :\n{err}")

    def on_export_patch(self):
        default_name = "patch_gpt_lba0_33.bin"
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Enregistrer le patch binaire",
            default_name,
            "Fichiers binaires (*.bin);;Tous les fichiers (*.*)",
        )
        if not out_path:
            return

        try:
            res = self.engine.export_patch_binary(out_path, self.patches)
            QMessageBox.information(
                self,
                "Patch Exporté",
                f"Patch binaire enregistré ({len(self.patches) * 512} octets) :\n\n{res}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))

    def on_generate_dd_script(self):
        script = self.engine.generate_dd_script(self.patches)
        dlg = QDialog(self)
        dlg.setWindowTitle("Commandes Shell 'dd' (Restauration Forensique)")
        dlg.resize(700, 450)
        vbox = QVBoxLayout(dlg)

        txt = QTextEdit()
        txt.setFont(QFont("Consolas", 10))
        txt.setPlainText(script)
        vbox.addWidget(txt)

        btn_copy = QPushButton("Copier dans le Presse-Papier")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(script))
        vbox.addWidget(btn_copy)

        dlg.exec()
