"""
DFR-Forensics - Dialogue de Sélection de Disque Physique
Permet d'énumérer, d'inspecter et d'ouvrir en lecture seule stricte
les disques physiques connectés (SATA, NVMe, USB, SCSI).
"""

import sys
import os
from typing import Optional, List
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QFrame,
    QApplication,
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon, QFont, QColor

from core.i18n import t
from core.physical_disk import (
    PhysicalDriveInfo,
    enumerate_physical_drives,
    is_admin,
    relaunch_as_admin,
)


class DriveDiscoveryThread(QThread):
    """Thread d'énumération des disques physiques en arrière-plan pour ne pas bloquer l'UI."""
    drives_discovered = Signal(list)
    error_occurred = Signal(str)

    def run(self):
        try:
            drives = enumerate_physical_drives()
            self.drives_discovered.emit(drives)
        except Exception as e:
            self.error_occurred.emit(str(e))


class PhysicalDriveDialog(QDialog):
    """Fenêtre modale de sélection de disque physique bas niveau."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(t("dlg_physical_title"))
        self.resize(850, 480)

        # Icône de la fenêtre
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.selected_drive_path: Optional[str] = None
        self.drives: List[PhysicalDriveInfo] = []
        self._discovery_thread: Optional[DriveDiscoveryThread] = None

        self._setup_ui()
        self.refresh_drives()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Description
        self.lbl_desc = QLabel(t("dlg_physical_desc"))
        self.lbl_desc.setWordWrap(True)
        layout.addWidget(self.lbl_desc)

        # Bandeau de statut Administrateur
        self.admin_frame = QFrame()
        self.admin_frame.setFrameShape(QFrame.StyledPanel)
        admin_layout = QHBoxLayout(self.admin_frame)
        admin_layout.setContentsMargins(10, 8, 10, 8)

        self.is_currently_admin = is_admin()

        if self.is_currently_admin:
            self.admin_frame.setStyleSheet(
                "background-color: #1b382b; border: 1px solid #2ea043; border-radius: 6px;"
            )
            self.lbl_admin = QLabel(
                "🛡️ <b>Privilèges Administrateur Actifs</b> — L'accès direct aux disques physiques est autorisé."
            )
            self.lbl_admin.setStyleSheet("color: #7ee787;")
            admin_layout.addWidget(self.lbl_admin)
            self.btn_relaunch = None
        else:
            self.admin_frame.setStyleSheet(
                "background-color: #3d2c18; border: 1px solid #d29922; border-radius: 6px;"
            )
            self.lbl_admin = QLabel(t("admin_required_banner"))
            self.lbl_admin.setStyleSheet("color: #e3b341;")
            admin_layout.addWidget(self.lbl_admin)

            self.btn_relaunch = QPushButton(t("btn_relaunch_admin"))
            self.btn_relaunch.setStyleSheet(
                "background-color: #238636; color: white; font-weight: bold; padding: 4px 12px; border-radius: 4px;"
            )
            self.btn_relaunch.clicked.connect(self._on_relaunch_as_admin)
            admin_layout.addWidget(self.btn_relaunch)

        layout.addWidget(self.admin_frame)

        # Tableau des disques physiques
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            t("col_drive_id"),
            t("col_drive_model"),
            t("col_drive_size"),
            t("col_drive_interface"),
            t("col_drive_media"),
            t("col_drive_sector"),
        ])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)

        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.table.cellDoubleClicked.connect(self._on_table_double_clicked)
        layout.addWidget(self.table)

        # Barre inférieure de boutons
        btn_layout = QHBoxLayout()

        self.btn_refresh = QPushButton(t("btn_refresh_drives"))
        self.btn_refresh.clicked.connect(self.refresh_drives)
        btn_layout.addWidget(self.btn_refresh)

        btn_layout.addStretch()

        self.btn_cancel = QPushButton("Annuler" if t("btn_refresh_drives") != "Refresh List" else "Cancel")
        self.btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_cancel)

        self.btn_open = QPushButton(t("btn_open_selected_drive"))
        self.btn_open.setEnabled(False)
        self.btn_open.setStyleSheet(
            "QPushButton:enabled { background-color: #1f6feb; color: white; font-weight: bold; padding: 6px 16px; border-radius: 4px; }"
            "QPushButton:disabled { background-color: #21262d; color: #8b949e; }"
        )
        self.btn_open.clicked.connect(self._on_open_clicked)
        btn_layout.addWidget(self.btn_open)

        layout.addLayout(btn_layout)

    def refresh_drives(self):
        """Lance l'actualisation asynchrone des disques physiques."""
        self.btn_refresh.setEnabled(False)
        self.table.setRowCount(0)

        self._discovery_thread = DriveDiscoveryThread()
        self._discovery_thread.drives_discovered.connect(self._on_drives_discovered)
        self._discovery_thread.error_occurred.connect(self._on_discovery_error)
        self._discovery_thread.start()

    def _on_drives_discovered(self, drives: List[PhysicalDriveInfo]):
        self.btn_refresh.setEnabled(True)
        self.drives = drives
        self.table.setRowCount(len(drives))

        for row, d in enumerate(drives):
            item_id = QTableWidgetItem(d.device_id)
            item_id.setData(Qt.UserRole, d.device_id)

            item_model = QTableWidgetItem(d.model)
            item_model.setFont(QFont("Segoe UI", 9, QFont.Bold))

            size_gb = d.size_bytes / (1024 ** 3)
            if size_gb >= 1000:
                size_str = f"{size_gb / 1024:.2f} To"
            else:
                size_str = f"{size_gb:.1f} Go"
            item_size = QTableWidgetItem(size_str)
            item_size.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            item_iface = QTableWidgetItem(d.interface_type)
            item_media = QTableWidgetItem(d.media_type)
            item_sec = QTableWidgetItem(f"{d.sector_size} o")
            item_sec.setTextAlignment(Qt.AlignCenter)

            self.table.setItem(row, 0, item_id)
            self.table.setItem(row, 1, item_model)
            self.table.setItem(row, 2, item_size)
            self.table.setItem(row, 3, item_iface)
            self.table.setItem(row, 4, item_media)
            self.table.setItem(row, 5, item_sec)

        if drives:
            self.table.selectRow(0)

    def _on_discovery_error(self, err_msg: str):
        self.btn_refresh.setEnabled(True)
        QMessageBox.warning(self, "Erreur", f"Erreur lors de la détection des disques :\n{err_msg}")

    def _on_selection_changed(self):
        selected_rows = self.table.selectionModel().selectedRows()
        self.btn_open.setEnabled(len(selected_rows) > 0)

    def _on_table_double_clicked(self, row: int, col: int):
        self._on_open_clicked()

    def _on_open_clicked(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        item = self.table.item(row, 0)
        if not item:
            return

        drive_path = item.data(Qt.UserRole) or item.text()

        # Vérifier si on a les privilèges administrateur sous Windows
        if sys.platform == "win32" and not is_admin():
            reply = QMessageBox.question(
                self,
                "Privilèges Administrateur Requis",
                t("admin_required_banner") + "\n\nSouhaitez-vous relancer l'application en tant qu'administrateur ?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                try:
                    relaunch_as_admin(target_device=drive_path)
                except Exception as ex:
                    QMessageBox.critical(self, "Erreur UAC", f"Impossible d'élever les privilèges :\n{ex}")
            return

        self.selected_drive_path = drive_path
        self.accept()

    def closeEvent(self, event):
        if self._discovery_thread and self._discovery_thread.isRunning():
            self._discovery_thread.wait(1500)
        super().closeEvent(event)

    def reject(self):
        if self._discovery_thread and self._discovery_thread.isRunning():
            self._discovery_thread.wait(1500)
        super().reject()

    def _on_relaunch_as_admin(self):
        selected_rows = self.table.selectionModel().selectedRows()
        target = None
        if selected_rows:
            row = selected_rows[0].row()
            item = self.table.item(row, 0)
            if item:
                target = item.data(Qt.UserRole) or item.text()

        try:
            relaunch_as_admin(target_device=target)
        except Exception as e:
            QMessageBox.critical(self, "Erreur UAC", f"Impossible d'élever les privilèges :\n{e}")
