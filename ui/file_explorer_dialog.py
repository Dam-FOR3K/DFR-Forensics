"""
WipeRescue-Forensics - Explorateur de Fichiers Virtuel & MFT Undelete (Couche In-Memory COW)
Permet d'explorer l'arborescence des partitions réparées sans montage externe,
de visualiser les fichiers actifs et supprimés (NTFS Undelete), de calculer les empreintes (MD5/SHA256)
et d'extraire les artefacts avec intégrité médico-légale garantie.
"""

import os
import hashlib
from typing import Optional, List, Dict
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTreeWidget,
    QTreeWidgetItem,
    QPushButton,
    QFileDialog,
    QMessageBox,
    QSplitter,
    QTextEdit,
    QComboBox,
    QLineEdit,
    QCheckBox,
    QHeaderView,
    QApplication,
    QProgressDialog,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor, QBrush, QIcon

from core.i18n import t, get_lang
from core.image_reader import ForensicImageReader
from core.scanner import ScanDiagnostic, GPTPartitionEntry
from core.ntfs_reader import NTFSReader, NTFSFileEntry
from core.fat_reader import FATReader, FATFileEntry
from core.ext_reader import ExtReader, ExtFileEntry
from core.qnx_reader import QNXReader, QNXFileEntry
from core.apfs_reader import APFSReader, APFSFileEntry, APFSVolumeInfo
from core.crypto_engine import EncryptedVolumeHandler
from core.partition_exporter import export_partition
from ui.unlock_dialog import UnlockVolumeDialog


def format_size(size_bytes: int) -> str:
    """Formate une taille en octets en chaîne lisible bilingue."""
    is_fr = get_lang() == "fr"
    u_b = "octets" if is_fr else "bytes"
    u_k = "Ko" if is_fr else "KB"
    u_m = "Mo" if is_fr else "MB"
    u_g = "Go" if is_fr else "GB"
    if size_bytes < 1024:
        return f"{size_bytes} {u_b}"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} {u_k}"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} {u_m}"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} {u_g}"


def format_hex_dump(data: bytes, max_bytes: int = 2048) -> str:
    """Génère un hex dump forensique classique (Offset | Hex | ASCII)."""
    lines = []
    chunk = data[:max_bytes]
    for i in range(0, len(chunk), 16):
        line_bytes = chunk[i : i + 16]
        hex_part = " ".join(f"{b:02X}" for b in line_bytes)
        # padding hex
        if len(line_bytes) < 16:
            hex_part += "   " * (16 - len(line_bytes))
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in line_bytes)
        lines.append(f"{i:08X}  {hex_part:<48}  |{ascii_part}|")
    if len(data) > max_bytes:
        trunc_msg = (f"\n[... Troncature de l'aperçu à {max_bytes} octets sur un total de {len(data):,} octets ...]"
                     if get_lang() == "fr" else
                     f"\n[... Preview truncated to {max_bytes} bytes out of {len(data):,} total bytes ...]")
        lines.append(trunc_msg)
    return "\n".join(lines)


class VirtualExplorerDialog(QDialog):
    """Explorateur virtuel arborescent de systèmes de fichiers avec moteur NTFS Undelete."""

    def __init__(self, reader: ForensicImageReader, diag: ScanDiagnostic, parent=None):
        super().__init__(parent)
        self.reader = reader
        self.diag = diag
        self.current_ntfs: Optional[NTFSReader] = None
        self.current_fat: Optional[FATReader] = None
        self.current_ext: Optional[ExtReader] = None
        self.current_qnx: Optional[QNXReader] = None
        self.current_apfs: Optional[APFSReader] = None
        self.active_fs_override: Optional[str] = None
        self.all_tree_items: List[QTreeWidgetItem] = []
        self.crypto_handlers: Dict[int, EncryptedVolumeHandler] = {}

        self.setWindowTitle(t("explorer_title"))
        self.resize(1100, 720)

        self.setup_ui()
        self.populate_partitions()

    def setup_ui(self):
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if not os.path.exists(icon_path):
            icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # En-tête informatif COW
        lbl_info = QLabel(t("explorer_info"))
        lbl_info.setWordWrap(True)
        lbl_info.setStyleSheet("color: #00d2ff; font-size: 12px; background: #141926; padding: 8px; border-radius: 4px; border: 1px solid #1e293b;")
        layout.addWidget(lbl_info)

        # Bandeau d'avertissement Multi-FS (DFTT Test #10)
        from PySide6.QtWidgets import QWidget
        is_fr = get_lang() == "fr"
        self.banner_multifs = QWidget()
        self.banner_multifs.setStyleSheet("background: #2b1f00; border: 1px solid #f59e0b; border-radius: 4px; padding: 4px;")
        b_layout = QHBoxLayout(self.banner_multifs)
        b_layout.setContentsMargins(8, 4, 8, 4)
        multifs_txt = ("⚠️ Ambiguïté Médico-Légale Multi-FS : Plusieurs systèmes de fichiers coexistent sur cette partition !" if is_fr
                       else "⚠️ Forensic Multi-FS Ambiguity: Multiple filesystems coexist on this partition!")
        self.lbl_multifs_msg = QLabel(multifs_txt)
        self.lbl_multifs_msg.setStyleSheet("color: #fbbf24; font-weight: bold; font-size: 12px;")
        b_layout.addWidget(self.lbl_multifs_msg)
        b_layout.addStretch()

        b_layout.addWidget(QLabel(f"<b>{'Système affiché :' if is_fr else 'Displayed System:'}</b>"))
        self.combo_multifs_switch = QComboBox()
        self.combo_multifs_switch.setStyleSheet("background-color: #1e222d; color: #fbbf24; font-weight: bold; padding: 3px 8px; border: 1px solid #f59e0b;")
        self.combo_multifs_switch.currentIndexChanged.connect(self.on_multifs_switch)
        b_layout.addWidget(self.combo_multifs_switch)
        self.banner_multifs.setVisible(False)
        layout.addWidget(self.banner_multifs)

        # Bandeau de déverrouillage cryptographique (LUKS / BitLocker)
        self.banner_crypto = QWidget()
        self.banner_crypto.setStyleSheet("background: #1e1b4b; border: 1px solid #6366f1; border-radius: 4px; padding: 4px;")
        c_layout = QHBoxLayout(self.banner_crypto)
        c_layout.setContentsMargins(8, 4, 8, 4)
        self.lbl_crypto_msg = QLabel("🔒 Conteneur Chiffré Détecté" if is_fr else "🔒 Encrypted Container Detected")
        self.lbl_crypto_msg.setStyleSheet("color: #a5b4fc; font-weight: bold; font-size: 12px;")
        c_layout.addWidget(self.lbl_crypto_msg)
        c_layout.addStretch()

        self.btn_unlock_partition = QPushButton("🔓 Déverrouiller le volume..." if is_fr else "🔓 Unlock volume...")
        self.btn_unlock_partition.setStyleSheet("background-color: #4f46e5; color: #fff; font-weight: bold; padding: 4px 14px; border-radius: 4px;")
        self.btn_unlock_partition.clicked.connect(self.on_click_unlock_partition)
        c_layout.addWidget(self.btn_unlock_partition)
        self.banner_crypto.setVisible(False)
        layout.addWidget(self.banner_crypto)

        # Barre supérieure : Sélecteur de partition + Recherche + Filtre Undelete
        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel(f"<b>{t('explorer_partition_label')}</b>"))
        self.combo_parts = QComboBox()
        self.combo_parts.setMinimumWidth(380)
        self.combo_parts.setStyleSheet("background-color: #222530; color: #fff; padding: 4px; border: 1px solid #3b4252;")
        self.combo_parts.currentIndexChanged.connect(self.on_partition_selected)
        top_bar.addWidget(self.combo_parts)

        top_bar.addSpacing(15)

        # Filtre texte
        self.edit_filter = QLineEdit()
        self.edit_filter.setPlaceholderText(t("explorer_search_placeholder"))
        self.edit_filter.setStyleSheet("background-color: #1e222d; color: #fff; padding: 4px 8px; border: 1px solid #3b4252; border-radius: 4px;")
        self.edit_filter.textChanged.connect(self.filter_tree)
        top_bar.addWidget(self.edit_filter)

        # Case à cocher pour afficher/masquer les fichiers supprimés
        self.chk_show_deleted = QCheckBox(t("explorer_show_deleted"))
        self.chk_show_deleted.setChecked(True)
        self.chk_show_deleted.setStyleSheet("color: #ffaa00; font-weight: bold;")
        self.chk_show_deleted.stateChanged.connect(self.on_deleted_toggle)
        top_bar.addWidget(self.chk_show_deleted)

        top_bar.addStretch()
        layout.addLayout(top_bar)

        # Splitter Arborescence (gauche) / Aperçu & Métadonnées (droite)
        splitter = QSplitter(Qt.Horizontal)

        # Arborescence
        self.tree = QTreeWidget()
        headers = [
            t("explorer_col_name"),
            t("explorer_col_size"),
            t("explorer_col_type"),
            t("explorer_col_modified"),
            t("explorer_col_mft"),
        ]
        self.tree.setHeaderLabels(headers)
        self.tree.setColumnWidth(0, 320)
        self.tree.setColumnWidth(1, 90)
        self.tree.setColumnWidth(2, 160)
        self.tree.setColumnWidth(3, 160)
        self.tree.setColumnWidth(4, 70)
        self.tree.setStyleSheet(
            """
            QTreeWidget {
                background-color: #10121a;
                color: #e0e6ed;
                border: 1px solid #282c3c;
                font-size: 12px;
            }
            QTreeWidget::item {
                padding: 3px 0px;
            }
            QTreeWidget::item:selected {
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
        self.tree.itemSelectionChanged.connect(self.on_item_selected)
        self.tree.itemExpanded.connect(self.on_item_expanded)
        splitter.addWidget(self.tree)

        # Panneau d'Aperçu & Propriétés Forensiques
        preview_widget = QTextEdit()
        preview_widget.setReadOnly(True)
        preview_widget.setFont(QFont("Consolas", 10))
        preview_widget.setStyleSheet(
            """
            QTextEdit {
                background-color: #0d0f14;
                color: #00ffcc;
                border: 1px solid #282c3c;
                padding: 8px;
                line-height: 1.4;
            }
            """
        )
        self.preview_text = preview_widget
        splitter.addWidget(preview_widget)

        splitter.setSizes([620, 480])
        layout.addWidget(splitter, 1)

        # Boutons d'action en bas
        btn_layout = QHBoxLayout()

        self.btn_export_file = QPushButton(t("explorer_btn_export"))
        self.btn_export_file.setStyleSheet(
            "background-color: #27ae60; color: #fff; font-weight: bold; padding: 8px 18px; border-radius: 4px; font-size: 13px;"
        )
        self.btn_export_file.clicked.connect(self.export_selected_file)
        btn_layout.addWidget(self.btn_export_file)

        export_part_txt = "💾 Exporter la partition (.dd / .raw)..." if get_lang() == "fr" else "💾 Export partition (.dd / .raw)..."
        self.btn_export_partition = QPushButton(export_part_txt)
        self.btn_export_partition.setStyleSheet(
            "background-color: #0284c7; color: #fff; font-weight: bold; padding: 8px 18px; border-radius: 4px; font-size: 13px;"
        )
        self.btn_export_partition.clicked.connect(self.on_export_partition_clicked)
        btn_layout.addWidget(self.btn_export_partition)

        carve_part_txt = "🔬 Carving de la partition..." if get_lang() == "fr" else "🔬 Carve this partition..."
        self.btn_carve_partition = QPushButton(carve_part_txt)
        self.btn_carve_partition.setStyleSheet(
            "background-color: #7c3aed; color: #fff; font-weight: bold; padding: 8px 18px; border-radius: 4px; font-size: 13px;"
        )
        self.btn_carve_partition.clicked.connect(self.on_carve_partition_clicked)
        btn_layout.addWidget(self.btn_carve_partition)

        btn_layout.addStretch()

        btn_close = QPushButton(t("explorer_btn_close"))
        btn_close.setStyleSheet("background-color: #444b5d; color: #fff; padding: 8px 18px; border-radius: 4px; font-size: 13px;")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)

    def populate_partitions(self):
        self.combo_parts.clear()
        if not self.diag.partitions:
            return

        is_fr = get_lang() == "fr"
        for idx, p in enumerate(self.diag.partitions, 1):
            fs = p.detected_fs or p.type_name or ("Partition Inconnue" if is_fr else "Unknown Partition")
            vol_name = p.name or ("Volume" if is_fr else "Volume")
            to_word = "à" if is_fr else "to"
            label = f"Partition {idx} : {vol_name} (LBA {p.first_lba:,} {to_word} {p.last_lba:,}) [{fs}]"
            self.combo_parts.addItem(label, p)

    def on_partition_selected(self, index: int):
        p = self.combo_parts.currentData()
        if not p:
            return
        self.active_fs_override = None
        self.load_partition_tree(p)

    def on_multifs_switch(self, index: int):
        fs_choice = self.combo_multifs_switch.itemData(index)
        if fs_choice and fs_choice != self.active_fs_override:
            self.active_fs_override = fs_choice
            p = self.combo_parts.currentData()
            if p:
                self.load_partition_tree(p)

    def on_deleted_toggle(self):
        show_deleted = self.chk_show_deleted.isChecked()
        filter_text = self.edit_filter.text().strip().lower()
        self._apply_filter(filter_text, show_deleted)

    def filter_tree(self, text: str):
        show_deleted = self.chk_show_deleted.isChecked()
        self._apply_filter(text.strip().lower(), show_deleted)

    def _apply_filter(self, filter_text: str, show_deleted: bool):
        filter_text = filter_text.strip().lower()

        # Si aucun filtre et qu'on affiche les supprimés : tout réafficher
        if not filter_text and show_deleted:
            for item in self.all_tree_items:
                item.setHidden(False)
            return

        def item_matches(item: QTreeWidgetItem) -> bool:
            entry = item.data(0, Qt.UserRole)
            if not entry:
                return False

            is_del = getattr(entry, "is_deleted", False)
            if is_del and not show_deleted:
                return False

            if not filter_text:
                return True

            name = getattr(entry, "name", item.text(0)).lower()
            return filter_text in name

        # 1. Identifier les éléments qui correspondent et marquer toute leur chaîne d'ancêtres
        visible_set = set()
        for item in self.all_tree_items:
            if item_matches(item):
                visible_set.add(item)
                p = item.parent()
                while p:
                    visible_set.add(p)
                    p.setExpanded(True)
                    p = p.parent()

        # 2. Si filtre textuel vide mais qu'on masque seulement les éléments supprimés
        if not filter_text and not show_deleted:
            for item in self.all_tree_items:
                entry = item.data(0, Qt.UserRole)
                is_del = getattr(entry, "is_deleted", False) if entry else False
                item.setHidden(is_del)
            return

        # 3. Masquer uniquement les nœuds qui ne correspondent pas et n'ont aucun enfant correspondant
        for item in self.all_tree_items:
            item.setHidden(item not in visible_set)

    def load_partition_tree(self, p: GPTPartitionEntry):
        self.tree.clear()
        self.all_tree_items.clear()
        self.preview_text.clear()
        self.current_ntfs = None
        self.current_fat = None
        self.current_ext = None

        coexisting = getattr(p, "coexisting_filesystems", [])
        if len(coexisting) > 1:
            self.banner_multifs.setVisible(True)
            self.lbl_multifs_msg.setText(
                f"⚠️ Ambiguïté Médico-Légale Multi-FS : {len(coexisting)} systèmes coexistent ({', '.join(coexisting)}) !"
            )
            self.combo_multifs_switch.blockSignals(True)
            self.combo_multifs_switch.clear()
            for fs_opt in coexisting:
                self.combo_multifs_switch.addItem(f"Vue {fs_opt}", fs_opt)

            idx = 0
            if self.active_fs_override:
                for i in range(self.combo_multifs_switch.count()):
                    if self.combo_multifs_switch.itemData(i) == self.active_fs_override:
                        idx = i
                        break
            self.combo_multifs_switch.setCurrentIndex(idx)
            self.combo_multifs_switch.blockSignals(False)
        else:
            self.banner_multifs.setVisible(False)

        chosen_fs = self.active_fs_override or (coexisting[0] if coexisting else "") or (p.detected_fs or "").upper()
        part_offset = p.first_lba * self.reader.sector_size

        # Gestion des conteneurs chiffrés (LUKS / BitLocker)
        part_key = p.first_lba
        handler = self.crypto_handlers.get(part_key)

        if not handler:
            try:
                from core.crypto_engine import EncryptedVolumeHandler
                h = EncryptedVolumeHandler(self.reader, p.first_lba, p.total_sectors)
                if h.is_encrypted:
                    handler = h
                    self.crypto_handlers[part_key] = handler
                    p.detected_fs = f"{h.crypto_type} Encrypted Volume"
                    p.crypto_metadata = h.metadata
            except Exception:
                handler = None

        if handler and handler.is_encrypted:
            # Si le volume est déjà déverrouillé dans la session Windows active, auto-déverrouiller directement !
            if not handler.is_unlocked and handler.metadata.get("windows_is_unlocked"):
                handler.unlock_with_windows_volume()

            self.banner_crypto.setVisible(True)
            if handler.is_unlocked:
                via_txt = handler.metadata.get("unlocked_via", "Déverrouillé")
                self.lbl_crypto_msg.setText(f"🔓 Volume Chiffré {handler.crypto_type} : Déverrouillé avec succès ({via_txt})")
                self.btn_unlock_partition.setVisible(False)
                active_reader = handler.decrypted_reader
                active_offset = 0
            else:
                self.lbl_crypto_msg.setText(f"🔒 Conteneur Chiffré {handler.crypto_type} : Verrouillé")
                self.btn_unlock_partition.setVisible(True)
                root = QTreeWidgetItem(self.tree, [f"/ ({p.name or handler.crypto_type})", "", f"{handler.crypto_type} Container", "", ""])
                root.setExpanded(True)
                self.all_tree_items.append(root)
                QTreeWidgetItem(root, [f"[{handler.crypto_type} Chiffré - Verrouillé]", "Accès protégé", "Volume Chiffré", "", ""])
                for slot in handler.metadata.get("slots_detail", []):
                    QTreeWidgetItem(root, [slot, "", "Keyslot", "", ""])

                txt_lines = [
                    f"=== CONTENEUR CHIFFRÉ {handler.crypto_type} DÉTECTÉ ===",
                    "",
                    "Statut       : 🔒 VERROUILLÉ (Authentification requise)",
                    f"Offset début : LBA {p.first_lba:,} ({part_offset:,} octets)",
                    f"Taille       : {p.total_sectors * self.reader.sector_size:,} octets ({p.total_sectors * self.reader.sector_size / (1024**3):.2f} Gio)",
                ]
                if handler.metadata.get("uuid"):
                    txt_lines.append(f"UUID         : {handler.metadata['uuid']}")
                if handler.metadata.get("encryption"):
                    txt_lines.append(f"Chiffrement  : {handler.metadata['encryption']}")
                if handler.metadata.get("slots_detail"):
                    txt_lines.append(f"Keyslots     : {', '.join(handler.metadata['slots_detail'])}")
                if handler.metadata.get("version"):
                    txt_lines.append(f"Version      : {handler.metadata['version']}")
                if handler.metadata.get("windows_drive_letter"):
                    txt_lines.append(f"Lecteur Win  : {handler.metadata['windows_drive_letter']}")
                txt_lines.append("\n👉 Cliquez sur le bouton '🔓 Déverrouiller le volume...' ci-dessus pour saisir votre mot de passe, clé de récupération ou utiliser la session Windows.")
                self.preview_text.setPlainText("\n".join(txt_lines))
                return
        else:
            self.banner_crypto.setVisible(False)
            active_reader = self.reader
            active_offset = part_offset

        # Inspection directe du boot sector sur active_reader à active_offset
        boot_sig = b""
        try:
            boot_hdr = active_reader.read_sector(active_offset // active_reader.sector_size, count=1)
            if len(boot_hdr) >= 512:
                if boot_hdr[3:11] == b"NTFS    ":
                    boot_sig = b"NTFS"
                    chosen_fs = "NTFS"
                    if handler and handler.is_unlocked:
                        p.detected_fs = f"NTFS ({handler.crypto_type} Déverrouillé)"
                elif boot_hdr[3:11] == b"EXFAT   ":
                    boot_sig = b"EXFAT"
                    chosen_fs = "EXFAT"
                    if handler and handler.is_unlocked:
                        p.detected_fs = f"exFAT ({handler.crypto_type} Déverrouillé)"
                elif boot_hdr[0x52:0x57] == b"FAT32" or boot_hdr[0x36:0x39] == b"FAT":
                    boot_sig = b"FAT"
                    chosen_fs = "FAT"
        except Exception:
            pass

        # 0. Gestion Conteneur Logique AD1 (AccessData FTK Imager)
        if "AD1" in chosen_fs or hasattr(active_reader, "ad1"):
            ad1_obj = getattr(active_reader, "ad1", None)
            if ad1_obj:
                self._populate_ad1_tree(ad1_obj, p)
                return

        # 1. Gestion NTFS Réelle (MFT + Undelete) - Vérifié en premier si boot signature NTFS ou fs NTFS
        if boot_sig == b"NTFS" or "NTFS" in chosen_fs.upper() or (handler and handler.is_unlocked and boot_sig != b"FAT"):
            try:
                ntfs = NTFSReader(active_reader, partition_offset_bytes=active_offset)
                if ntfs.is_valid_ntfs and ntfs.root_entry:
                    self._populate_ntfs_tree(ntfs, p)
                    return
            except Exception as e:
                if "NTFS" in chosen_fs.upper():
                    self.preview_text.setPlainText(f"Erreur d'analyse NTFS : {e}")

        # 2. Gestion Ext2/Ext3/Ext4
        if "EXT" in chosen_fs.upper() or (handler and handler.is_unlocked and boot_sig == b""):
            try:
                ext = ExtReader(active_reader, partition_offset_bytes=active_offset)
                if ext.is_valid_ext and ext.root_entry:
                    self._populate_ext_tree(ext, p)
                    return
            except Exception as e:
                if "EXT" in chosen_fs.upper():
                    self.preview_text.setPlainText(f"Erreur d'analyse Ext : {e}")

        # 3. Gestion FAT12 / FAT16 / FAT32
        if boot_sig == b"FAT" or "FAT" in chosen_fs.upper() or (handler and handler.is_unlocked):
            try:
                fat = FATReader(active_reader, partition_offset_bytes=active_offset)
                if fat.is_valid_fat and fat.root_entry:
                    self._populate_fat_tree(fat, p)
                    return
            except Exception as e:
                if "FAT" in chosen_fs.upper():
                    self.preview_text.setPlainText(f"Erreur d'analyse FAT : {e}")

        # 4. Fallback NTFS si pas encore tenté
        if boot_sig != b"NTFS" and "NTFS" not in chosen_fs.upper():
            try:
                ntfs = NTFSReader(active_reader, partition_offset_bytes=active_offset)
                if ntfs.is_valid_ntfs and ntfs.root_entry:
                    self._populate_ntfs_tree(ntfs, p)
                    return
            except Exception:
                pass

        # Fallback automatique : Tester FAT puis Ext2
        try:
            fat = FATReader(active_reader, partition_offset_bytes=active_offset)
            if fat.is_valid_fat and fat.root_entry:
                self._populate_fat_tree(fat, p)

                return
        except Exception:
            pass

        try:
            ext = ExtReader(active_reader, partition_offset_bytes=active_offset)
            if ext.is_valid_ext and ext.root_entry:
                self._populate_ext_tree(ext, p)

                return
        except Exception:
            pass

        # 4. Gestion QNX (QNX4 & QNX6 Power-Safe)
        if "QNX" in chosen_fs.upper():
            try:
                part_size = p.total_sectors * self.reader.sector_size
                qnx = QNXReader(active_reader, partition_offset_bytes=active_offset, partition_size_bytes=part_size)
                if qnx.is_valid_qnx and qnx.root_entry:
                    self._populate_qnx_tree(qnx, p)
    
                    return
            except Exception as e:
                self.preview_text.setPlainText(f"Erreur d'analyse QNX : {e}")

        # 5. Gestion Apple APFS (Multi-Volumes & Fichiers)
        if "APFS" in chosen_fs.upper():
            try:
                part_size = p.total_sectors * self.reader.sector_size
                apfs_r = APFSReader(active_reader, partition_offset_bytes=active_offset, partition_size_bytes=part_size)
                if apfs_r.is_valid_apfs and apfs_r.volumes:
                    self._populate_apfs_tree(apfs_r, p)
    
                    return
            except Exception as e:
                self.preview_text.setPlainText(f"Erreur d'analyse APFS : {e}")

        # Fallback automatique : Tester QNX puis APFS si les précédents n'ont rien retourné
        try:
            part_size = p.total_sectors * self.reader.sector_size
            qnx = QNXReader(active_reader, partition_offset_bytes=active_offset, partition_size_bytes=part_size)
            if qnx.is_valid_qnx and qnx.root_entry:
                self._populate_qnx_tree(qnx, p)

                return
        except Exception:
            pass

        try:
            part_size = p.total_sectors * self.reader.sector_size
            apfs_r = APFSReader(active_reader, partition_offset_bytes=active_offset, partition_size_bytes=part_size)
            if apfs_r.is_valid_apfs and apfs_r.volumes:
                self._populate_apfs_tree(apfs_r, p)

                return
        except Exception:
            pass

        # 6. Autre FS
        root = QTreeWidgetItem(self.tree, [f"/ ({p.name or 'Partition'})", "", chosen_fs or "Système Inconnu", "", ""])
        self.all_tree_items.append(root)
        self.preview_text.setPlainText(f"Système de fichiers : {chosen_fs}\nSecteur début : LBA {p.first_lba:,}\n")

    def on_item_expanded(self, item: QTreeWidgetItem):
        """Développe dynamiquement un dossier lors de son ouverture (Lazy-Loading non-bloquant)."""
        is_loaded = item.data(0, Qt.UserRole + 1)
        if is_loaded is not False:
            return

        item.setData(0, Qt.UserRole + 1, True)
        self.tree.setUpdatesEnabled(False)
        try:
            item.takeChildren()
            node = item.data(0, Qt.UserRole)
            fs_type = item.data(0, Qt.UserRole + 2)

            if fs_type == "AD1" and node:
                self._add_ad1_level(item, node)
            elif fs_type == "APFS" and node:
                self._add_apfs_level(item, node)
            elif fs_type == "QNX" and node:
                self._add_qnx_level(item, node)
            elif fs_type == "FAT" and node:
                self._add_fat_level(item, node)
            elif fs_type == "EXT" and node:
                self._add_ext_level(item, node)
            elif fs_type == "NTFS" and node:
                self._add_ntfs_level(item, node)
        finally:
            self.tree.setUpdatesEnabled(True)

    # --- 1. Gestionnaire QNX ---
    def _add_qnx_level(self, parent_item: QTreeWidgetItem, parent_entry: QNXFileEntry):
        try:
            children = parent_entry.children
        except Exception:
            children = []
        sorted_children = sorted(children, key=lambda e: (not e.is_dir(), e.name.lower()))
        for ch in sorted_children:
            is_dir = ch.is_dir()
            status_str = t("explorer_status_active")
            type_str = f"📁 Dossier ({status_str})" if is_dir else f"📄 Fichier ({status_str})"
            size_str = "" if is_dir else format_size(ch.size)
            mtime_str = ch.mtime.strftime("%Y-%m-%d %H:%M:%S") if ch.mtime else ""

            item = QTreeWidgetItem(parent_item, [
                ch.name,
                size_str,
                type_str,
                mtime_str,
                "",
            ])
            item.setData(0, Qt.UserRole, ch)
            item.setData(0, Qt.UserRole + 2, "QNX")

            if is_dir:
                item.setForeground(0, QBrush(QColor("#ffffff")))
                item.setForeground(2, QBrush(QColor("#3498db")))
                item.setData(0, Qt.UserRole + 1, False)
                dummy = QTreeWidgetItem(item, ["Chargement...", "", "", "", ""])
                dummy.setData(0, Qt.UserRole, None)
            else:
                item.setForeground(0, QBrush(QColor("#e0e6ed")))
                item.setForeground(2, QBrush(QColor("#2ecc71")))
                item.setData(0, Qt.UserRole + 1, True)

            self.all_tree_items.append(item)

    def _populate_qnx_tree(self, qnx: QNXReader, p: GPTPartitionEntry):
        """Construit le QTreeWidget avec l'arborescence QNX4 / QNX6 (Lazy-Loading)."""
        self.current_qnx = qnx
        root_node = qnx.root_entry
        root_label = f"/ [{qnx.version} Root: {p.name or 'Volume'}]"
        root_item = QTreeWidgetItem(self.tree, [root_label, "", f"Racine {qnx.version}", "", ""])
        root_item.setData(0, Qt.UserRole, root_node)
        root_item.setData(0, Qt.UserRole + 1, True)
        root_item.setData(0, Qt.UserRole + 2, "QNX")
        self.all_tree_items.append(root_item)

        if root_node:
            self._add_qnx_level(root_item, root_node)
        root_item.setExpanded(True)

        self.preview_text.setPlainText(
            f"=== SYSTÈME DE FICHIERS EMBARQUÉ {qnx.version.upper()} ===\n\n"
            f"Partition : {p.name or 'QNX Volume'}\n"
            f"Offset partition : LBA {p.first_lba:,} ({p.first_lba * self.reader.sector_size:,} octets)\n"
            f"Taille totale : {p.total_sectors * self.reader.sector_size:,} octets\n"
            f"Mode d'exploration : Navigation virtuelle ultra-rapide (Lazy-Loading actif)\n\n"
            "Sélectionnez un fichier pour prévisualiser son contenu et calculer ses empreintes MD5 / SHA-256."
        )

    # --- 2. Gestionnaire APFS ---
    def _add_apfs_level(self, parent_item: QTreeWidgetItem, parent_entry: APFSFileEntry):
        try:
            children = parent_entry.children
        except Exception:
            children = []
        sorted_children = sorted(children, key=lambda e: (not e.is_dir(), e.name.lower()))
        for ch in sorted_children:
            is_dir = ch.is_dir()
            status_str = t("explorer_status_active")
            type_str = f"📁 Dossier ({status_str})" if is_dir else f"📄 Fichier ({status_str})"
            size_str = "" if is_dir else format_size(ch.size)
            mtime_str = ch.mtime.strftime("%Y-%m-%d %H:%M:%S") if ch.mtime else ""

            item = QTreeWidgetItem(parent_item, [
                ch.name,
                size_str,
                type_str,
                mtime_str,
                "",
            ])
            item.setData(0, Qt.UserRole, ch)
            item.setData(0, Qt.UserRole + 2, "APFS")

            if is_dir:
                item.setForeground(0, QBrush(QColor("#ffffff")))
                item.setForeground(2, QBrush(QColor("#3498db")))
                item.setData(0, Qt.UserRole + 1, False)
                dummy = QTreeWidgetItem(item, ["Chargement...", "", "", "", ""])
                dummy.setData(0, Qt.UserRole, None)
            else:
                item.setForeground(0, QBrush(QColor("#e0e6ed")))
                item.setForeground(2, QBrush(QColor("#2ecc71")))
                item.setData(0, Qt.UserRole + 1, True)

            self.all_tree_items.append(item)

    def _populate_apfs_tree(self, apfs_r: APFSReader, p: GPTPartitionEntry):
        """Construit le QTreeWidget avec l'arborescence Apple APFS (Lazy-Loading)."""
        self.current_apfs = apfs_r
        root_label = f"/ [Apple APFS Container: {p.name or 'NXSB'}]"
        root_item = QTreeWidgetItem(self.tree, [root_label, "", "Conteneur APFS", "", ""])
        root_item.setExpanded(True)
        self.all_tree_items.append(root_item)

        for v in apfs_r.volumes:
            enc_tag = " [Chiffré]" if v.is_encrypted else ""
            vol_item = QTreeWidgetItem(root_item, [f"📦 Volume: {v.name}{enc_tag}", "", "Volume APFS", "", v.uuid])
            vol_item.setForeground(0, QBrush(QColor("#f39c12") if v.is_encrypted else QColor("#00d2ff")))
            self.all_tree_items.append(vol_item)

            if v.is_encrypted:
                locked_item = QTreeWidgetItem(vol_item, ["🔒 Volume APFS Chiffré (FileVault)", "", "Verrouillé", "", ""])
                self.all_tree_items.append(locked_item)
            elif v.root_entry:
                vol_item.setData(0, Qt.UserRole, v.root_entry)
                vol_item.setData(0, Qt.UserRole + 1, True)
                vol_item.setData(0, Qt.UserRole + 2, "APFS")
                self._add_apfs_level(vol_item, v.root_entry)
                vol_item.setExpanded(True)

        self.preview_text.setPlainText(
            f"=== CONTENEUR APPLE FILE SYSTEM (APFS NXSB) ===\n\n"
            f"Volumes détectés : {len(apfs_r.volumes)}\n"
            + "\n".join(f" • {v.name} (UUID: {v.uuid}){' - Chiffré FileVault' if v.is_encrypted else ''}" for v in apfs_r.volumes)
            + f"\n\nMode d'exploration : Navigation virtuelle ultra-rapide (Lazy-Loading actif)\n"
            "Sélectionnez un fichier pour prévisualiser son contenu et calculer ses empreintes MD5 / SHA-256."
        )

    # --- 3. Gestionnaire FAT ---
    def _add_fat_level(self, parent_item: QTreeWidgetItem, parent_entry: FATFileEntry):
        try:
            children = parent_entry.children
        except Exception:
            children = []
        sorted_children = sorted(children, key=lambda e: (not e.is_dir, e.name.lower()))
        for ch in sorted_children:
            is_del = ch.is_deleted
            status_str = t("explorer_status_deleted") if is_del else t("explorer_status_active")

            if ch.is_hidden_volume_file:
                type_str = f"🏷️ Fichier Caché 0x08 ({status_str})"
                size_str = format_size(ch.size)
                display_name = f"🏷️ {ch.name}"
            elif ch.is_dir:
                type_str = f"📁 Dossier ({status_str})"
                size_str = ""
                display_name = f"🗑️ {ch.name}" if is_del else ch.name
            else:
                type_str = f"📄 Fichier ({status_str})"
                size_str = format_size(ch.size)
                display_name = f"🗑️ {ch.name}" if is_del else ch.name

            item = QTreeWidgetItem(parent_item, [
                display_name,
                size_str,
                type_str,
                ch.modified,
                str(ch.first_cluster),
            ])
            item.setData(0, Qt.UserRole, ch)
            item.setData(0, Qt.UserRole + 2, "FAT")

            if ch.is_hidden_volume_file:
                item.setForeground(0, QBrush(QColor("#f39c12")))
                item.setForeground(2, QBrush(QColor("#e67e22")))
                item.setData(0, Qt.UserRole + 1, True)
            elif is_del:
                item.setForeground(0, QBrush(QColor("#ff6b6b")))
                item.setForeground(2, QBrush(QColor("#ffaa00")))
            elif ch.is_dir:
                item.setForeground(0, QBrush(QColor("#ffffff")))
                item.setForeground(2, QBrush(QColor("#3498db")))
            else:
                item.setForeground(0, QBrush(QColor("#ffffff")))
                item.setForeground(2, QBrush(QColor("#2ecc71")))

            if ch.is_dir:
                item.setData(0, Qt.UserRole + 1, False)
                dummy = QTreeWidgetItem(item, ["Chargement...", "", "", "", ""])
                dummy.setData(0, Qt.UserRole, None)
            else:
                item.setData(0, Qt.UserRole + 1, True)

            self.all_tree_items.append(item)

    def _populate_fat_tree(self, fat: FATReader, p: GPTPartitionEntry):
        """Construit le QTreeWidget avec l'arborescence FAT12/16/32 (Lazy-Loading)."""
        self.current_fat = fat
        root_node = fat.root_entry
        root_label = f"/ [{fat.fat_type} Root: {fat.bpb_label or p.name or 'Volume'}]"
        root_item = QTreeWidgetItem(self.tree, [root_label, "", f"Racine {fat.fat_type}", "", ""])
        root_item.setData(0, Qt.UserRole, root_node)
        root_item.setData(0, Qt.UserRole + 1, True)
        root_item.setData(0, Qt.UserRole + 2, "FAT")
        self.all_tree_items.append(root_item)

        if root_node:
            self._add_fat_level(root_item, root_node)
        root_item.setExpanded(True)

        summary_lines = [
            f"=== SYSTÈME DE FICHIERS {fat.fat_type} FORENSIQUE ===",
            f"Étiquette BPB (Boot Sector)  : '{fat.bpb_label}'",
            f"Étiquette Répertoire Racine   : '{fat.root_label or 'N/A'}'",
            f"Taille de cluster             : {fat.cluster_size} octets ({fat.sectors_per_cluster} secteurs)",
            f"Mode d'exploration           : Navigation virtuelle ultra-rapide (Lazy-Loading actif)",
        ]
        if fat.label_discrepancy:
            summary_lines.append("\n⚠️ ALERTE MÉDICO-LÉGALE (DFTT Test #9) : Discordance détectée entre l'étiquette BPB et l'étiquette Racine !")
        if fat.anomalies:
            summary_lines.append("\nAnomalies médico-légales identifiées :")
            for a in fat.anomalies:
                summary_lines.append(f"  • {a}")
        self.preview_text.setPlainText("\n".join(summary_lines))

    # --- 4. Gestionnaire Linux Ext ---
    def _add_ext_level(self, parent_item: QTreeWidgetItem, parent_entry: ExtFileEntry):
        try:
            children = parent_entry.children
        except Exception:
            children = []
        sorted_children = sorted(children, key=lambda e: (not e.is_dir, e.name.lower()))
        for ch in sorted_children:
            is_del = ch.is_deleted
            status_str = t("explorer_status_deleted") if is_del else t("explorer_status_active")
            type_str = f"📁 Dossier ({status_str})" if ch.is_dir else f"📄 Fichier ({status_str})"
            size_str = "" if ch.is_dir else format_size(ch.size)
            display_name = f"🗑️ {ch.name}" if is_del else ch.name

            item = QTreeWidgetItem(parent_item, [
                display_name,
                size_str,
                type_str,
                ch.modified,
                str(ch.inode_number),
            ])
            item.setData(0, Qt.UserRole, ch)
            item.setData(0, Qt.UserRole + 2, "EXT")

            if is_del:
                item.setForeground(0, QBrush(QColor("#ff6b6b")))
                item.setForeground(2, QBrush(QColor("#ffaa00")))
            elif ch.is_dir:
                item.setForeground(0, QBrush(QColor("#ffffff")))
                item.setForeground(2, QBrush(QColor("#3498db")))
            else:
                item.setForeground(0, QBrush(QColor("#ffffff")))
                item.setForeground(2, QBrush(QColor("#2ecc71")))

            if ch.is_dir:
                item.setData(0, Qt.UserRole + 1, False)
                dummy = QTreeWidgetItem(item, ["Chargement...", "", "", "", ""])
                dummy.setData(0, Qt.UserRole, None)
            else:
                item.setData(0, Qt.UserRole + 1, True)

            self.all_tree_items.append(item)

    def _populate_ext_tree(self, ext: ExtReader, p: GPTPartitionEntry):
        """Construit le QTreeWidget avec l'arborescence Linux Ext2/3/4 (Lazy-Loading)."""
        self.current_ext = ext
        root_node = ext.root_entry
        root_label = f"/ [Ext2/Ext3 Root: {ext.volume_name or p.name or 'Linux'}]"
        root_item = QTreeWidgetItem(self.tree, [root_label, "", "Racine Linux Ext", root_node.modified if root_node else "", "2"])
        if root_node:
            root_item.setData(0, Qt.UserRole, root_node)
        root_item.setData(0, Qt.UserRole + 1, True)
        root_item.setData(0, Qt.UserRole + 2, "EXT")
        self.all_tree_items.append(root_item)

        if root_node:
            self._add_ext_level(root_item, root_node)
        root_item.setExpanded(True)

        summary_lines = [
            f"=== SYSTÈME DE FICHIERS LINUX EXT2/EXT3/EXT4 ===",
            f"Nom de volume  : '{ext.volume_name or 'Sans nom'}'",
            f"Taille de bloc : {ext.block_size} octets",
            f"Nombre d'inodes: {ext.inodes_count:,}",
            f"Mode d'exploration : Navigation virtuelle ultra-rapide (Lazy-Loading actif)",
        ]
        self.preview_text.setPlainText("\n".join(summary_lines))

    # --- 5. Gestionnaire AD1 (FTK Imager) ---
    def _add_ad1_level(self, parent_item: QTreeWidgetItem, ad1_node):
        try:
            children = list(ad1_node.children)
        except Exception:
            children = []

        sorted_children = sorted(children, key=lambda c: (not c.is_dir(), c.name.lower()))
        for ch in sorted_children:
            is_dir = ch.is_dir()
            try:
                raw_sz = ch.size
            except Exception:
                raw_sz = getattr(getattr(ch, "entry", None), "size", 0)
            size_str = "" if is_dir else format_size(raw_sz)
            type_str = "📁 Dossier (AD1)" if is_dir else "📄 Fichier (AD1)"

            mtime_str = ""
            try:
                if ch.mtime:
                    mtime_str = ch.mtime.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                pass

            item = QTreeWidgetItem(parent_item, [
                ch.name,
                size_str,
                type_str,
                mtime_str,
                "AD1",
            ])
            item.setData(0, Qt.UserRole, ch)
            item.setData(0, Qt.UserRole + 2, "AD1")

            if is_dir:
                item.setForeground(0, QBrush(QColor("#ffffff")))
                item.setForeground(2, QBrush(QColor("#3498db")))
                item.setData(0, Qt.UserRole + 1, False)
                dummy = QTreeWidgetItem(item, ["Chargement...", "", "", "", ""])
                dummy.setData(0, Qt.UserRole, None)
            else:
                item.setForeground(0, QBrush(QColor("#e0e6ed")))
                item.setForeground(2, QBrush(QColor("#2ecc71")))
                item.setData(0, Qt.UserRole + 1, True)

            self.all_tree_items.append(item)

    def _populate_ad1_tree(self, ad1_obj, p: GPTPartitionEntry):
        """Construit l'arborescence d'un conteneur logique AD1 avec lazy loading fluide."""
        root_label = f"/ [AD1: {p.name or 'AccessData Logical Image'}]"
        root_item = QTreeWidgetItem(self.tree, [root_label, "", "Conteneur AD1", "", "AD1"])
        root_item.setData(0, Qt.UserRole, ad1_obj.root)
        root_item.setData(0, Qt.UserRole + 1, True)
        root_item.setData(0, Qt.UserRole + 2, "AD1")
        self.all_tree_items.append(root_item)

        self._add_ad1_level(root_item, ad1_obj.root)
        root_item.setExpanded(True)

        self.preview_text.setPlainText(
            f"=== CONTENEUR LOGIQUE ACCESSDATA FTK IMAGER (AD1) ===\n\n"
            f"Fichier image : {os.path.basename(self.reader.path)}\n"
            f"Segments AD1 : {len(getattr(self.reader, 'segment_paths', [1]))}\n"
            f"Mode d'exploration : Navigation virtuelle ultra-rapide (Lazy-Loading actif)\n\n"
            "Développez les dossiers pour explorer l'arborescence de manière fluide.\n"
            "Sélectionnez un fichier dans l'arborescence pour afficher ses métadonnées,\n"
            "ses hachages forensiques (MD5 / SHA-256) et prévisualiser son contenu."
        )

    # --- 6. Gestionnaire NTFS (MFT + Undelete) ---
    def _add_ntfs_level(self, parent_item: QTreeWidgetItem, parent_entry: NTFSFileEntry):
        try:
            children = parent_entry.children
        except Exception:
            children = []
        sorted_children = sorted(children, key=lambda e: (not e.is_dir, e.name.lower()))
        for ch in sorted_children:
            is_del = ch.is_deleted
            status_str = t("explorer_status_deleted") if is_del else t("explorer_status_active")
            type_str = f"📁 Dossier ({status_str})" if ch.is_dir else f"📄 Fichier ({status_str})"
            size_str = "" if ch.is_dir else format_size(ch.size)
            display_name = f"🗑️ {ch.name}" if is_del else ch.name

            item = QTreeWidgetItem(parent_item, [
                display_name,
                size_str,
                type_str,
                ch.modified,
                str(ch.record_number),
            ])
            item.setData(0, Qt.UserRole, ch)
            item.setData(0, Qt.UserRole + 2, "NTFS")

            if is_del:
                item.setForeground(0, QBrush(QColor("#ff6b6b")))
                item.setForeground(2, QBrush(QColor("#ffaa00")))
            elif ch.is_dir:
                item.setForeground(0, QBrush(QColor("#ffffff")))
                item.setForeground(2, QBrush(QColor("#3498db")))
            else:
                item.setForeground(0, QBrush(QColor("#ffffff")))
                item.setForeground(2, QBrush(QColor("#2ecc71")))

            if ch.is_dir:
                item.setData(0, Qt.UserRole + 1, False)
                dummy = QTreeWidgetItem(item, ["Chargement...", "", "", "", ""])
                dummy.setData(0, Qt.UserRole, None)
            else:
                item.setData(0, Qt.UserRole + 1, True)

            self.all_tree_items.append(item)

    def _populate_ntfs_tree(self, ntfs: NTFSReader, p: GPTPartitionEntry):
        """Construit le QTreeWidget avec la hiérarchie NTFS réelle (Lazy-Loading)."""
        self.current_ntfs = ntfs
        root_node = ntfs.root_entry
        root_label = f"/ [NTFS Root: {p.name or 'Partition'}]"
        root_item = QTreeWidgetItem(self.tree, [root_label, "", "Racine NTFS", root_node.modified if root_node else "", str(root_node.record_number) if root_node else ""])
        if root_node:
            root_item.setData(0, Qt.UserRole, root_node)
        root_item.setData(0, Qt.UserRole + 1, True)
        root_item.setData(0, Qt.UserRole + 2, "NTFS")
        self.all_tree_items.append(root_item)

        if root_node:
            self._add_ntfs_level(root_item, root_node)
        root_item.setExpanded(True)

        if ntfs.orphaned_entries:
            orphan_group = QTreeWidgetItem(self.tree, [t("explorer_orphaned_node"), "", "Conteneur Virtuel", "", ""])
            orphan_group.setForeground(0, QBrush(QColor("#e67e22")))
            self.all_tree_items.append(orphan_group)
            for orph in ntfs.orphaned_entries:
                status_str = t("explorer_status_deleted") if orph.is_deleted else t("explorer_status_active")
                type_str = f"{'📁 Dossier' if orph.is_dir else '📄 Fichier'} ({status_str})"
                item = QTreeWidgetItem(orphan_group, [
                    f"🗑️ {orph.name}" if orph.is_deleted else orph.name,
                    format_size(orph.size),
                    type_str,
                    orph.modified,
                    str(orph.record_number),
                ])
                item.setData(0, Qt.UserRole, orph)
                item.setData(0, Qt.UserRole + 1, True)
                item.setData(0, Qt.UserRole + 2, "NTFS")
                item.setForeground(0, QBrush(QColor("#ff6b6b") if orph.is_deleted else QColor("#ffffff")))
                self.all_tree_items.append(item)

        all_e = getattr(ntfs, "all_entries", getattr(ntfs, "entries", []))
        total_files = len(all_e)
        del_files = sum(1 for e in all_e if getattr(e, "is_deleted", False))
        self.preview_text.setPlainText(
            f"=== SYSTÈME DE FICHIERS NTFS MONTÉ EN MÉMOIRE (COW) ===\n\n"
            f"Cluster Size : {ntfs.cluster_size} octets\n"
            f"Taille Enregistrement MFT : {ntfs.record_size} octets\n"
            f"Total Entrées MFT Analysées : {total_files}\n"
            f"Éléments Supprimés Détectés (Undelete) : {del_files}\n"
            f"Mode d'exploration : Navigation virtuelle ultra-rapide (Lazy-Loading actif)\n\n"
            "Cliquez sur un fichier dans l'arborescence pour prévisualiser son contenu et ses hachages MD5/SHA-256."
        )

    def on_item_selected(self):
        items = self.tree.selectedItems()
        if not items:
            return
        item = items[0]
        entry = item.data(0, Qt.UserRole)

        if not entry:
            self.preview_text.setPlainText(f"Élément sélectionné : {item.text(0)}")
            return

        is_dir = entry.is_dir() if callable(getattr(entry, "is_dir", None)) else getattr(entry, "is_dir", False)
        name = getattr(entry, "name", item.text(0))

        # 1. Dossier
        if is_dir:
            children_count = len(getattr(entry, "children", []))
            if isinstance(entry, NTFSFileEntry):
                self.preview_text.setPlainText(
                    f"=== DOSSIER FORENSIQUE (NTFS) ===\n\n"
                    f"Nom : {entry.name}\n"
                    f"Enregistrement MFT : #{entry.record_number}\n"
                    f"Statut : {'🗑️ SUPPRIMÉ (Undelete)' if entry.is_deleted else '✔️ ACTIF'}\n"
                    f"Dossier Parent MFT : #{entry.parent_record_number}\n"
                    f"Date Création ($SI) : {entry.created or 'N/A'}\n"
                    f"Date Modification ($SI) : {entry.modified or 'N/A'}\n"
                    f"Date MFT Change ($SI) : {entry.mft_modified or 'N/A'}\n"
                    f"Date Dernier Accès ($SI) : {entry.accessed or 'N/A'}\n"
                    f"Nombre de sous-éléments : {children_count}\n"
                )
            elif isinstance(entry, (QNXFileEntry, APFSFileEntry)):
                fs_label = "QNX" if isinstance(entry, QNXFileEntry) else "APPLE APFS"
                mtime_str = entry.mtime.strftime("%Y-%m-%d %H:%M:%S") if getattr(entry, "mtime", None) else "N/A"
                self.preview_text.setPlainText(
                    f"=== DOSSIER FORENSIQUE ({fs_label}) ===\n\n"
                    f"Nom : {name}\n"
                    f"Chemin virtuel : {getattr(entry, 'path', name)}\n"
                    f"Date Modification : {mtime_str}\n"
                    f"Nombre de sous-éléments directs : {children_count}\n"
                )
            else:
                mtime_str = ""
                try:
                    if entry.mtime:
                        mtime_str = entry.mtime.strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    pass
                self.preview_text.setPlainText(
                    f"=== DOSSIER FORENSIQUE (ARCHIVE / SYSTÈME) ===\n\n"
                    f"Nom : {name}\n"
                    f"Date Modification : {mtime_str or 'N/A'}\n"
                    f"Nombre de sous-éléments directs : {children_count}\n"
                )
            return

        # 2. Fichier
        content = b""
        size = 0
        md5_hash = "N/A"
        sha256_hash = "N/A"

        if isinstance(entry, NTFSFileEntry):
            if self.current_ntfs:
                content = self.current_ntfs.extract_file_content(entry)
            size = entry.size
            if content:
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()

            meta_header = (
                f"=== MÉTADONNÉES FORENSIQUES DU FICHIER (NTFS) ===\n\n"
                f"Nom de fichier : {entry.name}\n"
                f"Enregistrement MFT : #{entry.record_number} (Séquence : {entry.sequence_number})\n"
                f"Statut : {'🗑️ SUPPRIMÉ / EFFACÉ (Récupéré par Undelete)' if entry.is_deleted else '✔️ ACTIF (Alloué)'}\n"
                f"Taille Réelle : {entry.size:,} octets ({format_size(entry.size)})\n"
                f"Taille Allouée : {entry.allocated_size:,} octets\n"
                f"Stockage : {'Résident dans le record MFT ($DATA resident)' if entry.is_resident else f'Non-résident ({len(entry.data_runs)} runs de clusters)'}\n"
                f"Horodatage Création ($SI) : {entry.created or 'N/A'}\n"
                f"Horodatage Modifié ($SI)  : {entry.modified or 'N/A'}\n"
                f"Horodatage MFT ($SI)      : {entry.mft_modified or 'N/A'}\n"
                f"Horodatage Accès ($SI)    : {entry.accessed or 'N/A'}\n\n"
                f"Empreinte MD5    : {md5_hash}\n"
                f"Empreinte SHA-256: {sha256_hash}\n\n"
                f"--------------------------------------------------------------------------------\n"
            )
        elif isinstance(entry, FATFileEntry):
            if self.current_fat:
                content = self.current_fat.extract_file_content(entry)
            size = entry.size
            if content:
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()

            anomaly_alert = ""
            if entry.is_hidden_volume_file:
                anomaly_alert = "\n⚠️ ANOMALIE FORENSIQUE (DFTT Test #9) : Fichier dissimulé sous attribut 0x08 (Volume Label) avec clusters alloués !\n"

            meta_header = (
                f"=== MÉTADONNÉES FORENSIQUES DU FICHIER (FAT) ===\n\n"
                f"Nom de fichier : {entry.name}\n"
                f"Premier Cluster: #{entry.first_cluster}\n"
                f"Statut : {'🗑️ SUPPRIMÉ / EFFACÉ' if entry.is_deleted else '✔️ ACTIF'}\n"
                f"Taille Réelle : {entry.size:,} octets ({format_size(entry.size)})\n"
                f"Horodatage Création : {entry.created or 'N/A'}\n"
                f"Horodatage Modifié  : {entry.modified or 'N/A'}\n"
                f"Horodatage Accès    : {entry.accessed or 'N/A'}\n"
                f"{anomaly_alert}\n"
                f"Empreinte MD5    : {md5_hash}\n"
                f"Empreinte SHA-256: {sha256_hash}\n\n"
                f"--------------------------------------------------------------------------------\n"
            )
        elif isinstance(entry, ExtFileEntry):
            if self.current_ext:
                content = self.current_ext.extract_file_content(entry)
            size = entry.size
            if content:
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()

            meta_header = (
                f"=== MÉTADONNÉES FORENSIQUES DU FICHIER (LINUX EXT) ===\n\n"
                f"Nom de fichier : {entry.name}\n"
                f"Numéro d'Inode : #{entry.inode_number}\n"
                f"UID / GID      : {entry.uid} / {entry.gid}\n"
                f"Mode POSIX     : {oct(entry.mode)}\n"
                f"Statut : {'🗑️ SUPPRIMÉ' if entry.is_deleted else '✔️ ACTIF'}\n"
                f"Taille Réelle : {entry.size:,} octets ({format_size(entry.size)})\n"
                f"Horodatage Inode/Création : {entry.created or 'N/A'}\n"
                f"Horodatage Modifié        : {entry.modified or 'N/A'}\n"
                f"Horodatage Accès          : {entry.accessed or 'N/A'}\n\n"
                f"Empreinte MD5    : {md5_hash}\n"
                f"Empreinte SHA-256: {sha256_hash}\n\n"
                f"--------------------------------------------------------------------------------\n"
            )
        elif isinstance(entry, QNXFileEntry):
            if self.current_qnx:
                content = self.current_qnx.extract_file_content(entry)
            size = entry.size
            if content:
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()

            mtime_str = entry.mtime.strftime("%Y-%m-%d %H:%M:%S") if entry.mtime else "N/A"
            meta_header = (
                f"=== MÉTADONNÉES FORENSIQUES DU FICHIER (QNX EMBARQUÉ) ===\n\n"
                f"Nom de fichier : {entry.name}\n"
                f"Chemin virtuel : {entry.path}\n"
                f"Statut : ✔️ ACTIF\n"
                f"Taille Réelle : {entry.size:,} octets ({format_size(entry.size)})\n"
                f"Horodatage Modifié : {mtime_str}\n\n"
                f"Empreinte MD5    : {md5_hash}\n"
                f"Empreinte SHA-256: {sha256_hash}\n\n"
                f"--------------------------------------------------------------------------------\n"
            )
        elif isinstance(entry, APFSFileEntry):
            if self.current_apfs:
                content = self.current_apfs.extract_file_content(entry)
            size = entry.size
            if content:
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()

            mtime_str = entry.mtime.strftime("%Y-%m-%d %H:%M:%S") if entry.mtime else "N/A"
            meta_header = (
                f"=== MÉTADONNÉES FORENSIQUES DU FICHIER (APPLE APFS) ===\n\n"
                f"Nom de fichier : {entry.name}\n"
                f"Chemin virtuel : {entry.path}\n"
                f"Statut : ✔️ ACTIF\n"
                f"Taille Réelle : {entry.size:,} octets ({format_size(entry.size)})\n"
                f"Horodatage Modifié : {mtime_str}\n\n"
                f"Empreinte MD5    : {md5_hash}\n"
                f"Empreinte SHA-256: {sha256_hash}\n\n"
                f"--------------------------------------------------------------------------------\n"
            )
        else:
            # AD1 FileEntry
            raw_sz = getattr(entry, "size", None)
            if raw_sz is None:
                raw_sz = getattr(getattr(entry, "entry", None), "size", 0)
            size = raw_sz or 0

            md5_hash = "N/A"
            sha256_hash = "N/A"
            if hasattr(entry, "md5") and entry.md5:
                md5_hash = str(entry.md5)
            if hasattr(entry, "sha256") and entry.sha256:
                sha256_hash = str(entry.sha256)

            content = b""
            try:
                with entry.open() as f_ad1:
                    if size > 10 * 1024 * 1024:
                        content = f_ad1.read(65536)
                        if md5_hash == "N/A":
                            md5_hash = "(Fichier volumineux > 10 Mo - calculé lors de l'exportation)"
                            sha256_hash = "(Fichier volumineux > 10 Mo - calculé lors de l'exportation)"
                    else:
                        content = f_ad1.read()
                        if content and md5_hash == "N/A":
                            md5_hash = hashlib.md5(content).hexdigest()
                            sha256_hash = hashlib.sha256(content).hexdigest()
            except Exception:
                content = b""

            c_time = getattr(entry, "ctime", None)
            m_time = getattr(entry, "mtime", None)
            a_time = getattr(entry, "atime", None)
            c_str = c_time.strftime("%Y-%m-%d %H:%M:%S UTC") if c_time else "N/A"
            m_str = m_time.strftime("%Y-%m-%d %H:%M:%S UTC") if m_time else "N/A"
            a_str = a_time.strftime("%Y-%m-%d %H:%M:%S UTC") if a_time else "N/A"

            meta_header = (
                f"=== MÉTADONNÉES FORENSIQUES DU FICHIER (ACCESSDATA AD1) ===\n\n"
                f"Nom de fichier : {name}\n"
                f"Format Source : Archive Logique FTK Imager (AD1)\n"
                f"Taille Décompressée : {size:,} octets ({format_size(size)})\n"
                f"Horodatage Création : {c_str}\n"
                f"Horodatage Modifié  : {m_str}\n"
                f"Horodatage Accès    : {a_str}\n\n"
                f"Empreinte MD5    : {md5_hash}\n"
                f"Empreinte SHA-256: {sha256_hash}\n\n"
                f"--------------------------------------------------------------------------------\n"
            )

        # Déterminer si le contenu est texte affichable
        is_text = False
        text_preview = ""
        if content:
            try:
                printable_count = sum(1 for b in content[:1024] if 32 <= b <= 126 or b in (9, 10, 13))
                if printable_count / min(len(content), 1024) > 0.85:
                    text_preview = content[:2048].decode("utf-8", errors="replace")
                    is_text = True
            except Exception:
                is_text = False

        if not content:
            body = "[Fichier vide ou sans données allouées]"
        elif is_text:
            body = f"--- APERÇU TEXTUEL (UTF-8 / ASCII) ---\n\n{text_preview}"
        else:
            body = f"--- DUMP HEXADÉCIMAL FORENSIQUE (Premier secteur / en-tête) ---\n\n{format_hex_dump(content)}"

        self.preview_text.setPlainText(meta_header + body)

    def export_selected_file(self):
        items = self.tree.selectedItems()
        if not items:
            QMessageBox.warning(self, "Sélection requise", "Veuillez sélectionner un fichier à exporter.")
            return

        entry = items[0].data(0, Qt.UserRole)
        if not entry:
            QMessageBox.warning(self, "Extraction non supportée", "Veuillez sélectionner un fichier valide.")
            return

        is_dir = entry.is_dir() if callable(getattr(entry, "is_dir", None)) else getattr(entry, "is_dir", False)
        if is_dir:
            QMessageBox.information(self, "Dossier sélectionné", "L'exportation directe est réservée aux fichiers. Sélectionnez un fichier individuel.")
            return

        clean_name = getattr(entry, "name", "extracted_file").replace("🗑️", "").strip()
        out_path, _ = QFileDialog.getSaveFileName(self, "Enregistrer l'artefact extrait", clean_name, "Tous les fichiers (*.*)")
        if not out_path:
            return

        # 1. Cas spécifique AD1 : streaming par blocs de 1 Mo pour supporter les fichiers de plusieurs Go
        if not isinstance(entry, (NTFSFileEntry, FATFileEntry, ExtFileEntry, QNXFileEntry, APFSFileEntry)):
            hasher_md5 = hashlib.md5()
            hasher_sha = hashlib.sha256()
            total_written = 0
            try:
                with entry.open() as f_ad1, open(out_path, "wb") as f_out:
                    while True:
                        chunk = f_ad1.read(1024 * 1024)
                        if not chunk:
                            break
                        f_out.write(chunk)
                        hasher_md5.update(chunk)
                        hasher_sha.update(chunk)
                        total_written += len(chunk)
            except Exception as e:
                QMessageBox.critical(self, "Erreur d'extraction", f"Impossible d'extraire le fichier de l'archive :\n\n{e}")
                return

            if total_written == 0:
                QMessageBox.warning(self, "Fichier vide", t("explorer_export_empty_msg"))
                return

            msg = t("explorer_export_success_msg", path=out_path, size=total_written, md5=hasher_md5.hexdigest(), sha256=hasher_sha.hexdigest())
            QMessageBox.information(self, t("explorer_export_success_title"), msg)
            return

        # 2. Autres systèmes de fichiers
        content = b""
        if isinstance(entry, NTFSFileEntry):
            if self.current_ntfs:
                content = self.current_ntfs.extract_file_content(entry)
        elif isinstance(entry, FATFileEntry):
            if self.current_fat:
                content = self.current_fat.extract_file_content(entry)
        elif isinstance(entry, ExtFileEntry):
            if self.current_ext:
                content = self.current_ext.extract_file_content(entry)
        elif isinstance(entry, QNXFileEntry):
            if self.current_qnx:
                content = self.current_qnx.extract_file_content(entry)
        elif isinstance(entry, APFSFileEntry):
            if self.current_apfs:
                content = self.current_apfs.extract_file_content(entry)

        if not content:
            QMessageBox.warning(self, "Fichier vide", t("explorer_export_empty_msg"))
            return

        with open(out_path, "wb") as f:
            f.write(content)

        md5 = hashlib.md5(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        msg = t("explorer_export_success_msg", path=out_path, size=len(content), md5=md5, sha256=sha256)
        QMessageBox.information(self, t("explorer_export_success_title"), msg)

    def on_click_unlock_partition(self):
        """Ouvre le dialogue de déverrouillage cryptographique pour la partition sélectionnée."""
        p = self.combo_parts.currentData()
        if not p:
            return
        part_key = p.first_lba
        handler = self.crypto_handlers.get(part_key)
        if not handler or not handler.is_encrypted:
            return

        dlg = UnlockVolumeDialog(handler, p, self)
        if dlg.exec():
            if handler.is_unlocked:
                self.load_partition_tree(p)

    def on_export_partition_clicked(self):
        """Exporte l'intégralité de la partition (brute ou déchiffrée) vers un fichier .dd/.raw avec hachages et audit."""
        p = self.combo_parts.currentData()
        if not p:
            QMessageBox.warning(self, "Exportation de Partition", "Aucune partition sélectionnée.")
            return

        part_key = p.first_lba
        handler = self.crypto_handlers.get(part_key)
        decrypted_reader = None

        if handler and handler.is_unlocked:
            reply = QMessageBox.question(
                self,
                "Mode d'exportation forensique",
                f"La partition '{p.name or 'Volume'}' est actuellement déverrouillée.\n\n"
                "Souhaitez-vous exporter le volume DÉCHIFFRÉ ?\n\n"
                "• [Oui] : Exporter le système de fichiers déchiffré\n"
                "• [Non] : Exporter les secteurs bruts chiffrés originaux",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Yes,
            )
            if reply == QMessageBox.Cancel:
                return
            if reply == QMessageBox.Yes:
                decrypted_reader = handler.decrypted_reader

        clean_name = "".join(c for c in (p.name or "partition") if c.isalnum() or c in "_-")
        default_name = f"partition_{clean_name}_{p.first_lba}{'_decrypted' if decrypted_reader else ''}.dd"
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
            decrypted_reader=decrypted_reader,
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

    def on_carve_partition_clicked(self):
        """Ouvre l'outil de carving médico-légal ciblé sur la partition actuellement sélectionnée."""
        p = self.combo_parts.currentData()
        if not p:
            QMessageBox.warning(self, "Carving", "Aucune partition sélectionnée.")
            return

        part_key = p.first_lba
        handler = self.crypto_handlers.get(part_key)
        active_reader = self.reader
        if handler and handler.is_unlocked and handler.decrypted_reader:
            active_reader = handler.decrypted_reader

        from ui.carver_dialog import CarverDialog
        dlg = CarverDialog(
            reader=active_reader,
            diag=self.diag,
            parent=self,
            initial_lba_range=(p.first_lba, p.last_lba),
        )
        dlg.exec()

