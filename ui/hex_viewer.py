"""
WipeRescue-Forensics - Inspecteur hexadécimal de secteurs LBA
Visualise n'importe quel secteur au format 'xxd' avec sauts rapides,
détection de signatures (APFS, LUKS, NTFS, MBR, GPT) et synchronisation bidirectionnelle.
"""

from typing import Optional
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QSpinBox,
    QPushButton,
    QTextEdit,
    QComboBox,
    QAbstractItemView,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor
from core.image_reader import ForensicImageReader
from core.scanner import ScanDiagnostic
from core.i18n import t, get_lang


class HexViewer(QWidget):
    """Inspecteur hexadécimal de secteurs LBA."""

    lba_navigated = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.reader: Optional[ForensicImageReader] = None
        self.diag: Optional[ScanDiagnostic] = None
        self.current_lba: int = 0

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(6)

        # Barre supérieure : Contrôle LBA et raccourcis
        ctrl_layout = QHBoxLayout()

        self.lbl_lba = QLabel(t("hex_lba_label"))
        self.lbl_lba.setStyleSheet("color: #00d2ff; font-weight: bold; font-size: 12px;")
        ctrl_layout.addWidget(self.lbl_lba)

        self.spin_lba = QSpinBox()
        self.spin_lba.setRange(0, 0)
        self.spin_lba.setValue(0)
        self.spin_lba.setMinimumWidth(160)
        self.spin_lba.setStyleSheet(
            """
            QSpinBox {
                background-color: #222530;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #444;
                border-radius: 3px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                font-weight: bold;
            }
            """
        )
        self.spin_lba.valueChanged.connect(self.on_lba_changed)
        ctrl_layout.addWidget(self.spin_lba)

        self.btn_prev = QPushButton(t("hex_btn_prev"))
        self.btn_prev.setStyleSheet("padding: 5px 10px;")
        self.btn_prev.clicked.connect(self.prev_sector)
        ctrl_layout.addWidget(self.btn_prev)

        self.btn_next = QPushButton(t("hex_btn_next"))
        self.btn_next.setStyleSheet("padding: 5px 10px;")
        self.btn_next.clicked.connect(self.next_sector)
        ctrl_layout.addWidget(self.btn_next)

        ctrl_layout.addSpacing(20)

        # Menu déroulant de sauts rapides forensiques (très lisible et spacieux)
        self.lbl_jump = QLabel(t("hex_jump_label"))
        self.lbl_jump.setStyleSheet("color: #ffaa00; font-weight: bold; font-size: 12px;")
        ctrl_layout.addWidget(self.lbl_jump)

        self.combo_jump = QComboBox()
        self.combo_jump.setMinimumWidth(460)
        self.combo_jump.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.combo_jump.setStyleSheet(
            """
            QComboBox {
                background-color: #222530;
                color: #ffffff;
                padding: 5px 10px;
                border: 1px solid #555;
                border-radius: 4px;
                font-size: 12px;
            }
            QComboBox QAbstractItemView {
                background-color: #1a1c24;
                color: #ffffff;
                selection-background-color: #0088cc;
                border: 1px solid #555;
                padding: 4px;
                min-width: 500px;
            }
            """
        )
        self.combo_jump.view().setTextElideMode(Qt.ElideNone)
        self.combo_jump.currentIndexChanged.connect(self.on_jump_selected)
        ctrl_layout.addWidget(self.combo_jump)

        ctrl_layout.addStretch()
        layout.addLayout(ctrl_layout)

        # Zone d'affichage Hexadécimal
        self.text_hex = QTextEdit()
        self.text_hex.setReadOnly(True)
        self.text_hex.setFont(QFont("Consolas", 10))
        self.text_hex.setStyleSheet(
            """
            QTextEdit {
                background-color: #10121a;
                color: #00ffcc;
                border: 1px solid #2d3142;
                font-family: 'Consolas', 'Courier New', monospace;
                line-height: 1.3;
            }
            """
        )
        layout.addWidget(self.text_hex)

    def set_reader_and_diag(self, reader: ForensicImageReader, diag: ScanDiagnostic):
        self.reader = reader
        self.diag = diag
        self.spin_lba.setRange(0, max(0, reader.total_sectors - 1))
        self.populate_jump_menu()
        self.load_sector(0)

    def populate_jump_menu(self):
        self.combo_jump.blockSignals(True)
        self.combo_jump.clear()
        self.combo_jump.addItem(t("hex_jump_default"), None)
        self.combo_jump.addItem(t("hex_jump_mbr"), 0)
        self.combo_jump.addItem(t("hex_jump_primary_hdr"), 1)
        self.combo_jump.addItem(t("hex_jump_primary_tbl"), 2)

        if self.diag:
            if self.diag.wipe_frontier_lba and self.diag.wipe_frontier_lba > 0:
                self.combo_jump.addItem(
                    t("hex_jump_wipe_frontier", lba=self.diag.wipe_frontier_lba),
                    self.diag.wipe_frontier_lba,
                )

            for idx, p in enumerate(self.diag.partitions, 1):
                fs_label = p.detected_fs or p.type_name
                label = f"📁 Part {idx} : {p.name or 'Partition'} (LBA {p.first_lba:,}) [{fs_label}]"
                self.combo_jump.addItem(label, p.first_lba)

            if self.diag.backup_gpt_present and self.diag.backup_gpt_header:
                b_hdr_lba = self.diag.backup_gpt_header.partition_entries_lba
                last_lba = self.diag.total_sectors - 1
                self.combo_jump.addItem(t("hex_jump_backup_tbl", lba=b_hdr_lba), b_hdr_lba)
                self.combo_jump.addItem(t("hex_jump_backup_hdr", lba=last_lba), last_lba)

        self.combo_jump.blockSignals(False)

    def on_jump_selected(self, index: int):
        lba = self.combo_jump.currentData()
        if lba is not None:
            self.spin_lba.setValue(lba)

    def on_lba_changed(self, value: int):
        self.load_sector(value)
        self.lba_navigated.emit(value)

    def prev_sector(self):
        if self.spin_lba.value() > 0:
            self.spin_lba.setValue(self.spin_lba.value() - 1)

    def next_sector(self):
        if self.spin_lba.value() < self.spin_lba.maximum():
            self.spin_lba.setValue(self.spin_lba.value() + 1)

    def retranslate_ui(self):
        """Met à jour instantanément les textes dans la langue active."""
        self.lbl_lba.setText(t("hex_lba_label"))
        self.btn_prev.setText(t("hex_btn_prev"))
        self.btn_next.setText(t("hex_btn_next"))
        self.lbl_jump.setText(t("hex_jump_label"))
        curr_idx = self.combo_jump.currentIndex()
        self.populate_jump_menu()
        if 0 <= curr_idx < self.combo_jump.count():
            self.combo_jump.setCurrentIndex(curr_idx)
        if self.reader:
            self.load_sector(self.current_lba)

    def load_sector(self, lba: int):
        self.current_lba = lba
        if not self.reader:
            self.text_hex.setPlainText(t("hex_no_image"))
            return

        try:
            data = self.reader.read_sector(lba)
        except Exception as e:
            self.text_hex.setPlainText(t("hex_read_error", lba=lba, error=str(e)))
            return

        # Rendu formaté style 'xxd'
        lines = []
        lines.append(t("hex_sector_title", lba=lba, offset=lba * self.reader.sector_size))

        # Détection immédiate du contenu
        is_all_zeros = data == b"\x00" * len(data)
        if is_all_zeros:
            lines.append(t("hex_sector_wiped") + "\n")
        elif data.startswith(b"EFI PART"):
            sig_name = "EFI PART (UEFI GPT Header)" if get_lang() == "en" else "EFI PART (En-tête GPT UEFI)"
            lines.append(t("hex_sig_detected", sig=sig_name) + "\n")
        elif data.startswith(b"NXSB"):
            lines.append(t("hex_sig_detected", sig="Apple APFS Container Superblock (NXSB)") + "\n")
        elif data.startswith(b"LUKS\xba\xbe"):
            lines.append(t("hex_sig_detected", sig="LUKS Encrypted Container") + "\n")
        elif b"NTFS    " in data[:8]:
            lines.append(t("hex_sig_detected", sig="NTFS Boot Sector") + "\n")
        elif data[510:512] == b"\x55\xaa":
            lines.append(t("hex_sig_mbr") + "\n")
        else:
            lines.append("")

        for offset in range(0, len(data), 16):
            chunk = data[offset : offset + 16]
            # Hex bytes
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            # ASCII part
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{offset:08x}:  {hex_part:<48}  |{ascii_part}|")

        self.text_hex.setPlainText("\n".join(lines))
