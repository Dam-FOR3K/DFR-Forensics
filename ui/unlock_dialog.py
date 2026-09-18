"""
DFR-Forensics - Dialogue de Déverrouillage Cryptographique (LUKS / BitLocker)
Fournit une interface intuitive et sécurisée pour déverrouiller des conteneurs chiffrés.
"""

import os
from typing import Optional, Dict, Any
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QButtonGroup,
    QFileDialog,
    QFrame,
    QApplication,
    QMessageBox,
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QIcon

from core.crypto_engine import EncryptedVolumeHandler
from core.gpt_structures import GPTPartitionEntry
from core.i18n import t


class CryptoUnlockWorker(QThread):
    """Thread d'arrière-plan pour dériver les clés KDF (Argon2 / PBKDF2) sans figer l'interface."""

    finished_signal = Signal(bool, str)  # (success, error_message)

    def __init__(self, handler: EncryptedVolumeHandler, mode: str, credential: str):
        super().__init__()
        self.handler = handler
        self.mode = mode  # "passphrase", "recovery", "keyfile"
        self.credential = credential

    def run(self):
        try:
            if self.mode == "passphrase":
                ok, err = self.handler.unlock_with_passphrase(self.credential)
            elif self.mode == "recovery":
                ok, err = self.handler.unlock_with_recovery_password(self.credential)
            elif self.mode == "keyfile":
                ok, err = self.handler.unlock_with_key_file(self.credential)
            elif self.mode == "windows":
                ok, err = self.handler.unlock_with_windows_volume(self.credential)
            else:
                ok, err = False, "Mode de déverrouillage inconnu."

            self.finished_signal.emit(ok, err or "")
        except Exception as e:
            self.finished_signal.emit(False, str(e))


class UnlockVolumeDialog(QDialog):
    """Boîte de dialogue permettant à l'analyste de fournir les identifiants de déverrouillage."""

    def __init__(self, handler: EncryptedVolumeHandler, partition: GPTPartitionEntry, parent=None):
        super().__init__(parent)
        self.handler = handler
        self.partition = partition
        self.worker: Optional[CryptoUnlockWorker] = None

        self.setWindowTitle("Déverrouillage Cryptographique Forensique")
        self.resize(580, 480)

        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if not os.path.exists(icon_path):
            icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.setStyleSheet(
            """
            QDialog {
                background-color: #1a1c23;
                color: #e2e8f0;
            }
            QLabel {
                color: #e2e8f0;
            }
            QLineEdit {
                background-color: #0f1117;
                color: #00ffcc;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 8px;
                font-family: Consolas, monospace;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #00d2ff;
            }
            QRadioButton {
                color: #cbd5e1;
                font-size: 13px;
                spacing: 6px;
            }
            QRadioButton::indicator:checked {
                background-color: #00d2ff;
                border: 2px solid #00d2ff;
            }
            QPushButton {
                padding: 8px 18px;
                border-radius: 4px;
                font-size: 13px;
                font-weight: bold;
            }
            """
        )

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # 1. En-tête
        hdr_layout = QHBoxLayout()
        lbl_icon = QLabel("🔒")
        lbl_icon.setFont(QFont("Segoe UI Emoji", 24))
        hdr_layout.addWidget(lbl_icon)

        v_titles = QVBoxLayout()
        lbl_title = QLabel(f"<b>Volume Chiffré Détecté : {self.handler.crypto_type}</b>")
        lbl_title.setStyleSheet("font-size: 16px; color: #00d2ff;")
        v_titles.addWidget(lbl_title)

        lbl_sub = QLabel(f"Partition : {self.partition.name or 'Volume'} (LBA {self.partition.first_lba:,} à {self.partition.last_lba:,})")
        lbl_sub.setStyleSheet("font-size: 12px; color: #94a3b8;")
        v_titles.addWidget(lbl_sub)
        hdr_layout.addLayout(v_titles)
        hdr_layout.addStretch()
        layout.addLayout(hdr_layout)

        # 2. Carte d'informations techniques
        info_frame = QFrame()
        info_frame.setStyleSheet("background-color: #12141a; border: 1px solid #282c3c; border-radius: 6px; padding: 10px;")
        info_vbox = QVBoxLayout(info_frame)
        info_vbox.setSpacing(4)

        meta = self.handler.metadata
        if meta.get("uuid"):
            lbl_uuid = QLabel(f"<b>UUID :</b> <code style='color:#38bdf8;'>{meta['uuid']}</code>")
            lbl_uuid.setTextFormat(Qt.RichText)
            info_vbox.addWidget(lbl_uuid)

        if meta.get("encryption"):
            lbl_enc = QLabel(f"<b>Chiffrement :</b> {meta['encryption']}")
            info_vbox.addWidget(lbl_enc)

        if meta.get("slots_detail"):
            slots_str = ", ".join(meta["slots_detail"])
            lbl_slots = QLabel(f"<b>Keyslots :</b> {slots_str}")
            lbl_slots.setWordWrap(True)
            info_vbox.addWidget(lbl_slots)

        if meta.get("version"):
            lbl_ver = QLabel(f"<b>Version BitLocker :</b> {meta['version']}")
            info_vbox.addWidget(lbl_ver)

        layout.addWidget(info_frame)

        # 3. Sélecteur de méthode d'authentification
        layout.addWidget(QLabel("<b>Sélectionnez la méthode de déverrouillage :</b>"))

        self.btn_group = QButtonGroup(self)

        has_win_unlocked = self.handler.metadata.get("windows_is_unlocked", False)
        win_letter = self.handler.metadata.get("windows_drive_letter", "")
        self.radio_windows = None
        if has_win_unlocked and win_letter:
            self.radio_windows = QRadioButton(f"⚡ Session Windows active (Lecteur {win_letter} déjà déverrouillé)")
            self.radio_windows.setStyleSheet("color: #4ade80; font-weight: bold; font-size: 13px;")
            self.btn_group.addButton(self.radio_windows)
            layout.addWidget(self.radio_windows)
            self.radio_windows.toggled.connect(self.on_mode_changed)

        self.radio_passphrase = QRadioButton("Phrase secrète / Mot de passe (Passphrase)")
        if not self.radio_windows:
            self.radio_passphrase.setChecked(True)
        else:
            self.radio_windows.setChecked(True)
        self.btn_group.addButton(self.radio_passphrase)
        layout.addWidget(self.radio_passphrase)

        self.radio_recovery = QRadioButton("Clé de récupération numérique (48 chiffres - BitLocker)")
        self.btn_group.addButton(self.radio_recovery)
        if self.handler.crypto_type == "BitLocker":
            layout.addWidget(self.radio_recovery)
        else:
            self.radio_recovery.setVisible(False)

        self.radio_keyfile = QRadioButton("Fichier de clé (Key file / Fichier .BEK)")
        self.btn_group.addButton(self.radio_keyfile)
        layout.addWidget(self.radio_keyfile)

        self.radio_passphrase.toggled.connect(self.on_mode_changed)
        self.radio_recovery.toggled.connect(self.on_mode_changed)
        self.radio_keyfile.toggled.connect(self.on_mode_changed)

        # 4. Champ de saisie dynamique
        self.input_container = QVBoxLayout()

        # Input Passphrase / Recovery Key
        self.pass_layout = QHBoxLayout()
        self.edit_secret = QLineEdit()
        self.edit_secret.setEchoMode(QLineEdit.Password)
        self.edit_secret.setPlaceholderText("Entrez la phrase secrète ou le mot de passe...")
        self.pass_layout.addWidget(self.edit_secret)

        self.btn_toggle_eye = QPushButton("👁")
        self.btn_toggle_eye.setFixedWidth(42)
        self.btn_toggle_eye.setStyleSheet("background-color: #334155; color: #fff; padding: 6px;")
        self.btn_toggle_eye.setCheckable(True)
        self.btn_toggle_eye.clicked.connect(self.toggle_echo_mode)
        self.pass_layout.addWidget(self.btn_toggle_eye)

        self.input_container.addLayout(self.pass_layout)

        # Input Fichier Clé (initialement masqué)
        self.file_layout = QHBoxLayout()
        self.edit_file_path = QLineEdit()
        self.edit_file_path.setPlaceholderText("Sélectionnez le fichier clé (.bek, .key, .raw)...")
        self.edit_file_path.setReadOnly(True)
        self.file_layout.addWidget(self.edit_file_path)

        self.btn_browse_key = QPushButton("Parcourir...")
        self.btn_browse_key.setStyleSheet("background-color: #3b82f6; color: #fff;")
        self.btn_browse_key.clicked.connect(self.browse_key_file)
        self.file_layout.addWidget(self.btn_browse_key)

        self.widget_file = QFrame()
        self.widget_file.setLayout(self.file_layout)
        self.widget_file.setVisible(False)
        self.input_container.addWidget(self.widget_file)

        layout.addLayout(self.input_container)

        # Message d'état / Erreur
        self.lbl_status = QLabel("")
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 12px;")
        layout.addWidget(self.lbl_status)

        layout.addStretch()

        # 5. Boutons d'action
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.btn_cancel = QPushButton("Annuler")
        self.btn_cancel.setStyleSheet("background-color: #475569; color: #fff;")
        self.btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_cancel)

        self.btn_unlock = QPushButton("🔓 Déverrouiller le volume")
        self.btn_unlock.setStyleSheet("background-color: #10b981; color: #fff; padding: 8px 22px;")
        self.btn_unlock.clicked.connect(self.start_unlock)
        btn_layout.addWidget(self.btn_unlock)

        layout.addLayout(btn_layout)

    def on_mode_changed(self):
        if getattr(self, "radio_windows", None) and self.radio_windows.isChecked():
            self.pass_layout.itemAt(0).widget().setVisible(False)
            self.pass_layout.itemAt(1).widget().setVisible(False)
            self.widget_file.setVisible(False)
            win_let = self.handler.metadata.get("windows_drive_letter", "Windows")
            self.lbl_status.setText(f"Prêt à utiliser les flux déchiffrés du lecteur Windows ({win_let}).")
        elif self.radio_passphrase.isChecked():
            self.pass_layout.itemAt(0).widget().setVisible(True)
            self.pass_layout.itemAt(1).widget().setVisible(True)
            self.widget_file.setVisible(False)
            self.edit_secret.setPlaceholderText("Entrez la phrase secrète ou le mot de passe...")
            self.lbl_status.setText("")
        elif self.radio_recovery.isChecked():
            self.pass_layout.itemAt(0).widget().setVisible(True)
            self.pass_layout.itemAt(1).widget().setVisible(True)
            self.widget_file.setVisible(False)
            self.edit_secret.setPlaceholderText("Entrez la clé de récupération (ex: 123456-123456-...)")
            self.lbl_status.setText("")
        elif self.radio_keyfile.isChecked():
            self.pass_layout.itemAt(0).widget().setVisible(False)
            self.pass_layout.itemAt(1).widget().setVisible(False)
            self.widget_file.setVisible(True)
            self.lbl_status.setText("")

    def toggle_echo_mode(self):
        if self.btn_toggle_eye.isChecked():
            self.edit_secret.setEchoMode(QLineEdit.Normal)
        else:
            self.edit_secret.setEchoMode(QLineEdit.Password)

    def browse_key_file(self):
        filter_str = "Fichiers Clés (*.bek *.key *.bin *.raw);;Tous les fichiers (*.*)"
        path, _ = QFileDialog.getOpenFileName(self, "Sélectionner un fichier de clé", "", filter_str)
        if path:
            self.edit_file_path.setText(path)

    def start_unlock(self):
        mode = "passphrase"
        cred = ""

        if getattr(self, "radio_windows", None) and self.radio_windows.isChecked():
            mode = "windows"
            cred = self.handler.metadata.get("windows_drive_letter", "")
        elif self.radio_passphrase.isChecked():
            mode = "passphrase"
            cred = self.edit_secret.text().strip()
            if not cred:
                self.lbl_status.setText("Veuillez saisir un mot de passe ou une phrase secrète.")
                return
        elif self.radio_recovery.isChecked():
            mode = "recovery"
            cred = self.edit_secret.text().strip()
            if not cred:
                self.lbl_status.setText("Veuillez saisir la clé de récupération numérique.")
                return
        elif self.radio_keyfile.isChecked():
            mode = "keyfile"
            cred = self.edit_file_path.text().strip()
            if not cred or not os.path.exists(cred):
                self.lbl_status.setText("Veuillez sélectionner un fichier de clé valide.")
                return

        self.lbl_status.setStyleSheet("color: #38bdf8; font-weight: bold;")
        self.lbl_status.setText("⏳ Dérivation cryptographique et vérification en cours...")
        self.btn_unlock.setEnabled(False)
        self.btn_cancel.setEnabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)

        self.worker = CryptoUnlockWorker(self.handler, mode, cred)
        self.worker.finished_signal.connect(self.on_unlock_finished)
        self.worker.start()

    def on_unlock_finished(self, success: bool, error_msg: str):
        QApplication.restoreOverrideCursor()
        self.btn_unlock.setEnabled(True)
        self.btn_cancel.setEnabled(True)

        if success:
            self.lbl_status.setStyleSheet("color: #10b981; font-weight: bold;")
            self.lbl_status.setText("✅ Volume déverrouillé avec succès !")
            self.accept()
        else:
            self.lbl_status.setStyleSheet("color: #ef4444; font-weight: bold;")
            self.lbl_status.setText(f"❌ {error_msg}")
