"""
DFR-Forensics - Widget graphique de cartographie spatiale interactive du disque
Affiche la disposition des partitions, l'aiguille de lecture synchronisée avec l'inspecteur hexadécimal,
un zoom progressif multidirectionnel (molette, boutons +/-, pan clic-droit), une minimap de navigation,
et une cartographie thermique haute précision de la présence réelle des données (données vs zéros vs chiffré).
"""

import math
import threading
from typing import List, Optional, Tuple
from PySide6.QtWidgets import QWidget, QToolTip
from PySide6.QtCore import Qt, Signal, QRectF, QPoint, QTimer, QObject
from PySide6.QtGui import QPainter, QColor, QBrush, QPen, QFont, QMouseEvent, QWheelEvent

from core.scanner import ScanDiagnostic
from core.image_reader import ForensicImageReader
from core.entropy import shannon_entropy, zero_ratio


class VisualBlock:
    """Représente une région logique sur la barre des partitions."""

    def __init__(self, start_lba: int, end_lba: int, label: str, color: QColor, category: str):
        self.start_lba = start_lba
        self.end_lba = end_lba
        self.label = label
        self.color = color
        self.category = category  # 'wiped', 'partition', 'luks', 'apfs', 'backup', 'free'


class DensitySample:
    """Échantillon de présence et d'entropie pour la cartographie des données."""

    def __init__(self, start_lba: int, end_lba: int, zeros_ratio: float, entropy: float, category: str):
        self.start_lba = start_lba
        self.end_lba = end_lba
        self.zeros_ratio = zeros_ratio
        self.entropy = entropy
        self.category = category  # 'wiped', 'data', 'encrypted', 'sparse'


class DensitySignaler(QObject):
    """Émetteur de signal Qt thread-safe pour les travailleurs d'arrière-plan."""

    density_ready = Signal(int, list)  # generation_id, samples


class DiskCanvas(QWidget):
    """Bandeau visuel interactif avec zoom, minimap et cartographie de densité de données."""

    sector_selected = Signal(int)
    viewport_changed = Signal(int, int, float)  # start_lba, end_lba, zoom_factor

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(135)
        self.setMaximumHeight(160)
        self.setMouseTracking(True)

        self.reader: Optional[ForensicImageReader] = None
        self.diagnostic: Optional[ScanDiagnostic] = None
        self.blocks: List[VisualBlock] = []

        # État du Zoom & Navigation
        self.zoom_factor: float = 1.0
        self.view_start_lba: int = 0
        self.view_end_lba: int = 0

        # Échantillons de densité de données (Zéro vs Données vs Chiffré)
        self.density_samples: List[DensitySample] = []
        self.full_disk_density: List[DensitySample] = []

        # Curseur et survol
        self.current_cursor_lba: int = 0
        self._hovered_block: Optional[VisualBlock] = None
        self._hover_lba: Optional[int] = None
        self._hover_density: Optional[DensitySample] = None

        # Interaction souris
        self._is_dragging_cursor: bool = False
        self._is_panning: bool = False
        self._is_dragging_minimap: bool = False
        self._pan_start_x: float = 0
        self._pan_start_start_lba: int = 0

        # Debounce et travailleur asynchrone pour la cartographie de densité
        self._sector_cache: dict = {}
        self._sample_gen: int = 0
        self._density_signaler = DensitySignaler()
        self._density_signaler.density_ready.connect(self._on_density_ready)
        self._density_timer = QTimer(self)
        self._density_timer.setSingleShot(True)
        self._density_timer.setInterval(120)  # 120 ms debounce
        self._density_timer.timeout.connect(self._start_background_resample)

    def set_source(self, reader: Optional[ForensicImageReader], diag: ScanDiagnostic):
        """Initialise le canvas avec le lecteur d'image et le diagnostic forensique."""
        self.reader = reader
        self.diagnostic = diag
        self.zoom_factor = 1.0

        if diag and diag.total_sectors > 0:
            self.view_start_lba = 0
            self.view_end_lba = diag.total_sectors - 1
        else:
            self.view_start_lba = 0
            self.view_end_lba = 0

        self.build_blocks()
        self._sector_cache.clear()
        self._sample_gen += 1
        self._density_timer.stop()

        self._compute_full_density_map(num_points=100)
        self._start_background_resample()
        self.viewport_changed.emit(self.view_start_lba, self.view_end_lba, self.zoom_factor)
        self.update()

    def set_diagnostic(self, diag: ScanDiagnostic):
        """Compatibilité rétroactive."""
        self.set_source(self.reader, diag)

    def set_cursor_lba(self, lba: int):
        """Met à jour la position de l'aiguille de lecture synchronisée."""
        if self.current_cursor_lba != lba:
            self.current_cursor_lba = lba
            # Si le curseur sort de la vue zoomée, centrer la vue sur le curseur
            if self.zoom_factor > 1.0 and (lba < self.view_start_lba or lba > self.view_end_lba):
                self.center_on_lba(lba)
            self.update()

    def build_blocks(self):
        """Construit les blocs logiques des partitions."""
        self.blocks.clear()
        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            return

        tot = self.diagnostic.total_sectors

        # Cas d'un volume autonome
        if getattr(self.diagnostic, "is_standalone_volume", False) and self.diagnostic.partitions:
            p = self.diagnostic.partitions[0]
            cat = "apfs" if "APFS" in (p.detected_fs or "") else "partition"
            col = QColor("#d35400") if cat == "apfs" else QColor("#27ae60")
            self.blocks.append(
                VisualBlock(0, tot - 1, f"Volume Autonome : {p.detected_fs or 'Volume Brut'}", col, cat)
            )
            return

        # 1. Zone Wipée
        if self.diagnostic.wipe_frontier_lba and self.diagnostic.wipe_frontier_lba > 0:
            wf = self.diagnostic.wipe_frontier_lba
            self.blocks.append(
                VisualBlock(
                    0,
                    wf - 1,
                    f"Zone Wipée (LBA 0 à {wf - 1:,}) - 100% Zéros",
                    QColor("#4a1a1a"),
                    "wiped",
                )
            )

        # 2. Partitions
        for idx, p in enumerate(self.diagnostic.partitions, 1):
            fs = p.detected_fs or p.type_name
            if "LUKS" in fs:
                color = QColor("#8e44ad")
                cat = "luks"
            elif "APFS" in fs:
                color = QColor("#d35400")
                cat = "apfs"
            elif "BitLocker" in fs:
                color = QColor("#9b59b6")
                cat = "encrypted"
            elif "QNX" in fs:
                color = QColor("#0097e6")
                cat = "qnx"
            else:
                color = QColor("#27ae60")
                cat = "partition"

            label = f"Part {idx}: {p.name or 'Partition'} ({fs})"
            self.blocks.append(VisualBlock(p.first_lba, p.last_lba, label, color, cat))

        # 3. Backup GPT
        if self.diagnostic.backup_gpt_present:
            backup_start = max(0, tot - 34)
            self.blocks.append(
                VisualBlock(backup_start, tot - 1, "Backup GPT (Intact)", QColor("#00a8ff"), "backup")
            )

        self.blocks.sort(key=lambda b: b.start_lba)

    def _compute_full_density_map(self, num_points: int = 100):
        """Échantillonne le disque pour la minimap globale en utilisant le cache mémoire."""
        self.full_disk_density.clear()
        if not self.reader or not self.diagnostic or self.diagnostic.total_sectors == 0:
            return

        tot = self.diagnostic.total_sectors
        step = max(1, tot // num_points)

        for i in range(num_points):
            s_lba = i * step
            e_lba = min(tot - 1, (i + 1) * step - 1)
            if s_lba >= tot:
                break

            cached = self._sector_cache.get(s_lba)
            if cached is not None:
                z_ratio, ent, cat = cached
            else:
                try:
                    data = self.reader.read_sector(s_lba, count=1)
                    z_ratio = zero_ratio(data)
                    ent = shannon_entropy(data)
                except Exception:
                    z_ratio = 1.0
                    ent = 0.0

                if z_ratio > 0.98 or (data and data.count(b"\xff") > len(data) * 0.98):
                    cat = "wiped"
                elif ent > 7.88:
                    cat = "encrypted"
                elif ent > 7.4:
                    cat = "compressed"
                elif ent > 2.0:
                    cat = "data"
                else:
                    cat = "sparse"

                self._sector_cache[s_lba] = (z_ratio, ent, cat)

            self.full_disk_density.append(DensitySample(s_lba, e_lba, z_ratio, ent, cat))

    def _schedule_density_resample(self):
        """Planifie un rééchantillonnage de densité via un timer de debounce non-bloquant."""
        self._sample_gen += 1
        self._density_timer.start(120)

    def _start_background_resample(self):
        """Lance l'échantillonnage de la vue dans un thread daemon sans bloquer l'interface."""
        if not self.reader or not self.diagnostic or self.diagnostic.total_sectors == 0:
            return

        self._sample_gen += 1
        gen_id = self._sample_gen
        reader = self.reader
        start_lba = self.view_start_lba
        end_lba = self.view_end_lba
        num_points = 120
        sector_cache = self._sector_cache

        def worker():
            if end_lba < start_lba:
                return
            span = max(1, end_lba - start_lba + 1)
            step = max(1, span // num_points)
            samples = []

            for i in range(num_points):
                if gen_id != self._sample_gen:
                    return

                s_lba = start_lba + i * step
                e_lba = min(end_lba, start_lba + (i + 1) * step - 1)
                if s_lba > end_lba:
                    break

                cached = sector_cache.get(s_lba)
                if cached is not None:
                    z_ratio, ent, cat = cached
                else:
                    try:
                        data = reader.read_sector(s_lba, count=1)
                        z_ratio = zero_ratio(data)
                        ent = shannon_entropy(data)
                    except Exception:
                        z_ratio = 1.0
                        ent = 0.0

                    if z_ratio > 0.98 or (data and data.count(b"\xff") > len(data) * 0.98):
                        cat = "wiped"
                    elif ent > 7.88:
                        cat = "encrypted"
                    elif ent > 7.4:
                        cat = "compressed"
                    elif ent > 2.0:
                        cat = "data"
                    else:
                        cat = "sparse"

                    sector_cache[s_lba] = (z_ratio, ent, cat)

                samples.append(DensitySample(s_lba, e_lba, z_ratio, ent, cat))

            if gen_id == self._sample_gen:
                self._density_signaler.density_ready.emit(gen_id, samples)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _on_density_ready(self, gen_id: int, samples: list):
        """Reçoit les échantillons calculés en arrière-plan."""
        if gen_id == self._sample_gen:
            self.density_samples = samples
            self.update()

    # --- Fonctions de Zoom et Navigation Spatiale Fluides (60 FPS) ---
    def zoom_in(self, center_ratio: float = 0.5, factor: float = 1.6):
        """Effectue un zoom avant centré sur un ratio horizontal (0.0 à 1.0)."""
        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            return
        if self.zoom_factor >= 500.0:
            return

        new_zoom = min(500.0, self.zoom_factor * factor)
        self._apply_zoom(new_zoom, center_ratio)

    def zoom_out(self, center_ratio: float = 0.5, factor: float = 1.6):
        """Effectue un zoom arrière centré sur un ratio horizontal (0.0 à 1.0)."""
        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            return
        if self.zoom_factor <= 1.0:
            return

        new_zoom = max(1.0, self.zoom_factor / factor)
        self._apply_zoom(new_zoom, center_ratio)

    def reset_zoom(self):
        """Réinitialise la vue à 100% de la surface du disque."""
        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            return
        self.zoom_factor = 1.0
        self.view_start_lba = 0
        self.view_end_lba = self.diagnostic.total_sectors - 1
        self._schedule_density_resample()
        self.viewport_changed.emit(self.view_start_lba, self.view_end_lba, self.zoom_factor)
        self.update()

    def center_on_lba(self, target_lba: int):
        """Centre la fenêtre de zoom actuelle autour d'un secteur LBA donné."""
        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            return
        tot = self.diagnostic.total_sectors
        span = self.view_end_lba - self.view_start_lba + 1

        new_start = max(0, min(tot - span, target_lba - span // 2))
        new_end = new_start + span - 1

        self.view_start_lba = new_start
        self.view_end_lba = new_end
        self._schedule_density_resample()
        self.viewport_changed.emit(self.view_start_lba, self.view_end_lba, self.zoom_factor)
        self.update()

    def _apply_zoom(self, new_zoom: float, center_ratio: float):
        tot = self.diagnostic.total_sectors
        center_lba = self.view_start_lba + int(center_ratio * (self.view_end_lba - self.view_start_lba))

        new_span = max(64, int(tot / new_zoom))
        new_start = max(0, min(tot - new_span, center_lba - int(center_ratio * new_span)))
        new_end = min(tot - 1, new_start + new_span - 1)

        self.zoom_factor = new_zoom
        self.view_start_lba = new_start
        self.view_end_lba = new_end

        self._schedule_density_resample()
        self.viewport_changed.emit(self.view_start_lba, self.view_end_lba, self.zoom_factor)
        self.update()

    def pan_lba(self, delta_lba: int):
        """Déplace la fenêtre visible horizontalement sans aucun blocage."""
        if not self.diagnostic or self.diagnostic.total_sectors == 0 or self.zoom_factor <= 1.0:
            return
        tot = self.diagnostic.total_sectors
        span = self.view_end_lba - self.view_start_lba + 1

        new_start = max(0, min(tot - span, self.view_start_lba + delta_lba))
        new_end = new_start + span - 1

        if new_start != self.view_start_lba:
            self.view_start_lba = new_start
            self.view_end_lba = new_end
            self._schedule_density_resample()
            self.viewport_changed.emit(self.view_start_lba, self.view_end_lba, self.zoom_factor)
            self.update()

    # --- Rendu Graphique (PaintEvent) ---
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = self.rect()
        w = rect.width()
        h = rect.height()

        # Fond sombre
        painter.fillRect(rect, QColor("#0d0f14"))

        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            painter.setPen(QColor("#7f8c8d"))
            painter.setFont(QFont("Segoe UI", 10))
            painter.drawText(rect, Qt.AlignCenter, "Glissez-déposez une image médico-légale pour afficher la cartographie spatiale")
            return

        tot = self.diagnostic.total_sectors
        view_span = max(1, self.view_end_lba - self.view_start_lba + 1)

        # ----------------------------------------------------
        # 1. BANDEAU MINIMAP GLOBALE DU DISQUE ENTIER (H: 12px)
        # ----------------------------------------------------
        mm_y = 5
        mm_h = 12
        painter.fillRect(0, mm_y, w, mm_h, QColor("#1a1e2b"))

        # Blocs logiques dans la minimap
        for b in self.blocks:
            mx_s = int((b.start_lba / tot) * w)
            mx_e = int(((b.end_lba + 1) / tot) * w)
            mw = max(2, mx_e - mx_s)
            painter.fillRect(mx_s, mm_y, mw, mm_h, b.color.darker(120))

        # Cadre de la fenêtre zoomée actuelle sur la minimap
        vx_s = int((self.view_start_lba / tot) * w)
        vx_e = int(((self.view_end_lba + 1) / tot) * w)
        vw = max(4, vx_e - vx_s)

        painter.fillRect(vx_s, mm_y, vw, mm_h, QColor(0, 210, 255, 75))
        painter.setPen(QPen(QColor("#ffffff"), 1.2))
        painter.drawRect(vx_s, mm_y, vw, mm_h)

        # ----------------------------------------------------
        # 2. BANDEAU PARTITIONS ET VOLUMES ZOOMÉS (H: 38px)
        # ----------------------------------------------------
        p_y = 22
        p_h = 38
        painter.fillRect(0, p_y, w, p_h, QColor("#171b26"))

        for b in self.blocks:
            # Vérifier si le bloc intersecte la fenêtre visible
            if b.end_lba < self.view_start_lba or b.start_lba > self.view_end_lba:
                continue

            # Coordonnées projetées dans la fenêtre zoomée
            clamped_s = max(self.view_start_lba, b.start_lba)
            clamped_e = min(self.view_end_lba, b.end_lba)

            x_s = int(((clamped_s - self.view_start_lba) / view_span) * w)
            x_e = int(((clamped_e - self.view_start_lba + 1) / view_span) * w)
            bw = max(3, x_e - x_s)

            col = b.color
            if b == self._hovered_block:
                col = col.lighter(130)

            b_rect = QRectF(x_s, p_y, bw, p_h)
            painter.fillRect(b_rect, col)
            painter.setPen(QPen(QColor("#0b0e14"), 1))
            painter.drawRect(b_rect)

            # Étiquette textuelle si le bloc est assez large
            if bw > 85:
                painter.setPen(QColor("#ffffff"))
                painter.setFont(QFont("Segoe UI", 8, QFont.Bold))
                text_rect = b_rect.adjusted(6, 2, -6, -2)
                painter.drawText(text_rect, Qt.AlignVCenter | Qt.AlignLeft, b.label)

        # Bordure du bandeau partitions
        painter.setPen(QPen(QColor("#2c3e50"), 1))
        painter.drawRect(0, p_y, w - 1, p_h)

        # ----------------------------------------------------
        # 3. CARTE DE DENSITÉ & PRÉSENCE RÉELLE DES DONNÉES (H: 32px)
        # ----------------------------------------------------
        d_y = 63
        d_h = 32
        painter.fillRect(0, d_y, w, d_h, QColor("#0e111a"))

        # Légende discrète sur le côté gauche
        painter.setPen(QPen(QColor("#00d2ff"), 0.5))
        painter.drawRect(0, d_y, w - 1, d_h)

        # Rendu des tranches d'échantillons
        if self.density_samples:
            sample_w = max(1.0, w / len(self.density_samples))
            for i, smp in enumerate(self.density_samples):
                sx = i * sample_w

                if smp.category == "wiped":
                    c = QColor("#221010")  # Noir bordeaux = 100% Zéros / Effacé
                elif smp.category == "encrypted":
                    c = QColor("#8e44ad")  # Violet = Haute entropie / Chiffré
                elif smp.category == "compressed":
                    c = QColor("#0984e3")  # Bleu dodger / Cyan = Données compressées / Médias
                elif smp.category == "data":
                    # Dégrader la luminosité du vert selon le ratio de données
                    data_ratio = 1.0 - smp.zeros_ratio
                    val = int(140 + data_ratio * 115)
                    c = QColor(39, val, 96)  # Vert émeraude = Données claires
                else:
                    c = QColor("#1e293b")  # Espace sparse

                if smp == self._hover_density:
                    c = c.lighter(150)

                painter.fillRect(QRectF(sx, d_y + 1, sample_w + 0.5, d_h - 2), c)

        # Label d'identification de la barre de données
        painter.setPen(QColor(255, 255, 255, 140))
        painter.setFont(QFont("Segoe UI", 7, QFont.Bold))
        from core.i18n import get_lang
        legend_txt = ("ANALYSE D'ENTROPIE (BINWALK) & PRÉSENCE (VERT = CLAIR | BLEU = COMPRESSÉ | VIOLET = CHIFFRÉ | NOIR = EFFACÉ)" if get_lang() == "fr"
                      else "BINWALK ENTROPY & DATA PRESENCE (GREEN = CLEAR | BLUE = COMPRESSED | PURPLE = ENCRYPTED | BLACK = ERASED)")
        painter.drawText(6, d_y + 12, legend_txt)

        # ----------------------------------------------------
        # 4. CURSEUR SYNCHRONISÉ ET AIGUILLE LBA
        # ----------------------------------------------------
        if self.view_start_lba <= self.current_cursor_lba <= self.view_end_lba:
            cur_ratio = (self.current_cursor_lba - self.view_start_lba) / view_span
            cur_x = int(cur_ratio * w)
            cur_x = max(1, min(w - 2, cur_x))

            # Aiguille jaune fluo traversant les bandes partitions et données
            painter.setPen(QPen(QColor("#ffea00"), 2))
            painter.drawLine(cur_x, p_y - 2, cur_x, d_y + d_h + 2)

            # Triangle supérieur
            painter.setBrush(QBrush(QColor("#ffea00")))
            painter.setPen(Qt.NoPen)
            poly_top = [QPoint(cur_x - 5, p_y - 4), QPoint(cur_x + 5, p_y - 4), QPoint(cur_x, p_y)]
            painter.drawPolygon(poly_top)

            # Badge LBA au-dessus de l'aiguille
            painter.setPen(QColor("#ffea00"))
            painter.setFont(QFont("Consolas", 8, QFont.Bold))
            badge_text = f"LBA {self.current_cursor_lba:,}"
            text_w = painter.fontMetrics().horizontalAdvance(badge_text)
            text_x = max(4, min(w - text_w - 4, cur_x - text_w // 2))
            painter.drawText(text_x, p_y - 6, badge_text)

        # Ligne en pointillés sous le curseur de survol souris
        if self._hover_lba is not None and self.view_start_lba <= self._hover_lba <= self.view_end_lba:
            h_ratio = (self._hover_lba - self.view_start_lba) / view_span
            h_x = int(h_ratio * w)
            painter.setPen(QPen(QColor(255, 255, 255, 90), 1, Qt.DashLine))
            painter.drawLine(h_x, p_y, h_x, d_y + d_h)

        # ----------------------------------------------------
        # 5. RÈGLE GRADUÉE LBA ET INDICATEUR DE ZOOM (H: 24px)
        # ----------------------------------------------------
        r_y = d_y + d_h + 16
        painter.setPen(QColor("#94a3b8"))
        painter.setFont(QFont("Consolas", 8))

        # Début et Fin LBA de la vue
        painter.drawText(6, r_y, f"LBA {self.view_start_lba:,}")
        mid_lba = self.view_start_lba + view_span // 2
        painter.drawText(w // 2 - 45, r_y, f"~LBA {mid_lba:,}")

        end_str = f"LBA {self.view_end_lba:,}"
        end_w = painter.fontMetrics().horizontalAdvance(end_str)
        painter.drawText(w - end_w - 6, r_y, end_str)

        # Badge Zoom
        zoom_str = f"Zoom: {self.zoom_factor:.1f}x"
        painter.setPen(QColor("#00d2ff"))
        painter.drawText(w // 2 - 30, mm_y + 10, zoom_str)

    # --- Gestion des Événements Souris ---
    def _lba_at_x(self, x: float) -> int:
        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            return 0
        w = max(1, self.width())
        ratio = max(0.0, min(1.0, x / w))
        span = self.view_end_lba - self.view_start_lba
        return self.view_start_lba + int(ratio * span)

    def wheelEvent(self, event: QWheelEvent):
        """Zoom avant / arrière avec la molette de la souris centré sur le curseur."""
        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            return

        x = event.position().x()
        w = max(1, self.width())
        ratio = max(0.0, min(1.0, x / w))

        delta = event.angleDelta().y()
        if delta > 0:
            self.zoom_in(center_ratio=ratio, factor=1.4)
        elif delta < 0:
            self.zoom_out(center_ratio=ratio, factor=1.4)

        event.accept()

    def mousePressEvent(self, event: QMouseEvent):
        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            return

        y = event.position().y()
        x = event.position().x()

        # Clic sur la minimap : recadrer directement la vue
        if y <= 18:
            tot = self.diagnostic.total_sectors
            target_lba = int((x / max(1, self.width())) * tot)
            self.center_on_lba(target_lba)
            return

        # Clic gauche : sélection de secteur
        if event.button() == Qt.LeftButton:
            self._is_dragging_cursor = True
            lba = self._lba_at_x(x)
            self.current_cursor_lba = lba
            self.sector_selected.emit(lba)
            self.update()

        # Clic droit ou milieu : Pan (déplacement latéral)
        elif event.button() in (Qt.RightButton, Qt.MiddleButton):
            self._is_panning = True
            self._pan_start_x = x
            self._pan_start_start_lba = self.view_start_lba

    def mouseMoveEvent(self, event: QMouseEvent):
        if not self.diagnostic or self.diagnostic.total_sectors == 0:
            return

        x = event.position().x()
        y = event.position().y()
        w = max(1, self.width())

        # Pan horizontal par glissement
        if self._is_panning:
            delta_px = self._pan_start_x - x
            span = self.view_end_lba - self.view_start_lba + 1
            delta_lba = int((delta_px / w) * span)
            self.pan_lba(delta_lba)
            return

        # Scrubbing curseur avec bouton gauche enfoncé
        if self._is_dragging_cursor or (event.buttons() & Qt.LeftButton and y > 18):
            lba = self._lba_at_x(x)
            self.current_cursor_lba = lba
            self.sector_selected.emit(lba)
            self.update()
            return

        # Survol normal : calcul des infobulles
        lba = self._lba_at_x(x)
        self._hover_lba = lba

        # Identifier bloc partition survolé
        found_block = None
        for b in self.blocks:
            if b.start_lba <= lba <= b.end_lba:
                found_block = b
                break
        self._hovered_block = found_block

        # Identifier échantillon de densité survolé
        self._hover_density = None
        if self.density_samples:
            idx = int((x / w) * len(self.density_samples))
            if 0 <= idx < len(self.density_samples):
                self._hover_density = self.density_samples[idx]

        self.update()

        # Construction de l'infobulle enrichie
        from core.i18n import get_lang
        is_fr = get_lang() == "fr"
        off_unit = "octets" if is_fr else "bytes"
        lbl_lba = "Secteur LBA" if is_fr else "LBA Sector"
        tip_lines = [f"<b>{lbl_lba} : {lba:,}</b> (Offset : {lba * self.diagnostic.sector_size:,} {off_unit})"]

        if found_block:
            size_mb = (found_block.end_lba - found_block.start_lba + 1) * self.diagnostic.sector_size / (1024 * 1024)
            unit_mb = "Mo" if is_fr else "MB"
            lbl_zone = "Zone logique" if is_fr else "Logical Zone"
            tip_lines.append(f"<b>{lbl_zone} :</b> {found_block.label} ({size_mb:.1f} {unit_mb})")

        if self._hover_density:
            d = self._hover_density
            if d.category == "wiped":
                status = "❌ 100% ZÉROS (Espace Wipé / Non-Alloué)" if is_fr else "❌ 100% ZEROS (Wiped / Unallocated Space)"
            elif d.category == "encrypted":
                status = (f"🔒 HAUTE ENTROPIE / CHIFFRÉ (Entropie: {d.entropy:.2f}/8.0)" if is_fr
                          else f"🔒 HIGH ENTROPY / ENCRYPTED (Entropy: {d.entropy:.2f}/8.0)")
            elif d.category == "compressed":
                status = (f"📦 DONNÉES COMPRESSÉES / MÉDIAS (Entropie: {d.entropy:.2f}/8.0)" if is_fr
                          else f"📦 COMPRESSED / MEDIA DATA (Entropy: {d.entropy:.2f}/8.0)")
            elif d.category == "data":
                data_pct = (1.0 - d.zeros_ratio) * 100
                status = (f"✔️ DONNÉES CLAIRES ACTIVES (Densité: {data_pct:.1f}% | Entropie: {d.entropy:.2f})" if is_fr
                          else f"✔️ CLEAR ACTIVE DATA (Density: {data_pct:.1f}% | Entropy: {d.entropy:.2f})")
            else:
                status = "Espace clairsemé" if is_fr else "Sparse Space"
            lbl_pres = "Présence physique" if is_fr else "Physical Presence"
            tip_lines.append(f"<b>{lbl_pres} :</b> {status}")

        hint_txt = ("<i>👉 Clic gauche: Examiner en hexadécimal | Molette: Zoomer | Clic droit: Déplacer la vue</i>" if is_fr
                    else "<i>👉 Left-click: Inspect in hex | Scroll wheel: Zoom | Right-click: Pan view</i>")
        tip_lines.append(hint_txt)
        QToolTip.showText(event.globalPosition().toPoint(), "<br/>".join(tip_lines), self)

    def mouseReleaseEvent(self, event: QMouseEvent):
        self._is_dragging_cursor = False
        self._is_panning = False

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        """Double-clic pour réinitialiser le zoom à 100%."""
        self.reset_zoom()

    def leaveEvent(self, event):
        self._hover_lba = None
        self._hovered_block = None
        self._hover_density = None
        self.update()
