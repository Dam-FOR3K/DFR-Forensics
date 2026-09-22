"""
DFR-Forensics - Générateur de Whitepapers Techniques & Guides d'Architecture
Produit une documentation forensique approfondie multi-pages (FR et EN)
destinée aux analystes médico-légaux, ingénieurs en rétro-ingénierie et auditeurs.
Auteur : Dam-FOR3K | Version : v2.7.2
"""

import os
import sys
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        self.doc_title = kwargs.pop("doc_title", "DFR-Forensics - Manuel Technique")
        self.doc_lang = kwargs.pop("doc_lang", "fr")
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        w, h = A4

        # En-tête (à partir de la page 2)
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#0f172a"))
            self.drawString(45, h - 35, self.doc_title.upper())

            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawRightString(w - 45, h - 35, "Dam-FOR3K | Forensic Architecture")

            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.6)
            self.line(45, h - 40, w - 45, h - 40)

        # Pied de page (sur toutes les pages)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.6)
        self.line(45, 45, w - 45, 45)

        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        label_conf = "CONFIDENTIEL & USAGE MÉDICO-LÉGAL STRICT" if self.doc_lang == "fr" else "CONFIDENTIAL & STRICT FORENSIC USE"
        self.drawString(45, 32, label_conf)

        page_str = f"Page {self._pageNumber} / {page_count}" if self.doc_lang == "fr" else f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(w - 45, 32, page_str)

        self.restoreState()


def create_styles():
    base = getSampleStyleSheet()

    title = ParagraphStyle(
        "DocTitle",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0f172a"),
        alignment=0,
        spaceAfter=6,
    )

    subtitle = ParagraphStyle(
        "DocSubtitle",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=14,
    )

    h1 = ParagraphStyle(
        "SectionH1",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True,
    )

    h2 = ParagraphStyle(
        "SectionH2",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0369a1"),
        spaceBefore=10,
        spaceAfter=5,
        keepWithNext=True,
    )

    body = ParagraphStyle(
        "Body",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6,
    )

    bullet = ParagraphStyle(
        "BulletText",
        parent=body,
        leftIndent=14,
        firstLineIndent=-10,
        spaceAfter=4,
    )

    code = ParagraphStyle(
        "CodeSnippet",
        parent=base["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=8,
    )

    table_cell = ParagraphStyle(
        "TableCell",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
    )

    table_header = ParagraphStyle(
        "TableHeader",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.white,
    )

    return {
        "title": title,
        "subtitle": subtitle,
        "h1": h1,
        "h2": h2,
        "body": body,
        "bullet": bullet,
        "code": code,
        "table_cell": table_cell,
        "table_header": table_header,
    }


def build_french_whitepaper(output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=45,
        rightMargin=45,
        topMargin=50,
        bottomMargin=50,
    )
    s = create_styles()
    story = []

    story.append(Paragraph("DFR-FORENSICS", s["title"]))
    story.append(Paragraph("Disk & File Resurrection : Guide d'Architecture & Manuel Forensique", s["subtitle"]))

    meta_table_data = [
        [
            Paragraph("<b>Auteur :</b> Dam-FOR3K", s["table_cell"]),
            Paragraph("<b>Version :</b> v2.7.2", s["table_cell"]),
            Paragraph("<b>Date :</b> Septembre 2026", s["table_cell"]),
            Paragraph("<b>Licence :</b> MIT Open-Source", s["table_cell"]),
        ]
    ]
    t_meta = Table(meta_table_data, colWidths=[125, 125, 125, 130])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 12))

    story.append(Paragraph("1. Problématique Médico-Légale & Philosophie Architecturale", s["h1"]))
    story.append(Paragraph(
        "Dans les contextes d'attaques cybernétiques modernes (ransomwares destructeurs, wipers industriels tels que "
        "<i>HermeticWiper</i>, <i>CaddyWiper</i> ou <i>WhisperGate</i>) ou lors de défaillances matérielles critiques "
        "(secteurs défectueux initiaux, coupures d'alimentation pendant un repartitionnement), les structures d'amorçage "
        "d'un disque dur ou d'un SSD sont les premières cibles détruites. Dès lors que le secteur LBA 0 (MBR) ou LBA 1 (GPT) "
        "est écrasé par des zéros ou corrompu, les systèmes d'exploitation (Windows, Linux, macOS) et la majorité des "
        "logiciels forensiques commerciaux considèrent le disque comme <b>entièrement non-initialisé ou vierge</b>.",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>DFR-Forensics</b> (<i>Disk & File Resurrection</i>) a été conçu par <b>Dam-FOR3K</b> pour combler cette faille d'investigation en appliquant les principes directeurs suivants :",
        s["body"]
    ))
    story.append(Paragraph("• <b>Politique stricte de lecture seule (Zero-Write Policy)</b> : Aucune écriture n'est jamais effectuée sur le support d'origine. Les images brutes (RAW, DD, E01, AD1, AFF4) et les disques physiques (<i>\\\\.\\PhysicalDriveX</i>) sont ouverts avec des flags stricts en lecture seule.", s["bullet"]))
    story.append(Paragraph("• <b>Architecture virtuelle Copy-On-Write (COW)</b> : Toutes les réparations de géométrie, déchiffrements de conteneurs et reconstructions de tables s'exécutent dans un calque virtuel en mémoire vive, permettant l'exploration dynamique sans altérer la preuve.", s["bullet"]))
    story.append(Paragraph("• <b>Reconstruction mathématique par invariants</b> : Aucun décalage ni taille n'est figé. Le moteur recherche les invariants structurels (descripteurs de médias, relations de clusters, signatures magiques) pour recalculer la géométrie exacte même lorsque tous les en-têtes primaires sont anéantis.", s["bullet"]))

    story.append(Paragraph("2. Architecture Bas-Niveau des Tables de Partitionnement", s["h1"]))
    story.append(Paragraph("A. Master Boot Record (MBR) & Chaînes EBR", s["h2"]))
    story.append(Paragraph(
        "Le secteur 0 (LBA 0) héberge traditionnellement le MBR standard : 446 octets de bootstrap machine, suivis de "
        "4 entrées de partitionnement de 16 octets (offsets 446 à 509) et du mot magique <code>0x55AA</code> (offsets 510-511). "
        "Chaque descripteur code l'état d'amorçage (0x80 = actif), le type de système de fichiers (ex: 0x07 NTFS/exFAT, 0x83 Linux Native), "
        "le premier secteur LBA et le nombre total de secteurs. Lorsque des partitions étendues existent, l'outil traverse récursivement "
        "les secteurs <b>EBR (Extended Boot Record)</b> organisés en liste chaînée sur le disque (chaînage dynamique des partitions étendues).",
        s["body"]
    ))

    story.append(Paragraph("B. Spécification UEFI GPT (GUID Partition Table 2.10)", s["h2"]))
    story.append(Paragraph(
        "Sur les supports modernes, l'UEFI GPT remplace les limitations du MBR. La structure comprend :",
        s["body"]
    ))
    story.append(Paragraph("• <b>LBA 0 (Protective MBR)</b> : MBR factice contenant une unique partition de type <code>0xEE</code> occupant tout le disque pour empêcher les utilitaires DOS historiques d'écraser la table.", s["bullet"]))
    story.append(Paragraph("• <b>LBA 1 (Primary GPT Header)</b> : En-tête de 92 octets débutant par la signature <code>EFI PART</code> (<code>0x5452415020494645</code>). Il contient les GUIDs du disque, le pointeur vers le tableau de partitions (LBA 2), le pointeur vers l'en-tête de secours (LBA N-1), et deux sommes de contrôle CRC32 distinctes.", s["bullet"]))
    story.append(Paragraph("• <b>LBA 2 à 33 (Partition Entry Array)</b> : Tableau de 128 entrées de 128 octets chacune (16 384 octets au total). Chaque entrée définit le GUID de type, le GUID unique, le premier LBA, le dernier LBA, les attributs et le nom Unicode UTF-16LE de la partition.", s["bullet"]))
    story.append(Paragraph("• <b>LBA N-33 à N-2 (Backup Array)</b> et <b>LBA N-1 (Backup Header)</b> : Réplication intégrale en fin de disque assurant la tolérance aux pannes.", s["bullet"]))

    story.append(Paragraph("C. Algorithme de Réparation & Recalcul CRC32 (IEEE 802.3)", s["h2"]))
    story.append(Paragraph(
        "Lorsqu'un wiper efface les premiers mégaoctets du disque (LBA 0..2048), la GPT Primaire est détruite mais la GPT de secours (LBA N-1) "
        "demeure souvent intacte en fin de support. Le moteur de réparation de DFR-Forensics procède comme suit :",
        s["body"]
    ))
    story.append(Paragraph(
        "1. Extraction du tableau de partitions depuis <code>LBA N-33</code> et copie vers <code>LBA 2..33</code>.<br/>"
        "2. Inversion des pointeurs de géométrie : <code>CurrentLBA</code> devient 1, <code>BackupLBA</code> devient N-1, <code>PartitionEntriesLBA</code> devient 2.<br/>"
        "3. Recalcul de la somme de contrôle CRC32 du tableau de partitions (16 384 octets) via le polynôme réfléchi <code>0xEDB88320</code>.<br/>"
        "4. Remise à zéro des 4 octets du champ <code>Header CRC32</code> (offset 16), puis calcul du CRC32 sur les 92 octets de l'en-tête et réinjection.<br/>"
        "5. Synthèse d'un Protective MBR valide à LBA 0.",
        s["code"]
    ))

    story.append(PageBreak())
    story.append(Paragraph("3. Systèmes de Fichiers & Algorithmes de Reconstruction Autonome", s["h1"]))

    story.append(Paragraph("A. Moteur FAT12 / FAT16 / FAT32 & Bascule Boot Sector de Secours", s["h2"]))
    story.append(Paragraph(
        "Dans la norme FAT (File Allocation Table), le <b>BPB (BIOS Parameter Block)</b> situé dans le secteur d'amorçage (VBR / LBA 0) "
        "gouverne toute l'architecture : taille des secteurs, secteurs réservés, nombre de tables FAT, entrées racine et secteurs par cluster (SPC). "
        "Si un wiper remplit le LBA 0 de zéros, <b>DFR-Forensics</b> déploie une stratégie de résilience à deux niveaux :",
        s["body"]
    ))
    story.append(Paragraph("• <b>Bascule sur le Boot Sector de Secours (LBA 6)</b> : En FAT32, le système interroge automatiquement le secteur 6 (réplique OEM officielle de l'amorçage). Si ce secteur est intact, la géométrie d'origine est restaurée instantanément sans dérivation heuristique.", s["bullet"]))
    story.append(Paragraph("• <b>Reconstruction Mathématique de BPB Orphelin</b> : Si les secteurs 0 et 6 sont tous deux détruits :<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;1. Balayage des signatures <code>0xF8 / 0xF0</code> pour localiser FAT1.<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;2. Calcul exact : <b>Secteurs par FAT = LBA(FAT2) - LBA(FAT1)</b>.<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;3. Localisation immédiate du Root Directory en fin de FAT2.<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;4. Résolution dynamique du SPC par corrélation mathématique sur les en-têtes réels de fichiers (JPEG, PDF, ZIP).", s["bullet"]))

    story.append(Paragraph("B. Moteur Linux EXT2 / EXT3 / EXT4 & Arbre d'Extents", s["h2"]))
    story.append(Paragraph(
        "Sous Linux EXT, les données sont organisées en groupes de blocs (Block Groups). En cas de destruction du superbloc principal (LBA 2) ou de fragmentation lourde :",
        s["body"]
    ))
    story.append(Paragraph("• <b>Détection des Superblocs de Secours (Sparse Superblock)</b> : Sonde automatique de l'offset 8 389 632 (LBA 16 386) et balayage jusqu'à 32 Mo pour identifier le magic <code>0xEF53</code> et charger la table des descripteurs de groupes.", s["bullet"]))
    story.append(Paragraph("• <b>Support Intégral des Extents EXT4 (magic <code>0xF30A</code>)</b> : Prise en charge native de l'arbre d'extents stocké dans les 60 octets <code>i_block</code> des inodes modernes. Décodage récursif des nœuds d'index (<code>depth &gt; 0</code>) et des descripteurs de feuilles (<code>ee_block</code>, <code>ee_start</code>, <code>ee_len</code>), garantissant la réassignation bit-à-bit des fichiers fragmentés de plusieurs gigaoctets.", s["bullet"]))
    story.append(Paragraph("• <b>Défragmentation des Pointeurs Classiques (Directs, Indirects, Doubles Indirects)</b> : Résolution chirurgicale de l'arbre de blocs Ext2/3 éliminant les blocs de pointeurs de métadonnées de 1 024 octets intercalés dans les fichiers volumineux.", s["bullet"]))
    story.append(Paragraph("• <b>Récupération dans l'espace résiduel des répertoires (Directory Slack Space)</b> : Extraction des enregistrements de fichiers supprimés masqués dans la longueur résiduelle des entrées actives (champ <code>rec_len</code>).", s["bullet"]))

    story.append(Paragraph("C. Moteur Windows NTFS ($MFT, $MFTMirr & Backup VBR)", s["h2"]))
    story.append(Paragraph(
        "L'analyseur NTFS décode directement la table des fichiers maîtres <b>$MFT</b> et intègre deux mécanismes de secours critiques :",
        s["body"]
    ))
    story.append(Paragraph("• <b>Bascule sur $MFTMirr (cluster offset 0x38)</b> : Si le Record 0 de la $MFT primaire est effacé ou altéré par un wiper, l'outil bascule automatiquement sur le miroir <code>$MFTMirr</code> pour récupérer la définition non-résidente de l'attribut <code>$DATA</code> cartographiant l'intégralité des runs de la MFT.", s["bullet"]))
    story.append(Paragraph("• <b>Résolution du Backup VBR (dernier secteur LBA N-1)</b> : Si le secteur d'amorçage initial est vierge, le paramétrage BPB complet (secteurs par cluster, taille d'enregistrement, clusters MFT) est restauré depuis la fin du volume.", s["bullet"]))
    story.append(Paragraph("• <b>Carving du journal de transactions ($LogFile) & Undelete</b> : Reconstitution complète des fichiers et répertoires actifs et supprimés avec horodatages quadruples MACB ($STANDARD_INFORMATION).", s["bullet"]))

    story.append(Paragraph("D. Moteur Natif exFAT (Main & Backup VBR)", s["h2"]))
    story.append(Paragraph(
        "Implémentation forensique pur-Python dédiée aux supports de stockage amovibles et cartes mémoires : "
        "tolérance de panne via le Backup VBR (secteur 12), décodage des chaînes de descripteurs de 32 octets "
        "(entrées primaires <code>0x85</code> actives et <code>0x05</code> supprimées, extensions de flux <code>0xC0</code> avec drapeaux d'allocation contiguë <code>NoFatChain</code>, et séquences de noms Unicode <code>0xC1</code>). "
        "Extraction bit-à-bit directe sans dépendance externe.",
        s["body"]
    ))

    story.append(Paragraph("E. Systèmes Embarqués, UNIX & Volumes Chiffrés", s["h2"]))
    story.append(Paragraph(
        "• <b>QNX4 & QNX6 Power-Safe</b> : Analyse des systèmes automobiles et embarqués industriels via les superblocs <code>0x68191122</code> à LBA 8192 et 11776, arborescence d'inodes et journal de transactions.<br/>"
        "• <b>Apple APFS</b> : Décodage du Container Superblock <code>NXSB</code>, parcours des B-Trees de l'Object Map (OMAP) et énumération des volumes chiffrés ou clairs.<br/>"
        "• <b>BitLocker & LUKS1/2</b> : Extraction des métadonnées cryptographiques, calcul des dérivations PBKDF2 / Argon2id, et montage d'un flux virtuel déchiffré à la volée.",
        s["body"]
    ))

    story.append(PageBreak())
    story.append(Paragraph("4. Moteur de Carving Intelligent & Prévisualisation Résiliente", s["h1"]))
    story.append(Paragraph(
        "Contrairement aux carvers naïfs qui extraient des blocs arbitraires en provoquant d'innombrables faux positifs, "
        "<b>DFR-Forensics</b> intègre un moteur de validation mathématique et structurelle propre à chaque format :",
        s["body"]
    ))

    carver_table_data = [
        [
            Paragraph("Format", s["table_header"]),
            Paragraph("Signature d'En-tête", s["table_header"]),
            Paragraph("Algorithme de Validation & Calcul de Longueur", s["table_header"]),
        ],
        [
            Paragraph("<b>JPEG / JFIF</b>", s["table_cell"]),
            Paragraph("<code>FF D8 FF E0 / E1</code>", s["table_cell"]),
            Paragraph("Validation séquentielle des marqueurs de trame (SOF, DQT, DHT, SOS), extraction des vignettes EXIF imbriquées et détection de fin de flux <code>FF D9</code>.", s["table_cell"]),
        ],
        [
            Paragraph("<b>PNG</b>", s["table_cell"]),
            Paragraph("<code>89 50 4E 47 0D 0A 1A 0A</code>", s["table_cell"]),
            Paragraph("Vérification intégrale des sommes de contrôle CRC-32 (IEEE 802.3) sur chaque bloc (IHDR, IDAT, IEND) et validation de dimensions non nulles.", s["table_cell"]),
        ],
        [
            Paragraph("<b>BMP</b>", s["table_cell"]),
            Paragraph("<code>42 4D ('BM')</code>", s["table_cell"]),
            Paragraph("Extraction de la taille physique encodée en Little-Endian (octets 2..5) et validation des dimensions géométriques non négatives.", s["table_cell"]),
        ],
        [
            Paragraph("<b>GIF</b>", s["table_cell"]),
            Paragraph("<code>GIF87a / GIF89a</code>", s["table_cell"]),
            Paragraph("Validation du descripteur logique d'écran, parcours exhaustif de la chaîne des blocs (extensions <code>0x21</code>, descripteurs <code>0x2C</code>, sous-blocs LZW) jusqu'au trailer légitime <code>0x3B</code> pour une étendue exacte au byte près.", s["table_cell"]),
        ],
        [
            Paragraph("<b>OLE CFBF (DOC, XLS, PPT)</b>", s["table_cell"]),
            Paragraph("<code>D0 CF 11 E0 A1 B1 1A E1</code>", s["table_cell"]),
            Paragraph("Parcours de la FAT interne du conteneur Microsoft Compound File pour déterminer la taille physique exacte et éviter toute troncature.", s["table_cell"]),
        ],
        [
            Paragraph("<b>PDF</b>", s["table_cell"]),
            Paragraph("<code>%PDF-1.x</code>", s["table_cell"]),
            Paragraph("Balayage linéaire borné à la recherche du marqueur <code>%%EOF</code> le plus proche pour empêcher l'absorption de documents consécutifs.", s["table_cell"]),
        ],
        [
            Paragraph("<b>TIFF 6.0</b>", s["table_cell"]),
            Paragraph("<code>49 49 2A 00 ('II*\\x00')<br/>4D 4D 00 2A ('MM\\x00*')</code>", s["table_cell"]),
            Paragraph("Prise en charge Little-Endian et Big-Endian. Traversée de l'Image File Directory (IFD), calcul d'étendue exacte par Strip/Tile ByteCounts, et filtrage strict des faux positifs EXIF JPEG.", s["table_cell"]),
        ],
        [
            Paragraph("<b>ZIP / Office XML</b>", s["table_cell"]),
            Paragraph("<code>50 4B 03 04 ('PK..')</code>", s["table_cell"]),
            Paragraph("Traversée des Local File Headers et validation par le Central Directory Record (<code>PK\\x01\\x02</code>) et End of Central Directory (<code>PK\\x05\\x06</code>).", s["table_cell"]),
        ],
    ]
    t_carver = Table(carver_table_data, colWidths=[100, 130, 275])
    t_carver.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_carver)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Options Stratégiques de Carving & Alignement Sectoriel", s["h2"]))
    story.append(Paragraph(
        "Pour s'adapter à toutes les topologies de supports analysés, le moteur propose des options de configuration précises :",
        s["body"]
    ))
    story.append(Paragraph("• <b>512 octets (Secteurs standard - Recommandé)</b> : Mode par défaut ultra-rapide calé sur les frontières sectorielles physiques. Idéal pour disques durs (HDD/SSD), clés USB et cartes mémoires.", s["bullet"]))
    story.append(Paragraph("• <b>1 octet (Exhaustif / Tout décalage)</b> : Analyse chirurgicale octet par octet (offset libre). Indispensable pour la mémoire vive (RAM), les flux réseaux ou les images brutes dont les fichiers débutent avec un décalage arbitraire (1, 2, 17 octets...).", s["bullet"]))
    story.append(Paragraph("• <b>4 096 octets (Clusters standard)</b> : Balayage accéléré aligné sur la taille standard des clusters de fichiers (NTFS, ext4).", s["bullet"]))
    story.append(Paragraph("• <b>Espace non alloué uniquement (Fichiers effacés)</b> : Cible exclusivement les zones libérées et orphelines du disque en interrogeant les tables d'allocation et bitmaps de systèmes de fichiers (NTFS $Bitmap, FAT tables, exFAT allocation bitmap, EXT2/3/4 block bitmaps, QNX4/6 allocation tables, Apple APFS Spaceman & conteneurs, et zones non partitionnées). Cette stratégie élimine les redondances avec les fichiers sains de l'arborescence active et accélère le scan de 5 à 10 fois.", s["bullet"]))
    story.append(Paragraph("• <b>Dé-tressage Avancé (De-Braiding / BraidResolver)</b> : Désactivé par défaut pour préserver la structure brute des fichiers et éviter tout découpage involontaire. Lorsqu'il est activé à la demande, il sépare mathématiquement les flux mutuellement entrelacés en quinconce (motif 1A-1B-2A-2B) avec validation réelle du décodage de pixels.", s["bullet"]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Conformité aux Standards NIST CFTT & Dé-tressage Automatique (De-Braiding)", s["h2"]))
    story.append(Paragraph(
        "<b>DFR-Forensics</b> valide avec succès l'intégralité de la suite officielle de référence <b>NIST CFTT Graphic Carving</b> "
        "(8 images disques médico-légales de test) :",
        s["body"]
    ))
    story.append(Paragraph("• <b>graphic-basic & graphic-nofill</b> : 40/40 fichiers contigus (BMP, GIF, JPG, PNG, TIFF) sculptés avec dimensions et hashs parfaits.", s["bullet"]))
    story.append(Paragraph("• <b>graphic-shifted & notshifted</b> : Extraction sans perte des flux non alignés (décalages de 1 à 511 octets au sein des secteurs).", s["bullet"]))
    story.append(Paragraph("• <b>graphic-partials</b> : Récupération résiliente des flux d'images tronqués sans crash de l'analyseur.", s["bullet"]))
    story.append(Paragraph("• <b>graphic-braid (Dé-tressage In-Memory)</b> : Le moteur <code>BraidResolver</code> détecte et sépare mathématiquement les paires de fichiers mutuellement entrelacées [1A, 1B, 2A, 2B] sans artéfact de pixels ni corruption visuelle (100% des 20 fichiers décodés avec succès).", s["bullet"]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Le Cocktail de Résilience Visuelle pour Fichiers Endommagés", s["h2"]))
    story.append(Paragraph(
        "Dans les affaires réelles, les images extraites de disques wipés ou accidentés présentent fréquemment des corruptions partielles. "
        "L'outil implémente trois boucliers de tolérance graphique :",
        s["body"]
    ))
    story.append(Paragraph("1. <b>Auto-fermeture des flux tronqués</b> : Lorsqu'un flux JPEG s'interrompt brutalement sans le marqueur <code>FF D9</code>, l'outil injecte virtuellement les 2 octets en mémoire vive. Le moteur graphique restitue ainsi la quasi-totalité de l'image au lieu d'afficher une boîte d'erreur vide.", s["bullet"]))
    story.append(Paragraph("2. <b>Mode de décodage permissif</b> : Intégration en fallback de Pillow configuré avec <code>LOAD_TRUNCATED_IMAGES = True</code> si le parser strict de Qt rejette l'image.", s["bullet"]))
    story.append(Paragraph("3. <b>Tolérance chirurgicale aux en-têtes altérés</b> : En cas d'altération d'un octet dans une table de quantification DQT (ex. altération <code>FF DB 00 00</code> au lieu de la longueur standard), le moteur corrige la longueur attendue à la volée et restaure la prévisualisation sans jamais toucher au fichier source.", s["bullet"]))

    story.append(Paragraph("5. Cartographie d'Entropie Multi-Niveaux & Validation Médico-Légale", s["h1"]))
    story.append(Paragraph("Échelle Forensique de Densité & Entropie de Shannon", s["h2"]))
    story.append(Paragraph(
        "L'entropie de Shannon mesure le niveau d'aléa de l'information selon la formule mathématique : "
        "<b>H(X) = -SUM(p(x) * log2(p(x)))</b>. "
        "Pour éviter la confusion courante entre fichiers multimédias compressés et conteneurs chiffrés, la barre de présence des données "
        "du canevas spatial utilise désormais une échelle médico-légale à 4 niveaux :",
        s["body"]
    ))
    story.append(Paragraph("• <b>Vert Émeraude (Données Claires - H &le; 7.4)</b> : Code source, documents texte, métadonnées, tables de partitions et structures non-compressées.", s["bullet"]))
    story.append(Paragraph("• <b>Bleu Dodger / Cyan (Compressé & Médias - 7.4 &lt; H &le; 7.88)</b> : Flux JPEG, vidéos MP4/WMV/MOV, archives ZIP et PDF.", s["bullet"]))
    story.append(Paragraph("• <b>Violet Sombre (Haute Entropie / Chiffrement Réel - H &gt; 7.88)</b> : Volumes BitLocker, conteneurs LUKS, clés cryptographiques aléatoires.", s["bullet"]))
    story.append(Paragraph("• <b>Noir Bordeaux (100% Zéros / Espace Wipé - Ratio &gt; 98%)</b> : Secteurs effacés ou non alloués.", s["bullet"]))

    story.append(Paragraph("Matrice de Résilience & Validation des Scénarios de Corruption", s["h2"]))

    dftt_table_data = [
        [
            Paragraph("Scénario de Corruption", s["table_header"]),
            Paragraph("Système Cible", s["table_header"]),
            Paragraph("Altération Appliquée", s["table_header"]),
            Paragraph("Mécanisme de Récupération", s["table_header"]),
            Paragraph("Intégrité des Données", s["table_header"]),
        ],
        [
            Paragraph("<b>Secteur de Boot Détruit (VBR)</b>", s["table_cell"]),
            Paragraph("FAT16 / FAT32", s["table_cell"]),
            Paragraph("Boot Sector LBA 0 wipé (zéros)<br/>Table de partition absente", s["table_cell"]),
            Paragraph("Reconstitution BPB autonome via miroir FAT & corrélation clusters", s["table_cell"]),
            Paragraph("<b>100% Bit-Exact</b><br/>Fichiers & structures restaurés", s["table_cell"]),
        ],
        [
            Paragraph("<b>Superbloc Primaire Détruit</b>", s["table_cell"]),
            Paragraph("Linux EXT2/3/4", s["table_cell"]),
            Paragraph("Superbloc LBA 2 wipé<br/>Fichiers supprimés en slack space", s["table_cell"]),
            Paragraph("Bascule superbloc de secours, défragmentation double indirecte & undelete", s["table_cell"]),
            Paragraph("<b>100% Bit-Exact</b><br/>Arborescence & hashs intègres", s["table_cell"]),
        ],
        [
            Paragraph("<b>Dissimulation Stéganographique</b>", s["table_cell"]),
            Paragraph("FAT12/16/32", s["table_cell"]),
            Paragraph("Fichier masqué sous l'attribut spécial Volume Label (0x08)", s["table_cell"]),
            Paragraph("Analyse des métadonnées de répertoire et extraction de la charge utile", s["table_cell"]),
            Paragraph("<b>100% Intact</b><br/>Anomalie identifiée & extraite", s["table_cell"]),
        ],
        [
            Paragraph("<b>Chaînes EBR Dégradées</b>", s["table_cell"]),
            Paragraph("DOS MBR / Extended", s["table_cell"]),
            Paragraph("Chaîne EBR imbriquée complexe avec intervalles logiques non alloués", s["table_cell"]),
            Paragraph("Traversée récursive étendue et détection des tables orphelines", s["table_cell"]),
            Paragraph("<b>100% Reconstitué</b><br/>Lecteurs logiques complets", s["table_cell"]),
        ],
        [
            Paragraph("<b>Flux Multimédias Tronqués</b>", s["table_cell"]),
            Paragraph("JPEG / PNG / BMP / OLE / PDF", s["table_cell"]),
            Paragraph("Marqueur EOF absent, altération d'octet dans l'en-tête (DQT)", s["table_cell"]),
            Paragraph("Cocktail de résilience : auto-fermeture FF D9, tolérance d'en-tête & décodage permissif", s["table_cell"]),
            Paragraph("<b>Restitution Visuelle</b><br/>Prévisualisation restaurée", s["table_cell"]),
        ],
    ]
    t_dftt = Table(dftt_table_data, colWidths=[95, 75, 140, 95, 100])
    t_dftt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_dftt)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Conclusion", s["h2"]))
    story.append(Paragraph(
        "Grâce à sa combinaison unique d'analyse géométrique UEFI GPT 2.10, de reconstruction mathématique des BPB orphelins, "
        "de défragmentation EXT2/3/4 et de validation granulaire de carving, <b>DFR-Forensics</b> constitue un instrument "
        "médico-légal robuste et autonome pour les laboratoires judiciaires, les équipes CSIRT/SOC et les experts en récupération de données d'urgence.",
        s["body"]
    ))

    doc.build(story, canvasmaker=lambda *args, **kwargs: NumberedCanvas(*args, doc_title="DFR-Forensics - Manuel Technique", doc_lang="fr", **kwargs))
    print(f"[OK] French Whitepaper generated: {output_path}")


def build_english_whitepaper(output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=45,
        rightMargin=45,
        topMargin=50,
        bottomMargin=50,
    )
    s = create_styles()
    story = []

    story.append(Paragraph("DFR-FORENSICS", s["title"]))
    story.append(Paragraph("Disk & File Resurrection : Low-Level Architecture & Technical Whitepaper", s["subtitle"]))

    meta_table_data = [
        [
            Paragraph("<b>Author:</b> Dam-FOR3K", s["table_cell"]),
            Paragraph("<b>Version:</b> v2.7.2", s["table_cell"]),
            Paragraph("<b>Date:</b> September 2026", s["table_cell"]),
            Paragraph("<b>License:</b> MIT Open-Source", s["table_cell"]),
        ]
    ]
    t_meta = Table(meta_table_data, colWidths=[125, 125, 125, 130])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 12))

    story.append(Paragraph("1. Forensic Problem Statement & Architectural Philosophy", s["h1"]))
    story.append(Paragraph(
        "In modern cyberattacks (destructive wipers like <i>HermeticWiper</i>, <i>CaddyWiper</i>, <i>WhisperGate</i>) "
        "and catastrophic storage hardware incidents (initial bad sector bursts, power loss during partitioning), "
        "storage boot structures are systematically targeted. When sector LBA 0 (MBR) or LBA 1 (GPT) is wiped with zeroes, "
        "operating systems (Windows, Linux, macOS) and traditional forensic tools flag the media as <b>completely unallocated or uninitialized</b>.",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>DFR-Forensics</b> (<i>Disk & File Resurrection</i>) was designed by <b>Dam-FOR3K</b> to bridge this critical gap through strict forensic paradigms:",
        s["body"]
    ))
    story.append(Paragraph("• <b>Strict Zero-Write Policy</b>: No write operations are ever performed on the target evidence. Raw images (RAW, DD, E01, AD1, AFF4) and live physical disks (<i>\\\\.\\PhysicalDriveX</i>) are opened with strict read-only hardware flags.", s["bullet"]))
    story.append(Paragraph("• <b>Virtual Copy-On-Write (COW) Architecture</b>: All table restorations, container decryptions, and superblock syntheses are executed purely in an in-memory virtual layer, ensuring 100% evidence integrity.", s["bullet"]))
    story.append(Paragraph("• <b>Mathematical Reconstruction via Invariants</b>: No offsets or cluster sizes are hardcoded. The engine derives architecture from universal filesystem laws (media descriptors, cluster chain relationships, and magic headers).", s["bullet"]))

    story.append(Paragraph("2. Low-Level Partition Table Architecture", s["h1"]))
    story.append(Paragraph("A. Master Boot Record (MBR) & EBR Chains", s["h2"]))
    story.append(Paragraph(
        "Sector LBA 0 hosts the legacy MBR: 446 bytes of bootstrap code, 4 partition descriptor entries of 16 bytes each "
        "(offsets 446 to 509), and the boot signature <code>0x55AA</code> (offsets 510-511). "
        "Each entry stores the boot flag, filesystem type ID (e.g. 0x07 NTFS/exFAT, 0x83 Linux Native), starting LBA, and total sector count. "
        "When extended partitions are used, the tool recursively navigates the linked chain of <b>Extended Boot Records (EBR)</b>.",
        s["body"]
    ))

    story.append(Paragraph("B. UEFI GPT Specification (GUID Partition Table 2.10)", s["h2"]))
    story.append(Paragraph(
        "Modern storage adheres to the UEFI GPT layout:",
        s["body"]
    ))
    story.append(Paragraph("• <b>LBA 0 (Protective MBR)</b> : Dummy MBR containing a single partition of type <code>0xEE</code> spanning the entire drive to prevent legacy utilities from misidentifying the disk.", s["bullet"]))
    story.append(Paragraph("• <b>LBA 1 (Primary GPT Header)</b> : 92-byte header beginning with signature <code>EFI PART</code> (<code>0x5452415020494645</code>). Stores disk GUIDs, partition table pointer (LBA 2), backup header pointer (LBA N-1), and two independent CRC32 checksums.", s["bullet"]))
    story.append(Paragraph("• <b>LBA 2 to 33 (Partition Entry Array)</b> : 128 entries of 128 bytes each (16,384 bytes). Each record specifies partition type GUID, unique GUID, first LBA, last LBA, attributes, and UTF-16LE partition label.", s["bullet"]))
    story.append(Paragraph("• <b>LBA N-33 to N-2 (Backup Array)</b> and <b>LBA N-1 (Backup Header)</b> : Full replica at the end of the disk providing fault tolerance.", s["bullet"]))

    story.append(Paragraph("C. CRC32 Recalculation Algorithm (IEEE 802.3)", s["h2"]))
    story.append(Paragraph(
        "When a wiper zeroes out the first megabytes of a disk (LBA 0..2048), the Primary GPT is wiped, but the Secondary GPT (LBA N-1) "
        "is frequently intact. DFR-Forensics restores the structure as follows :",
        s["body"]
    ))
    story.append(Paragraph(
        "1. Extract partition array from <code>LBA N-33</code> and map to <code>LBA 2..33</code>.<br/>"
        "2. Invert geometry pointers: <code>CurrentLBA</code> = 1, <code>BackupLBA</code> = N-1, <code>PartitionEntriesLBA</code> = 2.<br/>"
        "3. Recalculate CRC32 of partition array (16,384 bytes) using reflected polynomial <code>0xEDB88320</code>.<br/>"
        "4. Reset the 4 bytes of <code>Header CRC32</code> (offset 16) to zero, calculate CRC32 over the 92-byte header, and inject back.<br/>"
        "5. Synthesize a valid Protective MBR at LBA 0.",
        s["code"]
    ))

    story.append(PageBreak())
    story.append(Paragraph("3. Filesystem Engines & Autonomous Recovery Algorithms", s["h1"]))
    story.append(Paragraph("A. FAT12 / FAT16 / FAT32 & Backup Boot Sector Failover", s["h2"]))
    story.append(Paragraph(
        "In FAT filesystems, the <b>BPB (BIOS Parameter Block)</b> in the Volume Boot Record (LBA 0) dictates all cluster geometry: "
        "bytes per sector, reserved sectors, number of FAT tables, root entries, and sectors per cluster (SPC). "
        "When LBA 0 is zeroed out by a wiper, <b>DFR-Forensics</b> applies a dual-tier resilience strategy:",
        s["body"]
    ))
    story.append(Paragraph("• <b>Backup Boot Sector Failover (LBA 6)</b>: Under FAT32, the engine probes sector 6 (official OEM boot sector backup). If intact, original volume geometry is restored instantly without heuristic derivation.", s["bullet"]))
    story.append(Paragraph("• <b>Mathematical Orphan BPB Reconstruction</b>: When both sectors 0 and 6 are destroyed:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;1. Scans media descriptor bytes (<code>0xF8 / 0xF0</code>) to locate FAT1.<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;2. Computes: <b>Sectors Per FAT = LBA(FAT2) - LBA(FAT1)</b>.<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;3. Positions the Root Directory table immediately following FAT2.<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;4. Dynamically solves cluster size (SPC) by testing candidate offsets against real file signatures (JPEG, PDF, ZIP).", s["bullet"]))

    story.append(Paragraph("B. Linux EXT2 / EXT3 / EXT4 & Extents Tree Architecture", s["h2"]))
    story.append(Paragraph(
        "Linux EXT organizes storage into Block Groups. When the primary superblock is wiped (LBA 2) or files are fragmented:",
        s["body"]
    ))
    story.append(Paragraph("• <b>Sparse Superblock Discovery</b>: Automatically sweeps offset 8,389,632 (LBA 16,386) and group boundaries up to 32 MB to detect magic <code>0xEF53</code> and restore group descriptors.", s["bullet"]))
    story.append(Paragraph("• <b>Full EXT4 Extents Support (magic <code>0xF30A</code>)</b>: Native traversal of the extent tree stored within modern 60-byte inode blocks. Recursively decodes index nodes (<code>depth &gt; 0</code>) and leaf extent descriptors (<code>ee_block</code>, <code>ee_start</code>, <code>ee_len</code>), ensuring bit-exact reassembly of multi-gigabyte fragmented files.", s["bullet"]))
    story.append(Paragraph("• <b>Direct, Indirect & Double Indirect Pointer Resolution</b>: Chirurgical traversal of legacy Ext2/3 block trees, skipping 1,024-byte pointer metadata blocks interspersed throughout large files.", s["bullet"]))
    story.append(Paragraph("• <b>Directory Slack Space Undelete</b>: Unlinked file records absorbed by active entries' <code>rec_len</code> are extracted with original names and metadata.", s["bullet"]))

    story.append(Paragraph("C. Windows NTFS ($MFT, $MFTMirr & Backup VBR)", s["h2"]))
    story.append(Paragraph(
        "Direct pure-Python <b>$MFT</b> parsing with critical failover mechanisms:",
        s["body"]
    ))
    story.append(Paragraph("• <b>$MFTMirr Failover (cluster offset 0x38)</b>: When Record 0 of the primary $MFT is damaged or wiped, the engine fails over to <code>$MFTMirr</code> to recover non-resident <code>$DATA</code> runlists mapping the entire MFT across disk clusters.", s["bullet"]))
    story.append(Paragraph("• <b>Backup VBR Resolution (Last Sector LBA N-1)</b>: When the partition boot sector is blank, BPB parameters (cluster size, record size, MFT cluster) are retrieved from the volume end.", s["bullet"]))
    story.append(Paragraph("• <b>Transaction Log Carving ($LogFile) & Undelete</b>: Comprehensive reconstruction of active and deleted files with quadruple MACB timestamps ($STANDARD_INFORMATION).", s["bullet"]))

    story.append(Paragraph("D. Native exFAT Engine (Main & Backup VBR)", s["h2"]))
    story.append(Paragraph(
        "Pure-Python forensic parser for flash and external storage media: "
        "Backup VBR failover (sector 12), directory entry chain parsing (primary active <code>0x85</code> / deleted <code>0x05</code>, "
        "stream extension <code>0xC0</code> with contiguous allocation flag <code>NoFatChain</code>, and Unicode name sequences <code>0xC1</code>). "
        "Direct bit-exact extraction without third-party drivers.",
        s["body"]
    ))

    story.append(Paragraph("E. Embedded & Unix Systems (QNX, APFS, LUKS, BitLocker)", s["h2"]))
    story.append(Paragraph(
        "• <b>QNX4 & QNX6 Power-Safe</b>: Automotive head units and embedded controllers via superblocks <code>0x68191122</code> at LBA 8192/11776 and transaction logs.<br/>"
        "• <b>Apple APFS</b>: Container Superblock <code>NXSB</code>, Object Map (OMAP) B-Tree traversal, and multi-volume container enumeration.<br/>"
        "• <b>BitLocker & LUKS1/2</b>: Metadata extraction, PBKDF2/Argon2id key derivation, and transparent in-memory streaming decryption.",
        s["body"]
    ))

    story.append(PageBreak())
    story.append(Paragraph("4. Intelligent Carving Engine & Resilient Preview Cocktail", s["h1"]))
    story.append(Paragraph(
        "Unlike naive carvers that extract arbitrary chunks and flood analysts with false positives, "
        "<b>DFR-Forensics</b> enforces format-specific structural and mathematical validation:",
        s["body"]
    ))

    carver_table_data = [
        [
            Paragraph("Format", s["table_header"]),
            Paragraph("Header Signature", s["table_header"]),
            Paragraph("Validation Algorithm & Length Computation", s["table_header"]),
        ],
        [
            Paragraph("<b>JPEG / JFIF</b>", s["table_cell"]),
            Paragraph("<code>FF D8 FF E0..FE</code>", s["table_cell"]),
            Paragraph("Sequential marker parsing (SOF, DQT, DHT, SOS). MCU block validation and strict search for EOI marker <code>FF D9</code>.", s["table_cell"]),
        ],
        [
            Paragraph("<b>PNG</b>", s["table_cell"]),
            Paragraph("<code>89 50 4E 47 0D 0A 1A 0A</code>", s["table_cell"]),
            Paragraph("Full CRC-32 (IEEE 802.3) integrity verification on each chunk (IHDR, IDAT, IEND). File boundary locked at the final IEND chunk byte.", s["table_cell"]),
        ],
        [
            Paragraph("<b>BMP</b>", s["table_cell"]),
            Paragraph("<code>42 4D ('BM')</code>", s["table_cell"]),
            Paragraph("Little-endian total filesize verification from bytes 2..5. Non-negative dimensions and valid DIB header validation.", s["table_cell"]),
        ],
        [
            Paragraph("<b>GIF</b>", s["table_cell"]),
            Paragraph("<code>GIF87a / GIF89a</code>", s["table_cell"]),
            Paragraph("Logical Screen Descriptor dimensions check, full block structure traversal (extensions <code>0x21</code>, image descriptors <code>0x2C</code>, LZW sub-blocks) down to the legitimate trailer <code>0x3B</code> for byte-exact boundary determination.", s["table_cell"]),
        ],
        [
            Paragraph("<b>OLE CFBF (DOC, XLS, PPT)</b>", s["table_cell"]),
            Paragraph("<code>D0 CF 11 E0 A1 B1 1A E1</code>", s["table_cell"]),
            Paragraph("Internal OLE FAT traversal to compute exact sector allocation and avoid truncated documents.", s["table_cell"]),
        ],
        [
            Paragraph("<b>PDF</b>", s["table_cell"]),
            Paragraph("<code>%PDF-1.x</code>", s["table_cell"]),
            Paragraph("Bounded forward scan for the nearest <code>%%EOF</code> marker to prevent document concatenation.", s["table_cell"]),
        ],
        [
            Paragraph("<b>TIFF 6.0</b>", s["table_cell"]),
            Paragraph("<code>49 49 2A 00 ('II*\\x00')<br/>4D 4D 00 2A ('MM\\x00*')</code>", s["table_cell"]),
            Paragraph("Full Little-Endian and Big-Endian support. Traverses Image File Directory (IFD), computes exact physical span via Strip/Tile ByteCounts, and filters embedded JPEG EXIF false positives.", s["table_cell"]),
        ],
        [
            Paragraph("<b>ZIP / Office XML</b>", s["table_cell"]),
            Paragraph("<code>50 4B 03 04 ('PK..')</code>", s["table_cell"]),
            Paragraph("Local File Header chaining and validation via Central Directory (<code>PK\\x01\\x02</code>) and EOCD (<code>PK\\x05\\x06</code>).", s["table_cell"]),
        ],
    ]
    t_carver = Table(carver_table_data, colWidths=[100, 130, 275])
    t_carver.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_carver)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Strategic Carving Options & Sector Alignment", s["h2"]))
    story.append(Paragraph(
        "To adapt to any storage topology or memory dump, the engine offers surgical configuration options:",
        s["body"]
    ))
    story.append(Paragraph("• <b>512 bytes (Standard sectors - Recommended)</b>: High-speed default mode aligned on physical sector boundaries. Ideal for HDD, SSD, USB flash drives, and SD cards.", s["bullet"]))
    story.append(Paragraph("• <b>1 byte (Exhaustive / Any offset)</b>: Byte-by-byte exhaustive sweep (unaligned). Indispensable for RAM dumps, network streams, or shifted raw disk images where files begin at arbitrary offsets (1, 2, 17 bytes...).", s["bullet"]))
    story.append(Paragraph("• <b>4,096 bytes (Standard clusters)</b>: Accelerated scan aligned on standard filesystem cluster boundaries (NTFS, ext4).", s["bullet"]))
    story.append(Paragraph("• <b>Unallocated Space Only (Deleted Files)</b>: Targets exclusively freed and unassigned disk clusters by interrogating filesystem allocation tables and bitmaps (NTFS $Bitmap, FAT tables, exFAT allocation bitmap, EXT2/3/4 block bitmaps, QNX4/6 allocation tables, Apple APFS Spaceman & containers, and unpartitioned gaps). This strategy eliminates duplicate extraction of healthy active files and accelerates the carving scan by 5x to 10x.", s["bullet"]))
    story.append(Paragraph("• <b>Advanced De-Braiding (BraidResolver)</b>: Disabled by default to preserve raw file integrity and prevent accidental fragmentation on standard systems. When explicitly enabled by the analyst, it mathematically separates interleaved file pairs (1A-1B-2A-2B pattern) with verified in-memory pixel decompression.", s["bullet"]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("NIST CFTT Graphic Carving Compliance & Automated De-Braiding", s["h2"]))
    story.append(Paragraph(
        "<b>DFR-Forensics</b> successfully passes the complete official <b>NIST CFTT Graphic Carving</b> test suite "
        "(8 forensic benchmark disk images):",
        s["body"]
    ))
    story.append(Paragraph("• <b>graphic-basic & graphic-nofill</b>: 40/40 contiguous files (BMP, GIF, JPG, PNG, TIFF) carved with 100% bit-exact dimensions and hashes.", s["bullet"]))
    story.append(Paragraph("• <b>graphic-shifted & notshifted</b>: Lossless extraction of unaligned streams (offsets 1 to 511 bytes within sectors).", s["bullet"]))
    story.append(Paragraph("• <b>graphic-partials</b>: Resilient recovery of truncated image streams without parser failures.", s["bullet"]))
    story.append(Paragraph("• <b>graphic-braid (In-Memory De-Braiding)</b>: The <code>BraidResolver</code> engine automatically identifies and mathematically disentangles interleaved file pairs [1A, 1B, 2A, 2B] without Frankenstein pixel corruption (100% of 20 images successfully decoded in memory).", s["bullet"]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("The Resilient Preview Cocktail for Damaged Images", s["h2"]))
    story.append(Paragraph(
        "Real-world forensic images often exhibit partial corruptions. The tool integrates a three-tier resilience cocktail:",
        s["body"]
    ))
    story.append(Paragraph("1. <b>Truncated Stream Auto-Closing</b>: Injects virtual <code>FF D9</code> in memory if EOI is missing, allowing graphical renderers to display all intact MCUs up to the cut.", s["bullet"]))
    story.append(Paragraph("2. <b>Permissive Decoding Mode</b>: Pillow fallback with <code>LOAD_TRUNCATED_IMAGES = True</code> when strict Qt parsers reject damaged images.", s["bullet"]))
    story.append(Paragraph("3. <b>Surgical Header Tolerance</b>: Dynamically patches corrupted marker lengths (e.g. corrupted DQT table length <code>FF DB 00 00</code>) in memory to achieve 100% visual preview.", s["bullet"]))

    story.append(Paragraph("5. Multi-Tier Shannon Entropy & Forensic Resilience Validation", s["h1"]))
    story.append(Paragraph("Four-Tier Forensic Entropy Scale", s["h2"]))
    story.append(Paragraph(
        "Shannon entropy measures information randomness: "
        "<b>H(X) = -SUM(p(x) * log2(p(x)))</b>. "
        "To avoid misidentifying normal compressed media as encrypted storage, the disk presence bar utilizes a 4-tier scale:",
        s["body"]
    ))
    story.append(Paragraph("• <b>Emerald Green (Clear Active Data - H &le; 7.4)</b>: Plain text, partition tables, metadata, and uncompressed structures.", s["bullet"]))
    story.append(Paragraph("• <b>Dodger Blue / Cyan (Compressed & Media - 7.4 &lt; H &le; 7.88)</b>: JPEG, MP4/WMV/MOV, ZIP archives, and PDFs.", s["bullet"]))
    story.append(Paragraph("• <b>Deep Purple (High Entropy / True Encryption - H &gt; 7.88)</b>: BitLocker, LUKS, and cryptographic keystores.", s["bullet"]))
    story.append(Paragraph("• <b>Bordeaux Black (100% Zeroes / Wiped Space - Ratio &gt; 98%)</b>: Wiped or unallocated sectors.", s["bullet"]))

    story.append(Paragraph("Corruption Scenarios & Resilience Validation Matrix", s["h2"]))

    dftt_table_data = [
        [
            Paragraph("Corruption Scenario", s["table_header"]),
            Paragraph("Target System", s["table_header"]),
            Paragraph("Applied Corruption", s["table_header"]),
            Paragraph("Recovery Engine Mechanism", s["table_header"]),
            Paragraph("Data Integrity", s["table_header"]),
        ],
        [
            Paragraph("<b>Severed Boot Sector (VBR)</b>", s["table_cell"]),
            Paragraph("FAT16 / FAT32", s["table_cell"]),
            Paragraph("Boot Sector LBA 0 wiped (zeroes)<br/>Missing partition table", s["table_cell"]),
            Paragraph("Autonomous BPB derivation via mirror FAT & cluster magic correlation", s["table_cell"]),
            Paragraph("<b>100% Bit-Exact</b><br/>Files & directory tree restored", s["table_cell"]),
        ],
        [
            Paragraph("<b>Severed Primary Superblock</b>", s["table_cell"]),
            Paragraph("Linux EXT2/3/4", s["table_cell"]),
            Paragraph("Primary superblock wiped<br/>Deleted files in directory slack space", s["table_cell"]),
            Paragraph("Backup superblock failover, double-indirect defragmentation & undelete", s["table_cell"]),
            Paragraph("<b>100% Bit-Exact</b><br/>Full tree & hashes verified", s["table_cell"]),
        ],
        [
            Paragraph("<b>Steganographic Volume Label</b>", s["table_cell"]),
            Paragraph("FAT12/16/32", s["table_cell"]),
            Paragraph("File payload concealed under Volume Label attribute (0x08)", s["table_cell"]),
            Paragraph("Directory metadata attribute analysis & automated payload extraction", s["table_cell"]),
            Paragraph("<b>100% Intact</b><br/>Stego anomaly flagged & dumped", s["table_cell"]),
        ],
        [
            Paragraph("<b>Fragmented Extended Partitions</b>", s["table_cell"]),
            Paragraph("DOS MBR / Extended", s["table_cell"]),
            Paragraph("Complex nested EBR linked chain with unallocated gaps", s["table_cell"]),
            Paragraph("Recursive EBR parsing & orphan boot record discovery", s["table_cell"]),
            Paragraph("<b>100% Reconstructed</b><br/>All logical drives recovered", s["table_cell"]),
        ],
        [
            Paragraph("<b>Truncated & Corrupted Media</b>", s["table_cell"]),
            Paragraph("JPEG / PNG / BMP / OLE / PDF", s["table_cell"]),
            Paragraph("Missing EOF marker, header table byte corruption", s["table_cell"]),
            Paragraph("Resilience cocktail: auto-closure (FF D9), header tolerance & permissive decoding", s["table_cell"]),
            Paragraph("<b>Visual Recovery</b><br/>Preview restored seamlessly", s["table_cell"]),
        ],
    ]
    t_dftt = Table(dftt_table_data, colWidths=[95, 75, 140, 95, 100])
    t_dftt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_dftt)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Conclusion", s["h2"]))
    story.append(Paragraph(
        "By fusing low-level UEFI GPT 2.10 repair, autonomous orphan BPB derivation, EXT2/3/4 defragmentation, "
        "and granular intelligent carving, <b>DFR-Forensics</b> stands as a definitive, battle-tested forensic instrument "
        "for law enforcement agencies, digital forensics labs, CSIRT/SOC incident responders, and data recovery specialists.",
        s["body"]
    ))

    doc.build(story, canvasmaker=lambda *args, **kwargs: NumberedCanvas(*args, doc_title="DFR-Forensics - Technical Whitepaper", doc_lang="en", **kwargs))
    print(f"[OK] English Whitepaper generated: {output_path}")


if __name__ == "__main__":
    docs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
    os.makedirs(docs_dir, exist_ok=True)
    fr_path = os.path.join(docs_dir, "DFR_Forensics_Technical_Whitepaper_FR.pdf")
    en_path = os.path.join(docs_dir, "DFR_Forensics_Technical_Whitepaper_EN.pdf")

    build_french_whitepaper(fr_path)
    build_english_whitepaper(en_path)
