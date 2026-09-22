"""
DFR-Forensics - Générateur de Whitepapers Techniques & Guides d'Architecture
Produit une documentation forensique approfondie multi-pages (FR et EN)
destinée aux analystes médico-légaux, ingénieurs en rétro-ingénierie et auditeurs.
Auteur : Dam-FOR3K | Version : v2.8.0
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
        fontSize=11.5,
        leading=16,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=12,
    )

    h1 = ParagraphStyle(
        "SectionH1",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=7,
        keepWithNext=True,
    )

    h2 = ParagraphStyle(
        "SectionH2",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#0369a1"),
        spaceBefore=9,
        spaceAfter=4,
        keepWithNext=True,
    )

    body = ParagraphStyle(
        "Body",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=5,
    )

    bullet = ParagraphStyle(
        "BulletText",
        parent=body,
        leftIndent=14,
        firstLineIndent=-10,
        spaceAfter=3.5,
    )

    code = ParagraphStyle(
        "CodeSnippet",
        parent=base["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=5,
        spaceBefore=3,
        spaceAfter=6,
    )

    table_cell = ParagraphStyle(
        "TableCell",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor("#1e293b"),
    )

    table_header = ParagraphStyle(
        "TableHeader",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10.5,
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

    # Title & Metadata
    story.append(Paragraph("DFR-FORENSICS v2.8.0", s["title"]))
    story.append(Paragraph("Disk & File Resurrection : Guide d'Architecture Forensique & Manuel Technique", s["subtitle"]))

    meta_table_data = [
        [
            Paragraph("<b>Auteur :</b> Dam-FOR3K", s["table_cell"]),
            Paragraph("<b>Version :</b> v2.8.0", s["table_cell"]),
            Paragraph("<b>Date :</b> Septembre 2026", s["table_cell"]),
            Paragraph("<b>Licence :</b> MIT Open-Source", s["table_cell"]),
        ]
    ]
    t_meta = Table(meta_table_data, colWidths=[125, 125, 125, 130])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # Section 1
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
        "<b>DFR-Forensics</b> (<i>Disk & File Resurrection</i>) a été développé par <b>Dam-FOR3K</b> comme une suite médico-légale "
        "autonome pur-Python de classe professionnelle, sans dépendance DLL fermée. Elle applique les paradigmes suivants :",
        s["body"]
    ))
    story.append(Paragraph("• <b>Politique stricte de lecture seule (Zero-Write Policy)</b> : Aucune écriture n'est jamais effectuée sur le support d'origine. Les images brutes (RAW, DD, VMDK, VHD/VHDX, QCOW2, E01, AD1, AFF4, DMG) et les disques physiques (<i>\\\\.\\PhysicalDriveX</i>) sont ouverts avec des flags stricts en lecture seule.", s["bullet"]))
    story.append(Paragraph("• <b>Architecture virtuelle Copy-On-Write (COW)</b> : Toutes les réparations de géométrie, déchiffrements de conteneurs (BitLocker, LUKS) et reconstructions de superblocs s'exécutent dans un calque virtuel en mémoire vive, garantissant la préservation absolue de la preuve.", s["bullet"]))
    story.append(Paragraph("• <b>Reconstruction mathématique par invariants</b> : Aucun décalage ni taille n'est figé. Le moteur recherche les invariants structurels (descripteurs de médias, relations de clusters, signatures magiques) pour recalculer la géométrie exacte même lorsque tous les en-têtes primaires sont anéantis.", s["bullet"]))
    story.append(Paragraph("• <b>Exploration Virtuelle Universelle</b> : Accompagnée d'une interface graphique interactive et d'un CLI scriptable pour SOC/CSIRT, la plateforme unifie la visualisation spatiale, l'analyse d'entropie, l'inspection de slack space, la recherche brute et l'extraction de fichiers sur tous les écosystèmes (Windows, Linux, Apple, Embarqué Flash, Automotive).", s["bullet"]))

    # Section 2
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

    # Section 3
    story.append(Paragraph("3. Moteurs de Systèmes de Fichiers Standards & Réparation Autonome", s["h1"]))

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

    story.append(PageBreak())

    # Section 4 (NEW v2.8.0)
    story.append(Paragraph("4. Systèmes Embarqués, Mobiles & Flash Avancés (Nouveautés v2.8.0)", s["h1"]))
    story.append(Paragraph(
        "La version 2.8.0 introduit des moteurs natifs dédiés aux firmwares industriels, aux calculateurs automobiles (IVI/ECU), "
        "aux systèmes mobiles et aux environnements Apple modernes :",
        s["body"]
    ))

    story.append(Paragraph("A. QNX Flash Filesystem (F3S / ETFS) - Calculateurs Automobiles & IoT", s["h2"]))
    story.append(Paragraph(
        "Dans l'industrie automobile et aérospatiale (BlackBerry QNX Neutrino), les mémoires flash NOR/NAND brutes n'utilisent pas "
        "de partitions traditionnelles mais le système <b>QNX F3S (Flash Filesystem v3)</b> ou <b>ETFS (Embedded Transaction FS)</b>. "
        "L'espace physique est découpé en <i>Erase Units</i> (blocs d'effacement de 64 Ko, 128 Ko ou 256 Ko) :",
        s["body"]
    ))
    story.append(Paragraph("• <b>En-têtes d'Erase Unit (magic <code>0x66</code>)</b> : Détection et validation des blocs de contrôle identifiant l'âge du bloc et l'état d'usure (wear leveling).", s["bullet"]))
    story.append(Paragraph("• <b>En-têtes de Fichiers & Extents (magic <code>0x76</code>)</b> : Traversée séquentielle des enregistrements stockant les métadonnées (nom UTF-8, taille, UID/GID, permissions) et les pointeurs de données brutes.", s["bullet"]))
    story.append(Paragraph("• <b>Reconstruction des Mises à Jour In-Place</b> : F3S écrivant les modifications dans de nouvelles unités sans écraser les anciennes, l'analyseur reconstitue la dernière version valide tout en offrant l'accès aux versions antérieures supprimées.", s["bullet"]))

    story.append(Paragraph("B. Apple HFS+ / HFSX & Carving Bitmap $AllocationFile", s["h2"]))
    story.append(Paragraph(
        "Bien qu'APFS domine sur macOS récent, HFS+ (Hierarchical File System Plus) demeure omniprésent sur les disques externes, "
        "sauvegardes Time Machine et matériels sous macOS hérité :",
        s["body"]
    ))
    story.append(Paragraph("• <b>Volume Header à l'offset 1024 (magics <code>'H+' 0x482B</code> et <code>'HX' 0x4858</code>)</b> : Extraction de la taille de bloc d'allocation, du nombre total de blocs et des descripteurs d'extents des fichiers spéciaux de métadonnées.", s["bullet"]))
    story.append(Paragraph("• <b>Arborescence B-Tree du Catalog File</b> : Décodage pur-Python de l'arbre B-Tree équilibré (nœuds d'en-tête, nœuds d'index et nœuds feuilles) associant chaque identifiant d'enregistrement de fichier (CNID) à ses forks de données et dates HFS UTC.", s["bullet"]))
    story.append(Paragraph("• <b>Carving Ciblé via $AllocationFile</b> : Décodage du fichier spécial de bitmap d'allocation (1 bit = 1 bloc d'allocation). DFR-Forensics cartographie instantanément les plages de blocs non alloués pour restreindre le carving aux données effacées.", s["bullet"]))

    story.append(Paragraph("C. Apple APFS (Apple File System) & Volumes Séparés", s["h2"]))
    story.append(Paragraph(
        "Dans l'architecture APFS, un conteneur physique unique (GUID <code>7C3457EF-0000-11AA-AA11-00306543ECAC</code>) regroupe "
        "plusieurs volumes logiques indépendants (System, Data, Preboot, Recovery, VM) partageant dynamiquement le même espace libre :",
        s["body"]
    ))
    story.append(Paragraph("• <b>Object Map (OMAP) & B-Trees d'Objets</b> : Décodage de l'arbre B-Tree virtuel traduisant les identifiants d'objets (OID) virtuels en adresses de blocs physiques (PBA).", s["bullet"]))
    story.append(Paragraph("• <b>Découverte & Affichage Séparé des Sous-Volumes</b> : Dès la v2.8.0, chaque sous-volume APFS est identifié individuellement dans la table de partitions principale (en sous-lignes indentées) et dans l'explorateur de fichiers. L'analyste peut ainsi explorer isolément le volume système scellé en lecture seule et le volume utilisateur <i>Data</i>.", s["bullet"]))

    story.append(Paragraph("D. Systèmes Linux Embarqués : SquashFS, CPIO, F2FS, EROFS, UBI/UBIFS", s["h2"]))
    story.append(Paragraph(
        "DFR-Forensics v2.8.0 intègre un ensemble de décodeurs pour les architectures embarquées et smartphones :",
        s["body"]
    ))
    story.append(Paragraph("• <b>SquashFS v4 (magic <code>'hsqs' 0x73717368</code>)</b> : Système de fichiers compressé en lecture seule utilisé sur les box Internet, routeurs et IoT. Décompression native des tables d'inodes, blocs de données et fragments compressés (Zlib, LZ4, Zstandard, XZ).", s["bullet"]))
    story.append(Paragraph("• <b>CPIO / Initramfs (format SVR4 portable <code>'070701'</code> et <code>'070702'</code> avec CRC)</b> : Décodage des images de démarrage initial Linux ramdisk, extraction des scripts d'init, modules kernel et binaires exécutables d'amorçage.", s["bullet"]))
    story.append(Paragraph("• <b>F2FS (Flash-Friendly File System, magic <code>0xF2F52010</code>)</b> : Détection des superblocs aux offsets 1024 et 5120 octets, validation de la structure de checkpoints et des segments d'allocation sur smartphones Android modernes.", s["bullet"]))
    story.append(Paragraph("• <b>EROFS (Enhanced Read-Only FS, magic <code>0xE0F5E1E2</code>)</b> : Détection du superbloc à l'offset 1024, exploration des inodes décompressés et métadonnées de partition système Android/Huawei.", s["bullet"]))
    story.append(Paragraph("• <b>UBI / UBIFS (Unsorted Block Images)</b> : Détection des en-têtes d'Erase Counter (<code>'UBI#' 0x55424923</code>) et Volume ID (<code>'UBI!' 0x55424921</code>) sur mémoires flash industrielles non émulées.", s["bullet"]))

    story.append(PageBreak())

    # Section 5 (NEW v2.8.0)
    story.append(Paragraph("5. Clichés Instantanés VSS, Inspection du Slack Space & Recherche Brute", s["h1"]))

    story.append(Paragraph("A. Clichés Instantanés Windows VSS (Volume Shadow Copies)", s["h2"]))
    story.append(Paragraph(
        "Sur les volumes Windows NTFS, le service VSS enregistre des instantanés temporels (Shadow Copies) conservant des versions antérieures "
        "de fichiers supprimés, registres système SAM/SYSTEM, et journaux d'événements :",
        s["body"]
    ))
    story.append(Paragraph("• <b>Balayage Heuristique du Catalogue VSS (magic <code>'scek' 0x7363656B</code>)</b> : L'outil explore les blocs de métadonnées du pilote de clichés instantanés dans l'espace système NTFS.", s["bullet"]))
    story.append(Paragraph("• <b>Décodage des Descripteurs de Snapshots</b> : Extraction des identifiants GUID de cliché, des dates de création Windows FILETIME (intervalles de 100 ns depuis 1601), et des volumes cibles.", s["bullet"]))
    story.append(Paragraph("• <b>Sélection Directe dans l'Explorateur</b> : Les clichés découverts sont listés directement dans le sélecteur de volumes de l'explorateur virtuel, permettant de voyager dans le temps pour comparer les états pré/post-incident.", s["bullet"]))

    story.append(Paragraph("B. Inspecteur Forensique de File Slack Space (RAM Slack & Drive Slack)", s["h2"]))
    story.append(Paragraph(
        "Lorsqu'un fichier de taille logique $L$ est enregistré sur un disque, le système lui alloue un nombre entier de clusters "
        "(taille physique allouée P = ceil(L / C) * C). La zone résiduelle entre L et P constitue le <b>File Slack</b>, "
        "hautement stratégique pour l'investigation médico-légale :",
        s["body"]
    ))
    story.append(Paragraph("• <b>RAM Slack (Fin du dernier secteur)</b> : Zone entre la fin exacte du fichier logique et la frontière du secteur de 512 octets. Sur les anciens OS, elle était comblée par des résidus directs de la mémoire vive (mots de passe, fragments d'e-mails, clés). Sur les OS modernes, elle est comblée de zéros.", s["bullet"]))
    story.append(Paragraph("• <b>Drive Slack / Volume Slack (Secteurs résiduels du cluster)</b> : Secteurs complets compris entre le secteur contenant la fin du fichier et la fin du cluster alloué. Cette zone contient les octets intouchés des anciens fichiers ayant occupé ce cluster auparavant (fichiers effacés, fragments de documents confidentiels, artefacts de logiciels malveillants désinstallés).", s["bullet"]))
    story.append(Paragraph("• <b>Action Clic-Droit & Extraction Immédiate</b> : Dans l'explorateur de fichiers virtuel, un simple clic droit sur n'importe quel fichier permet d'ouvrir l'inspecteur visuel hexadécimal du Slack Space et d'exporter ces octets résiduels pour une analyse stéganographique ou de carving secondaire.", s["bullet"]))

    story.append(Paragraph("C. Moteur de Recherche Brute Multi-Threadée (Raw Search)", s["h2"]))
    story.append(Paragraph(
        "Pour identifier des indicateurs de compromission (IOC), des mots-clés de dossiers criminels ou des expressions régulières sans "
        "dépendre de l'intégrité du système de fichiers, DFR-Forensics intègre un scanner multi-threadé en streaming continu :",
        s["body"]
    ))
    story.append(Paragraph("• <b>Encodages Multiples</b> : Recherche simultanée en ASCII, UTF-8 et UTF-16LE (caractères 16 bits Windows/Unicode).", s["bullet"]))
    story.append(Paragraph("• <b>Expressions Régulières & Insensibilité à la Casse</b> : Support complet des regex Python appliquées par blocs avec chevauchement (overlap) pour éviter qu'une signature ne soit tronquée à la frontière d'un chunk.", s["bullet"]))
    story.append(Paragraph("• <b>Rapport Détaillé & Export CSV</b> : Chaque occurrence est localisée au byte près et au LBA physique correspondant, accompagnée d'un aperçu textuel et hexadécimal contextuel.", s["bullet"]))

    story.append(Paragraph("D. Entropie Spécialisée Flash (Inspiration Binwalk & Détection 0xFF)", s["h2"]))
    story.append(Paragraph(
        "Sur les mémoires flash brutes (NAND/NOR, puces eMMC dessoudées / Chip-Off), les blocs effacés ne sont pas remplis de zéros "
        "(<code>0x00</code>) comme sur les disques mécaniques, mais de <b>0xFF</b> (cellules à l'état vierge non programmé). "
        "DFR-Forensics ajuste son moteur d'entropie spatiale pour distinguer immédiatement l'espace flash effacé (lignes grises 0xFF), "
        "le code non compressé (vert), les données compressées (bleu) et les conteneurs chiffrés réels (violet sombre).",
        s["body"]
    ))

    story.append(PageBreak())

    # Section 6 (Carving Engine)
    story.append(Paragraph("6. Moteur de Carving Intelligent, NIST CFTT & Dé-tressage BraidResolver", s["h1"]))
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
    t_carver = Table(carver_table_data, colWidths=[95, 125, 285])
    t_carver.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]))
    story.append(t_carver)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Stratégies Sectorielles & Dé-tressage NIST CFTT", s["h2"]))
    story.append(Paragraph("• <b>Alignement Sectoriel Flexible (512B, 4096B, 1B exhaustif)</b> : Balayage ultra-rapide aligné par défaut sur 512 octets, ou décalage libre octet par octet indispensable pour les captures de mémoire vive (RAM) et flux réseau.", s["bullet"]))
    story.append(Paragraph("• <b>Espace Non Alloué Uniquement</b> : Interrogation directe des bitmaps d'allocation (NTFS $Bitmap, FAT, exFAT bitmap, EXT block bitmaps, APFS Spaceman, HFS+ $AllocationFile) accélérant le traitement de 5 à 10 fois en éliminant les fichiers sains redondants.", s["bullet"]))
    story.append(Paragraph("• <b>Dé-tressage BraidResolver (NIST CFTT Graphic-Braid)</b> : Conçu pour résoudre le scénario où deux flux graphiques sont écrits de façon entrelacée en alternance de clusters [1A, 1B, 2A, 2B]. Le moteur sépare mathématiquement les deux flux avec test de décompression en mémoire, validant 100% de la suite officielle NIST.", s["bullet"]))
    story.append(Paragraph("• <b>Cocktail de Résilience Visuelle</b> : Auto-fermeture des marqueurs de fin de fichier tronqués (injection virtuelle <code>FF D9</code>), mode de décodage permissif (Pillow avec <code>LOAD_TRUNCATED_IMAGES</code>) et tolérance chirurgicale aux anomalies de longueur d'en-tête.", s["bullet"]))

    story.append(PageBreak())

    # Section 7 (Summary Matrix & Conclusion)
    story.append(Paragraph("7. Matrice des Capacités Forensiques & Validation Médico-Légale", s["h1"]))

    cap_table_data = [
        [
            Paragraph("Module / Domaine", s["table_header"]),
            Paragraph("Technologies Cibles", s["table_header"]),
            Paragraph("Capacités Clés DFR-Forensics", s["table_header"]),
            Paragraph("Statut v2.8.0", s["table_header"]),
        ],
        [
            Paragraph("<b>Conteneurs Disques</b>", s["table_cell"]),
            Paragraph("RAW, DD, VMDK, VHD, VHDX, QCOW2, E01, AD1, AFF4, DMG", s["table_cell"]),
            Paragraph("Ouverture stricte en lecture seule, lecture par blocs multi-threadée, flux virtuels Copy-On-Write", s["table_cell"]),
            Paragraph("<b>Prise en charge intégrale</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Tables de Partitions</b>", s["table_cell"]),
            Paragraph("MBR DOS, EBR chaînés, UEFI GPT 2.10 Primaire & Backup", s["table_cell"]),
            Paragraph("Réparation automatique GPT, recalcul CRC32 IEEE 802.3, restauration Protective MBR", s["table_cell"]),
            Paragraph("<b>Restauration Bit-Exact</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Systèmes Windows</b>", s["table_cell"]),
            Paragraph("FAT12/16/32, exFAT, NTFS ($MFT, $MFTMirr, $LogFile), VSS", s["table_cell"]),
            Paragraph("Reconstruction BPB orphelin, bascule $MFTMirr/VBR, instantanés VSS temporels, inspection File Slack", s["table_cell"]),
            Paragraph("<b>Avancé + VSS + Slack</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Systèmes Linux</b>", s["table_cell"]),
            Paragraph("EXT2, EXT3, EXT4 (Extents 0xF30A), CPIO, SquashFS v4", s["table_cell"]),
            Paragraph("Sparse superblocks, défragmentation double-indirecte, undelete slack space, décompression SquashFS", s["table_cell"]),
            Paragraph("<b>Avancé + SquashFS + CPIO</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Écosystème Apple</b>", s["table_cell"]),
            Paragraph("HFS+ / HFSX, APFS (Apple File System)", s["table_cell"]),
            Paragraph("B-Tree Catalog HFS, bitmap $AllocationFile, Object Map OMAP, volumes APFS individuels séparés", s["table_cell"]),
            Paragraph("<b>Nouveau v2.8.0 (HFS+ & APFS)</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Embarqué & Flash</b>", s["table_cell"]),
            Paragraph("QNX4, QNX6, QNX F3S / ETFS, F2FS, EROFS, UBI / UBIFS", s["table_cell"]),
            Paragraph("Erase units flash brutes, recalcul in-place, détection de superblocs flash, gestion 0xFF", s["table_cell"]),
            Paragraph("<b>Nouveau v2.8.0 (F3S / Flash)</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Recherche & Carving</b>", s["table_cell"]),
            Paragraph("Carving multi-formats, Raw Search, Entropie Binwalk", s["table_cell"]),
            Paragraph("Recherche streaming multi-threadée (Regex/Unicode), dé-tressage CFTT, validation de trames", s["table_cell"]),
            Paragraph("<b>Complet + NIST CFTT 100%</b>", s["table_cell"]),
        ],
    ]
    t_cap = Table(cap_table_data, colWidths=[90, 110, 215, 90])
    t_cap.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_cap)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Conclusion & Perspectives", s["h2"]))
    story.append(Paragraph(
        "Avec sa version <b>v2.8.0</b>, <b>DFR-Forensics</b> franchit une étape majeure en unifiant l'investigation sur disques conventionnels, "
        "postes de travail modernes et systèmes embarqués critiques. Grâce à la découverte autonome de clichés VSS, l'inspection chirurgicale "
        "du Slack Space, le carving guidé par les bitmaps $AllocationFile / $Bitmap, le décodage de volumes bruts QNX F3S et SquashFS, "
        "et la recherche brute multi-threadée, la plateforme offre aux laboratoires de criminalistique numérique, forces de l'ordre, "
        "équipes de réponse aux incidents (CSIRT) et analystes en rétro-ingénierie un instrument forensique fiable, transparent et "
        "strictement conforme aux normes médico-légales internationales.",
        s["body"]
    ))

    doc.build(story, canvasmaker=lambda *args, **kwargs: NumberedCanvas(*args, doc_title="DFR-Forensics - Guide d'Architecture Forensique", doc_lang="fr", **kwargs))
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

    # Title & Metadata
    story.append(Paragraph("DFR-FORENSICS v2.8.0", s["title"]))
    story.append(Paragraph("Disk & File Resurrection: Low-Level Architecture & Technical Whitepaper", s["subtitle"]))

    meta_table_data = [
        [
            Paragraph("<b>Author:</b> Dam-FOR3K", s["table_cell"]),
            Paragraph("<b>Version:</b> v2.8.0", s["table_cell"]),
            Paragraph("<b>Date:</b> September 2026", s["table_cell"]),
            Paragraph("<b>License:</b> MIT Open-Source", s["table_cell"]),
        ]
    ]
    t_meta = Table(meta_table_data, colWidths=[125, 125, 125, 130])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # Section 1
    story.append(Paragraph("1. Forensic Problem Statement & Architectural Philosophy", s["h1"]))
    story.append(Paragraph(
        "In modern cyberattacks (destructive wipers like <i>HermeticWiper</i>, <i>CaddyWiper</i>, <i>WhisperGate</i>) "
        "and catastrophic storage hardware incidents (initial bad sector bursts, power loss during partitioning), "
        "storage boot structures are systematically targeted. When sector LBA 0 (MBR) or LBA 1 (GPT) is wiped with zeroes, "
        "operating systems (Windows, Linux, macOS) and traditional commercial forensic suites flag the media as <b>completely unallocated or uninitialized</b>.",
        s["body"]
    ))
    story.append(Paragraph(
        "<b>DFR-Forensics</b> (<i>Disk & File Resurrection</i>) was engineered by <b>Dam-FOR3K</b> as an autonomous, professional-grade, "
        "pure-Python forensic platform operating without mandatory external closed-source DLLs. It enforces strict digital evidence principles:",
        s["body"]
    ))
    story.append(Paragraph("• <b>Strict Zero-Write Policy</b>: No write operations are ever performed on the target evidence. Raw disk images (RAW, DD, VMDK, VHD/VHDX, QCOW2, E01, AD1, AFF4, DMG) and live physical drives (<i>\\\\.\\PhysicalDriveX</i>) are mounted exclusively with hardware-level read-only flags.", s["bullet"]))
    story.append(Paragraph("• <b>Virtual Copy-On-Write (COW) Architecture</b>: All geometry repairs, volume table syntheses, cryptographic container decryptions (BitLocker, LUKS), and superblock restorations execute purely in an in-memory virtual abstraction layer, ensuring 100% evidentiary integrity.", s["bullet"]))
    story.append(Paragraph("• <b>Mathematical Reconstruction via Invariants</b>: No offsets or cluster sizes are hardcoded. The engine derives architecture from universal filesystem invariants (media descriptors, cluster chain relationships, and magic headers) to recalculate exact layout even when primary headers are wiped.", s["bullet"]))
    story.append(Paragraph("• <b>Universal Interactive & Headless Workflow</b>: Combining an interactive PySide6 graphical interface with a fully scriptable CLI for CSIRT/SOC incident response pipelines, the suite unifies spatial layout mapping, Binwalk-inspired entropy tracking, Slack Space inspection, multi-threaded raw pattern search, and tree-based virtual file extraction across all major desktop and embedded OS families.", s["bullet"]))

    # Section 2
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
    story.append(Paragraph("• <b>LBA 0 (Protective MBR)</b>: Dummy MBR containing a single partition of type <code>0xEE</code> spanning the entire drive to prevent legacy utilities from misidentifying the disk.", s["bullet"]))
    story.append(Paragraph("• <b>LBA 1 (Primary GPT Header)</b>: 92-byte header beginning with signature <code>EFI PART</code> (<code>0x5452415020494645</code>). Stores disk GUIDs, partition table pointer (LBA 2), backup header pointer (LBA N-1), and two independent CRC32 checksums.", s["bullet"]))
    story.append(Paragraph("• <b>LBA 2 to 33 (Partition Entry Array)</b>: 128 entries of 128 bytes each (16,384 bytes). Each record specifies partition type GUID, unique GUID, first LBA, last LBA, attributes, and UTF-16LE partition label.", s["bullet"]))
    story.append(Paragraph("• <b>LBA N-33 to N-2 (Backup Array)</b> and <b>LBA N-1 (Backup Header)</b>: Full replica at the end of the disk providing fault tolerance.", s["bullet"]))

    story.append(Paragraph("C. CRC32 Recalculation Algorithm (IEEE 802.3)", s["h2"]))
    story.append(Paragraph(
        "When a wiper zeroes out the first megabytes of a disk (LBA 0..2048), the Primary GPT is wiped, but the Secondary GPT (LBA N-1) "
        "is frequently intact. DFR-Forensics restores the structure as follows:",
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

    # Section 3
    story.append(Paragraph("3. Standard Filesystem Engines & Autonomous Recovery", s["h1"]))

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

    story.append(PageBreak())

    # Section 4 (NEW v2.8.0)
    story.append(Paragraph("4. Embedded, Mobile & Flash Filesystems (v2.8.0 Additions)", s["h1"]))
    story.append(Paragraph(
        "Version 2.8.0 expands DFR-Forensics beyond traditional PC storage into industrial firmware dumps, "
        "automotive infotainment systems (IVI/ECUs), mobile devices, and modern Apple architectures:",
        s["body"]
    ))

    story.append(Paragraph("A. QNX Flash Filesystem (F3S / ETFS) - Automotive & Industrial IoT", s["h2"]))
    story.append(Paragraph(
        "In automotive telematics and critical infrastructure (BlackBerry QNX Neutrino), raw NOR and NAND flash memories "
        "frequently use <b>QNX F3S (Flash Filesystem v3)</b> or <b>ETFS (Embedded Transaction FS)</b> instead of partition tables. "
        "Physical flash is organized in <i>Erase Units</i> (64 KB, 128 KB, or 256 KB blocks):",
        s["body"]
    ))
    story.append(Paragraph("• <b>Erase Unit Headers (magic <code>0x66</code>)</b>: Identification and parsing of block control records managing block wear leveling and sequence numbers.", s["bullet"]))
    story.append(Paragraph("• <b>File & Extent Headers (magic <code>0x76</code>)</b>: Sequential parsing of metadata records storing UTF-8 filenames, file sizes, POSIX permissions, UID/GID, and payload extents.", s["bullet"]))
    story.append(Paragraph("• <b>In-Place Update Reconstruction</b>: Because F3S writes updates across new flash units rather than overwriting in place, the parser resolves current file versions while also uncovering historical, superseded versions for deleted data recovery.", s["bullet"]))

    story.append(Paragraph("B. Apple HFS+ / HFSX & $AllocationFile Bitmap Carving", s["h2"]))
    story.append(Paragraph(
        "Although APFS is primary on recent macOS releases, HFS+ (Hierarchical File System Plus) remains widespread "
        "on external drives, Time Machine backups, and legacy forensic images:",
        s["body"]
    ))
    story.append(Paragraph("• <b>Volume Header at Offset 1024 (magics <code>'H+' 0x482B</code> and <code>'HX' 0x4858</code>)</b>: Extraction of allocation block sizes, total block counts, and extent descriptors for system metadata files.", s["bullet"]))
    story.append(Paragraph("• <b>Catalog B-Tree Traversal</b>: Pure-Python balanced B-Tree parser (header nodes, index nodes, leaf nodes) mapping Catalog Node IDs (CNID) to data forks, resource forks, and HFS UTC timestamps.", s["bullet"]))
    story.append(Paragraph("• <b>Targeted Carving via $AllocationFile Bitmap</b>: Decodes the allocation bitmap file (1 bit per allocation block). DFR-Forensics maps exact unallocated block intervals, accelerating carving scans and eliminating healthy file false positives.", s["bullet"]))

    story.append(Paragraph("C. Apple APFS (Apple File System) & Separated Volume Discovery", s["h2"]))
    story.append(Paragraph(
        "In APFS architectures, a single physical container (GUID <code>7C3457EF-0000-11AA-AA11-00306543ECAC</code>) hosts "
        "multiple logically independent volumes (System, Data, Preboot, Recovery, VM) sharing free space dynamically:",
        s["body"]
    ))
    story.append(Paragraph("• <b>Object Map (OMAP) & B-Tree Navigation</b>: Resolves virtual object IDs (OID) to physical block addresses (PBA).", s["bullet"]))
    story.append(Paragraph("• <b>Individual Sub-Volume Discovery</b>: As of v2.8.0, APFS sub-volumes are automatically discovered and displayed separately in the partition table (as indented child entries) and in the virtual file explorer dropdown, enabling analysts to investigate user data independently from sealed system volumes.", s["bullet"]))

    story.append(Paragraph("D. Embedded Linux Filesystems: SquashFS, CPIO, F2FS, EROFS, UBI/UBIFS", s["h2"]))
    story.append(Paragraph(
        "DFR-Forensics v2.8.0 integrates specialized parsers for embedded Linux distributions and mobile dumps:",
        s["body"]
    ))
    story.append(Paragraph("• <b>SquashFS v4 (magic <code>'hsqs' 0x73717368</code>)</b>: High-density compressed read-only filesystem found in routers, gateways, and IoT firmware. Decompresses metadata tables, directory entries, and data fragments (Zlib, LZ4, Zstandard, XZ).", s["bullet"]))
    story.append(Paragraph("• <b>CPIO / Initramfs (SVR4 portable formats <code>'070701'</code> and <code>'070702'</code> with CRC)</b>: Decodes Linux boot ramdisk archives, extracting init scripts, kernel modules, and embedded payloads.", s["bullet"]))
    story.append(Paragraph("• <b>F2FS (Flash-Friendly File System, magic <code>0xF2F52010</code>)</b>: Superblock probing at offsets 1024 and 5120 bytes, checkpoint status validation, and segment layout discovery for modern Android devices.", s["bullet"]))
    story.append(Paragraph("• <b>EROFS (Enhanced Read-Only FS, magic <code>0xE0F5E1E2</code>)</b>: Probes superblock at offset 1024, traversing uncompressed inodes and metadata on modern Android/Huawei vendor partitions.", s["bullet"]))
    story.append(Paragraph("• <b>UBI / UBIFS (Unsorted Block Images)</b>: Decodes Erase Counter headers (<code>'UBI#' 0x55424923</code>) and Volume ID headers (<code>'UBI!' 0x55424921</code>) on raw flash media without hardware FTL.", s["bullet"]))

    story.append(PageBreak())

    # Section 5 (NEW v2.8.0)
    story.append(Paragraph("5. Volume Shadow Copies (VSS), File Slack Inspection & Raw Search", s["h1"]))

    story.append(Paragraph("A. Windows Volume Shadow Copies (VSS Snapshots)", s["h2"]))
    story.append(Paragraph(
        "On NTFS partitions, the Windows VSS subsystem maintains point-in-time snapshots of filesystem states, "
        "preserving deleted files, previous registry hives (SAM, SYSTEM, SOFTWARE), and event logs:",
        s["body"]
    ))
    story.append(Paragraph("• <b>Heuristic VSS Catalog Sweeper (magic <code>'scek' 0x7363656B</code>)</b>: Sweeps metadata storage chunks within NTFS volume structures.", s["bullet"]))
    story.append(Paragraph("• <b>Snapshot Descriptor Decoding</b>: Extracts snapshot GUIDs, Windows FILETIME timestamps (100 ns intervals since Jan 1, 1601), and volume target associations.", s["bullet"]))
    story.append(Paragraph("• <b>Direct Explorer Integration</b>: Discovered snapshots appear directly in the virtual file explorer dropdown, allowing incident responders to inspect historical filesystem states before malware execution or anti-forensic wiping.", s["bullet"]))

    story.append(Paragraph("B. Forensic File Slack Inspector (RAM Slack & Drive Slack)", s["h2"]))
    story.append(Paragraph(
        "When a file with logical size $L$ is written to disk, the operating system allocates an integer number of clusters "
        "(physical allocated size P = ceil(L / C) * C). The residual bytes between L and P constitute <b>File Slack</b>, "
        "a critical goldmine for digital investigators:",
        s["body"]
    ))
    story.append(Paragraph("• <b>RAM Slack (Last Sector Remainder)</b>: The gap between the logical end of file and the end of the current 512-byte physical sector. On legacy operating systems, this region was padded with transient RAM buffer artifacts (passwords, email fragments, encryption keys). Modern OSs zero this area.", s["bullet"]))
    story.append(Paragraph("• <b>Drive Slack / Volume Slack (Remaining Cluster Sectors)</b>: The remaining unused sectors within the allocated cluster. This space contains uninitialized data from previous deleted files that previously occupied those sectors (deleted documents, malware fragments, residual plaintext).", s["bullet"]))
    story.append(Paragraph("• <b>Right-Click Context Inspection & Extraction</b>: In the virtual file explorer, right-clicking any file opens the Slack Space Inspector, displaying hexadecimal previews and providing one-click export for secondary carving or steganographic review.", s["bullet"]))

    story.append(Paragraph("C. Multi-Threaded Streaming Raw Keyword & Regex Search", s["h2"]))
    story.append(Paragraph(
        "To search for indicators of compromise (IOCs), case-specific keywords, or regular expressions without "
        "relying on filesystem catalog integrity, DFR-Forensics provides a multi-threaded streaming chunk scanner:",
        s["body"]
    ))
    story.append(Paragraph("• <b>Multi-Encoding Support</b>: Concurrently sweeps ASCII, UTF-8, and UTF-16LE (Windows Unicode).", s["bullet"]))
    story.append(Paragraph("• <b>Regular Expressions & Overlap Handling</b>: Full regex matching across chunks with sliding window overlap to guarantee signatures spanning chunk boundaries are never missed.", s["bullet"]))
    story.append(Paragraph("• <b>Detailed Reporting & CSV Export</b>: Every match is indexed by exact physical byte offset and LBA sector, with surrounding context snippets and instant CSV export.", s["bullet"]))

    story.append(Paragraph("D. Binwalk-Inspired Flash Entropy & 0xFF Unprogrammed Handling", s["h2"]))
    story.append(Paragraph(
        "On raw flash chips (NAND/NOR, Chip-Off dumps), unwritten or erased blocks are filled with <b>0xFF</b> bytes "
        "(unprogrammed cell state) rather than zeroes (<code>0x00</code>). DFR-Forensics adjusts its visual entropy mapper to "
        "discriminate 0xFF flash space (grey lines), clear code/text (green), compressed media (blue), and encrypted volumes (deep purple).",
        s["body"]
    ))

    story.append(PageBreak())

    # Section 6 (Carving Engine)
    story.append(Paragraph("6. Intelligent Carving Engine, NIST CFTT & BraidResolver", s["h1"]))
    story.append(Paragraph(
        "Unlike naive carvers that extract arbitrary byte spans resulting in false positives, "
        "<b>DFR-Forensics</b> applies strict format-specific structural and mathematical validation:",
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
    t_carver = Table(carver_table_data, colWidths=[95, 125, 285])
    t_carver.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]))
    story.append(t_carver)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Strategic Sector Alignment & NIST CFTT Compliance", s["h2"]))
    story.append(Paragraph("• <b>Flexible Sector Alignment (512B, 4096B, 1B unaligned)</b>: High-speed default mode aligned on 512-byte physical sectors, or 1-byte exhaustive scanning for unaligned memory dumps.", s["bullet"]))
    story.append(Paragraph("• <b>Unallocated Space Only</b>: Probes filesystem bitmaps directly (NTFS $Bitmap, FAT tables, exFAT bitmap, EXT bitmaps, APFS Spaceman, HFS+ $AllocationFile), accelerating carving 5x-10x.", s["bullet"]))
    story.append(Paragraph("• <b>BraidResolver De-Braiding (NIST CFTT Graphic-Braid)</b>: Successfully disentangles interleaved file pairs [1A, 1B, 2A, 2B] with verified in-memory pixel rendering, achieving 100% pass on the NIST suite.", s["bullet"]))
    story.append(Paragraph("• <b>Visual Resilience Cocktail</b>: Auto-closure of truncated streams (virtual <code>FF D9</code>), permissive decoding (Pillow <code>LOAD_TRUNCATED_IMAGES</code>), and surgical header tolerance.", s["bullet"]))

    story.append(PageBreak())

    # Section 7 (Summary Matrix & Conclusion)
    story.append(Paragraph("7. Forensic Capabilities Matrix & Verification", s["h1"]))

    cap_table_data = [
        [
            Paragraph("Module / Domain", s["table_header"]),
            Paragraph("Target Technologies", s["table_header"]),
            Paragraph("Key DFR-Forensics Capabilities", s["table_header"]),
            Paragraph("v2.8.0 Status", s["table_header"]),
        ],
        [
            Paragraph("<b>Disk Containers</b>", s["table_cell"]),
            Paragraph("RAW, DD, VMDK, VHD, VHDX, QCOW2, E01, AD1, AFF4, DMG", s["table_cell"]),
            Paragraph("Strict read-only mounting, chunk-based multi-threaded I/O, virtual Copy-On-Write streams", s["table_cell"]),
            Paragraph("<b>Full Support</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Partition Schemes</b>", s["table_cell"]),
            Paragraph("DOS MBR, Linked EBR, UEFI GPT 2.10 Primary & Backup", s["table_cell"]),
            Paragraph("Automated GPT restoration, IEEE 802.3 CRC32 recalculation, Protective MBR synthesis", s["table_cell"]),
            Paragraph("<b>Bit-Exact Repair</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Windows Systems</b>", s["table_cell"]),
            Paragraph("FAT12/16/32, exFAT, NTFS ($MFT, $MFTMirr, $LogFile), VSS", s["table_cell"]),
            Paragraph("Orphan BPB derivation, $MFTMirr failover, VSS snapshot timeline discovery, File Slack Inspector", s["table_cell"]),
            Paragraph("<b>Advanced + VSS + Slack</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Linux Systems</b>", s["table_cell"]),
            Paragraph("EXT2, EXT3, EXT4 (Extents 0xF30A), CPIO, SquashFS v4", s["table_cell"]),
            Paragraph("Sparse superblocks, double-indirect defragmentation, directory slack undelete, SquashFS reader", s["table_cell"]),
            Paragraph("<b>Advanced + SquashFS + CPIO</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Apple Ecosystem</b>", s["table_cell"]),
            Paragraph("HFS+ / HFSX, APFS (Apple File System)", s["table_cell"]),
            Paragraph("HFS B-Tree Catalog, $AllocationFile bitmap, Object Map OMAP, separated APFS sub-volumes", s["table_cell"]),
            Paragraph("<b>New v2.8.0 (HFS+ & APFS)</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Embedded & Flash</b>", s["table_cell"]),
            Paragraph("QNX4, QNX6, QNX F3S / ETFS, F2FS, EROFS, UBI / UBIFS", s["table_cell"]),
            Paragraph("Raw flash erase units, in-place versioning, flash superblock sweep, 0xFF unprogrammed handling", s["table_cell"]),
            Paragraph("<b>New v2.8.0 (F3S / Flash)</b>", s["table_cell"]),
        ],
        [
            Paragraph("<b>Search & Carving</b>", s["table_cell"]),
            Paragraph("Multi-format carving, Raw Search, Binwalk Entropy", s["table_cell"]),
            Paragraph("Multi-threaded streaming regex/Unicode search, CFTT de-braiding, strict frame validation", s["table_cell"]),
            Paragraph("<b>Complete + NIST CFTT 100%</b>", s["table_cell"]),
        ],
    ]
    t_cap = Table(cap_table_data, colWidths=[90, 110, 215, 90])
    t_cap.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_cap)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Conclusion & Outlook", s["h2"]))
    story.append(Paragraph(
        "With version <b>v2.8.0</b>, <b>DFR-Forensics</b> establishes a unified forensic framework bridging conventional storage drives, "
        "modern client workstations, and mission-critical embedded systems. Through automated VSS snapshot discovery, surgical File Slack "
        "space inspection, bitmap-guided carving ($AllocationFile / $Bitmap), QNX F3S and SquashFS embedded parsing, and multi-threaded "
        "streaming raw search, the platform equips law enforcement agencies, incident response teams (CSIRT), and reverse-engineering labs "
        "with an uncompromisingly rigorous, transparent, and standards-compliant forensic investigative suite.",
        s["body"]
    ))

    doc.build(story, canvasmaker=lambda *args, **kwargs: NumberedCanvas(*args, doc_title="DFR-Forensics - Low-Level Architecture & Technical Whitepaper", doc_lang="en", **kwargs))
    print(f"[OK] English Whitepaper generated: {output_path}")


if __name__ == "__main__":
    docs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
    os.makedirs(docs_dir, exist_ok=True)
    fr_path = os.path.join(docs_dir, "DFR_Forensics_Technical_Whitepaper_FR.pdf")
    en_path = os.path.join(docs_dir, "DFR_Forensics_Technical_Whitepaper_EN.pdf")

    build_french_whitepaper(fr_path)
    build_english_whitepaper(en_path)
