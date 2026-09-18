"""
WipeRescue-Forensics - Module d'Internationalisation (i18n)
Supporte le basculement dynamique Français <-> Anglais pour toute l'interface,
les messages, les rapports et les boîtes de dialogue.
"""

from typing import Dict, Any

CURRENT_LANG = "fr"

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    # Fenêtre principale & En-tête
    "app_title": {
        "fr": "DFR-Forensics : Disk & File Resurrection (v2.5.0)",
        "en": "DFR-Forensics : Disk & File Resurrection (v2.5.0)",
    },
    "header_no_image": {
        "fr": "<b>Image forensique :</b> Aucune image chargée (Glissez-déposez un fichier .raw, .e01, .aff4, .001 ici)",
        "en": "<b>Forensic Image:</b> No image loaded (Drag and drop a .raw, .e01, .aff4, .001 file here)",
    },
    "header_image_loaded": {
        "fr": "<b>Image :</b> {name} | <b>Taille :</b> {size:.2f} Gio ({bytes:,} octets) | <b>Secteurs :</b> {sectors:,}",
        "en": "<b>Image:</b> {name} | <b>Size:</b> {size:.2f} GiB ({bytes:,} bytes) | <b>Sectors:</b> {sectors:,}",
    },
    "btn_browse": {
        "fr": "📂 Parcourir une image...",
        "en": "📂 Browse Image...",
    },
    "btn_rescan": {
        "fr": "🔄 Re-scanner",
        "en": "🔄 Re-scan",
    },
    "btn_lang_toggle": {
        "fr": "🌐 English",
        "en": "🌐 Français",
    },

    # Badges de Triage
    "badge_mbr_valid": {
        "fr": "MBR : ✔️ Valide (0xEE)",
        "en": "MBR: ✔️ Valid (0xEE)",
    },
    "badge_mbr_destroyed": {
        "fr": "MBR : ❌ Détruit (100% Zéros)",
        "en": "MBR: ❌ Destroyed (100% Zeros)",
    },
    "badge_mbr_invalid": {
        "fr": "MBR : ⚠️ Invalide / Inconnu",
        "en": "MBR: ⚠️ Invalid / Unknown",
    },
    "badge_mbr_standalone": {
        "fr": "MBR : N/A (Image de Volume)",
        "en": "MBR: N/A (Volume Image)",
    },
    "badge_primary_intact": {
        "fr": "GPT Primaire : ✔️ Intacte",
        "en": "Primary GPT: ✔️ Intact",
    },
    "badge_primary_bad_crc": {
        "fr": "GPT Primaire : ⚠️ CRC Invalide",
        "en": "Primary GPT: ⚠️ Invalid CRC",
    },
    "badge_primary_destroyed": {
        "fr": "GPT Primaire : ❌ Écrasée / Absente",
        "en": "Primary GPT: ❌ Wiped / Missing",
    },
    "badge_backup_intact": {
        "fr": "GPT Secours : ✔️ Intacte (Exploitable)",
        "en": "Backup GPT: ✔️ Intact (Usable)",
    },
    "badge_backup_destroyed": {
        "fr": "GPT Secours : ❌ Invalide / Absente",
        "en": "Backup GPT: ❌ Invalid / Missing",
    },
    "badge_wipe_detected": {
        "fr": "Wipe Détecté : ⚠️ LBA 0 à {lba:,} ({mb:.1f} Mo effacés)",
        "en": "Wipe Detected: ⚠️ LBA 0 to {lba:,} ({mb:.1f} MB wiped)",
    },
    "badge_wipe_none": {
        "fr": "Wipe Détecté : Aucun effacement initial",
        "en": "Wipe Detected: No initial wipe detected",
    },
    "badge_wiper_profile": {
        "fr": "Profil d'Attaque : {profile}",
        "en": "Attack Profile: {profile}",
    },

    # Boutons d'Action Principale
    "btn_repair": {
        "fr": "🚀 Assistant de Restauration",
        "en": "🚀 Recovery Assistant",
    },
    "btn_explorer": {
        "fr": "📂 Explorateur Virtuel COW",
        "en": "📂 Virtual COW Explorer",
    },
    "btn_report": {
        "fr": "📄 Exporter Rapport PDF",
        "en": "📄 Export PDF Report",
    },
    "btn_carver": {
        "fr": "🔬 Carving Médico-Légal",
        "en": "🔬 Forensic Carving",
    },

    # Titres de Section
    "canvas_title": {
        "fr": "<b>Cartographie Spatiale des Blocs du Disque (Cliquez ou glissez pour inspecter) :</b>",
        "en": "<b>Spatial Disk Block Map (Click or drag needle to inspect):</b>",
    },
    "canvas_empty": {
        "fr": "Glissez-déposez une image médico-légale pour afficher la cartographie",
        "en": "Drag and drop a forensic image to display the block map",
    },
    "table_title": {
        "fr": "<b>Partitions et Conteneurs Détectés (Double-cliquez pour examiner en hexadécimal) :</b>",
        "en": "<b>Detected Partitions & Containers (Double-click to inspect in hex):</b>",
    },
    "table_cols": {
        "fr": ["#", "Nom", "Système / Chiffrement", "LBA Début", "LBA Fin", "Secteurs", "Taille", "GUID / Identifiant"],
        "en": ["#", "Name", "System / Encryption", "Start LBA", "End LBA", "Sectors", "Size", "GUID / Identifier"],
    },

    # Inspecteur Hexadécimal
    "hex_lba_label": {
        "fr": "Secteur LBA :",
        "en": "LBA Sector:",
    },
    "hex_btn_prev": {
        "fr": "◀ Précédent",
        "en": "◀ Previous",
    },
    "hex_btn_next": {
        "fr": "Suivant ▶",
        "en": "Next ▶",
    },
    "hex_jump_label": {
        "fr": "Saut Rapide vers :",
        "en": "Quick Jump to:",
    },
    "hex_jump_default": {
        "fr": "🎯 -- Sélectionner un repère d'intérêt --",
        "en": "🎯 -- Select landmark of interest --",
    },
    "hex_jump_mbr": {
        "fr": "📌 LBA 0 : Protective MBR (Secteur 0)",
        "en": "📌 LBA 0: Protective MBR (Sector 0)",
    },
    "hex_jump_primary_hdr": {
        "fr": "📌 LBA 1 : Primary GPT Header",
        "en": "📌 LBA 1: Primary GPT Header",
    },
    "hex_jump_primary_tbl": {
        "fr": "📌 LBA 2 : Tableau des Partitions Primaires (LBA 2 à 33)",
        "en": "📌 LBA 2: Primary Partition Table (LBA 2 to 33)",
    },
    "hex_jump_wipe_frontier": {
        "fr": "⚠️ LBA {lba:,} : Frontière du Wipe (Fin des zéros / Données)",
        "en": "⚠️ LBA {lba:,}: Wipe Frontier (End of zeros / Active data)",
    },
    "hex_jump_backup_tbl": {
        "fr": "🛡️ LBA {lba:,} : Backup Partition Entries (Table de secours)",
        "en": "🛡️ LBA {lba:,} : Backup Partition Entries (Secondary table)",
    },
    "hex_jump_backup_hdr": {
        "fr": "🛡️ LBA {lba:,} : Backup GPT Header (En-tête de secours)",
        "en": "🛡️ LBA {lba:,} : Backup GPT Header (Secondary header)",
    },
    "hex_sector_title": {
        "fr": "=== SECTEUR LBA {lba:,} (Offset octet : 0x{offset:012x}) ===",
        "en": "=== LBA SECTOR {lba:,} (Byte offset : 0x{offset:012x}) ===",
    },
    "hex_sector_wiped": {
        "fr": "[!] Secteur 100% à zéro (Zone Wipée ou Espace Non Alloué)",
        "en": "[!] Sector 100% zero-filled (Wiped Area or Unallocated Space)",
    },
    "hex_sig_detected": {
        "fr": "[+] Signature détectée : {sig}",
        "en": "[+] Detected signature : {sig}",
    },
    "hex_sig_mbr": {
        "fr": "[+] Signature MBR détectée : 0x55AA (Secteur de Boot / Partition Table)",
        "en": "[+] Detected MBR signature : 0x55AA (Boot Sector / Partition Table)",
    },
    "hex_no_image": {
        "fr": "Aucune image disque chargée.",
        "en": "No disk image loaded.",
    },
    "hex_read_error": {
        "fr": "Erreur de lecture du secteur LBA {lba} : {error}",
        "en": "Error reading LBA sector {lba} : {error}",
    },
    "header_physical_loaded": {
        "fr": "<b>🔌 Disque Physique :</b> {path} | <b>Taille :</b> {size:.2f} Gio ({bytes:,} octets) | <b>Secteurs :</b> {sectors:,}",
        "en": "<b>🔌 Physical Drive :</b> {path} | <b>Size :</b> {size:.2f} GiB ({bytes:,} bytes) | <b>Sectors :</b> {sectors:,}",
    },
    "zoom_out_tip": {
        "fr": "Zoom arrière (Molette vers le bas)",
        "en": "Zoom out (Scroll down)",
    },
    "zoom_in_tip": {
        "fr": "Zoom avant (Molette vers le haut)",
        "en": "Zoom in (Scroll up)",
    },
    "zoom_reset_tip": {
        "fr": "Réinitialiser la vue à 100% (Double-clic sur la barre)",
        "en": "Reset view to 100% (Double-click on bar)",
    },
    "zoom_status_label": {
        "fr": "Vue : LBA {start:,} à {end:,} ({pct:.1f}% du disque | Zoom {zoom:.1f}x)",
        "en": "View : LBA {start:,} to {end:,} ({pct:.1f}% of disk | Zoom {zoom:.1f}x)",
    },
    "unit_bytes": {
        "fr": "octets",
        "en": "bytes",
    },
    "status_intact": {
        "fr": "✔️ Intacte",
        "en": "✔️ Intact",
    },
    "status_wiped": {
        "fr": "❌ Wipée",
        "en": "❌ Wiped",
    },

    # Messages Dialogues
    "dlg_no_image_title": {
        "fr": "Aucune Image",
        "en": "No Image",
    },
    "dlg_no_image_msg": {
        "fr": "Veuillez charger une image médico-légale avant d'ouvrir la restauration.",
        "en": "Please load a forensic disk image before opening recovery.",
    },
    "dlg_standalone_title": {
        "fr": "Image de Volume Brut Autonome",
        "en": "Standalone Raw Volume Image",
    },
    "dlg_standalone_msg": {
        "fr": "Cette image correspond à un volume direct sans table de partitionnement GPT (ex: Conteneur Apple APFS autonome).\n\nLe système de fichiers est déjà accessible directement. Aucune table de partition n'est nécessaire ni à restaurer.",
        "en": "This image represents a direct standalone volume without a GPT partition table (e.g. standalone Apple APFS Container).\n\nThe filesystem is directly accessible. No partition table needs to be restored.",
    },
    "dlg_already_healthy_title": {
        "fr": "Table de Partition Déjà Saine",
        "en": "Partition Table Already Healthy",
    },
    "dlg_already_healthy_msg": {
        "fr": "La table de partition primaire de ce disque est déjà 100% saine et valide.\n\nSouhaitez-vous néanmoins ouvrir l'assistant pour régénérer la table, exporter un patch ou créer une copie miroir ?",
        "en": "The primary partition table on this disk is already 100% healthy and valid.\n\nWould you still like to open the assistant to re-generate the table, export a binary patch, or create a mirrored image?",
    },
    "dlg_severe_corruption_title": {
        "fr": "Restauration Automatique Indisponible",
        "en": "Automatic Recovery Unavailable",
    },
    "dlg_severe_corruption_msg": {
        "fr": "Aucune table GPT (primaire ou de secours) n'a pu être validée avec certitude sur cette image.\n\nDiagnostic actuel : {summary}\n\nSouhaitez-vous tenter une reconstruction synthétique de zéro par carving de superblocks ?",
        "en": "Neither primary nor backup GPT tables could be validated on this image.\n\nCurrent diagnostic: {summary}\n\nWould you like to attempt synthetic GPT generation from carved filesystem superblocks?",
    },

    # Explorateur Virtuel COW & MFT Undelete
    "explorer_title": {
        "fr": "DFR-Forensics - Explorateur Virtuel COW & MFT Undelete (In-Memory)",
        "en": "DFR-Forensics - Virtual COW & MFT Undelete Explorer (In-Memory)",
    },
    "explorer_info": {
        "fr": "<b>Couche Virtuelle In-Memory (Copy-On-Write) :</b> Les structures de systèmes de fichiers (NTFS, FAT, Ext4, QNX, APFS) sont analysées et montées virtuellement en mémoire. Vous pouvez inspecter les répertoires actifs, retrouver les <b>fichiers supprimés (Undelete)</b> et extraire les artefacts sans modifier la preuve d'origine.",
        "en": "<b>In-Memory Virtual Layer (Copy-On-Write):</b> Filesystem structures (NTFS, FAT, Ext4, QNX, APFS) are analyzed and virtually mounted in memory. You can browse active directories, recover <b>deleted files (Undelete)</b>, and extract artifacts without modifying original evidence.",
    },
    "explorer_partition_label": {
        "fr": "Partition cible :",
        "en": "Target Partition:",
    },
    "explorer_col_name": {
        "fr": "Nom de l'élément",
        "en": "Item Name",
    },
    "explorer_col_size": {
        "fr": "Taille",
        "en": "Size",
    },
    "explorer_col_type": {
        "fr": "Statut / Type",
        "en": "Status / Type",
    },
    "explorer_col_modified": {
        "fr": "Date Modifié ($SI)",
        "en": "Modified Date ($SI)",
    },
    "explorer_col_mft": {
        "fr": "MFT #",
        "en": "MFT #",
    },
    "explorer_btn_export": {
        "fr": "💾 Exporter le Fichier Sélectionné...",
        "en": "💾 Export Selected File...",
    },
    "explorer_btn_close": {
        "fr": "Fermer",
        "en": "Close",
    },
    "explorer_show_deleted": {
        "fr": "Afficher les éléments supprimés (Undelete)",
        "en": "Show deleted items (Undelete)",
    },
    "explorer_search_placeholder": {
        "fr": "Filtrer les fichiers par nom...",
        "en": "Filter files by name...",
    },
    "explorer_status_deleted": {
        "fr": "🗑️ SUPPRIMÉ (Undelete)",
        "en": "🗑️ DELETED (Undelete)",
    },
    "explorer_status_active": {
        "fr": "✔️ ACTIF",
        "en": "✔️ ACTIVE",
    },
    "explorer_orphaned_node": {
        "fr": "📦 Fichiers Orphelins & Non-Alloués",
        "en": "📦 Orphaned & Unallocated Files",
    },
    "explorer_export_success_title": {
        "fr": "Extraction Réussie",
        "en": "Extraction Successful",
    },
    "explorer_export_success_msg": {
        "fr": "L'artefact a été extrait avec succès :\n\nChemin : {path}\nTaille : {size:,} octets\nMD5 : {md5}\nSHA-256 : {sha256}",
        "en": "Artifact successfully extracted:\n\nPath: {path}\nSize: {size:,} bytes\nMD5: {md5}\nSHA-256: {sha256}",
    },
    "explorer_export_empty_msg": {
        "fr": "Ce fichier est vide ou n'a aucun flux de données alloué.",
        "en": "This file is empty or has no allocated data stream.",
    },

    # Conteneurs Logiques AD1 (FTK Imager)
    "badge_mbr_logical": {
        "fr": "MBR : N/A (Archive Logique)",
        "en": "MBR: N/A (Logical Archive)",
    },
    "badge_primary_logical_ad1": {
        "fr": "Conteneur : AccessData AD1",
        "en": "Container: AccessData AD1",
    },
    "badge_backup_logical": {
        "fr": "GPT Secours : N/A (Image Logique)",
        "en": "Backup GPT: N/A (Logical Image)",
    },
    "badge_wipe_logical": {
        "fr": "Wipe : N/A (Archive Logique)",
        "en": "Wipe: N/A (Logical Archive)",
    },
    "dlg_logical_ad1_title": {
        "fr": "Image Logique FTK Imager (AD1)",
        "en": "FTK Imager Logical Image (AD1)",
    },
    "dlg_logical_ad1_msg": {
        "fr": "Ce fichier est un conteneur de preuves médico-légales logique AccessData FTK Imager (.ad1).\n\nIl ne s'agit pas d'un disque physique brut : il ne comporte pas de table de partitions MBR/GPT à restaurer.\n\nCliquez sur le bouton 'Explorateur Virtuel COW' pour explorer immédiatement l'arborescence, inspecter les métadonnées et extraire les fichiers.",
        "en": "This file is an AccessData FTK Imager logical evidence container (.ad1).\n\nIt is not a raw physical disk and does not require partition table restoration.\n\nClick the 'Virtual COW Explorer' button directly to browse directories, inspect forensic metadata, and extract files.",
    },

    # Disques Physiques
    "menu_open_physical": {
        "fr": "🔌 Ouvrir un disque physique...",
        "en": "🔌 Open Physical Drive...",
    },
    "btn_open_physical": {
        "fr": "🔌 Disque physique...",
        "en": "🔌 Physical Drive...",
    },
    "dlg_physical_title": {
        "fr": "Sélectionner un Disque Physique (Accès Bas Niveau)",
        "en": "Select Physical Drive (Raw Access)",
    },
    "dlg_physical_desc": {
        "fr": "Sélectionnez un périphérique de stockage connecté pour une analyse forensique en <b>lecture seule stricte</b> :",
        "en": "Select a connected storage drive for <b>strict read-only</b> forensic analysis:",
    },
    "col_drive_id": {
        "fr": "Périphérique",
        "en": "Device",
    },
    "col_drive_model": {
        "fr": "Modèle / Fabricant",
        "en": "Model / Manufacturer",
    },
    "col_drive_size": {
        "fr": "Capacité",
        "en": "Capacity",
    },
    "col_drive_interface": {
        "fr": "Interface",
        "en": "Interface",
    },
    "col_drive_media": {
        "fr": "Type de média",
        "en": "Media Type",
    },
    "col_drive_sector": {
        "fr": "Secteur",
        "en": "Sector",
    },
    "btn_refresh_drives": {
        "fr": "🔄 Actualiser la liste",
        "en": "🔄 Refresh List",
    },
    "btn_open_selected_drive": {
        "fr": "✅ Ouvrir en Lecture Seule",
        "en": "✅ Open Read-Only",
    },
    "admin_required_banner": {
        "fr": "⚠️ L'accès direct aux disques physiques sous Windows requiert les privilèges Administrateur.",
        "en": "⚠️ Direct raw access to physical drives on Windows requires Administrator privileges.",
    },
    "btn_relaunch_admin": {
        "fr": "🛡️ Relancer en tant qu'administrateur",
        "en": "🛡️ Relaunch as Administrator",
    },
    "msg_no_physical_drives": {
        "fr": "Aucun disque physique détecté.",
        "en": "No physical drives detected.",
    },
    "msg_drive_open_error": {
        "fr": "Erreur lors de l'ouverture du disque physique :\n{error}",
        "en": "Error opening physical drive:\n{error}",
    },
    "badge_physical_drive": {
        "fr": "Source : 🔌 Disque Physique ({path})",
        "en": "Source: 🔌 Physical Drive ({path})",
    },

    # Carving Médico-Légal (Smart Carver)
    "carver_dialog_title": {
        "fr": "DFR-Forensics - Carving Médico-Légal Sémantique (In-Memory)",
        "en": "DFR-Forensics - Semantic In-Memory Forensic Carver",
    },
    "carver_range_label": {
        "fr": "Étendue du Carving :",
        "en": "Carving Scope:",
    },
    "carver_alignment_label": {
        "fr": "Alignement :",
        "en": "Alignment:",
    },
    "carver_targets_label": {
        "fr": "Cibles :",
        "en": "Targets:",
    },
    "cat_images": {
        "fr": "Images (JPEG, PNG)",
        "en": "Images (JPEG, PNG)",
    },
    "cat_databases": {
        "fr": "Bases de données (SQLite)",
        "en": "Databases (SQLite)",
    },
    "cat_documents": {
        "fr": "Documents (PDF, Office DOCX/XLSX)",
        "en": "Documents (PDF, Office DOCX/XLSX)",
    },
    "cat_logs": {
        "fr": "Journaux d'événements (EVTX)",
        "en": "Event Logs (EVTX)",
    },
    "cat_registry": {
        "fr": "Ruches Registre (regf)",
        "en": "Registry Hives (regf)",
    },
    "carver_btn_start": {
        "fr": "▶ Démarrer le Carving",
        "en": "▶ Start Carving",
    },
    "carver_btn_pause": {
        "fr": "⏸ Pause",
        "en": "⏸ Pause",
    },
    "carver_btn_resume": {
        "fr": "▶ Reprendre",
        "en": "▶ Resume",
    },
    "carver_btn_stop": {
        "fr": "⏹ Arrêter",
        "en": "⏹ Stop",
    },
    "carver_status_idle": {
        "fr": "Prêt. Sélectionnez l'étendue et lancez le scan.",
        "en": "Ready. Select scope and start carving.",
    },
    "carver_filter_placeholder": {
        "fr": "Filtrer les artefacts (format, LBA, mot-clé)...",
        "en": "Filter artefacts (format, LBA, keyword)...",
    },
    "carver_btn_select_all": {
        "fr": "Tout cocher",
        "en": "Select All",
    },
    "carver_btn_unselect_all": {
        "fr": "Tout décocher",
        "en": "Unselect All",
    },
    "col_filename": {
        "fr": "Fichier (Nom d'Origine / Source)",
        "en": "File (Original Name / Source)",
    },
    "col_cat": {
        "fr": "Catégorie",
        "en": "Category",
    },
    "col_type": {
        "fr": "Format",
        "en": "Format",
    },
    "col_lba": {
        "fr": "LBA Début",
        "en": "Start LBA",
    },
    "col_size": {
        "fr": "Taille",
        "en": "Size",
    },
    "col_details": {
        "fr": "Détails / Tables",
        "en": "Details / Tables",
    },
    "carver_preview_placeholder": {
        "fr": "Sélectionnez un artefact dans la liste pour prévisualiser son contenu en direct sans écriture sur disque.",
        "en": "Select an artefact from the list to preview its contents live in memory with zero disk writes.",
    },
    "carver_btn_export_single": {
        "fr": "💾 Exporter l'artefact sélectionné...",
        "en": "💾 Export selected artefact...",
    },
    "carver_btn_export_checked": {
        "fr": "💾 Exporter tous les éléments cochés...",
        "en": "💾 Export all checked items...",
    },
    "carver_btn_export_audit": {
        "fr": "📄 Exporter journal d'audit (CSV)...",
        "en": "📄 Export audit log (CSV)...",
    },
    "carver_btn_close": {
        "fr": "Fermer",
        "en": "Close",
    },
}


def get_lang() -> str:
    return CURRENT_LANG


def set_lang(lang: str):
    global CURRENT_LANG
    if lang in ("fr", "en"):
        CURRENT_LANG = lang


def toggle_lang() -> str:
    global CURRENT_LANG
    CURRENT_LANG = "en" if CURRENT_LANG == "fr" else "fr"
    return CURRENT_LANG


def t(key: str, **kwargs) -> Any:
    """Traduit une clé dans la langue active avec formatage optionnel."""
    entry = TRANSLATIONS.get(key)
    if not entry:
        return key
    val = entry.get(CURRENT_LANG, entry.get("fr", key))
    if isinstance(val, str) and kwargs:
        try:
            return val.format(**kwargs)
        except Exception:
            return val
    return val
