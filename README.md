# DFR-Forensics 🛡️
### *Disk & File Resurrection*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version: v2.8.0](https://img.shields.io/badge/Version-v2.8.0-blue.svg)](https://github.com/Dam-FOR3K/DFR-Forensics)
[![Author: Dam--FOR3K](https://img.shields.io/badge/Author-Dam--FOR3K-orange.svg)](https://github.com/Dam-FOR3K)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![GUI: PySide6](https://img.shields.io/badge/GUI-PySide6%20%2F%20Qt6-brightgreen.svg)](https://wiki.qt.io/Qt_for_Python)

> **DFR-Forensics** (*Disk & File Resurrection*) is an advanced low-level forensic disk analysis, partition table repair, in-memory recovery, intelligent carving, and filesystem exploration suite designed by **Dam-FOR3K** to inspect, repair, and recover data from damaged, corrupted, encrypted, or partially wiped disk images and live physical drives.

---

## 🚀 What the Tool Does

When storage media suffer destructive wiper attacks (*HermeticWiper*, *CaddyWiper*, *WhisperGate*), partition table corruption, or accidental formatting where initial sectors (LBA 0..2048) are overwritten with zeroes, standard operating systems and commercial forensic suites report the disk as unallocated, uninitialized, or empty.

**DFR-Forensics** operates in memory (**Virtual Copy-On-Write**) to analyze low-level disk structures, pinpoint the exact wiped boundary, restore or synthesize valid partition tables, transparently unlock encrypted volumes (BitLocker, LUKS), reconstruct destroyed filesystems without hardcoded offsets, and extract files with full mathematical integrity.

---

## ⚡ Core Features & Internal Architecture

#### 1. Low-Level UEFI GPT Repair (UEFI 2.10) & DOS MBR
* **1-Click Backup Restoration**: Detects intact secondary GPT headers at `LBA N-1` and copies partition entries to `LBA 1..33`.
* **Mathematical CRC32 Recalculation**: Adjusts `CurrentLBA`, `BackupLBA`, and `PartitionEntriesLBA`, resets the CRC field to zero, and recalculates the header and partition array CRC32 checksums (reflected polynomial `0xEDB88320`).
* **Protective MBR Synthesis**: Generates a valid type `0xEE` Protective MBR at `LBA 0` with the `0x55AA` boot signature.
* **DOS MBR & EBR Linked Chains**: Traverses complex extended partition hierarchies (*Extended Boot Records*) with nested logical drives and unallocated gaps.

### 2. Autonomous Orphan BPB & Backup Boot Sector (FAT12 / FAT16 / FAT32)
* **Official Backup Boot Sector Failover**: In FAT32, automatically detects and loads the OEM replica boot sector at LBA 6 if LBA 0 has been wiped or corrupted.
* **Mathematical Orphan BPB Reconstruction**: When both LBA 0 and backup sectors are destroyed:
  * **Media Descriptor Discovery**: Scans early sectors for the first FAT table (FAT1) matching media byte `0xF8` / `0xF0` and chain headers.
  * **Mathematical FAT Size Derivation**: Locates the redundant FAT2 copy and computes $\text{Sectors Per FAT} = \text{LBA}(\text{FAT}_2) - \text{LBA}(\text{FAT}_1)$.
  * **Root Directory Positioning**: Maps root directory records immediately following FAT2.
  * **Dynamic Cluster Size (SPC) Derivation**: Tests candidate power-of-2 cluster sizes against root directory entries and validates candidate sector offsets against file headers (JPEG `FF D8`, PDF `%PDF`, ZIP `PK`, OLE `D0 CF`).
  * Reconstructs the complete virtual BPB in memory, exposing all active and deleted files in the Virtual File Explorer.

### 3. Linux EXT2 / EXT3 / EXT4 Extents & Slack Recovery
* **Sparse Superblock Recovery**: Discovers backup superblocks at LBA 16,386 (`0xEF53`) and alternate group boundaries when the primary superblock at offset 1,024 is zeroed out.
* **EXT4 Extents Tree Support**: Full native parsing of EXT4 extent headers (`magic 0xF30A`), extent index nodes, and leaf extents, correctly reassembling fragmented and multi-gigabyte files.
* **Double Indirect Pointer Resolution**: Decodes legacy Ext2/3 block pointer trees (12 direct, single indirect, and double indirect pointer 13) without external tooling.
* **Directory Slack Space Undelete**: Scans residual slack space inside directory entry records (`rec_len`) to extract and reconstruct unlinked deleted files with original names and attributes.

### 4. Comprehensive Pure-Python Filesystem & Embedded Engines
* **NTFS $MFT, $MFTMirr, Undelete & Windows VSS**: Direct pure-Python parser reading `$MFT` 1,024-byte records, Update Sequence Array fixups, `$STANDARD_INFORMATION` (quadruple MACB timestamps), `$FILE_NAME`, and `$DATA` resident vs non-resident runlists. Automatic failover to `$MFTMirr` (offset `0x38`) when Record 0 is damaged, Backup VBR resolution at volume end ($LBA\ N-1$), and discovery of **Windows Volume Shadow Copies (VSS)** historical snapshots via `scek` catalog descriptors with 100ns FILETIME timestamps.
* **Native exFAT Engine**: Pure-Python implementation with Backup VBR (sector 12) failover, directory entry chain parsing (`0x85` File, `0xC0` Stream Extension, `0xC1` File Name), contiguous and FAT-chained cluster resolution, and deleted file undelete.
* **Apple APFS & Multi-Volume Container Support**: Parses `NXSB` Container Superblocks, Object Map (OMAP) B-Trees, and automatically exposes separated individual sub-volumes in both partition overview and file explorer.
* **Apple HFS+ / HFSX & $AllocationFile**: Native reader for Volume Header (`0x482B` 'H+' / `0x4858` 'HX'), Catalog B-Tree leaf node decoding, big-endian Unicode strings, file extents, and unallocated space mapping via `$AllocationFile` bitmap.
* **QNX Flash Filesystem (F3S / ETFS)**: Specialized forensic reader for embedded automotive NOR/NAND flash memory dumps (e.g. Continental, Harman, Bosch head units), parsing 64K–128K Erase Units, record headers, metadata, file data, and undeleting removed flash records.
* **QNX4 & QNX6 Power-Safe**: Multi-generation superblocks (`0x68191122`), transaction logs, and inode trees from automotive head units and IoT controllers.
* **Linux Embedded & IoT Systems**:
  * **SquashFS v4**: Read-only compressed filesystem parser supporting Little-Endian (`hsqs`) and Big-Endian (`sqsh`) formats with GZIP, XZ, and LZMA block decompression.
  * **CPIO / Initramfs**: Parser for boot archives (`070701` portable ASCII format and `070702` CRC format).
  * **F2FS, EROFS, UBI / UBIFS, JFFS2**: Structural recognition and metadata analysis for Android and flash media.
* **BitLocker & LUKS1/2**: Transparent in-memory cryptographic engine unlocking volumes via recovery password, passphrase, or raw key files.


### 5. Intelligent Carving Engine, Alignment Strategies & Controlled De-Braiding
* **Format-Specific Mathematical Validation**:
  * **TIFF 6.0**: Native Little-Endian (`II*\x00`) and Big-Endian (`MM\x00*`) Image File Directory (IFD) parser, calculating exact physical extent via Strip/Tile ByteCounts and tag arrays, with strict embedded JPEG EXIF filtering.
  * **JPEG**: Sequential marker parsing (SOF, DQT, DHT, SOS), MCU block verification, and strict EOI `FF D9` search.
  * **PNG**: Resilient chunk parsing with IEEE 802.3 CRC-32 verification and graceful recovery on fragmented streams.
  * **BMP**: DIB v1 to v5 headers (12, 40, 52, 56, 64, 108, 124 bytes) and little-endian filesize verification from header bytes 2..5.
  * **GIF (GIF87a / GIF89a)**: Full block-level traversal through extension blocks (`0x21`), Image Descriptors (`0x2C`), and LZW sub-blocks down to the legitimate trailer (`0x3B`), ensuring byte-exact boundary recovery without false-positive semicolons.
  * **OLE CFBF (DOC, XLS, PPT)**: Internal FAT traversal across sectors to compute exact physical file length.
  * **PDF**: Bounded forward scanning strictly limited to the nearest `%%EOF` marker.
  * **ZIP / Office XML**: Local File Header chaining and validation against Central Directory records.
* **Targeted Unallocated Space Carving (`Espace non alloué uniquement`)**:
  * Scans exclusively deleted and unassigned disk regions, automatically bypassing active filesystem files across **NTFS** (`$Bitmap` record 6 & data runs complement), **FAT12/16/32** (0-value clusters), **exFAT** (allocation bitmap), **EXT2/3/4** (block bitmap inspection), **QNX4/6** (block allocation tables), and **Apple APFS** (Space Manager chunk bitmaps & extents), plus unpartitioned drive slack.
  * Eliminates redundant extraction of already intact files, yielding a 5x to 10x speedup in forensic triage with zero duplicate clutter.
* **Strategic Sector Alignment & Sweep Modes**:
  * **512 bytes (Standard sectors - Recommended)**: Ultra-fast physical sector-aligned sweep for drives, SSDs, and USB storage.
  * **1 byte (Exhaustive / Any offset - Shifted files)**: Surgical byte-by-byte sweep capable of recovering shifted files starting at arbitrary offsets (RAM dumps, raw memory artifacts, unsynchronized disks).
  * **4,096 bytes (Standard clusters)**: Accelerated cluster-aligned sweep for NTFS/ext4 filesystems.
* **Controlled In-Memory De-Braiding Engine (`BraidResolver`)**:
  * Disabled by default to preserve raw file integrity and prevent accidental fragmentation on standard media.
  * When enabled on demand by the analyst, mathematically detects and disentangles interleaved file pairs `[Part 1A, Part 1B, Part 2A, Part 2B]`.
  * Verifies real in-memory pixel decompression (`img.load()`) before accepting any reconstructed candidate.
* **Resilient Visual Preview Cocktail**:
  * **Auto-Closing Truncated Streams**: Injects virtual `FF D9` in memory if EOI is missing, allowing graphical renderers to display all intact MCUs up to the cut.
  * **Permissive Decoding Mode**: Pillow fallback with `LOAD_TRUNCATED_IMAGES = True` when strict parsers reject damaged files.
  * **Surgical Header Tolerance**: Dynamically patches corrupted marker lengths (e.g. corrupted DQT table length `FF DB 00 00`) in memory to achieve 100% visual preview.

### 6. File Slack Inspector & Residual Data Analysis
* **Contextual Right-Click Exploration**: Inspects any file's exact residual slack allocation directly from the virtual file explorer tree.
* **RAM Slack**: Bytes between the logical end-of-file and the end of the containing 512-byte sector, revealing residual memory buffers leaked during OS write operations.
* **Drive Slack**: Unallocated sectors within the final cluster assigned to the file, preserving critical forensic traces of previous files, deleted records, or hidden payloads.
* **Live Hexadecimal Dump**: Immediate interactive hex inspection of slack bytes without manual offset math.

### 7. High-Throughput Streaming Raw Keyword & Regex Search
* **Multi-Threaded Architecture**: Independent background scanner streaming disk chunks with configurable overlap to prevent split-match omissions at boundary borders.
* **Flexible Querying**: Supports ASCII/UTF-8 literal strings (case-sensitive or insensitive) and complex regular expressions (e.g. credit cards, IP addresses, hashes, serial numbers, VINs).
* **Target Scopes**: Scan either the entire physical drive / container or exclusively unallocated clusters.
* **Forensic Audit Table & Export**: Live results list with LBA, exact byte offsets, matched terms, contextual ASCII and Hex dumps, and 1-click CSV export for official reports.

### 8. Binwalk-Inspired Shannon Entropy Heatmap & 0xFF Flash Detection
* Computes local Shannon entropy: $H(X) = -\sum_{i=0}^{255} p(x_i) \log_2 p(x_i)$.
* **Multi-level forensic classification**:
  * 🟩 **Emerald Green (`#27ae60`)**: Clear active data ($H \le 7.4$, code, text, metadata).
  * 🟦 **Dodger Blue / Cyan (`#0984e3`)**: Compressed media ($7.4 < H \le 7.88$, JPEG, MP4, ZIP, PDF).
  * 🟪 **Deep Purple (`#8e44ad`)**: High entropy / True encryption ($H > 7.88$, BitLocker, LUKS, encrypted volumes).
  * ⬛ **Bordeaux Black (`#221010`)**: 100% Zeroes / Wiped magnetic space (Zeros ratio $> 98\%$).
  * ⬜ **Light Grey Flash (`#d1d5db`)**: 100% 0xFF / Erased solid-state flash memory blocks.

### 9. Wipe Frontier Boundary Detection
* Two-phase search algorithm: fast macro-sampling followed by sector-level binary convergence down to 512-byte precision.
* Determines the exact boundary where wiper destruction ceased and intact data survives.

### 10. Live Physical Drives & Forensic Containers
* **Physical Hardware Access**: Direct raw access under Windows (`\\.\PhysicalDrive0..N`) and Linux/macOS (`/dev/sdX`, `/dev/nvmeX`) with automated bad sector tolerance.
* **Forensic Containers**: E01, Ex01, Split Raw (`.001`, `.002`), AFF4, AD1, and DMG.
* **Streaming Exporter**: Export raw or decrypted partitions with real-time **MD5** and **SHA-256** hash generation.

---

## 🔬 Forensic Resilience & Recovery Validation

| Forensic Corruption Scenario | Target Filesystem | Applied Destruction Pattern | Recovery Engine Action | Hash Integrity |
| :--- | :--- | :--- | :--- | :---: |
| **Severed Boot Sector (VBR)** | FAT16 / FAT32 / exFAT | LBA 0 wiped (zeros), partition table destroyed | Backup Boot Sector failover & autonomous BPB derivation | 🟢 **100% Bit-Exact Recovery** |
| **Damaged $MFT Record 0** | NTFS | Sector 0 MFT corrupted or zeroed | `$MFTMirr` (cluster 0x38) Data Runs fallback & Backup VBR | 🟢 **100% Tree Reconstruction** |
| **Historical NTFS Snapshots** | Windows VSS | Previous states locked in volume shadow copies | Heuristic `scek` catalog parsing & FILETIME timestamps | 🟢 **100% Snapshot Extraction** |
| **Fragmented Large Files** | Linux EXT4 | Non-contiguous multi-GB files | Inode Extent Tree parsing (`0xF30A`) across depth levels | 🟢 **100% Bit-Exact Recovery** |
| **Severed Primary Superblock** | Linux EXT2 / EXT3 / EXT4 | Superblock wiped, deleted directory slack space | Backup superblock failover & double-indirect defragmentation | 🟢 **100% Bit-Exact Recovery** |
| **Embedded Automotive Flash** | QNX F3S / ETFS | NOR/NAND raw chip dump with deleted files | Erase unit scan, record parsing & deleted file carving | 🟢 **100% Inode & File Extraction** |
| **Mac OS Extended Volume** | Apple HFS+ / HFSX | Primary partition unmounted, damaged catalogue | Leaf node B-Tree traversal & `$AllocationFile` unallocated carving | 🟢 **100% Bit-Exact Recovery** |
| **Compressed IoT Firmware** | Linux SquashFS v4 | Raw flash dump of router / dashcam firmware | Superblock parsing & block decompression (GZIP/XZ/LZMA) | 🟢 **100% Tree Reconstruction** |
| **Linux Initrd Archive** | CPIO / Initramfs | Embedded kernel ramdisk archive | SVR4 portable ASCII decoding & file stream extraction | 🟢 **100% Bit-Exact Recovery** |
| **Volume Label Steganography** | FAT12 / FAT16 / FAT32 | Payload concealed under Volume Label attribute `0x08` | Automated anomaly detection & directory attribute carving | 🟢 **100% File Integrity** |
| **Fragmented Partition Chains** | DOS MBR / Extended EBR | Fragmented EBR linked list with unallocated gaps | Deep recursive traversal & unallocated gap recovery | 🟢 **100% Tree Reconstruction** |
| **Braided / Interleaved Media** | NIST CFTT Graphic Suite | 1A-1B-2A-2B alternating interleaved pairs | `BraidResolver` spiral delta disentanglement & stream stitching | 🟢 **100% (20/20) Bit-Exact Carving** |
| **Truncated / Damaged Media** | JPEG / PNG / BMP / MP4 | Missing EOF marker, single-byte header corruption | Resilient tolerant decoding & automated EOF (`FF D9`) injection | 🟢 **Resilient Visual Preview** |

---

## 📦 Project Structure

```
DFR-Forensics/
├── core/                       # Core analytical & recovery engines
│   ├── image_reader.py         # Forensic container & physical drive abstraction (RAW, E01, AD1, AFF4, \\.\PhysicalDriveX)
│   ├── physical_disk.py        # Physical drive enumeration & UAC privilege manager
│   ├── scanner.py              # Low-level diagnostic, backup superblock & orphan BPB detector
│   ├── repair_engine.py        # UEFI GPT 2.10 repair and CRC32 recalculation
│   ├── synthesizer.py          # Superblock carver & heuristic GPT synthesis
│   ├── carver.py               # Intelligent format-specific carver & validators (JPEG, PNG, BMP, GIF, TIFF, OLE, PDF, ZIP)
│   ├── defragmenter.py         # In-Memory De-Braiding & fragmented stream reconstruction (NIST CFTT)
│   ├── unallocated.py          # Filesystem unallocated cluster & gap mapping (NTFS, FAT, exFAT, EXT, QNX, APFS, HFS+)
│   ├── correlator.py           # Orphan directory metadata correlator
│   ├── crypto_engine.py        # LUKS1/2 & BitLocker in-memory decryption
│   ├── ntfs_reader.py          # Pure-Python NTFS parser & MFT undelete
│   ├── fat_reader.py           # FAT12/16/32 parser & autonomous orphan BPB reconstruction
│   ├── exfat_reader.py         # Pure-Python exFAT parser, Backup VBR & stream resolution
│   ├── ext_reader.py           # Ext2/Ext3/Ext4 parser, extents tree & double-indirect defragmenter
│   ├── qnx_reader.py           # QNX4 & QNX6 Power-Safe parser
│   ├── f3s_reader.py           # QNX Flash Filesystem (F3S / ETFS) automotive NOR/NAND reader
│   ├── hfs_reader.py           # Apple HFS+ / HFSX B-Tree catalogue & allocation reader
│   ├── squashfs_reader.py      # Linux SquashFS v4 compressed filesystem parser
│   ├── cpio_reader.py          # Linux Initramfs / CPIO archive extractor
│   ├── embedded_flash.py       # Unified F2FS, EROFS, UBI/UBIFS, JFFS2 parser
│   ├── vss_reader.py           # Windows Volume Shadow Copies (VSS) snapshot parser
│   ├── raw_search.py           # Multi-threaded streaming raw keyword & regex scanner
│   ├── apfs_reader.py          # Apple APFS container & volume reader
│   ├── partition_exporter.py   # Streaming exporter with live MD5 & SHA-256
│   ├── entropy.py              # Shannon entropy computation engine
│   └── i18n.py                 # French & English UI translations
├── ui/                         # Graphical user interface (PySide6 / Qt6)
│   ├── app_gui.py              # Main window, controls, and docking layout
│   ├── physical_drive_dialog.py# Physical drive selector modal with UAC elevation
│   ├── disk_canvas.py          # Interactive zoomable spatial canvas & Binwalk entropy heatmap
│   ├── file_explorer_dialog.py # In-memory filesystem tree, slack inspector & file extractor
│   ├── carver_dialog.py        # Advanced carving dialog with resilient preview cocktail
│   ├── raw_search_dialog.py    # Multi-threaded streaming keyword/regex search dialog
│   ├── hex_viewer.py           # High-performance 512-byte sector hex viewer
│   └── repair_dialog.py        # UEFI GPT repair confirmation dialog
├── docs/                       # Technical whitepapers (PDF FR & EN)
│   ├── DFR_Forensics_Technical_Whitepaper_FR.pdf
│   └── DFR_Forensics_Technical_Whitepaper_EN.pdf
├── dist/                       # Standalone compiled portable binaries
│   └── DFR-Forensics/          # Self-contained executable (.exe)
├── cli.py                      # Headless command-line interface
├── main.py                     # GUI entry point
├── run_gui.bat                 # Script to launch GUI with local Python
├── run_standalone.bat          # Script to run pre-compiled standalone binary
└── requirements.txt            # Python dependencies
```

---

## 💻 Installation & Quickstart

### Option 1: Standalone Portable Binary (No Python Required)
Double-click `run_standalone.bat` or run:
```cmd
dist\DFR-Forensics\DFR-Forensics.exe
```

### Option 2: Run with Python 3.10+
1. Install dependencies:
```bash
pip install -r requirements.txt
```
2. Launch the Graphical Interface:
```bash
python main.py
```
Or with an image directly loaded:
```bash
python main.py disk_image.E01
```

### Option 3: Command-Line Interface (CLI)
```bash
# List all connected physical storage drives (SATA, NVMe, USB, SCSI)
python cli.py --list-drives

# Scan and diagnose a forensic disk image or raw physical drive
python cli.py scan image.E01
python cli.py scan "\\.\PhysicalDrive1"

# Generate a repaired mirror image with restored UEFI GPT 2.10
python cli.py repair disk.raw --output repaired_disk.raw
```

---

## 🌐 Bilingual Support
The graphical user interface supports **English** and **Français** out of the box. Use the `[ 🌐 English / Français ]` button in the top bar to toggle languages at any time.

---

## 📄 License & Author
* **Author**: Dam-FOR3K
* **Version**: v2.8.0
* **License**: MIT License. See [LICENSE](LICENSE) for details.

