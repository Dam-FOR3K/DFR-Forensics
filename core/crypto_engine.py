"""
DFR-Forensics - Moteur Cryptographique Forensique
Permet l'inspection des métadonnées, le déverrouillage sécurisé (LUKS1/LUKS2, BitLocker)
et l'accès en lecture seule au système de fichiers déchiffré.
"""

import io
import os
import sys
import json
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

from core.image_reader import ForensicImageReader

try:
    from dissect.fve import luks, bde
    FVE_AVAILABLE = True
except ImportError:
    luks = None
    bde = None
    FVE_AVAILABLE = False


class PartitionStream(io.RawIOBase):
    """Adaptateur de flux pour exposer une partition en tant qu'objet de type fichier binaire."""

    def __init__(self, reader: ForensicImageReader, offset_bytes: int, size_bytes: int):
        self.reader = reader
        self.offset = offset_bytes
        self.size = size_bytes
        self.pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, pos: int, whence: int = 0) -> int:
        if whence == 0:
            self.pos = pos
        elif whence == 1:
            self.pos += pos
        elif whence == 2:
            self.pos = self.size + pos
        self.pos = max(0, min(self.pos, self.size))
        return self.pos

    def tell(self) -> int:
        return self.pos

    def readinto(self, b: bytearray) -> int:
        length = len(b)
        if self.pos >= self.size or length == 0:
            return 0
        to_read = min(length, self.size - self.pos)
        data = self.reader.read_bytes(self.offset + self.pos, to_read)
        read_len = len(data)
        b[:read_len] = data
        self.pos += read_len
        return read_len

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size > (self.size - self.pos):
            size = self.size - self.pos
        if size <= 0:
            return b""
        data = self.reader.read_bytes(self.offset + self.pos, size)
        self.pos += len(data)
        return data


class DecryptedReader(ForensicImageReader):
    """
    Lecteur médico-légal émulant un ForensicImageReader au-dessus d'un flux déchiffré
    (LUKS ou BitLocker), permettant à NTFSReader, FATReader et ExtReader d'explorer
    les fichiers déchiffrés sans aucune modification.
    """

    def __init__(self, decrypted_stream, size_bytes: int, sector_size: int = 512, name: str = "Decrypted Volume"):
        super().__init__(name)
        self._stream = decrypted_stream
        self.total_size_bytes = size_bytes
        self.sector_size = sector_size
        self.total_sectors = max(1, (self.total_size_bytes + self.sector_size - 1) // self.sector_size)

    def read_bytes(self, offset: int, length: int) -> bytes:
        if offset >= self.total_size_bytes or length <= 0:
            return b""
        to_read = min(length, self.total_size_bytes - offset)
        try:
            if hasattr(self._stream, "readoffset"):
                return self._stream.readoffset(offset, to_read)
            elif hasattr(self._stream, "seek") and hasattr(self._stream, "read"):
                self._stream.seek(offset)
                return self._stream.read(to_read)
        except Exception:
            return b"\x00" * to_read
        return b"\x00" * to_read

    def close(self):
        try:
            if hasattr(self._stream, "close"):
                self._stream.close()
        except Exception:
            pass


class EncryptedVolumeHandler:
    """Gestionnaire forensique pour conteneurs chiffrés (LUKS et BitLocker)."""

    def __init__(self, reader: ForensicImageReader, start_lba: int, total_sectors: int):
        self.reader = reader
        self.start_lba = start_lba
        self.total_sectors = total_sectors
        self.offset_bytes = start_lba * reader.sector_size
        self.size_bytes = total_sectors * reader.sector_size

        self.stream = PartitionStream(self.reader, self.offset_bytes, self.size_bytes)
        self.crypto_type: Optional[str] = None
        self.luks_obj = None
        self.bde_obj = None
        self.unlocked_stream = None
        self.decrypted_reader: Optional[DecryptedReader] = None
        self.metadata: Dict[str, Any] = {}

        self._probe_volume()

    def _probe_volume(self):
        if not FVE_AVAILABLE:
            return

        # 1. Test LUKS
        try:
            self.stream.seek(0)
            if luks.is_luks_volume(self.stream):
                self.stream.seek(0)
                self.luks_obj = luks.LUKS(self.stream)
                hdr_sample = self.reader.read_bytes(self.offset_bytes, 16)
                ver = 2 if hdr_sample[6:8] == b"\x00\x02" else 1
                self.crypto_type = f"LUKS{ver}"
                self.metadata["type"] = self.crypto_type
                self.metadata["keyslots"] = list(self.luks_obj.keyslots.keys()) if self.luks_obj.keyslots else []

                if ver == 2:
                    try:
                        json_raw = self.reader.read_bytes(self.offset_bytes + 4096, 16384 - 4096)
                        null_pos = json_raw.find(b"\x00")
                        if null_pos > 0:
                            meta_json = json.loads(json_raw[:null_pos].decode("utf-8", errors="ignore"))
                            hdr_raw = self.reader.read_bytes(self.offset_bytes, 512)
                            uuid_str = hdr_raw[168:208].split(b"\x00")[0].decode("ascii", errors="ignore")
                            if uuid_str:
                                self.metadata["uuid"] = uuid_str

                            slots_info = meta_json.get("keyslots", {})
                            self.metadata["slots_detail"] = []
                            for s_id, s_val in slots_info.items():
                                cipher = s_val.get("area", {}).get("encryption", "N/A")
                                kdf = s_val.get("kdf", {}).get("type", "N/A")
                                self.metadata["slots_detail"].append(f"Slot {s_id} : {cipher} ({kdf})")
                            segments = meta_json.get("segments", {})
                            if "0" in segments:
                                self.metadata["encryption"] = segments["0"].get("encryption", "aes-xts-plain64")
                    except Exception:
                        pass
                return
        except Exception:
            pass

        # 2. Test BitLocker (BDE)
        try:
            self.stream.seek(0)
            if bde and bde.is_bde_volume(self.stream):
                self.stream.seek(0)
                self.bde_obj = bde.BDE(self.stream)
                self.crypto_type = "BitLocker"
                self.metadata["type"] = "BitLocker"
                self.metadata["version"] = getattr(self.bde_obj, "version", "N/A")
                self.metadata["has_passphrase"] = getattr(self.bde_obj, "has_passphrase", False)
                self.metadata["has_recovery_password"] = getattr(self.bde_obj, "has_recovery_password", False)
                self.metadata["has_bek"] = getattr(self.bde_obj, "has_bek", False)
        except Exception:
            pass

        # 2b. Signature de secours BitLocker (reconnaissance des GUIDs Microsoft modernes)
        if not self.crypto_type:
            hdr512 = self.reader.read_bytes(self.offset_bytes, 512)
            bde_g1 = b";\xd6gI).\xd8J\x83\x99\xf6\xa39\xe3\xd0\x01"
            bde_g2 = b";M\xa8\x92\x80\xdd\x0eM\x9eN\xb1\xe3(N\xae\xd8"
            if bde_g1 in hdr512 or bde_g2 in hdr512 or hdr512[3:11] == b"-FVE-FS-":
                self.crypto_type = "BitLocker"
                self.metadata["type"] = "BitLocker"
                self.metadata["version"] = "BitLocker (Windows 7/8/10/11/ToGo)"

        # 3. Vérification de session Windows active déverrouillée
        if sys.platform == "win32" and self.crypto_type == "BitLocker":
            try:
                from core.physical_disk import find_windows_drive_letter_for_partition
                win_letter = find_windows_drive_letter_for_partition(self.reader.path, self.start_lba, self.reader.sector_size)
                if win_letter:
                    self.metadata["windows_drive_letter"] = win_letter
                    # Tester si \\.\D: est accessible et renvoie du NTFS/FAT clair
                    dev_path = rf"\\.\{win_letter}"
                    try:
                        with open(dev_path, "rb", buffering=0) as f_chk:
                            b0 = f_chk.read(512)
                            if len(b0) >= 512 and (b0[3:11] in (b"NTFS    ", b"EXFAT   ", b"FAT32   ") or b0[54:62] == b"FAT16   "):
                                self.metadata["windows_is_unlocked"] = True
                    except Exception:
                        pass
            except Exception:
                pass

    @property
    def is_encrypted(self) -> bool:
        return self.crypto_type is not None

    @property
    def is_unlocked(self) -> bool:
        return self.decrypted_reader is not None

    def unlock_with_passphrase(self, passphrase: str, keyslot: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        if not self.is_encrypted:
            return False, "Ce volume n'est pas chiffré ou non reconnu."

        try:
            if self.crypto_type in ("LUKS1", "LUKS2"):
                if self.luks_obj is None:
                    self.stream.seek(0)
                    self.luks_obj = luks.LUKS(self.stream)
                self.luks_obj.unlock_with_passphrase(passphrase, keyslot=keyslot)
                unlocked = self.luks_obj.open()
                self._setup_decrypted_reader(unlocked)
                return True, None

            elif self.crypto_type == "BitLocker":
                if self.bde_obj is None:
                    self.stream.seek(0)
                    self.bde_obj = bde.BDE(self.stream)
                self.bde_obj.unlock_with_passphrase(passphrase)
                unlocked = self.bde_obj.open()
                self._setup_decrypted_reader(unlocked)
                return True, None

        except Exception as e:
            return False, f"Échec du déverrouillage : {e}"

        return False, "Mécanisme de déverrouillage non supporté."

    def unlock_with_recovery_password(self, recovery_password: str) -> Tuple[bool, Optional[str]]:
        if self.crypto_type != "BitLocker":
            return False, "La clé de récupération numérique de 48 chiffres est réservée à BitLocker."

        try:
            if self.bde_obj is None:
                self.stream.seek(0)
                self.bde_obj = bde.BDE(self.stream)
            clean_key = recovery_password.strip()
            self.bde_obj.unlock_with_recovery_password(clean_key)
            unlocked = self.bde_obj.open()
            self._setup_decrypted_reader(unlocked)
            return True, None
        except Exception as e:
            return False, f"Clé de récupération BitLocker invalide : {e}"

    def unlock_with_key_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        if not os.path.exists(file_path):
            return False, f"Fichier clé introuvable : {file_path}"

        try:
            p = Path(file_path)
            if self.crypto_type in ("LUKS1", "LUKS2"):
                if self.luks_obj is None:
                    self.stream.seek(0)
                    self.luks_obj = luks.LUKS(self.stream)
                self.luks_obj.unlock_with_key_file(p)
                unlocked = self.luks_obj.open()
                self._setup_decrypted_reader(unlocked)
                return True, None

            elif self.crypto_type == "BitLocker":
                if self.bde_obj is None:
                    self.stream.seek(0)
                    self.bde_obj = bde.BDE(self.stream)
                with open(file_path, "rb") as f_bek:
                    bek_bytes = f_bek.read()
                self.bde_obj.unlock_with_bek(bek_bytes)
                unlocked = self.bde_obj.open()
                self._setup_decrypted_reader(unlocked)
                return True, None
        except Exception as e:
            return False, f"Échec du déverrouillage avec le fichier clé : {e}"

        return False, "Format de volume non supporté pour fichier clé."

    def unlock_with_windows_volume(self, drive_letter: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Si le volume est déjà déverrouillé par Windows (ex: 'D:'),
        utilise directement le flux clair exposé par \\\\.\\D:.
        """
        target_letter = drive_letter or self.metadata.get("windows_drive_letter")
        if not target_letter:
            return False, "Aucun lecteur Windows associé identifié pour cette partition."

        clean_let = target_letter.strip().rstrip("\\/").upper()
        if not clean_let.endswith(":"):
            clean_let += ":"
        dev_path = rf"\\.\{clean_let}"

        try:
            from core.image_reader import PhysicalDiskReader
            reader = PhysicalDiskReader(dev_path, sector_size=512, total_size_bytes=self.size_bytes)
            sector = reader.read_sector(0, count=1)
            if len(sector) < 512:
                reader.close()
                return False, f"Impossible de lire les secteurs clairs du volume {dev_path}."

            self.decrypted_reader = reader
            self.unlocked_stream = reader._file
            self.metadata["unlocked_via"] = f"Session Windows ({clean_let})"
            return True, None
        except Exception as e:
            return False, f"Impossible d'accéder au lecteur Windows {clean_let} : {e}"

    def _setup_decrypted_reader(self, unlocked_stream):
        self.unlocked_stream = unlocked_stream
        decrypted_size = getattr(unlocked_stream, "size", self.size_bytes)
        self.decrypted_reader = DecryptedReader(
            decrypted_stream=unlocked_stream,
            size_bytes=decrypted_size,
            sector_size=self.reader.sector_size,
            name=f"{self.crypto_type} Déchiffré (LBA {self.start_lba})"
        )
