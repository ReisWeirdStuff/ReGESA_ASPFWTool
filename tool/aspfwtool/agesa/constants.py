# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
AMD PSP/BIOS directory constants and type definitions.

This module provides:
    - Directory kind constants
    - Cookie-to-kind mappings for binary parsing
    - Platform program table loaded from JSON configuration
    - PSP and BIOS entry type name mappings
"""

from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
import json
from pathlib import Path

from ..utils.debug_logger import get_logger


@dataclass
class Directory:
    """
    Represents a parsed directory location in firmware.

    Attributes:
        kind: Directory type identifier as DirKind enum.
        magic: Raw magic bytes as string.
        offset: Byte offset of the directory in the firmware image.
        count: Number of entries in this directory.
    """

    kind: "DirKind"
    magic: str
    offset: int
    count: int



""" Directory Kind Constants """


class DirKind(Enum):
    """AMD PSP/BIOS directory type identifiers."""
    # Combo directories (multi-platform)
    COMBO_PSP = "2PSP"  # Combo PSP Directory
    COMBO_BHD = "2BHD"  # Combo BIOS Directory
    # Level 1 directories
    PSP_L1 = "$PSP"     # PSP Level 1 Directory
    BHD_L1 = "$BHD"     # BIOS Level 1 Directory
    # Level 2 directories
    PSP_L2 = "$PL2"     # PSP Level 2 Directory
    BHD_L2 = "$BL2"     # BIOS Level 2 Directory

    @property
    def cookie(self) -> bytes:
        """Return the 4-byte magic cookie for this directory type."""
        return self.value.encode("ascii")

    @property
    def is_combo(self) -> bool:
        """Return True if this is a combo (multi-platform) directory."""
        return self in (DirKind.COMBO_PSP, DirKind.COMBO_BHD)

    @property
    def is_psp(self) -> bool:
        """Return True if this is a PSP directory (not BIOS)."""
        return self in (DirKind.COMBO_PSP, DirKind.PSP_L1, DirKind.PSP_L2)

    @property
    def is_bios(self) -> bool:
        """Return True if this is a BIOS directory."""
        return self in (DirKind.COMBO_BHD, DirKind.BHD_L1, DirKind.BHD_L2)

    @property
    def is_level2(self) -> bool:
        """Return True if this is a Level 2 directory."""
        return self in (DirKind.PSP_L2, DirKind.BHD_L2)

    @classmethod
    def from_cookie(cls, cookie: bytes) -> "DirKind | None":
        """Look up DirKind from 4-byte magic cookie."""
        for member in cls:
            if member.cookie == cookie:
                return member
        return None

    @classmethod
    def from_kind(cls, kind: str) -> "DirKind | None":
        """Look up DirKind from string kind identifier."""
        for member in cls:
            if member.value == kind:
                return member
        return None


# Cookie-to-DirKind mapping
COOKIE_KIND: Dict[bytes, DirKind] = {dk.cookie: dk for dk in DirKind}

# Editable directory kinds (including combo directories)
EDITABLE_DIRS: frozenset[DirKind] = frozenset({
    DirKind.COMBO_PSP,
    DirKind.COMBO_BHD,
    DirKind.PSP_L1,
    DirKind.PSP_L2,
    DirKind.BHD_L1,
    DirKind.BHD_L2,
})

def is_bios_dir(kind: DirKind | None) -> bool:
    """Check if a directory kind is a BIOS directory."""
    if kind is None:
        return False
    return kind.is_bios


def is_psp_dir(kind: DirKind | None) -> bool:
    """Check if a directory kind is a PSP directory."""
    if kind is None:
        return False
    return kind.is_psp


def is_combo_dir(kind: DirKind | None) -> bool:
    """Check if a directory kind is a combo directory."""
    if kind is None:
        return False
    return kind.is_combo


def is_level2_dir(kind: DirKind | None) -> bool:
    """Check if a directory kind is a level 2 directory."""
    if kind is None:
        return False
    return kind.is_level2


def is_real_dir(kind: DirKind | None) -> bool:
    """Check if a directory kind is a real (non-combo L1/L2) directory."""
    if kind is None:
        return False
    return not kind.is_combo


def is_real_bios_dir(kind: DirKind | None) -> bool:
    """Check if a directory kind is a real (non-combo) BIOS directory."""
    if kind is None:
        return False
    return kind.is_bios and not kind.is_combo


def is_real_psp_dir(kind: DirKind | None) -> bool:
    """Check if a directory kind is a real (non-combo) PSP directory."""
    if kind is None:
        return False
    return kind.is_psp and not kind.is_combo


def get_zone(kind: DirKind | None) -> str:
    """Return 'bios' or 'psp' based on directory kind."""
    return "bios" if is_bios_dir(kind) else "psp"



""" JSON Loaders for Updatable Data""" 

_MODULE_ROOT = Path(__file__).resolve().parent.parent
_UPDATABLE_DIR = _MODULE_ROOT.parent / "Updatable"


def _load_program_table() -> Dict[str, Dict[str, Any]]:
    """
    Load ProgramTable from JSON file.
    
    The JSON format includes:
    - AndMask: Hex string for CPU family/model mask
    - PSPID: Hex string for PSP ID (may be empty for unknown)
    - FamilyModel: Human-readable CPU family description (read-only)
    - Description: Codename and notes (read-only)
    """
    json_path = _UPDATABLE_DIR / "program_table.json"
    if not json_path.exists():
        return {}
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    programs = data.get("programs", {})
    if not isinstance(programs, dict):
        return {}
    # Convert hex strings back to integers, preserve read-only fields
    result: Dict[str, Dict[str, Any]] = {}
    for name, info in programs.items():
        if name.startswith("_") or not isinstance(info, dict):
            continue
        try:
            and_mask_str = info.get("AndMask", "0xFFFFFFFF")
            pspid_str = info.get("PSPID", "")
            entry: Dict[str, Any] = {
                "AndMask": int(and_mask_str, 16) if and_mask_str else 0xFFFFFFFF,
                "PSPID": int(pspid_str, 16) if pspid_str else 0,
            }
            # Include read-only reference fields
            if "FamilyModel" in info:
                entry["FamilyModel"] = info["FamilyModel"]
            if "Description" in info:
                entry["Description"] = info["Description"]
            result[name] = entry
        except (ValueError, TypeError) as exc:
            get_logger().debug(f"_load_program_table: failed to parse entry '{name}': {exc}")
            continue
    return result


def _load_type_names(filename: str) -> Dict[int, List[Any]]:
    """Load type names from JSON file."""
    json_path = _UPDATABLE_DIR / filename
    if not json_path.exists():
        return {}
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        get_logger().debug(f"_load_type_names: failed to load {json_path}: {exc}")
        return {}
    if not isinstance(data, dict):
        return {}
    types = data.get("types", {})
    if not isinstance(types, dict):
        return {}
    # Convert hex string keys to integers
    result: Dict[int, List[Any]] = {}
    for key, value in types.items():
        if key.startswith("_") or key == "metadata":
            continue
        try:
            result[int(key, 16)] = value
        except (ValueError, TypeError) as exc:
            get_logger().debug(f"_load_type_names({filename}): failed to parse key '{key}': {exc}")
            continue
    return result


@lru_cache(maxsize=1)
def _get_program_table() -> Dict[str, Dict[str, Any]]:
    """Cached loader for ProgramTable."""
    return _load_program_table()


@lru_cache(maxsize=1)
def _get_psp_type_names() -> Dict[int, List[Any]]:
    """Cached loader for PSPTypeNames."""
    return _load_type_names("psp_type_names.json")


@lru_cache(maxsize=1)
def _get_bios_type_names() -> Dict[int, List[Any]]:
    """Cached loader for BIOSTypeNames."""
    return _load_type_names("bios_type_names.json")


def reload_program_table() -> Dict[str, Dict[str, Any]]:
    """Force reload of ProgramTable from JSON file."""
    _get_program_table.cache_clear()
    global ProgramTable
    ProgramTable = _get_program_table()
    return ProgramTable


def reload_type_names() -> None:
    """Force reload of PSPTypeNames and BIOSTypeNames from JSON files."""
    _get_psp_type_names.cache_clear()
    _get_bios_type_names.cache_clear()
    global PSPTypeNames, BIOSTypeNames
    PSPTypeNames = _get_psp_type_names()
    BIOSTypeNames = _get_bios_type_names()


# Exported names - loaded from JSON at import time (cached)
ProgramTable: Dict[str, Dict[str, Any]] = _get_program_table()
PSPTypeNames: Dict[int, List[Any]] = _get_psp_type_names()
BIOSTypeNames: Dict[int, List[Any]] = _get_bios_type_names()


# ============================================================================
# Cryptographic and Key Management Constants
# ============================================================================

# PSP entry types that can contain cryptographic keys
PSP_KEY_TYPES = {0x00, 0x0A, 0x0D, 0x43, 0x50, 0x51, 0x8D, 0x97}

# BIOS entry types that can contain cryptographic keys
BIOS_KEY_TYPES = {0x07, 0x74}

# Key database types restricted to TEE (Trusted Execution Environment)
TEE_KEY_DB_TYPES = {0x51}

# PSP entry types that are TEE-related (verified using Type 0x51 TOS Public Key)
TEE_ENTRY_TYPES = {
    0x02,  # PspOs - PSP Secure OS firmware
    0x0C,  # PspTrustlet - PSP trustlet binary
    0x0D,  # TrustletKey - Trustlet key (signed public portion)
    0x15,  # TeeDrvIpKeyMgr - TEE IP Key Manager Driver
    0x1A,  # TeeSevDrv - TEE SEV driver
    0x1B,  # TeeBootDrv - TEE Boot driver
    0x1C,  # TeeSocDrv - TEE Soc driver
    0x1D,  # TeeDbgDrv - TEE Dbg driver
    0x1F,  # TeeIntfDrv - TEE Interface driver
    0x28,  # TeeRtcDrv - TEE RTC driver
    0x2C,  # TeeI2cDrv - TEE I2C driver
    0x2D,  # Runtime ABL binary
    0x45,  # TosSecurityPolicy - TOS Security Policy
    0x47,  # DrtmTa - DRTM TA
    0x51,  # TosPublicKey - TOS Public Key (self-reference)
    0x5C,  # Wmos - WMOS
    0x64,  # RAS Driver
    0x67,  # TEE related
    0x68,  # TEE related
    0x69,  # TEE related
    0x6A,  # TEE related
    0x6B,  # TEE related
    0x6C,  # TEE related
}

