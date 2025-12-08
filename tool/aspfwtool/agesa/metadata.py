# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Version extraction utilities for PSP firmware entries.

This module provides:
    - Version decoding for various PSP entry types
    - Type-specific version format handlers
    - Version string formatting utilities
    - SMU platform identification via signature matching

The _VERSION_INFO_DIR table is the single source of truth for version parsing.
Each entry can specify:
    - version_offset: byte offset to read version data from
    - unpack_format: struct format string (little-endian assumed)
    - print_format: Python format string for output
    - function: name of special handler for complex parsing logic
    - redirect: tuple (zone, type_id) to inherit config from another entry
"""

import json
import struct
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import constants as _constants
from . import crypto as _crypto
from . import keys as _keys
from . import ps1 as _ps1


""" 
SMU Platform Identification:
    Different processors may share the same PSPID, 
    Identifing by PSPID and SubProgram ID is so annoying so we identify by content.

    We also hash the entry to map the AGESA version (agesa.py), current smu method should be good enough. 
"""

_UPDATABLE_DIR = Path(__file__).resolve().parent.parent / "updatable"


@dataclass(frozen=True)
class _PlatformSignature:
    """SMU platform signature for content-based identification."""

    family: str
    name: str
    description: str
    pattern: Tuple[Optional[int], ...]
    offset: int = 0

    @staticmethod
    def from_tokens(
        *, family: str, name: str, description: str, signature: str, offset: int = 0
    ) -> "_PlatformSignature":
        """Parse signature from space-separated hex tokens (use '?' for wildcard)."""
        tokens = signature.split()
        parsed: List[Optional[int]] = []
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            if token == "?":
                parsed.append(None)
            else:
                parsed.append(int(token, 16))
        return _PlatformSignature(
            family=family,
            name=name,
            description=description,
            pattern=tuple(parsed),
            offset=offset,
        )

    def search(self, data: bytes) -> Optional[int]:
        """Search for pattern in data, returns match offset or None."""
        needle = self.pattern
        if not needle:
            return None
        limit = len(data) - len(needle)
        if limit < 0:
            return None
        for start in range(limit + 1):
            for index, byte in enumerate(needle):
                if byte is not None and data[start + index] != byte:
                    break
            else:
                return start
        return None


def _load_smu_signatures() -> Tuple[_PlatformSignature, ...]:
    """Load SMU signatures from JSON file."""
    json_path = _UPDATABLE_DIR / "smu_signatures.json"
    if not json_path.exists():
        return ()
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return ()
    if not isinstance(data, dict):
        return ()
    signatures_data = data.get("signatures", [])
    if not isinstance(signatures_data, list):
        return ()
    result: List[_PlatformSignature] = []
    for item in signatures_data:
        if not isinstance(item, dict):
            continue
        family = item.get("family", "")
        name = item.get("name", "")
        description = item.get("description", "")
        signature = item.get("signature", "")
        offset = item.get("offset", 0)
        if not signature:
            continue
        result.append(
            _PlatformSignature.from_tokens(
                family=family,
                name=name,
                description=description,
                signature=signature,
                offset=offset,
            )
        )
    return tuple(result)


@lru_cache(maxsize=1)
def _get_smu_signatures() -> Tuple[_PlatformSignature, ...]:
    """Cached loader for SMU signatures."""
    return _load_smu_signatures()


def identify_smu_platform(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Identify SMU firmware platform by content signature matching.

    Args:
        data: SMU firmware binary data

    Returns:
        Dict with platform info (family, name, description, match_offset, detail_offset)
        or None if no match found
    """
    if not data:
        return None
    for signature in _get_smu_signatures():
        match_offset = signature.search(data)
        if match_offset is None:
            continue
        return {
            "family": signature.family,
            "name": signature.name,
            "description": signature.description,
            "match_offset": match_offset,
            "detail_offset": match_offset + signature.offset,
        }
    return None


"""
Version Information Table

    Maps (zone, type_id) tuples to version extraction configuration.
    Format keys:
    - version_offset: byte offset in payload to read version data
    - unpack_format: struct format (without endian prefix, '<' is assumed)
    - print_format: format string, receives unpacked tuple as positional args
    - function: special handler name for complex logic (see _SPECIAL_HANDLERS)
    - redirect: (zone, type_id) to inherit config from

    Note: For DWORD values needing byte extraction, use "BBBB" format instead of "I"
        to enable direct indexing in print_format (e.g., {3:X}.{2:X}.{1:X}.{0:X})

"""

_VERSION_INFO_DIR: Dict[Any, Dict[str, Any]] = {
    # PSP Directory Entry Types
    # Type 0x00: AMD Public Key - special format with 16-byte ID
    ("psp", 0x00): {
        "version_offset": 0x0,
        "unpack_format": "I16s",
        "function": "amd_pubkey",
    },
    # Type 0x01: PSP Boot Loader - Version at 0x60, format X.X.X.X (hex BE)
    ("psp", 0x01): {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:X}.{2:X}.{1:X}.{0:X}",
    },
    # Type 0x02: PSP Secure OS
    ("psp", 0x02): {"redirect": ("psp", 0x01)},
    # Type 0x03: PSP Recovery Boot Loader
    ("psp", 0x03): {"redirect": ("psp", 0x01)},
    # Type 0x04: PspNv
        ("psp", 0x04): {
        "version_offset": 0x0,
        "unpack_format": "",
        "print_format": "",
    },
    # Type 0x05: Public Key (alternate)
    ("psp", 0x05): {"redirect": ("psp", 0x00)},
    # Type 0x08: SMU Firmware - requires format detection (old vs new)
    ("psp", 0x08): {"function": "smu_fw"},
    # Type 0x09: Public Key (alternate)
    ("psp", 0x09): {"redirect": ("psp", 0x00)},
    # Type 0x0A: Public Key (alternate)
    ("psp", 0x0A): {"redirect": ("psp", 0x00)},
    # Type 0x0B: Soft Fuse Chain - no version info
    ("psp", 0x0B): {
        "version_offset": 0x0,
        "unpack_format": "",
        "print_format": "",
    },
    # Type 0x0C: SMU Off-Chip Firmware
    ("psp", 0x0C): {"redirect": ("psp", 0x08)},
    # Type 0x0D: Public Key (alternate)
    ("psp", 0x0D): {"redirect": ("psp", 0x00)},
    # Type 0x12: SMU Firmware (alternate)
    ("psp", 0x12): {"redirect": ("psp", 0x08)},
    # Type 0x13: Debug Unlock
    ("psp", 0x13): {"redirect": ("psp", 0x01)},
    # Type 0x24: SEC Gasket - SMU-based version
    ("psp", 0x24): {"redirect": ("psp", 0x08)},
    # Type 0x25: SMU Firmware (alternate)
    ("psp", 0x25): {"redirect": ("psp", 0x08)},
    # Type 0x28: Driver Entries / KVM Image - Version d.d.d (LE byte order)
    ("psp", 0x28): {
        "version_offset": 0x60,
        "unpack_format": "BBH",
        "print_format": "Ver={0:d}.{1:d}.{2:d}",
    },
    # Type 0x29: MP5 Firmware - Version d.d.d format
    ("psp", 0x29): {
        "version_offset": 0x60,
        "unpack_format": "BBH",
        "print_format": "Ver={0:d}.{1:d}.{2:d}",
    },
    # Type 0x2D: S0I3 Driver / DXIO/MPIO - Version d.d.d (byte swap: B1.B0.W)
    ("psp", 0x2D): {
        "version_offset": 0x60,
        "unpack_format": "BBH",
        "print_format": "Ver={1:d}.{0:d}.{2:d}",
    },
    # Type 0x30-0x37: ABL Firmware - complex format with pointer indirection
    ("psp", 0x30): {"function": "abl"},
    ("psp", 0x31): {"redirect": ("psp", 0x30)},
    ("psp", 0x32): {"redirect": ("psp", 0x30)},
    ("psp", 0x33): {"redirect": ("psp", 0x30)},
    ("psp", 0x34): {"redirect": ("psp", 0x30)},
    ("psp", 0x35): {"redirect": ("psp", 0x30)},
    ("psp", 0x36): {"redirect": ("psp", 0x30)},
    ("psp", 0x37): {"redirect": ("psp", 0x30)},
    # Type 0x3C: VBIOS Preload
    ("psp", 0x3C): {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:d}.{2:d}.{1:d}.{0:d}",
    },
    # Type 0x42: GEC Firmware / Security Policy Binary
    ("psp", 0x42): {
        "version_offset": 0x60,
        "unpack_format": "BBH",
        "print_format": "Ver={1:d}.{0:d}.{2:d}",
    },
    # Type 0x45: TOS Security Policy
    ("psp", 0x45): {"redirect": ("psp", 0x24)},
    # Type 0x47: DRTM TA / HSP Firmware - Version at 0xAC, 4x 16-bit values
    ("psp", 0x47): {
        "version_offset": 0xAC,
        "unpack_format": "HHHH",
        "print_format": "Ver={3:d}.{2:d}.{1:d}.{0:d}",
    },
    # Type 0x4C: SEV Data
    ("psp", 0x4C): {"redirect": ("psp", 0x01)},
    # Type 0x52: RIB Firmware - Version d.d.d.d (decimal BE)
    ("psp", 0x52): {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:d}.{2:d}.{1:d}.{0:d}",
    },
    # Type 0x54: PspNvRam
    ("psp", 0x54): {
        "version_offset": 0x0,
        "unpack_format": "",
        "print_format": "",
    },
    # Type 0x55: BL Rollback SPL
    ("psp", 0x55): {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:X}.{2:X}.{1:X}.{0:X}",
    },
    # Type 0x5A: MSMU Binary / DXIO PHY SRAM
    ("psp", 0x5A): {"redirect": ("psp", 0x2D)},
    # Type 0x5C: WMOS
    ("psp", 0x5C): {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:d}.{2:d}.{1:d}.{0:d}",
    },
    # Type 0x5D: DXIO PHY SRAM (alternate)
    ("psp", 0x5D): {"redirect": ("psp", 0x2D)},
    # Type 0x5F: FW PSP SMUSCS
    ("psp", 0x5F): {"redirect": ("psp", 0x08)},
    # Type 0x71: DMCUB Instructions
    ("psp", 0x71): {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:d}.{2:d}.{1:d}.{0:d}",
    },
    # Type 0x73: PSP FW Boot Loader (alternate)
    ("psp", 0x73): {"redirect": ("psp", 0x01)},
    # Type 0x76: PSP specific entry
    ("psp", 0x76): {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:d}.{2:d}.{1:d}.{0:d}",
    },
    # Type 0x91: Platform-specific
    ("psp", 0x91): {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:X}.{2:X}.{1:X}.{0:X}",
    },
    # Type 0x93: Platform-specific
    ("psp", 0x93): {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:d}.{2:d}.{1:d}.{0:d}",
    },
    # =========================================================================
    # BIOS Directory Entry Types
    # =========================================================================
    # Type 0x62: BIOS Binary - Size info at 0x14
    ("bios", 0x62): {
        "version_offset": 0x14,
        "unpack_format": "I",
        "print_format": "Size=0x{0:X}",
    },
    # Type 0x64: PSP-FW Delivery - Version X.X.X.X (hex)
    ("bios", 0x64): {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:X}.{2:X}.{1:X}.{0:X}",
    },
    # Type 0x65: PSP-FW Delivery (alternate)
    ("bios", 0x65): {"redirect": ("bios", 0x64)},
    # Type 0x66: Microcode Patch - Date/PatchId/EquivProcRevId format
    ("bios", 0x66): {
        "version_offset": 0x0,
        "unpack_format": "HBBL16xH",
        "print_format": "Date={2:X}/{1:X}/{0:X}, PatchId={3:#X}, EquivProcRevId={4:#X}",
    },
    # =========================================================================
    # Internal/Helper Configurations
    # =========================================================================
    # SMU standard format (used by function handler)
    "_smu": {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:d}.{2:d}.{1:d}.{0:d}",
    },
    # ABL base configuration (used by function handler)
    "_abl_base": {
        "version_offset": 0x60,
        "unpack_format": "I",
    },
    # ABL version pointer location
    "_abl_ptr": {
        "version_offset": 0x104,
        "unpack_format": "I",
    },
    # ABL firmware type offset
    "_abl_type": {
        "version_offset": 0x58,
        "unpack_format": "H",
    },
    # Default fallback for unknown PSP types
    "Default": {
        "version_offset": 0x60,
        "unpack_format": "BBBB",
        "print_format": "Ver={3:X}.{2:X}.{1:X}.{0:X}",
    },
}


""" Helper Functions """

def _zone_key(kind: str) -> str:
    """Determine zone (psp/bios) from directory kind."""
    return "bios" if _constants.is_bios_dir(kind) else "psp"


def _resolve_rule(zone: str, tid: int) -> Optional[Dict[str, Any]]:
    """Resolve the version rule for a (zone, type_id), following redirects."""
    seen: set = set()
    key = (zone, tid & 0xFF)
    rule = _VERSION_INFO_DIR.get(key)

    # Follow redirect chain
    while rule and "redirect" in rule:
        dst = rule["redirect"]
        if not (isinstance(dst, tuple) and len(dst) == 2):
            break
        key = (dst[0], int(dst[1]) & 0xFF)
        if key in seen:
            break
        seen.add(key)
        rule = _VERSION_INFO_DIR.get(key)

    if rule:
        return rule
    return _VERSION_INFO_DIR.get("Default") if zone == "psp" else None


def _try_unpack(payload: bytes, offset: int, fmt: str) -> Optional[Tuple[Any, ...]]:
    """Safely unpack binary data at offset using struct format."""
    if not fmt:
        return None
    try:
        sz = struct.calcsize("<" + fmt)
        if offset < 0 or offset + sz > len(payload):
            return None
        return struct.unpack("<" + fmt, payload[offset : offset + sz])
    except Exception:
        return None


def _slice_payload(buf: bytes, off_spi: int, size_hint: Optional[int]) -> bytes:
    """Extract payload slice from buffer."""
    if size_hint is None or size_hint <= 0:
        return bytes(memoryview(buf)[off_spi:])
    return bytes(memoryview(buf)[off_spi : off_spi + int(size_hint)])


def _format_version(rule: Dict[str, Any], payload: bytes) -> Optional[str]:
    """Generic version formatter using rule configuration."""
    fmt = rule.get("unpack_format")
    if not fmt:
        return None

    offset = int(rule.get("version_offset", 0))
    tup = _try_unpack(payload, offset, fmt)
    if tup is None:
        return None

    print_fmt = rule.get("print_format")
    if print_fmt:
        try:
            return print_fmt.format(*tup)
        except Exception:
            pass

    # Fallback: join tuple values with dots
    return ".".join(str(int(x) if isinstance(x, int) else x) for x in tup)


"""
Special Handler Functions:
These handle complex parsing logic that cannot be expressed declaratively.
"""

def _handle_amd_pubkey(payload: bytes, rule: Dict[str, Any]) -> Optional[str]:
    """Parse AMD Public Key: version (DWORD) + 16-byte ID."""
    offset = int(rule.get("version_offset", 0))
    t = _try_unpack(payload, offset, "I16s")
    if t is None:
        return None
    ver, id_bytes = t
    return f"Ver={ver:d}, ID={id_bytes.hex().upper()}"


def _handle_smu_fw(payload: bytes, rule: Dict[str, Any]) -> Optional[str]:
    """
    Parse SMU firmware with old/new format detection.

    Old format (ZP, PR): version at 0x60 with non-zero in bits 16-23
    New format: version at 0x0
    """
    # Try old format location first
    t = _try_unpack(payload, 0x60, "I")
    if t is None:
        return None

    val = t[0]

    # Detect format: old has significant value in bits 16-23
    if (val & 0x00FF0000) == 0:
        # New format at offset 0x0
        t = _try_unpack(payload, 0x0, "I")
        if t is None:
            return None
        val = t[0]

    # Format output: 4-part if high byte set, else 3-part
    if val & 0xFF000000:
        return f"Ver={(val >> 24) & 0xFF:d}.{(val >> 16) & 0xFF:d}.{(val >> 8) & 0xFF:d}.{val & 0xFF:d}"
    else:
        return f"Ver={(val >> 16) & 0xFFFF:d}.{(val >> 8) & 0xFF:d}.{val & 0xFF:d}"


def _handle_abl(
    payload: bytes, rule: Dict[str, Any], size_hint: Optional[int]
) -> Optional[str]:
    """
    Parse ABL firmware with pointer indirection and ESID detection.

    ABL has complex versioning:
    - Check firmware type at 0x58 (ESID = 0x157 uses dotted hex format)
    - Version at 0x60 if non-zero (old format)
    - Otherwise, follow pointer at 0x104 to find version
    """
    ESID_FIRMWARE_TYPE = 0x157
    VER_OFFSET = 0x60
    TYPE_OFFSET = 0x58
    PTR_OFFSET = 0x104

    # Get firmware type
    fw_type_t = _try_unpack(payload, TYPE_OFFSET, "H")
    fw_type = fw_type_t[0] if fw_type_t else 0
    is_esid = fw_type == ESID_FIRMWARE_TYPE

    def format_ver(v: int) -> str:
        if is_esid:
            return f"Ver={(v >> 24) & 0xFF:02X}.{(v >> 16) & 0xFF:02X}.{(v >> 8) & 0xFF:02X}.{v & 0xFF:02X}"
        return f"Ver={v:08X}"

    def zero_ver() -> str:
        return "Ver=00.00.00.00" if is_esid else "Ver=00000000"

    # Get version at standard offset
    vt = _try_unpack(payload, VER_OFFSET, "I")
    if vt is None:
        return None

    ver = vt[0]
    if ver > 0:
        return format_ver(ver)

    # Version is zero - follow pointer at 0x104
    ptr_t = _try_unpack(payload, PTR_OFFSET, "I")
    if ptr_t is None:
        return zero_ver()

    ptr = ptr_t[0]

    # Validate pointer bounds
    if size_hint is not None and ptr >= size_hint:
        return zero_ver()
    if ptr + VER_OFFSET + 4 > len(payload):
        return zero_ver()

    # Read version from pointed location
    vt2 = _try_unpack(payload, ptr + VER_OFFSET, "I")
    if vt2 is None:
        return zero_ver()

    return format_ver(vt2[0])


# Handler dispatch table
_SPECIAL_HANDLERS = {
    "amd_pubkey": _handle_amd_pubkey,
    "smu_fw": _handle_smu_fw,
    "abl": _handle_abl,
}


""" Utility Functions """


def metadata_tone_for_token(token: str) -> str:
    """Return the configured tone for a metadata token."""
    if not token:
        return "info"
    normalized = str(token).strip().lower()
    return "info" if not normalized else "info"


def _version_str_from_bytes(b: bytes) -> str:
    """Convert version bytes to X.X.X.X hex string (reversed order)."""
    return ".".join(f"{bb:X}" for bb in b[::-1])


def _sha_expected(hdr) -> Tuple[str, bytes]:
    """Determine expected SHA type and value from PS1 header."""
    if hdr.has_sha256_checksum:
        return "sha256", bytes(hdr.sha_region[:32])
    if hdr.has_sha384_checksum:
        return "sha384", bytes(hdr.sha_region[:48])
    return "sha_NA", b""


""" Public API """    

def decode_entry_metadata(
    buf: bytes,
    kind: str,
    type_id: int,
    off_spi: int,
    size_hint: Optional[int] = None,
    source: Optional[_keys.KeySource] = None,
    metadata_size: Optional[int] = None,
) -> Optional[str]:
    """
    Decode version/metadata string for a PSP/BIOS directory entry.
        Args:
            buf: Full firmware image buffer
            kind: Directory kind ($PSP, $BHD, etc.)
            type_id: Entry type ID
            off_spi: Offset of entry in SPI flash
            size_hint: Optional size hint for entry
            source: Optional key source for signature verification
            metadata_size: Optional override for BIOS 0x62 size display

        Returns:
            Formatted metadata string or None if parsing fails
    """
    zone = _zone_key(kind)
    rule = _resolve_rule(zone, type_id & 0xFF)
    if not rule:
        return None

    # Extract directory indices for scoped key verification
    directory_index = source.directory_index if source else None
    parent_directory_index = source.parent_directory_index if source else None

    # Opportunistic key ingestion (for types 0x00, 0x50, 0x51)
    try:
        _keys.maybe_ingest(kind, type_id, buf, off_spi, size_hint, source=source)
    except Exception:
        pass

    # Check for $PS1 container - use full crypto path
    ps1_info = _ps1.read_ps1_body(buf, off_spi, size_hint)
    if ps1_info is not None:
        return _decode_ps1_metadata(
            buf, off_spi, size_hint, type_id, ps1_info,
            directory_index, parent_directory_index
        )

    # Standard parsing path
    payload = _slice_payload(buf, off_spi, size_hint)

    # Check for special handler
    fn_name = rule.get("function")
    if fn_name and fn_name in _SPECIAL_HANDLERS:
        handler = _SPECIAL_HANDLERS[fn_name]
        # ABL handler needs size_hint
        if fn_name == "abl":
            return handler(payload, rule, size_hint)
        return handler(payload, rule)

    # Use generic format-based parsing
    result = _format_version(rule, payload)

    # Special case: BIOS 0x62 may need metadata_size override
    if (
        result is not None
        and metadata_size is not None
        and zone == "bios"
        and (type_id & 0xFF) == 0x62
    ):
        size_txt = f"Size=0x{int(metadata_size):X}"
        if "Size=" in result:
            result = re.sub(r"Size=0x[0-9A-Fa-f]+", size_txt, result, count=1)
        else:
            result = f"{size_txt}, {result}" if result else size_txt

    return result


def _decode_ps1_metadata(
    buf: bytes,
    off_spi: int,
    size_hint: Optional[int],
    type_id: int,
    ps1_info: Tuple[Any, bytes],
    directory_index: Optional[int] = None,
    parent_directory_index: Optional[int] = None,
) -> str:
    """Decode metadata for $PS1 container entries with full crypto verification."""
    hdr, body_raw = ps1_info
    version_str = _version_str_from_bytes(hdr.version_raw)

    # Decrypt if needed
    dec_res = _crypto.decrypt_body_if_needed(body_raw, hdr.encrypted)
    body_after_dec = dec_res.body

    # Decompress if needed
    body_decomp = _crypto.decompress_body_if_needed(
        body_after_dec,
        compressed=hdr.is_compressed,
        zlib_size=int(hdr.zlib_size),
    )

    # Prepare signed region for verification
    header_bytes = bytes(memoryview(buf)[off_spi : off_spi + _ps1.PS1_HEADER_LEN])
    signed_region = (header_bytes + body_after_dec)[
        : _ps1.PS1_HEADER_LEN + int(hdr.size_signed)
    ]

    # SHA verification
    sha_kind, sha_hdr = _sha_expected(hdr)
    if hdr.is_encrypted and dec_res.method is None and sha_kind != "SHA(N/A)":
        sha_tag = f"SHA{'384' if sha_kind == 'sha384' else '256'}(ENC)"
    elif sha_kind == "sha256":
        sha_tag = (
            "SHA256(OK)"
            if _crypto.check_sha256(body_decomp, sha_hdr)
            else "SHA256(NG)"
        )
    elif sha_kind == "sha384":
        sha_tag = (
            "SHA384(OK)"
            if _crypto.check_sha384(body_decomp, sha_hdr)
            else "SHA384(NG)"
        )
    else:
        sha_tag = ""

    # Signature verification
    rom_size = hdr.resolve_rom_size(off_spi, len(buf), size_hint)
    sig_result = None
    if not (hdr.is_encrypted and dec_res.method is None):
        sig_result = _crypto.verify_ps1_signature(
            buf=buf,
            off_spi=off_spi,
            rom_size=rom_size,
            signature_type=int(hdr.signature_type),
            fingerprint=bytes(hdr.signature_fingerprint),
            signed_region=signed_region,
            entry_type=int(type_id) & 0xFF,
            directory_index=directory_index,
            parent_directory_index=parent_directory_index,
        )

    # Build result string
    fp_short = hdr.signature_fingerprint[:2].hex().upper()
    if hdr.is_encrypted and dec_res.method is None:
        ver_tag = f"Encrypted({fp_short})"
    elif sig_result is True:
        ver_tag = f"Signature(OK)({fp_short})"
    elif sig_result is False:
        ver_tag = f"Signature(NG)({fp_short})"
    else:
        ver_tag = f"Signature(NO_KEY)({fp_short})"

    parts = ["Ver=" + (version_str or "0.0.0.0"), ver_tag]
    if sha_tag:
        parts.append(sha_tag)
    if hdr.is_compressed:
        parts.append("Compressed")

    return ", ".join(parts)
