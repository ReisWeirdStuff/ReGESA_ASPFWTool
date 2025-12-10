# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Shared utilities and constants for the main window components.

This module provides:
    - Common utility functions (formatting, sanitization, alignment)
    - Shared constants (editable directory kinds, compression types)
    - Type choice table generators for entry editing
"""

from __future__ import annotations

import gzip
import re
import zlib
from typing import Dict, List, Optional, Set, Tuple

from ...agesa import constants as _constants
from ...agesa.constants import (
    BIOSTypeNames,
    EDITABLE_DIRS,
    PSPTypeNames,
)
from ...agesa import ps1 as _ps1
from ...uefi import (
    EFI_CUSTOM_COMPRESSION_LZMA,
    EFI_STANDARD_COMPRESSION,
)

SEARCH_METHOD_LABELS: Dict[str, str] = {
    "psp-type": "Entry type/name",
    "psp-hex": "HEX pattern",
    "psp-metadata": "Metadata field",
    "uefi-hex": "HEX pattern",
    "uefi-guid": "GUID",
    "uefi-text": "Text",
}

# Re-export from agesa.constants for backwards compatibility
EDITABLE_DIRECTORY_KINDS = EDITABLE_DIRS

SUPPORTED_UEFI_COMPRESSION_TYPES = {
    EFI_STANDARD_COMPRESSION,
    EFI_CUSTOM_COMPRESSION_LZMA,
}

UEFI_SECTION_ALIGNMENT = 4


def _mask_u64(value: int) -> int:
    return int(value) & 0xFFFFFFFFFFFFFFFF


def _to_signed_64(value: int) -> int:
    masked = _mask_u64(value)
    if masked & (1 << 63):
        return masked - (1 << 64)
    return masked


_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _sanitize_filename(text: str, fallback: str = "entry") -> str:
    raw = str(text) if text is not None else ""
    cleaned = re.sub(r"[^0-9A-Za-z._-]+", "_", raw)
    cleaned = cleaned.strip()
    cleaned = cleaned.strip("._-")
    if not cleaned:
        cleaned = str(fallback) or "entry"
    cleaned = cleaned[:200].rstrip(" .")
    if not cleaned:
        cleaned = "entry"
    upper = cleaned.upper()
    if upper in _WINDOWS_RESERVED_NAMES:
        cleaned = f"_{cleaned}_"
    return cleaned or "entry"


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    mask = alignment - 1
    return (value + mask) & ~mask


def _format_bytes(value: int) -> str:
    return f"0x{value:X} ({value} bytes)"


def _format_optional_hex(value: Optional[int]) -> str:
    if value is None:
        return "-"
    return f"0x{int(value):X}"


def _format_size_short(value: int) -> str:
    if value <= 0:
        return "-"
    units = ["bytes", "KB", "MB", "GB"]
    size = float(value)
    unit_index = 0
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.2f} {units[unit_index]}"


def _format_dual_size(value: int) -> str:
    if value <= 0:
        return "0x0 (0B)"
    hex_part = f"0x{int(value):X}"
    units = [
        ("GiB", 1024**3),
        ("MiB", 1024**2),
        ("KiB", 1024),
        ("B", 1),
    ]
    for unit, factor in units:
        if value >= factor or unit == "B":
            if unit == "B":
                human = f"{value}{unit}"
            else:
                human = f"{value / factor:.2f}{unit}"
            break
    else:  # pragma: no cover - defensive fallback
        human = f"{value}B"
    return f"{hex_part} ({human})"


_COMBO_TYPE_CHOICES: Dict[int, str] = {
    0: "0 - Compare PSP ID",
    1: "1 - Compare chip family ID",
}


def _type_choice_table(kind) -> Dict[int, list]:
    if _constants.is_combo_dir(kind):
        return {key: ["combo", label, label] for key, label in _COMBO_TYPE_CHOICES.items()}
    if _constants.is_real_psp_dir(kind):
        return PSPTypeNames
    if _constants.is_real_bios_dir(kind):
        return BIOSTypeNames
    return {}


def _iter_type_choices(kind: str):
    table = _type_choice_table(kind)
    for type_id in sorted(table.keys()):
        record = table[type_id]
        if len(record) >= 2:
            yield type_id, record[1]
        else:
            yield type_id, f"0x{type_id:02X}"


def _try_zlib_decompress(sample: bytes, wbits: int) -> bool:
    try:
        decompressor = zlib.decompressobj(wbits)
        data = decompressor.decompress(sample)
    except Exception:
        return False
    consumed = len(sample) - len(decompressor.unused_data)
    if consumed <= 0 and not data:
        return False
    if not data and not decompressor.eof:
        return False
    return True


def _guess_compression_mode(blob: bytes) -> tuple[bool, Optional[str]]:
    if not blob:
        return False, None
    sample = bytes(memoryview(blob)[: min(len(blob), 0x4000)])
    candidates: List[Tuple[int, str]] = []
    if len(sample) >= 2:
        first, second = sample[0], sample[1]
        if first == 0x1F and second == 0x8B:
            candidates.append((31, "gzip"))
        if first == 0x78 and second in {0x01, 0x5E, 0x9C, 0xDA, 0x20, 0x7D}:
            candidates.append((15, "zlib"))
    tested: Set[Tuple[int, str]] = set()
    for wbits, mode in candidates + [(31, "gzip"), (15, "zlib"), (-15, "raw")]:
        key = (wbits, mode)
        if key in tested:
            continue
        tested.add(key)
        if _try_zlib_decompress(sample, wbits):
            return True, mode
    return False, None


def _attempt_decompress(blob: bytes, mode: Optional[str] = None) -> Optional[bytes]:
    if blob is None:
        return None
    if not blob:
        return b""
    normalized_mode = str(mode).lower() if isinstance(mode, str) else None
    if normalized_mode == "":
        normalized_mode = None
    ps1_header = None
    if (
        len(blob) >= _ps1.PS1_HEADER_LEN and blob[0x10:0x14] == b"$PS1"
    ) or normalized_mode == "ps1":
        resolved = _ps1.resolve_body_range(blob, 0, len(blob))
        if resolved is not None:
            ps1_header, start, end = resolved
            if ps1_header.zlib_size:
                end = min(start + int(ps1_header.zlib_size), len(blob))
            body = bytes(memoryview(blob)[start:end])
            if ps1_header.is_compressed or normalized_mode == "ps1":
                inner = _attempt_decompress(body, None)
                if inner is not None:
                    return inner
            if body:
                return body
            return b""
    candidates: List[int] = []
    if normalized_mode and normalized_mode != "ps1":
        mapping = {
            "gzip": 31,
            "gz": 31,
            "zlib": 15,
            "deflate": -15,
            "raw": -15,
        }
        guess = mapping.get(normalized_mode)
        if guess is not None:
            candidates.append(guess)
    candidates.extend([31, 15, -15])
    
    # Try decompression from various start offsets
    # Some entries (like compressed BIOS 0x62) have headers before the zlib stream
    start_offsets = [0]
    # Check for zlib header (0x78) at common header positions
    for header_offset in (0x100, 0x20):
        if header_offset < len(blob) and blob[header_offset] == 0x78:
            if header_offset + 1 < len(blob) and blob[header_offset + 1] in (0x01, 0x5E, 0x9C, 0xDA):
                start_offsets.insert(0, header_offset)  # Try this first
    
    for start_offset in start_offsets:
        chunk = blob[start_offset:] if start_offset > 0 else blob
        if not chunk:
            continue
        tried: Set[int] = set()
        for wbits in candidates:
            if wbits in tried:
                continue
            tried.add(wbits)
            try:
                return zlib.decompress(chunk, wbits)
            except Exception:
                continue
        try:
            return gzip.decompress(chunk)
        except Exception:
            continue
    return None


def _container_get(entry, key: str):
    try:
        if hasattr(entry, key):
            return getattr(entry, key)
    except Exception:  # pragma: no cover - defensive fallback
        pass
    try:
        return entry[key]
    except Exception:
        return None


def extract_entry_bytes(data: bytes, entry: dict) -> Optional[bytes]:
    """
    Extract raw bytes from a PSP/BIOS entry dictionary.
    
    This is a shared utility for extracting payload data from firmware entries.
    It handles three cases:
    - inline_offset: Data stored inline in the directory table
    - resolved_off: Data at a resolved offset in the image
    - inline_raw: Raw 64-bit value stored inline
    
    Args:
        data: The firmware image data (bytes or bytearray)
        entry: Entry dictionary with size, inline_offset, resolved_off, inline_raw
        
    Returns:
        Extracted bytes or None if extraction failed
    """
    size = int(entry.get("size") or 0)
    declared_size = int(entry.get("declared_size") or 0)
    inline_offset = entry.get("inline_offset")
    inline_raw = entry.get("inline_raw")
    offset = entry.get("resolved_off")
    ptr64 = entry.get("ptr64")
    
    # For mode 1 addresses (ARM physical), resolved_off may be incorrect or None.
    # Extract the correct flash offset from ptr64 low 46 bits.
    if ptr64 is not None and inline_raw is None:
        mode = (ptr64 >> 62) & 0x3
        if mode == 1:
            # Mode 1: direct flash offset in low 46 bits
            correct_offset = ptr64 & 0x3FFFFFFFFFFF
            if 0 < correct_offset < len(data):
                offset = correct_offset
    
    # For compressed entries (like 0x62), size may be decompressed size
    # Use declared_size (compressed size in flash) if it's smaller and valid
    extraction_size = size
    if declared_size > 0 and declared_size < size:
        extraction_size = declared_size
    # If extraction_size is still 0 but declared_size exists, use declared_size
    if extraction_size <= 0 and declared_size > 0:
        extraction_size = declared_size

    if inline_offset is not None and size > 0:
        start = int(inline_offset)
        end = start + size
        if 0 <= start < end <= len(data):
            return bytes(data[start:end])
    elif offset is not None and extraction_size > 0:
        start = int(offset)
        end = start + extraction_size
        if 0 <= start < end <= len(data):
            return bytes(data[start:end])
    elif inline_raw is not None:
        try:
            raw = int(inline_raw) & 0xFFFFFFFFFFFFFFFF
            return raw.to_bytes(8, "little")
        except Exception:
            pass

    return None


def get_ps1_flags(data: bytes, offset: Optional[int]) -> Tuple[bool, bool, bool]:
    """
    Get compression/encryption/signing flags from PS1 header.
    
    Args:
        data: The firmware image data
        offset: Offset to check for PS1 header (can be None)
        
    Returns:
        Tuple of (compressed, encrypted, signed) boolean flags
    """
    compressed = False
    encrypted = False
    signed = False
    
    if offset is None:
        return compressed, encrypted, signed
        
    ps1_header = _ps1.parse_ps1_header(data, offset)
    if ps1_header is not None:
        if ps1_header.is_compressed:
            compressed = True
        if ps1_header.is_encrypted:
            encrypted = True
        if ps1_header.signature_length > 0:
            signed = True
            
    return compressed, encrypted, signed
