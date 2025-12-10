# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Promontory firmware parsing utilities.

This module provides:
    - Promontory firmware header parsing
    - Firmware signature identification
    - Checksum validation
    - Firmware version extraction
"""

from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional, Dict
import json
import string
from pathlib import Path


# Constants and Configuration

_MODULE_ROOT = Path(__file__).resolve().parent.parent
_UPDATABLE_DIR = _MODULE_ROOT.parent / "Updatable"

PROM_MAGIC = b"_PT_"
PROM_HEADER_LEN = 0x200


@lru_cache(maxsize=1)
def _load_promontory_config() -> dict:
    """Load promontory configuration from program_table.json (cached)."""
    json_path = _UPDATABLE_DIR / "program_table.json"
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("promontory_codenames", {}).get("firmware_signatures", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


@lru_cache(maxsize=1)
def _build_label_types() -> Dict[str, str]:
    """Build firmware label to type name mapping from JSON config (cached).
    
    Maps signatures like '3306A_FW' -> 'Prom', '3328A_FW' -> 'Prom21'
    """
    config = _load_promontory_config()
    result = {}
    for sig_key, sig_data in config.items():
        fw_label = sig_data.get("fw_label", "")
        name = sig_data.get("name", "unknown")
        if fw_label:
            result[fw_label] = name
    return result


@lru_cache(maxsize=1)
def _build_tail_skips() -> Dict[str, int]:
    """Build type name to tail skip mapping from JSON config (cached)."""
    config = _load_promontory_config()
    result = {}
    for sig_key, sig_data in config.items():
        name = sig_data.get("name", "")
        tail_skip = sig_data.get("tail_skip", 0)
        if name:
            result[name] = tail_skip
    return result


# Build lookup tables from JSON configuration (loaded once at module init)
_PROM_SIGNATURES = _load_promontory_config()
_PROM_LABEL_TYPES = _build_label_types()
_PROM_TAIL_SKIPS = _build_tail_skips()


@dataclass
class PromInfo:
    """
    Parsed Promontory firmware block information.

    Attributes:
        offset: Byte offset in the firmware image.
        type_code: Firmware type code.
        type_name: Human-readable firmware type name.
        header_version: Header format version.
        expected_checksum: Checksum value from header.
        computed_checksum: Calculated checksum from data.
        checksum_ok: Whether checksums match.
        block_size: Total block size including padding.
        payload_offset: Offset to payload data.
        payload_size: Size of payload data.
        firmware_date: Firmware build date (if available).
        firmware_version: Firmware version string (if available).
        label: Firmware label string (if available).
    """

    offset: int
    type_code: int
    type_name: str
    header_version: int
    expected_checksum: int
    computed_checksum: int
    checksum_ok: bool
    block_size: int
    payload_offset: int
    payload_size: int
    firmware_date: Optional[str]
    firmware_version: Optional[str]
    label: Optional[str]


def _decode_bcd(byte_val: int) -> Optional[int]:
    high = (byte_val >> 4) & 0xF
    low = byte_val & 0xF
    if high >= 0xA or low >= 0xA:
        return None
    return high * 10 + low


def _extract_label(header: bytes, start: int) -> Optional[str]:
    if start >= len(header):
        return None
    while start < len(header) and header[start] == 0:
        start += 1
    if start >= len(header):
        return None
    end = start
    allowed = set(string.printable.encode("ascii")) - {0x00}
    while end < len(header):
        b = header[end]
        if b == 0 or b not in allowed:
            break
        end += 1
    if end <= start:
        return None
    try:
        return header[start:end].decode("ascii", "ignore").strip()
    except UnicodeDecodeError:
        return None


def _resolve_type(label: Optional[str], header: bytes) -> str:
    """
    Resolve Promontory type from firmware label or header signature.
    
    Searches for known firmware signatures (e.g., '3306A_FW', '3328A_FW')
    in the label or header to identify the chip type.
    """
    # First try to match from the label
    if label:
        normalized = label.strip()
        for fw_label, name in _PROM_LABEL_TYPES.items():
            if normalized.startswith(fw_label):
                return name
    
    # Fall back to searching the header for known signatures
    for sig_key, sig_data in _PROM_SIGNATURES.items():
        fw_label = sig_data.get("fw_label", "").encode("ascii", "ignore")
        if fw_label and fw_label in header:
            return sig_data.get("name", "unknown")
    
    return "unknown"


def parse_prom_blocks(buf: bytes) -> List[PromInfo]:
    results: List[PromInfo] = []
    start = 0
    while True:
        off = buf.find(PROM_MAGIC, start)
        if off < 0:
            break
        if off + 0x0C > len(buf):
            break

        total_length = int.from_bytes(buf[off + 4 : off + 8], "little")
        if total_length <= 0:
            start = off + len(PROM_MAGIC)
            continue
        block_end = off + total_length
        if block_end > len(buf):
            break

        header = buf[off : min(block_end, off + PROM_HEADER_LEN)]
        type_code = header[4] if len(header) > 4 else 0
        header_version = int.from_bytes(header[6:8], "little") if len(header) >= 8 else 0
        expected_checksum = int.from_bytes(buf[off + 8 : off + 12], "little")

        label = _extract_label(header, 0x92)
        type_name = _resolve_type(label, header)

        tail_skip = _PROM_TAIL_SKIPS.get(type_name, 0)
        sum_start = 0x0C
        sum_end = total_length - tail_skip
        if sum_end < sum_start:
            sum_end = sum_start
        computed_checksum = sum(buf[off + sum_start : off + sum_end]) & 0xFFFFFFFF
        checksum_ok = computed_checksum == expected_checksum

        day_raw = header[0x8C] if len(header) > 0x8C else 0
        month_raw = header[0x8D] if len(header) > 0x8D else 0
        year_raw = header[0x8E] if len(header) > 0x8E else 0
        day = _decode_bcd(day_raw)
        month = _decode_bcd(month_raw)
        year = _decode_bcd(year_raw)
        firmware_date = None
        if None not in (day, month, year):
            firmware_date = f"{day:02d}/{month:02d}/{year:02d}"

        major = header[0x8F] if len(header) > 0x8F else 0
        minor = header[0x90] if len(header) > 0x90 else 0
        patch = header[0x91] if len(header) > 0x91 else 0
        firmware_version = None
        if any([major, minor, patch]):
            firmware_version = f"{major:02X}_{minor:02X}_{patch:02X}"

        results.append(
            PromInfo(
                offset=off,
                type_code=type_code,
                type_name=type_name,
                header_version=header_version,
                expected_checksum=expected_checksum,
                computed_checksum=computed_checksum,
                checksum_ok=checksum_ok,
                block_size=total_length,
                payload_offset=off + sum_start,
                payload_size=max(0, sum_end - sum_start),
                firmware_date=firmware_date,
                firmware_version=firmware_version,
                label=label,
            )
        )

        start = block_end

    return results

