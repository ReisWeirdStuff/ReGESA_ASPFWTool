# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
APCB token parsing for AMD Platform Configuration Block.

This module provides parsing utilities for AMD Platform Configuration Block
(APCB) structures, supporting both V2 and V3 formats.

"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Tuple



# Configuration Paths

_MODULE_ROOT = Path(__file__).resolve().parent.parent
_UPDATABLE_DIR = _MODULE_ROOT.parent / "Updatable"
_APCB_V2_JSON = _UPDATABLE_DIR / "apcbv2_tokens.json"
_APCB_V3_JSON = _UPDATABLE_DIR / "apcbv3_tokens.json"


# APCB Header Constants


_APCB_MAGIC = b"APCB"
_APCB_V3_MAGIC2 = b"ECB2"
_APCB_MIN_HEADER_SIZE = 0x20  # Minimum header size (V2)

# APCB V3 Type context types (from APCB_TYPE_ATTR_CONTEXT_TYPE_*).
_CONTEXT_TYPE_STRUCT = 0
_CONTEXT_TYPE_PARAMETER = 1
_CONTEXT_TYPE_TOKEN = 2

# APCB V3 token unit size.
_V3_TOKEN_UNIT_SIZE = 8


def _load_tokens_from_file(path: Path) -> Dict[int, Dict[str, str]]:
    """
    Load tokens from a JSON file:
    Handles both flat structure (V3) and nested structure (V2 with sections).
    """
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    
    result: Dict[int, Dict[str, str]] = {}
    
    def extract_tokens(d: dict, prefix: str = "") -> None:
        """Recursively extract tokens from nested dict structure."""
        for key, value in d.items():
            if key.startswith("_"):
                # Skip metadata keys
                continue
            if isinstance(value, dict):
                if "name" in value:
                    # This is a token entry
                    try:
                        uid = int(key, 16)
                        result[uid] = {
                            "name": str(value.get("name", f"0x{uid:04X}")),
                            "brief": str(value.get("brief", "")),
                            "details": str(value.get("details", "")),
                        }
                    except (ValueError, TypeError):
                        pass
                else:
                    # Nested section - recurse
                    extract_tokens(value, key)
    
    # Try flat "tokens" structure first (V3)
    if "tokens" in data:
        token_map = data.get("tokens", {})
        if isinstance(token_map, dict):
            extract_tokens(token_map)
    
    # Try nested sections (V2 organized structure)
    for section_key in ["config_tokens", "cbs_cmn_tokens", "cbs_dbg_tokens"]:
        if section_key in data:
            section = data[section_key]
            if isinstance(section, dict):
                extract_tokens(section)
    
    return result


@lru_cache(maxsize=1)
def _load_token_db() -> Dict[int, Dict[str, str]]:
    """Load and merge APCB token metadata from V2 and V3 JSON files."""
    tokens = _load_tokens_from_file(_APCB_V2_JSON)
    tokens.update(_load_tokens_from_file(_APCB_V3_JSON))
    return tokens


class ApcbParseError(RuntimeError):
    """Raised when APCB token parsing fails."""


@dataclass
class ApcbTokenRecord:
    """
    Container describing an individual APCB token.

    Attributes:
        token_uid: Unique token identifier.
        value: Parsed integer value.
        value_bytes: Raw byte representation of the value.
        name: Human-readable token name.
        usage: Token usage description.
        details: Additional details about the token.
    """

    token_uid: int
    value: int
    value_bytes: bytes
    name: str
    usage: str
    details: str

    @property
    def value_hex(self) -> str:
        if not self.value_bytes:
            return "0x0"
        return "0x" + self.value_bytes[::-1].hex().upper()


@dataclass
class ApcbParseResult:
    """
    Represents the result of parsing an APCB blob.

    Attributes:
        version: APCB format version string ('V2' or 'V3').
        tokens: List of parsed token records.
    """

    version: str
    tokens: List[ApcbTokenRecord]



# APCB Version Detection


# APCB version BCD values (from header Version field at offset 6).
_V2_VERSION = 0x0020  # BCD 0x20 = V2
_V3_VERSION = 0x0030  # BCD 0x30 = V3

# V2 token groups (GroupId -> set of TypeIds containing tokens).
_V2_TOKEN_TYPES: Dict[int, set] = {
    0x1701: {0x01, 0x02},
    0x1702: {0x03, 0x04},
    0x1703: {0x05, 0x06},
    0x1704: {0x07, 0x08},
    0x1705: {0x09, 0x0A},
    0x1706: {0x0B, 0x0C},
    0x1707: {0x0D, 0x0F},
}

# V3 token group (uses ContextType=2 in APCB_V3_TYPE_HEADER)
_V3_TOKEN_GROUP = 0x3000


def lookup_token_metadata(uid: int) -> Tuple[str, str, str]:
    """Return (name, brief, details) for the token UID."""
    info = _load_token_db().get(uid)
    fallback = f"0x{uid:04X}"
    if not info:
        return fallback, "", ""
    return info.get("name", fallback), info.get("brief", ""), info.get("details", "")


def lookup_token_name(uid: int) -> str:
    """Return display name for uid, falling back to hex value."""
    return lookup_token_metadata(uid)[0]


def _detect_version(data: bytes) -> Tuple[bool, str, int]:
    """
    Detect APCB version from header.
    
    APCB Header layout:
        0x00: Signature (UINT32) = "APCB"
        0x04: SizeOfHeader (UINT16) - tells us where groups start
        0x06: Version (UINT16) BCD - 0x20=V2, 0x30=V3
        0x08: SizeOfApcb (UINT32)
        ...
        0x20: Signature2 (UINT32) = "ECB2" (V3 only)
    
    Returns: (is_v3, version_label, header_size)
    """
    if len(data) < _APCB_MIN_HEADER_SIZE:
        raise ApcbParseError("APCB blob is too small for header")
    
    # Read SizeOfHeader at offset 4 - this is the actual header size
    header_size = struct.unpack_from("<H", data, 4)[0]
    if header_size < _APCB_MIN_HEADER_SIZE:
        header_size = _APCB_MIN_HEADER_SIZE  # Fallback
    
    # Read Version field at offset 6 (UINT16 BCD)
    version_bcd = struct.unpack_from("<H", data, 6)[0]
    
    # Check for V3 extended header (ECB2 signature at 0x20)
    is_v3 = False
    if len(data) >= 0x24 and data[0x20:0x24] == _APCB_V3_MAGIC2:
        is_v3 = True
    
    # Determine version label
    major = (version_bcd >> 4) & 0xF
    minor = version_bcd & 0xF
    if is_v3 or major >= 3:
        return True, f"V3.{minor}" if minor else "V3", header_size
    return False, f"V2.{minor}" if minor else "V2", header_size


def _parse_v2_tokens(payload: bytes) -> List[ApcbTokenRecord]:
    """
    Parse V2 token stream format.
    
    V2 tokens use variable-size encoding:
    - Header entries: 4 bytes each, packed sequentially until sentinel (token_id=0x1FFF)
    - Value data: follows header entries, sizes determined by header
    
    Header entry format (32-bit):
        bits 0-7:   flags
        bits 8-20:  token_uid (13 bits, max 0x1FFF)
        bits 21-24: size - 1 (4 bits, so size 1-16 bytes)
        bits 25-31: reserved
    """
    if len(payload) < 8:
        return []
    
    # Parse header entries until sentinel
    entries: List[int] = []
    pos = 0
    while pos + 4 <= len(payload):
        word = int.from_bytes(payload[pos:pos + 4], "little")
        token_id = (word >> 8) & 0x1FFF
        entries.append(word)
        pos += 4
        if token_id == 0x1FFF:  # Sentinel: CONFIG_LIMIT
            break
    else:
        raise ApcbParseError("APCB V2 token stream sentinel not found")

    # Parse value data
    value_data = payload[pos:]
    cursor = 0
    records: List[ApcbTokenRecord] = []
    for header in entries[:-1]:  # Skip sentinel
        size = ((header >> 21) & 0xF) + 1
        token_uid = (header >> 8) & 0x1FFF
        value_bytes = value_data[cursor:cursor + size]
        if len(value_bytes) != size:
            raise ApcbParseError("APCB V2 token payload truncated")
        cursor += size
        name, usage, details = lookup_token_metadata(token_uid)
        records.append(ApcbTokenRecord(
            token_uid=token_uid,
            value=int.from_bytes(value_bytes, "little"),
            value_bytes=value_bytes,
            name=name, usage=usage, details=details,
        ))
    return records


def _parse_v3_tokens(payload: bytes) -> List[ApcbTokenRecord]:
    """
    Parse V3 token stream format.
    
    V3 tokens use fixed 8-byte records (APCB_TYPE_ATTR_UNITSIZE_TOKEN_V3 = 8):
        0x00: token_uid (UINT32) - 32-bit hashed UID
        0x04: value (UINT32)
    
    Type header has ContextType=2 (APCB_TYPE_ATTR_CONTEXT_TYPE_TOKEN)
    and UnitSize=8.
    """
    if len(payload) % _V3_TOKEN_UNIT_SIZE:
        raise ApcbParseError("APCB V3 token payload not aligned to 8 bytes")
    
    records: List[ApcbTokenRecord] = []
    for offset in range(0, len(payload), _V3_TOKEN_UNIT_SIZE):
        token_uid, value = struct.unpack_from("<II", payload, offset)
        name, usage, details = lookup_token_metadata(token_uid)
        records.append(ApcbTokenRecord(
            token_uid=token_uid,
            value=value,
            value_bytes=struct.pack("<I", value),
            name=name, usage=usage, details=details,
        ))
    return records


def _is_v3_token_type(type_header: bytes) -> bool:
    """
    Check if V3 type header indicates token data.
    
    APCB_V3_TYPE_HEADER extended fields (offset 8-15):
        0x08: ContextType (UINT8) - 2 = token
        0x09: ContextFormat (UINT8)
        0x0A: UnitSize (UINT8) - 8 for tokens
        ...
    """
    if len(type_header) < 0x10:
        return False
    context_type = type_header[8]
    unit_size = type_header[10]
    return context_type == _CONTEXT_TYPE_TOKEN and unit_size == _V3_TOKEN_UNIT_SIZE


def parse_apcb_tokens(blob: bytes) -> ApcbParseResult:
    """
    Parse an APCB binary blob and return discovered tokens.
    Supports both V2 and V3 APCB formats.
    
    Structure hierarchy:
        APCB_HEADER (size from SizeOfHeader field at offset 4)
        |-- APCB_GROUP_HEADER (0x10 bytes)
            |-- APCB_TYPE_HEADER / APCB_V3_TYPE_HEADER (0x10 bytes)
                |-- Token payload data
    """
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError("APCB payload must be bytes-like")
    data = bytes(blob)
    
    if len(data) < _APCB_MIN_HEADER_SIZE:
        raise ApcbParseError("APCB blob is too small")
    if data[:4] != _APCB_MAGIC:
        raise ApcbParseError("Data does not start with APCB magic")

    # Detect version and get header size (groups start after header)
    is_v3, version_label, header_size = _detect_version(data)
    
    # Get declared size from SizeOfApcb field (offset 8)
    declared_size = struct.unpack_from("<I", data, 8)[0]
    body_end = min(len(data), declared_size) if declared_size else len(data)
    
    # Groups start after header (header_size from SizeOfHeader field)
    groups_data = data[header_size:body_end]

    tokens: List[ApcbTokenRecord] = []
    offset = 0
    
    # Parse APCB_GROUP_HEADER entries
    while offset + 0x10 <= len(groups_data):
        """
        APCB_GROUP_HEADER layout (0x10 bytes):
         - 0x00: Signature (UINT32)
         - 0x04: GroupId (UINT16)
         - 0x06: SizeOfHeader (UINT16)
         - 0x08: Version (UINT16)
         - 0x0A: Reserved (UINT16)
         - 0x0C: SizeOfGroup (UINT32)
        """
        group_size = struct.unpack_from("<I", groups_data, offset + 0x0C)[0]
        if group_size <= 0x10:
            raise ApcbParseError("Invalid APCB group size")
        group_end = offset + group_size
        if group_end > len(groups_data):
            raise ApcbParseError("APCB group extends beyond container size")

        group_id = struct.unpack_from("<H", groups_data, offset + 0x04)[0]
        group_header_size = struct.unpack_from("<H", groups_data, offset + 0x06)[0]
        if group_header_size == 0:
            group_header_size = 0x10
        
        types_blob = groups_data[offset + group_header_size:group_end]
        offset = group_end

        # Parse APCB_TYPE_HEADER entries within this group
        type_offset = 0
        while type_offset + 0x10 <= len(types_blob):
            """
            APCB_TYPE_HEADER layout (0x10 bytes):
             - 0x00: GroupId (UINT16)
             - 0x02: TypeId (UINT16)
             - 0x04: SizeOfType (UINT16)
             - 0x06: InstanceId (UINT16)
             - 0x08-0x0F: Reserved / V3 extended fields
            """
            type_header = types_blob[type_offset:type_offset + 0x10]
            type_id = struct.unpack_from("<H", type_header, 2)[0]
            type_size = struct.unpack_from("<H", type_header, 4)[0]
            if type_size < 0x10:
                raise ApcbParseError("APCB type size too small")

            payload = types_blob[type_offset + 0x10:type_offset + type_size]
            
            # Determine if this type contains tokens
            if is_v3:
                # V3: Check ContextType field in extended header
                if _is_v3_token_type(type_header):
                    tokens.extend(_parse_v3_tokens(payload))
            else:
                # V2: Use known group/type combinations
                if type_id in _V2_TOKEN_TYPES.get(group_id, set()):
                    tokens.extend(_parse_v2_tokens(payload))
            
            type_offset += type_size

    tokens.sort(key=lambda r: r.token_uid)
    return ApcbParseResult(version=version_label, tokens=tokens)
