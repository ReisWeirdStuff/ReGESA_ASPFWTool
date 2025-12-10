# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Soft Fuse Chain (TypeId 0x0B) parsing and interpretation for AMD PSP.

This module provides:
    - Soft fuse field definitions loaded from JSON configuration
    - Soft fuse chain parsing and description generation
    - Human-readable labels for fuse bit states
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional



# Data Classes



@dataclass(frozen=True)
class SoftFuseField:
    """
    Editable bit field within the Soft Fuse Chain.
        Attributes:
            bit: Bit position (0-63).
            zero_label: Description when bit is 0.
            one_label: Description when bit is 1.
    """

    bit: int
    zero_label: str
    one_label: str

    def label_for(self, value: int) -> str:
        return self.one_label if value else self.zero_label


@dataclass(frozen=True)
class SoftFuseChain:
    """
    Parsed soft fuse chain value with field interpretations.
        Attributes:
            raw_value: The 64-bit raw fuse chain value.
            fields: List of known fields with their definitions.
            reserved_bits: List of reserved bit positions that are set.
    """

    raw_value: int
    fields: List[SoftFuseField]
    reserved_bits: List[int]

    @property
    def descriptions(self) -> List[str]:
        desc = [
            field.label_for((self.raw_value >> field.bit) & 0x1)
            for field in self.fields
        ]
        desc.extend(f"Reserved bit {bit} set" for bit in self.reserved_bits)
        return desc

    def describe(self) -> str:
        desc = self.descriptions
        if not desc:
            return f"0x{self.raw_value:016X}"
        return f"0x{self.raw_value:016X} (" + "; ".join(desc) + ")"



""" Configuration Loading """


# Path to the JSON file containing soft fuse field definitions.
_MODULE_ROOT = Path(__file__).resolve().parent.parent
_JSON_PATH = _MODULE_ROOT.parent / "Updatable" / "softfuse_fields.json"

# Cached fields loaded from JSON.
_CACHED_FIELDS: Optional[List[SoftFuseField]] = None


def _load_fields_from_json() -> List[SoftFuseField]:
    """Load soft fuse field definitions from JSON file."""
    try:
        with open(_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        fields = []
        for entry in data.get("fields", []):
            fields.append(SoftFuseField(
                bit=entry["bit"],
                zero_label=entry["zero_label"],
                one_label=entry["one_label"],
            ))
        return fields
    except Exception:
        # Fall back to empty list if JSON can't be loaded
        return []


def get_known_fields() -> List[SoftFuseField]:
    """Get the list of known soft fuse fields, loading from JSON if needed."""
    global _CACHED_FIELDS
    if _CACHED_FIELDS is None:
        _CACHED_FIELDS = _load_fields_from_json()
    return _CACHED_FIELDS


def reload_fields() -> List[SoftFuseField]:
    """Force reload of soft fuse fields from JSON file."""
    global _CACHED_FIELDS
    _CACHED_FIELDS = _load_fields_from_json()
    return _CACHED_FIELDS


def parse_soft_fuse_chain(raw: int) -> SoftFuseChain:
    """Parse a raw 64-bit soft fuse value into a SoftFuseChain.

    Args:
        raw: The 64-bit soft fuse chain value.

    Returns:
        SoftFuseChain with interpreted fields and reserved bits.
    """
    raw &= 0xFFFFFFFFFFFFFFFF
    fields = get_known_fields()
    known_bits = {field.bit for field in fields}
    hidden_reserved_bits = {}
    reserved_bits: List[int] = []
    for bit in range(64):
        if bit in known_bits or bit in hidden_reserved_bits:
            continue
        if raw & (1 << bit):
            reserved_bits.append(bit)
    return SoftFuseChain(raw_value=raw, fields=fields, reserved_bits=reserved_bits)
