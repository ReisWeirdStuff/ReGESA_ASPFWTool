# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Entry type definitions and lookup utilities for PSP/BIOS directories.

This module provides:
    - Entry kind constants (IMAGE, POINT, VALUE)
    - EntryDefinition dataclass for type metadata
    - Type lookup functions for PSP and BIOS directories
"""

from dataclasses import dataclass
from typing import Optional

from .constants import PSPTypeNames, BIOSTypeNames
from . import constants as _constants


# Entry Kind Constants


IMAGE_ENTRY = "IMAGE"  # Points to actual binary data
POINT_ENTRY = "POINT"  # Points to another directory or structure
VALUE_ENTRY = "VALUE"  # Contains inline value data

_ENTRY_KIND_LABELS = {
    IMAGE_ENTRY: "Image",
    POINT_ENTRY: "Pointer",
    VALUE_ENTRY: "Value",
}


@dataclass(frozen=True)
class EntryDefinition:
    """
    Metadata describing a directory entry type.

    Attributes:
        entry_type: Entry kind (IMAGE, POINT, VALUE) or None if unknown.
        name: Human-readable short name for the entry type.
        description: Longer description of the entry's purpose.
    """

    entry_type: Optional[str]
    name: str
    description: str

    @property
    def kind_label(self) -> str:
        if self.entry_type is None:
            return "Unknown"
        return _ENTRY_KIND_LABELS.get(self.entry_type, self.entry_type)


def _lookup(table, type_id: int) -> Optional[EntryDefinition]:
    rec = table.get(type_id)
    if not rec:
        return None
    return EntryDefinition(entry_type=rec[0], name=rec[1], description=rec[2])


def lookup_entry_definition(dir_kind: str, type_id: int) -> EntryDefinition:
    """
    Look up the definition for a directory entry type.

    Args:
        dir_kind: Directory kind ('2PSP', '$PSP', '$PL2', '2BHD', '$BHD', '$BL2').
        type_id: Entry type ID (lower 8 bits are used).

    Returns:
        EntryDefinition with type metadata, or unknown placeholder.
    """
    base = type_id & 0xFF
    if _constants.is_psp_dir(dir_kind):
        rec = _lookup(PSPTypeNames, base)
        if rec:
            return rec
    elif _constants.is_bios_dir(dir_kind):
        rec = _lookup(BIOSTypeNames, base)
        if rec:
            return rec
    return EntryDefinition(entry_type=None, name="unknown", description="")


def entry_type_label(entry_type: Optional[str]) -> str:
    """
    Get a readable label for an entry type.

    Args:
        entry_type: Entry kind constant or None.

    Returns:
        Display label for the entry type.
    """
    if entry_type is None:
        return "Unknown"
    return _ENTRY_KIND_LABELS.get(entry_type, entry_type)
