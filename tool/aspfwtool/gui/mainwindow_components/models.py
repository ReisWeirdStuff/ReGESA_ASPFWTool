# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Data models for the main window components.

This module provides dataclasses for:
    - LoadedImage: Container for a loaded firmware image and its parsed data
    - UefiRoot: UEFI root information within an image
    - UefiFileContextInfo: Context for UEFI file operations
    - UefiVolumeContextInfo: Context for UEFI volume operations
    - PspTypeFields/BiosTypeFields: Parsed type field structures
    - CompressedBiosInfo: Info about compressed BIOS entry (0x62) for edits
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ...agesa.directory import Directory
from ...agesa.efs import EfsInfo
from ...agesa.keys import KeyDisplayRecord
from ...agesa.prom import PromInfo
from ...uefi import (
    EnumeratedFirmwareFile,
    EnumeratedFirmwareSection,
    EnumeratedFirmwareVolume,
)


@dataclass
class CompressedBiosInfo:
    """
    Information about a compressed BIOS entry (type 0x62) for edit operations.

        For AMD Secured Boot, entry 0x62 with reset_image flag contains a zlib-compressed
        UEFI image. When editing, we need to:
        1. Decompress, apply edits, recompress
        2. Update entry's `size` field (compressed size)
        3. Update entry's `destination` field to keep reset vector fixed
        
        Reset Vector = destination + decompressed_size - 0x10
        new_destination = old_destination + old_decompressed_size - new_decompressed_size
    """
    directory_index: int  # Index of directory containing the entry
    entry_index: int  # Index of entry within directory
    entry_offset: int  # Flash offset of directory entry (for patching)
    source_offset: int  # Flash offset of compressed blob
    destination: int  # Memory destination address
    compressed_size: int  # Size of compressed blob in flash
    decompressed_size: int  # Size after decompression
    zlib_offset: int = 0x100  # Offset where zlib stream starts in blob
    reset_vector: int = 0  # Calculated reset vector address
    
    def __post_init__(self):
        if self.reset_vector == 0:
            self.reset_vector = self.destination + self.decompressed_size - 0x10
    
    def calculate_new_destination(self, new_decompressed_size: int) -> int:
        """Calculate new destination to keep reset vector at same address."""
        return self.reset_vector + 0x10 - new_decompressed_size


@dataclass
class UefiRoot:
    image_index: int
    directory_index: int
    directory_kind: str
    entry_index: Optional[int]
    entry_label: str
    offset: int
    size: int
    volumes: List[EnumeratedFirmwareVolume]
    detail: str
    # For compressed BIOS entries (type 0x62 with reset_image)
    compressed_bios_info: Optional[CompressedBiosInfo] = None
    decompressed_data: Optional[bytes] = None  # Cached decompressed content


@dataclass
class BiosEntryRef:
    """
    Reference to a BIOS entry (0x62) that points to a region in the image.
    
    Used to cross-reference UEFI volumes with their source PSP entry.
    """
    directory_index: int  # Index of directory containing the entry
    entry_index: int  # Index of entry within directory
    source_offset: int  # Flash offset where BIOS content starts
    size: int  # Size of the BIOS content region (decompressed if applicable)
    destination: Optional[int]  # Memory destination address (from entry)
    compressed: bool  # Whether the entry was compressed


@dataclass
class LoadedImage:
    path: Path
    data: bytearray
    directories: List[Directory]
    efs_infos: List[EfsInfo] = field(default_factory=list)
    prom_infos: List[PromInfo] = field(default_factory=list)
    uefi_roots: List[UefiRoot] = field(default_factory=list)
    psp_entries: List[dict] = field(default_factory=list)
    keyring_entries: List[KeyDisplayRecord] = field(default_factory=list)
    dirty: bool = False
    needs_reparse: bool = False
    change_log: List[str] = field(default_factory=list)
    was_capsule: bool = False
    psp_modified_entries: Set[Tuple[int, Optional[int]]] = field(default_factory=set)
    modified_ranges: List[Tuple[int, int]] = field(default_factory=list)
    pending_entry_actions: Dict[Tuple[int, Optional[int]], dict] = field(default_factory=dict)
    psp_entry_actions: Dict[Tuple[int, Optional[int]], str] = field(default_factory=dict)
    pending_uefi_actions: Dict[str, dict] = field(default_factory=dict)
    # Track 0x62 BIOS entry regions for cross-referencing with UEFI volumes
    bios_entry_refs: List[BiosEntryRef] = field(default_factory=list)


@dataclass
class UefiFileContextInfo:
    image_index: int
    image: "LoadedImage"
    volume_chain: List[EnumeratedFirmwareVolume]
    file_chain: List[EnumeratedFirmwareFile]
    section_chain: List[EnumeratedFirmwareSection]
    section_path: List[int]
    root_volume: EnumeratedFirmwareVolume
    target_volume: EnumeratedFirmwareVolume
    root_file: EnumeratedFirmwareFile
    target_file: EnumeratedFirmwareFile
    file_index: Optional[int]
    virtual: bool


@dataclass
class UefiVolumeContextInfo:
    image_index: int
    image: "LoadedImage"
    volume_chain: List[EnumeratedFirmwareVolume]
    file_chain: List[EnumeratedFirmwareFile]
    section_chain: List[EnumeratedFirmwareSection]
    section_path: List[int]
    root_volume: EnumeratedFirmwareVolume
    target_volume: EnumeratedFirmwareVolume
    root_file: Optional[EnumeratedFirmwareFile]  # File containing compressed section (for virtual)
    virtual: bool


@dataclass
class PspTypeFields:
    entry_type: int
    subprogram: int
    rom_id: int
    writable: int
    instance: int
    reserved: int

    @classmethod
    def from_value(cls, value: int) -> "PspTypeFields":
        base = int(value) if value is not None else 0
        return cls(
            entry_type=base & 0xFF,
            subprogram=(base >> 8) & 0xFF,
            rom_id=(base >> 16) & 0x3,
            writable=(base >> 18) & 0x1,
            instance=(base >> 19) & 0xF,
            reserved=(base >> 23) & 0x1FF,
        )

    def to_value(self) -> int:
        value = int(self.entry_type) & 0xFF
        value |= (int(self.subprogram) & 0xFF) << 8
        value |= (int(self.rom_id) & 0x3) << 16
        value |= (int(self.writable) & 0x1) << 18
        value |= (int(self.instance) & 0xF) << 19
        value |= (int(self.reserved) & 0x1FF) << 23
        return value & 0xFFFFFFFF


@dataclass
class BiosTypeFields:
    entry_type: int
    region_type: int
    reset_image: int
    copy_image: int
    read_only: int
    compressed: int
    instance: int
    subprogram: int
    rom_id: int
    writable: int
    reserved: int

    @classmethod
    def from_value(cls, value: int) -> "BiosTypeFields":
        base = int(value) if value is not None else 0
        return cls(
            entry_type=base & 0xFF,
            region_type=(base >> 8) & 0xFF,
            reset_image=(base >> 16) & 0x1,
            copy_image=(base >> 17) & 0x1,
            read_only=(base >> 18) & 0x1,
            compressed=(base >> 19) & 0x1,
            instance=(base >> 20) & 0xF,
            subprogram=(base >> 24) & 0x7,
            rom_id=(base >> 27) & 0x3,
            writable=(base >> 29) & 0x1,
            reserved=(base >> 30) & 0x3,
        )

    def to_value(self) -> int:
        value = int(self.entry_type) & 0xFF
        value |= (int(self.region_type) & 0xFF) << 8
        value |= (int(self.reset_image) & 0x1) << 16
        value |= (int(self.copy_image) & 0x1) << 17
        value |= (int(self.read_only) & 0x1) << 18
        value |= (int(self.compressed) & 0x1) << 19
        value |= (int(self.instance) & 0xF) << 20
        value |= (int(self.subprogram) & 0x7) << 24
        value |= (int(self.rom_id) & 0x3) << 27
        value |= (int(self.writable) & 0x1) << 29
        value |= (int(self.reserved) & 0x3) << 30
        return value & 0xFFFFFFFF
