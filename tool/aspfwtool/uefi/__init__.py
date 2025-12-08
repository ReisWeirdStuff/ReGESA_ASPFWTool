# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
UEFI Firmware File System (FFS) parsing and manipulation package.

This package provides utilities for working with UEFI firmware volumes,
including:

    - Firmware volume scanning and enumeration
    - FFS file parsing and construction
    - Section compression/decompression (EFI, LZMA, AMD-specific)
    - GUID name lookup from JSON configuration
    - File insertion, replacement, and removal operations
"""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Sequence, Tuple
from uuid import UUID

from .ffs import (
    FirmwareVolumeInfo,
    FirmwareFileInfo,
    FirmwareSectionInfo,
    FirmwareMutationError,
    FirmwareParseError,
    EFI_SECTION_COMPRESSION,
    EFI_STANDARD_COMPRESSION,
    EFI_CUSTOM_COMPRESSION_LZMA,
    EFI_FV_FILETYPE_SECURITY_CORE,
    PAD_FILE_GUID,
    VTF_FILE_GUID,
    RECOVERY_STARTUP_AP_DATA_X86_128K,
    RECOVERY_STARTUP_AP_DATA_X86_SIZE,
    scan_firmware_volumes,
    build_ffs_file,
    build_compression_section,
    compress_section_payload,
    decompress_compression_section,
    insert_ffs_file,
    replace_ffs_file,
    remove_ffs_file,
    parse_ffs_file_bytes,
)



# GUID Name Mapping (Loaded from JSON)


_GUID_JSON_PATH = Path(__file__).parent.parent / "updatable" / "guid_names.json"


def _load_guid_name_map() -> Dict[UUID, str]:
    """Load the GUID to name map from the JSON file."""
    if not _GUID_JSON_PATH.exists():
        return {}
    try:
        with _GUID_JSON_PATH.open("r", encoding="utf-8") as guid_file:
            data = json.load(guid_file)
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Support both flat format and nested format with metadata
    guid_map = data.get("guids", data)
    if not isinstance(guid_map, dict):
        return {}
    # Skip metadata key if present
    result: Dict[UUID, str] = {}
    for key, value in guid_map.items():
        if key == "metadata":
            continue
        try:
            result[UUID(key)] = value
        except (ValueError, TypeError):
            continue
    return result


@lru_cache(maxsize=1)
def _get_guid_name_map() -> Dict[UUID, str]:
    """Cached loader for GUID name map."""
    return _load_guid_name_map()


# Mutable reference for runtime updates (e.g., adding new GUIDs)
GUID_NAME_MAP: Dict[UUID, str] = {}


def _init_guid_name_map() -> None:
    """Initialize the mutable GUID_NAME_MAP from the cached loader."""
    global GUID_NAME_MAP
    GUID_NAME_MAP.update(_get_guid_name_map())


_init_guid_name_map()


@dataclass
class EnumeratedFirmwareSection:
    info: FirmwareSectionInfo
    sections: List["EnumeratedFirmwareSection"]
    volumes: List["EnumeratedFirmwareVolume"]


@dataclass
class EnumeratedFirmwareFile:
    index: int | None
    info: FirmwareFileInfo
    sections: List[EnumeratedFirmwareSection]


@dataclass
class EnumeratedFirmwareVolume:
    index: int | None
    info: FirmwareVolumeInfo
    files: List[EnumeratedFirmwareFile]


def _enumerate_sections(
    sections: Sequence[FirmwareSectionInfo],
    fv_index: int,
    ffs_index: int,
) -> Tuple[List[EnumeratedFirmwareSection], int, int]:
    enumerated: List[EnumeratedFirmwareSection] = []
    for section in sections:
        nested_volumes, fv_index, ffs_index = enumerate_volumes(
            section.nested_volumes, fv_start=fv_index, ffs_start=ffs_index
        )
        nested_sections, fv_index, ffs_index = _enumerate_sections(
            section.nested_sections, fv_index, ffs_index
        )
        enumerated.append(
            EnumeratedFirmwareSection(
                info=section,
                sections=nested_sections,
                volumes=nested_volumes,
            )
        )
    return enumerated, fv_index, ffs_index


def enumerate_volumes(
    volumes: Sequence[FirmwareVolumeInfo],
    *,
    fv_start: int = 0,
    ffs_start: int = 0,
) -> Tuple[List[EnumeratedFirmwareVolume], int, int]:
    enumerated: List[EnumeratedFirmwareVolume] = []
    fv_index = fv_start
    ffs_index = ffs_start
    for volume in volumes:
        files: List[EnumeratedFirmwareFile] = []
        for file_info in volume.files:
            file_index = ffs_index
            ffs_index += 1
            sections, fv_index, ffs_index = _enumerate_sections(
                file_info.sections, fv_index, ffs_index
            )
            files.append(
                EnumeratedFirmwareFile(
                    index=file_index,
                    info=file_info,
                    sections=sections,
                )
            )
        enumerated.append(
            EnumeratedFirmwareVolume(index=fv_index, info=volume, files=files)
        )
        fv_index += 1
    return enumerated, fv_index, ffs_index


def wrap_volume(volume: FirmwareVolumeInfo) -> EnumeratedFirmwareVolume:
    enumerated, _, _ = enumerate_volumes([volume], fv_start=0, ffs_start=0)
    return enumerated[0]


def lookup_guid_name(guid: object) -> str | None:
    if guid is None:
        return None
    if isinstance(guid, UUID):
        return GUID_NAME_MAP.get(guid)
    if isinstance(guid, str):
        text = guid.strip()
        if not text:
            return None
        if text.startswith("{") and text.endswith("}"):
            text = text[1:-1]
        try:
            guid_obj = UUID(text)
        except (ValueError, TypeError):
            return None
        return GUID_NAME_MAP.get(guid_obj)
    if isinstance(guid, (bytes, bytearray)):
        data = bytes(guid)
        if len(data) != 16:
            return None
        try:
            guid_obj = UUID(bytes=data)
        except (ValueError, TypeError):
            return None
        return GUID_NAME_MAP.get(guid_obj)
    return None
