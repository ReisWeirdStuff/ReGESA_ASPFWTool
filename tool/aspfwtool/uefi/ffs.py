# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
UEFI Firmware File System (FFS) parsing and manipulation.

This module provides comprehensive support for UEFI FFS operations:

    - Firmware volume scanning and parsing
    - FFS file header parsing and construction
    - Section parsing (compression, GUID-defined, nested FV, etc.)
    - File insertion, replacement, and removal operations
    - Volume checksum calculation and validation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from uuid import UUID
import lzma
import struct

from .compressor import (
    EFI_NOT_COMPRESSED,
    EFI_STANDARD_COMPRESSION,
    EFI_CUSTOM_COMPRESSION_LZMA,
    EFI_CUSTOM_COMPRESSION_AMD_DEFLATE,
    EFI_CUSTOM_COMPRESSION_AMD_DEFLATE1,    
    COMPRESSION_TYPE_NAMES,
    compress_section_payload,
    _compress_deflate_like,
    _compress_lzma_custom,
    _lzma_alone_encode,
    _lzma_alone_encode_known_size_cpython,
    detect_zlib_flevel_from_data,
    map_flevel_to_zlib_level,
)
from .decompressor import (
    FirmwareMutationError,
    FirmwareParseError,
    _decompress_deflate_like,
    _decompress_lzma_custom,
    _decompress_standard,
    decompress_guid_defined as _decompress_guid_defined,
)
from ..utils.debug_logger import get_logger


# Known GUIDs


from .guids import (  # type: ignore
    EFI_GUIDED_SECTION_LZMA,
    EFI_GUIDED_SECTION_ZLIB_AMD,
    EFI_GUIDED_SECTION_ZLIB_AMD2,
)


# FFS Constants


FVH_SIGNATURE = b"_FVH"
ALIGN_FILE = 8
ALIGN_SEC = 4
FF_FILL = 0xFF
EFI_FFS_ATTRIB_CHECKSUM = 0x40


# FFS File Types (UEFI PI Spec)


FFS_TYPE_NAMES = {
    0x00: "ALL",
    0x01: "RAW",
    0x02: "FREEFORM",
    0x03: "SECURITY_CORE",
    0x04: "PEI_CORE",
    0x05: "DXE_CORE",
    0x06: "PEIM",
    0x07: "DRIVER",
    0x08: "COMBINED_PEIM_DRIVER",
    0x09: "APPLICATION",
    0x0A: "MM",
    0x0B: "FIRMWARE_VOLUME_IMAGE",
    0x0C: "COMBINED_MM_DXE",
    0x0D: "MM_CORE",
    0x0E: "MM_STANDALONE",
    0x0F: "MM_CORE_STANDALONE",
    0xF0: "PAD",
}

PAD_FILE_GUID = UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")

# Volume Top File (VTF) GUID - contains reset vector, must not be moved
VTF_FILE_GUID = UUID("1BA0062E-C779-4582-8566-336AE8F78F09")

# SEC Core file type - often near reset vector
EFI_FV_FILETYPE_SECURITY_CORE = 0x03

# Recovery Startup AP Data pattern (x86 128K)
RECOVERY_STARTUP_AP_DATA_X86_128K = b"\xEA\xD0\xFF\x00\xF0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x27\x2D"
RECOVERY_STARTUP_AP_DATA_X86_SIZE = 16


# Section Type Constants (UEFI PI Spec)


EFI_SECTION_COMPRESSION            = 0x01
EFI_SECTION_GUID_DEFINED           = 0x02
EFI_SECTION_DISPOSABLE             = 0x03
EFI_SECTION_PE32                   = 0x10
EFI_SECTION_PIC                    = 0x11
EFI_SECTION_TE                     = 0x12
EFI_SECTION_DXE_DEPEX              = 0x13
EFI_SECTION_VERSION                = 0x14
EFI_SECTION_USER_INTERFACE         = 0x15
EFI_SECTION_COMPATIBILITY16        = 0x16
EFI_SECTION_FIRMWARE_VOLUME_IMAGE  = 0x17
EFI_SECTION_FREEFORM_SUBTYPE_GUID  = 0x18
EFI_SECTION_RAW                    = 0x19
EFI_SECTION_PEI_DEPEX              = 0x1B
EFI_SECTION_MM_DEPEX               = 0x1C

EFI_SECTION_UI        = EFI_SECTION_USER_INTERFACE
EFI_SECTION_FV_IMAGE  = EFI_SECTION_FIRMWARE_VOLUME_IMAGE
EFI_SECTION_SMM_DEPEX = EFI_SECTION_MM_DEPEX
EFI_SECTION_SMM_DEPEX_LEGACY = 0x1A  # Rare legacy


# Section Type Names


SECTION_TYPE_NAMES = {
    EFI_SECTION_COMPRESSION:            "COMPRESSION",
    EFI_SECTION_GUID_DEFINED:           "GUID_DEFINED",
    EFI_SECTION_DISPOSABLE:             "DISPOSABLE",
    EFI_SECTION_PE32:                   "PE32",
    EFI_SECTION_PIC:                    "PIC",
    EFI_SECTION_TE:                     "TE",
    EFI_SECTION_DXE_DEPEX:              "DXE_DEPEX",
    EFI_SECTION_VERSION:                "VERSION",
    EFI_SECTION_USER_INTERFACE:         "USER_INTERFACE",
    EFI_SECTION_COMPATIBILITY16:        "COMPATIBILITY16",
    EFI_SECTION_FIRMWARE_VOLUME_IMAGE:  "FIRMWARE_VOLUME_IMAGE",
    EFI_SECTION_FREEFORM_SUBTYPE_GUID:  "FREEFORM_SUBTYPE_GUID",
    EFI_SECTION_RAW:                    "RAW",
    EFI_SECTION_PEI_DEPEX:              "PEI_DEPEX",
    EFI_SECTION_MM_DEPEX:               "MM_DEPEX",
													
    EFI_SECTION_SMM_DEPEX_LEGACY:       "SMM_DEPEX(legacy)",
}

## compression names moved to compressor.COMPRESSION_TYPE_NAMES

EFI_GUIDED_SECTION_PROCESSING_REQUIRED = 0x0001
EFI_GUIDED_SECTION_AUTH_STATUS_VALID   = 0x0002

_GUIDS_FORCE_DECOMPRESSION = {
    EFI_GUIDED_SECTION_ZLIB_AMD,
    EFI_GUIDED_SECTION_ZLIB_AMD2,
}


def _align(value: int, alignment: int) -> int:
    mask = alignment - 1
    return (value + mask) & ~mask


def _read_u24(data: bytes) -> int:
    return struct.unpack_from("<I", data + b"\x00")[0]


def _write_u24(value: int) -> bytes:
    if not (0 <= value < (1 << 24)):
        raise ValueError("value out of range for 24-bit field")
    return int(value).to_bytes(3, "little")


def _all_erased(data: memoryview) -> bool:
    return all(b == FF_FILL for b in data)


def _uuid_from_bytes_le(data: bytes) -> UUID:
    return UUID(bytes_le=bytes(data[:16]))


def _checksum8(data: bytes) -> int:
    return (-sum(data)) & 0xFF


def _apply_header_checksum(header: bytearray) -> None:
    """
    Header checksum over the entire header with:
      - header[16] (Header Checksum) set to 0
      - header[17] (File Checksum)   set to 0
      - header[23] (State)           set to 0
    """
    tmp = bytearray(header)
    if len(tmp) < 24:
        raise ValueError("FFS header too small")
    tmp[16] = 0
    tmp[17] = 0
    tmp[23] = 0
    header[16] = _checksum8(tmp)


def _build_ffs_header(
    *,
    guid: UUID,
    file_type: int,
    attributes: int,
    state: int,
    payload_length: int,
) -> bytes:
    if payload_length < 0:
        raise ValueError("payload length must be non-negative")
    header_length = 24
    total_length = header_length + payload_length
    if total_length >= 0x1000000:
        header_length = 32
        total_length = header_length + payload_length
    header = bytearray(header_length)
    header[:16] = guid.bytes_le
    raw_state = int(state) ^ 0xFF
    header[18] = int(file_type) & 0xFF
    header[19] = int(attributes) & 0xFF
    if header_length == 24:
        header[20:23] = _write_u24(total_length)
    else:
        header[20:23] = b"\xFF\xFF\xFF"
        header[24:32] = int(total_length).to_bytes(8, "little")
    header[23] = raw_state & 0xFF
    _apply_header_checksum(header)
    return bytes(header)


def _compute_file_checksum(header: bytes, payload: bytes, use_checksum: bool) -> int:
    """
    File checksum is 0xAA if EFI_FFS_ATTRIB_CHECKSUM is clear.
    Otherwise it is the 8-bit checksum over (header+payload) with
    FileChecksum and State treated as zero.
    """
    if not use_checksum:
        return 0xAA
    tmp = bytearray(header)
    tmp[17] = 0
    tmp[23] = 0
    total = (sum(tmp) + sum(payload)) & 0xFF
    return (-total) & 0xFF


def _build_ffs_file_bytes(
    *,
    guid: UUID,
    file_type: int,
    attributes: int,
    state: int,
    payload: bytes,
) -> bytes:
    payload_bytes = bytes(payload)
    header = bytearray(
        _build_ffs_header(
            guid=guid,
            file_type=file_type,
            attributes=attributes,
            state=state,
            payload_length=len(payload_bytes),
        )
    )
    use_file_cksum = bool(attributes & EFI_FFS_ATTRIB_CHECKSUM)
    header[17] = _compute_file_checksum(header, payload_bytes, use_file_cksum)
    _apply_header_checksum(header)  # recompute header checksum last
    return bytes(header) + payload_bytes


def _pad_file_bytes(data: bytes) -> bytes:
    aligned = _align(len(data), ALIGN_FILE)
    if aligned == len(data):
        return data
    return data + bytes([FF_FILL]) * (aligned - len(data))


def _tail_start(volume: "FirmwareVolumeInfo") -> int:
    if not volume.files:
        return int(volume.header_length)
    last = volume.files[-1]
    return _align(last.relative_offset + last.size, ALIGN_FILE)


def _extract_volume_data(buf: bytearray, volume: "FirmwareVolumeInfo") -> Tuple[int, bytearray]:
    if volume.absolute_offset is None:
        raise FirmwareMutationError("volume is missing absolute offset information")
    start = int(volume.absolute_offset)
    end = start + int(volume.size)
    if not (0 <= start < end <= len(buf)):
        raise FirmwareMutationError("volume range is outside the provided buffer")
    return start, bytearray(buf[start:end])


def _commit_volume_data(buf: bytearray, start: int, data: bytearray) -> None:
    end = start + len(data)
    buf[start:end] = data


def _reparse_volume(buf: bytearray, start: int, size: int, *, log_callback=None) -> "FirmwareVolumeInfo":
    end = start + int(size)
    view = memoryview(buf)[start:end]
    info = _parse_firmware_volume_view(view, start, log_callback=log_callback)
    if info is None:
        raise FirmwareMutationError("mutated firmware volume could not be reparsed")
    info.absolute_offset = start
    info.relative_offset = 0
    return info


def _refresh_volume(target: "FirmwareVolumeInfo", source: "FirmwareVolumeInfo") -> "FirmwareVolumeInfo":
    target.absolute_offset = source.absolute_offset
    target.relative_offset = source.relative_offset
    target.size = source.size
    target.header_length = source.header_length
    target.attributes = source.attributes
    target.revision = source.revision
    target.checksum = source.checksum
    target.filesystem_guid = source.filesystem_guid
    target.blocks = list(source.blocks)
    target.files = source.files
    target.used_size = source.used_size
    target.free_size = source.free_size
    return target


def _is_uniform_erased(payload: memoryview) -> Tuple[bool, int]:
    if not payload:
        return False, FF_FILL
    for byte in payload:
        if byte != FF_FILL:
            return False, payload[0]
    return True, FF_FILL


def _pad_payload_metrics(
    file_info: "FirmwareFileInfo",
    view: memoryview,
) -> Tuple[memoryview, int, int]:
    header_len = int(getattr(file_info, "header_length", 0) or 0)
    size = int(getattr(file_info, "size", 0) or 0)
    relative = int(getattr(file_info, "relative_offset", 0) or 0)
    if size <= header_len:
        return view[0:0], 0, 0
    end = relative + size
    if relative < 0 or end > len(view):
        return view[0:0], 0, 0
    payload = view[relative + header_len : end]
    if not payload:
        return payload, 0, 0
    tail = len(payload)
    while tail > 0 and payload[tail - 1] == FF_FILL:
        tail -= 1
    content_len = tail
    free_tail = len(payload) - tail
    return payload, content_len, free_tail


def _pad_payload_metrics_extended(
    file_info: "FirmwareFileInfo",
    view: memoryview,
) -> Tuple[memoryview, int, int, int]:
    """Extended metrics for padding files including leading free space.
    
    Returns:
        (payload, content_len, free_tail, free_lead)
        - payload: memoryview of the file payload (after header)
        - content_len: length of non-FF content (from start of actual data to end of actual data)
        - free_tail: trailing FF bytes that can be reclaimed
        - free_lead: leading FF bytes that can be reclaimed (for Startup AP files, etc.)
    """
    header_len = int(getattr(file_info, "header_length", 0) or 0)
    size = int(getattr(file_info, "size", 0) or 0)
    relative = int(getattr(file_info, "relative_offset", 0) or 0)
    if size <= header_len:
        return view[0:0], 0, 0, 0
    end = relative + size
    if relative < 0 or end > len(view):
        return view[0:0], 0, 0, 0
    payload = view[relative + header_len : end]
    if not payload:
        return payload, 0, 0, 0
    
    # Find trailing FF bytes
    tail = len(payload)
    while tail > 0 and payload[tail - 1] == FF_FILL:
        tail -= 1
    free_tail = len(payload) - tail
    
    # Find leading FF bytes
    lead = 0
    while lead < len(payload) and payload[lead] == FF_FILL:
        lead += 1
    free_lead = lead
    
    # Content length is from first non-FF to last non-FF
    content_len = max(0, tail - lead)
    
    return payload, content_len, free_tail, free_lead


def _detect_startup_ap_data(payload: bytes | memoryview) -> bool:
    """Check if the payload contains the x86 Startup AP data pattern.
    
    The Startup AP data is used for Application Processor startup during
    system boot. It starts with a far jump instruction (EA D0 FF 00 F0)
    followed by specific padding. This is commonly found in padding files
    at the end of boot firmware volumes.
    
    Returns True if the pattern is detected.
    """
    if len(payload) < RECOVERY_STARTUP_AP_DATA_X86_SIZE:
        return False
    
    # Skip leading 0xFF bytes to find actual content
    start = 0
    while start < len(payload) and payload[start] == FF_FILL:
        start += 1
    
    if start + RECOVERY_STARTUP_AP_DATA_X86_SIZE > len(payload):
        return False
    
    # Check for the Startup AP data pattern
    return bytes(payload[start:start + RECOVERY_STARTUP_AP_DATA_X86_SIZE]) == RECOVERY_STARTUP_AP_DATA_X86_128K


def _is_reset_vector_protected_pad(
    volume: "FirmwareVolumeInfo",
    pad_index: int,
) -> bool:
    """Check if a padding file protects the reset vector area.
    
    Returns True if the padding file should NOT be shrunk because:
    - It's in a PHYSICAL volume and shrinking would move VTF/SecCore
    
    For VIRTUAL volumes (inside compressed sections), positions don't
    affect the reset vector since it points to physical addresses.
    Startup AP data padding files in virtual volumes can be safely shrunk.
    
    The 16-byte startup AP data at the start is preserved by normal
    shrinking logic (we only remove trailing 0xFF bytes).
    """
    total = len(volume.files)
    if pad_index < 0 or pad_index >= total:
        return False
    
    pad_file = volume.files[pad_index]
    is_startup_ap = getattr(pad_file, "display_name", None) == "Startup AP data padding file"
    
    # Virtual volumes (no absolute_offset) - positions don't affect reset vector
    # Startup AP data padding files can be safely shrunk in virtual volumes
    if volume.absolute_offset is None and is_startup_ap:
        return False
    
    # Check the file immediately after this padding
    if pad_index + 1 < total:
        next_file = volume.files[pad_index + 1]
        next_guid = getattr(next_file, "guid", None)
        next_type = int(getattr(next_file, "type", 0))
        
        # VTF file - contains reset vector, must stay at fixed location
        if next_guid == VTF_FILE_GUID:
            # In virtual volumes with Startup AP, we can shrink safely
            if volume.absolute_offset is None and is_startup_ap:
                return False
            return True
        
        # SEC_CORE file - typically needs alignment for reset vector jump
        if next_type == EFI_FV_FILETYPE_SECURITY_CORE:
            if volume.absolute_offset is None and is_startup_ap:
                return False
            return True
    
    # Check if this is the second-to-last and last is VTF/SEC
    if pad_index == total - 2 and total >= 2:
        last_file = volume.files[total - 1]
        last_guid = getattr(last_file, "guid", None)
        last_type = int(getattr(last_file, "type", 0))
        if last_guid == VTF_FILE_GUID or last_type == EFI_FV_FILETYPE_SECURITY_CORE:
            if volume.absolute_offset is None and is_startup_ap:
                return False
            return True
    
    # Last padding file - check if it's a Startup AP data padding file in virtual volume
    if pad_index == total - 1:
        if is_startup_ap:
            # Startup AP padding has lots of free space - allow shrinking
            return False
        # Regular last padding file - protect it
        return True
    
    return False


def _find_resizable_pad(
    volume: "FirmwareVolumeInfo", data: bytearray | memoryview
) -> Optional[Tuple[int, "FirmwareFileInfo", int, int]]:
    """Find a padding file that can be safely shrunk to reclaim space.
    
    Skips padding files that protect the reset vector area.
    """
    view = data if isinstance(data, memoryview) else memoryview(data)
    total = len(volume.files)
    for idx in range(total - 1, -1, -1):
        file_info = volume.files[idx]
        if int(getattr(file_info, "type", 0)) != 0xF0:
            continue
        guid = getattr(file_info, "guid", None)
        if guid != PAD_FILE_GUID:
            continue
        
        # Skip padding files that protect reset vector alignment
        if _is_reset_vector_protected_pad(volume, idx):
            continue
        
        payload, content_len, free_tail = _pad_payload_metrics(file_info, view)
        if not payload:
            continue
        if free_tail <= 0:
            continue
        return idx, file_info, content_len, free_tail
    return None


def _shrink_pad_file(
    buf: bytearray,
    volume: "FirmwareVolumeInfo",
    pad_index: int,
    required: int,
) -> Tuple["FirmwareVolumeInfo", int]:
    if required <= 0:
        return volume, 0
    if pad_index < 0 or pad_index >= len(volume.files):
        return volume, 0
    pad_info = volume.files[pad_index]
    header_len = int(getattr(pad_info, "header_length", 0) or 0)
    total_size = int(getattr(pad_info, "size", 0) or 0)
    if total_size <= header_len:
        return volume, 0
    payload_len = total_size - header_len
    start, data = _extract_volume_data(buf, volume)
    original_length = len(data)
    rel_start = _align(int(pad_info.relative_offset), ALIGN_FILE)
    old_span = _align(total_size, ALIGN_FILE)
    if rel_start + old_span > original_length:
        return volume, 0
    shrink_target = min(payload_len, _align(required, ALIGN_FILE))
    if shrink_target <= 0:
        return volume, 0
    data_view = memoryview(data)
    payload_slice, content_len, free_tail = _pad_payload_metrics(pad_info, data_view)
    if not payload_slice:
        return volume, 0
    if free_tail <= 0:
        return volume, 0
    shrinkable = min(free_tail, shrink_target)
    if shrinkable <= 0:
        return volume, 0
    keep_tail = free_tail - shrinkable
    if keep_tail < 0:
        keep_tail = 0
    head_bytes = bytes(payload_slice[:content_len]) if content_len > 0 else b""
    tail_bytes = bytes([FF_FILL]) * keep_tail
    new_payload_bytes = head_bytes + tail_bytes
    new_file_bytes = build_ffs_file(
        new_payload_bytes,
        guid=pad_info.guid,
        file_type=pad_info.type,
        attributes=pad_info.attributes,
        state=pad_info.state,
    )
    shrunk = _pad_file_bytes(new_file_bytes)
    new_span = len(shrunk)
    if new_span >= old_span:
        return volume, 0
    data[rel_start : rel_start + new_span] = shrunk
    data[rel_start + new_span : rel_start + old_span] = bytes([FF_FILL]) * (old_span - new_span)
    _commit_volume_data(buf, start, data)
    refreshed = _reparse_volume(buf, start, original_length, log_callback=None)
    volume = _refresh_volume(volume, refreshed)
    freed = old_span - new_span
    return volume, freed


def _compact_volume(volume: "FirmwareVolumeInfo", buf: bytearray) -> "FirmwareVolumeInfo":
    start, data = _extract_volume_data(buf, volume)
    original_length = len(data)
    header_length = int(volume.header_length)
    snapshot = bytes(data)
    compacted = bytearray([FF_FILL]) * original_length
    view = memoryview(snapshot)
    if header_length > original_length:
        raise FirmwareMutationError("volume header larger than volume span")
    compacted[:header_length] = snapshot[:header_length]
    cursor = header_length
    for file_info in volume.files:
        rel = int(file_info.relative_offset)
        size = int(file_info.size)
        end = rel + size
        if rel < 0 or end > original_length:
            raise FirmwareMutationError("file extent outside volume during compaction")
        if int(file_info.type) == 0xF0:
            header_len = int(getattr(file_info, "header_length", 0) or 0)
            if header_len <= size:
                payload = view[rel + header_len : end]
                erased, _fill = _is_uniform_erased(payload)
                if not payload or erased:
                    continue
        cursor = _align(cursor, ALIGN_FILE)
        if cursor + size > original_length:
            raise FirmwareMutationError("volume overflow during compaction")
        compacted[cursor:cursor + size] = view[rel:end]
        pad_end = _align(cursor + size, ALIGN_FILE)
        if pad_end > original_length:
            raise FirmwareMutationError("volume overflow during compaction")
        if pad_end > cursor + size:
            compacted[cursor + size:pad_end] = bytes([FF_FILL]) * (pad_end - (cursor + size))
        cursor = pad_end
    if cursor < original_length:
        compacted[cursor:] = bytes([FF_FILL]) * (original_length - cursor)
    _commit_volume_data(buf, start, compacted)
    refreshed = _reparse_volume(buf, start, original_length, log_callback=None)
    return _refresh_volume(volume, refreshed)


@dataclass
class FirmwareSectionInfo:
    absolute_offset: Optional[int]
    relative_offset: int
    size: int
    type: int
    type_name: str
    header_length: int = 0
    data_offset: Optional[int] = None
    name: Optional[str] = None
    compression_type: Optional[int] = None
    compression_name: Optional[str] = None
    uncompressed_length: Optional[int] = None
    guid: Optional[UUID] = None
    attributes: Optional[int] = None
    notes: List[str] = field(default_factory=list)
    nested_sections: List["FirmwareSectionInfo"] = field(default_factory=list)
    nested_volumes: List["FirmwareVolumeInfo"] = field(default_factory=list)
    virtual: bool = False
    processed_payload: Optional[bytes] = None


@dataclass
class FirmwareFileInfo:
    absolute_offset: Optional[int]
    relative_offset: int
    size: int
    header_length: int
    type: int
    type_name: str
    attributes: int
    state: int
    guid: UUID
    raw_data: Optional[bytes] = None
    sections: List[FirmwareSectionInfo] = field(default_factory=list)
    display_name: Optional[str] = None  # Special name when detected (e.g., "Startup AP data padding file")


@dataclass
class FirmwareVolumeInfo:
    absolute_offset: Optional[int]
    relative_offset: int
    size: int
    header_length: int
    attributes: int
    revision: int
    checksum: int
    filesystem_guid: Optional[UUID]
    blocks: List[Tuple[int, int]]
    raw_data: Optional[bytes] = None
    fv_name: Optional[UUID] = None
    files: List[FirmwareFileInfo] = field(default_factory=list)
    used_size: int = 0
    free_size: int = 0


def _parse_block_map(header_length: int, view: memoryview) -> List[Tuple[int, int]]:
    blocks: List[Tuple[int, int]] = []
    offset = 0x38
    while offset + 8 <= header_length:
        count, size = struct.unpack_from("<II", view, offset)
        if count == 0 and size == 0:
            break
        blocks.append((count, size))
        offset += 8
    return blocks


def _parse_sections(
    data: memoryview,
    base_offset: Optional[int],
    *,
    relative_base: int = 0,
    virtual: bool = False,
    log_callback=None,
) -> List[FirmwareSectionInfo]:
    sections: List[FirmwareSectionInfo] = []
    cursor = 0
    total = len(data)
    while cursor + 4 <= total:
        header = bytes(data[cursor : cursor + 4])
        size = _read_u24(header[:3])
        section_type = header[3]
        header_len = 4
        if size == 0:
            break
        if size == 0xFFFFFF:
            if cursor + 12 > total:
                break
            size = struct.unpack_from("<Q", data, cursor + 4)[0]
            header_len = 12
        end = cursor + size
        if end > total or size < header_len:
            break
        payload = data[cursor + header_len : end]
        abs_off = (base_offset + cursor) if base_offset is not None else None
        info = FirmwareSectionInfo(
            absolute_offset=abs_off,
            relative_offset=relative_base + cursor,
            size=size,
            type=section_type,
            type_name=SECTION_TYPE_NAMES.get(section_type, f"0x{section_type:02X}"),
            virtual=virtual,
        )
        info.header_length = header_len
        if abs_off is not None:
            info.data_offset = abs_off + header_len
        _populate_section_details(
            info,
            payload,
            base_offset=abs_off,
            relative_base=relative_base + cursor,
            log_callback=log_callback,
        )
        sections.append(info)
        cursor = _align(end, ALIGN_SEC)
    return sections


def _populate_section_details(
    info: FirmwareSectionInfo,
    payload: memoryview,
    *,
    base_offset: Optional[int],
    relative_base: int,
    log_callback=None,
) -> None:
    try:
        if info.type == EFI_SECTION_UI or info.type == EFI_SECTION_VERSION:
            info.name = _decode_utf16le(payload.tobytes())
        elif info.type == EFI_SECTION_COMPRESSION:
            _handle_compression_section(
                info, payload, base_offset, relative_base, log_callback=log_callback
            )
        elif info.type == EFI_SECTION_GUID_DEFINED:
            _handle_guid_defined_section(
                info, payload, base_offset, relative_base, log_callback=log_callback
            )
        elif info.type == EFI_SECTION_FV_IMAGE:
            nested = parse_firmware_volume_bytes(
                payload.tobytes(), base_offset, log_callback=log_callback
            )
            if nested:
                for volume in nested:
                    volume.relative_offset += relative_base
                info.nested_volumes.extend(nested)
        else:
            nested = parse_firmware_volume_bytes(
                payload.tobytes(), base_offset, log_callback=log_callback
            )
            if nested:
                for volume in nested:
                    volume.relative_offset += relative_base
                info.nested_volumes.extend(nested)
    except Exception as exc:
        info.notes.append(f"error parsing section payload: {exc}")


def _decode_utf16le(data: bytes) -> Optional[str]:
    try:
        text = data.decode("utf-16le", errors="ignore")
        return text.split("\x00", 1)[0] or None
    except Exception:
        return None


def _handle_compression_section(
    info: FirmwareSectionInfo,
    payload: memoryview,
    base_offset: Optional[int],
    relative_base: int,
    *,
    log_callback=None,
) -> None:
    if len(payload) < 6:
        info.notes.append("compression header too small")
        return
    compression_type = struct.unpack_from("<H", payload, 0)[0]
    uncompressed_length = struct.unpack_from("<I", payload, 2)[0]
    compressed_data = payload[6:]
    info.compression_type = compression_type
    info.compression_name = COMPRESSION_TYPE_NAMES.get(compression_type, f"0x{compression_type:04X}")
    info.uncompressed_length = uncompressed_length
    if compression_type == EFI_NOT_COMPRESSED:
        nested = _parse_sections(
            compressed_data,
            base_offset,
            relative_base=relative_base,
            virtual=True,
            log_callback=log_callback,
        )
        info.nested_sections.extend(nested)
        return
    if compression_type == EFI_STANDARD_COMPRESSION:
        def _decompress(payload_bytes: bytes) -> bytes:
            return _decompress_standard(payload_bytes, expected_length=uncompressed_length)
    else:
        codec = _CUSTOM_COMPRESSION_CODECS.get(compression_type)
        if codec is None:
            info.notes.append(f"unsupported compression type {compression_type}")
            return
        _, custom_decompress, _ = codec
        def _decompress(payload_bytes: bytes) -> bytes:
            return custom_decompress(payload_bytes, uncompressed_length)
    try:
        data = _decompress(compressed_data.tobytes())
        if isinstance(data, bytes):
            info.processed_payload = data
        else:
            info.processed_payload = bytes(data)
        nested = _parse_sections(
            memoryview(data),
            None,  # base_offset=None for decompressed content (virtual)
            relative_base=relative_base,
            virtual=True,
            log_callback=log_callback,
        )
        info.nested_sections.extend(nested)
    except Exception as exc:
        info.notes.append(f"decompress failed: {exc}")


def _handle_guid_defined_section(
    info: FirmwareSectionInfo,
    payload: memoryview,
    base_offset: Optional[int],
    relative_base: int,
    *,
    log_callback=None,
) -> None:
    if len(payload) < 20:
        info.notes.append("GUID-defined header too small")
        return
    guid = _uuid_from_bytes_le(bytes(payload[:16]))
    data_offset = struct.unpack_from("<H", payload, 16)[0]
    attributes = struct.unpack_from("<H", payload, 18)[0]
    info.guid = guid
    info.attributes = attributes
    if data_offset > len(payload):
        info.notes.append("invalid data offset")
        return
    preamble = payload[20:data_offset]
    body = payload[data_offset:]
    processing_required = bool(attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED)
    force_decompress = guid in _GUIDS_FORCE_DECOMPRESSION
    section_payload: memoryview = body
    virtual_decode = False
    try:
        if processing_required or force_decompress:
            decoded = _decompress_guid_defined(guid, preamble.tobytes(), body.tobytes())
            if decoded is None:
                if processing_required:
                    info.notes.append("no decompression handler for GUID")
                    return
            else:
                section_payload = memoryview(decoded)
                virtual_decode = True
                if isinstance(decoded, bytes):
                    info.processed_payload = decoded
                else:
                    info.processed_payload = bytes(decoded)
                info.virtual = True
        if not info.virtual and processing_required:
            info.virtual = True
        # Pass None for base_offset when content is decompressed (virtual)
        nested_base_offset = None if (processing_required or virtual_decode) else base_offset
        nested = _parse_sections(
            section_payload,
            nested_base_offset,
            relative_base=relative_base,
            virtual=processing_required or virtual_decode,
            log_callback=log_callback,
        )
        info.nested_sections.extend(nested)

        def _extract_section_payload_bytes(section: FirmwareSectionInfo) -> Optional[bytes]:
            try:
                local_offset = int(section.relative_offset) - int(relative_base)
            except Exception:
                return None
            if local_offset < 0 or local_offset >= len(section_payload):
                return None
            size = section.size
            if size <= 0:
                return None
            end = local_offset + size
            if end > len(section_payload):
                end = len(section_payload)
            payload_start = local_offset + section.header_length
            if payload_start > end:
                return None
            return section_payload[payload_start:end].tobytes()

        for idx in range(len(nested) - 1):
            first = nested[idx]
            second = nested[idx + 1]
            if first.type != EFI_SECTION_RAW or second.type != EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
                continue
            raw_bytes = _extract_section_payload_bytes(first)
            fv_bytes = _extract_section_payload_bytes(second)
            if not raw_bytes or not fv_bytes:
                continue
            combined = raw_bytes + fv_bytes
            try:
                combined_volumes = parse_firmware_volume_bytes(
                    combined,
                    None if info.virtual else base_offset,
                    log_callback=log_callback,
                )
            except Exception:
                continue
            if not combined_volumes:
                continue
            existing_file_total = sum(len(vol.files) for vol in second.nested_volumes)
            new_file_total = sum(len(vol.files) for vol in combined_volumes)
            if new_file_total <= existing_file_total:
                continue
            for volume in combined_volumes:
                volume.relative_offset += second.relative_offset
            second.nested_volumes = combined_volumes

        def _sections_have_volumes(sections: List[FirmwareSectionInfo]) -> bool:
            for section in sections:
                if section.nested_volumes:
                    return True
                if section.nested_sections and _sections_have_volumes(section.nested_sections):
                    return True
            return False

        need_volume_fallback = not _sections_have_volumes(nested)
        if need_volume_fallback and len(section_payload):
            try:
                candidate_volumes = parse_firmware_volume_bytes(
                    section_payload.tobytes(),
                    None if info.virtual else base_offset,
                    log_callback=log_callback,
                )
            except Exception as exc:
                info.notes.append(f"error parsing decoded FV: {exc}")
            else:
                for volume in candidate_volumes:
                    volume.relative_offset += relative_base
                info.nested_volumes.extend(candidate_volumes)
    except Exception as exc:
        info.notes.append(f"decompress failed: {exc}")

_CUSTOM_COMPRESSION_CODECS: Dict[
    int, Tuple[str, Callable[[bytes, Optional[int]], bytes], Callable[[bytes], bytes]]
] = {
    EFI_CUSTOM_COMPRESSION_LZMA: (
        "LZMA_CUSTOM",
        _decompress_lzma_custom,
        _compress_lzma_custom,
    ),
    EFI_CUSTOM_COMPRESSION_AMD_DEFLATE: (
        "AMD_DEFLATE",
        _decompress_deflate_like,   # uses size hint if caller has one
        _compress_deflate_like,     # zlib wrapper emission
    ),
    EFI_CUSTOM_COMPRESSION_AMD_DEFLATE1: (
        "AMD_DEFLATE",
        _decompress_deflate_like,   # uses size hint if caller has one
        _compress_deflate_like,     # zlib wrapper emission
    ),
}


## compress_section_payload moved to compressor.compress_section_payload


def parse_compression_section(section_bytes: bytes) -> tuple[int, int, int, bytes]:
    if len(section_bytes) < 4:
        raise FirmwareParseError("compression section too small")
    header_length = 4
    size = _read_u24(section_bytes[:3])
    if size == 0xFFFFFF:
        if len(section_bytes) < 12:
            raise FirmwareParseError("extended compression section header too small")
        header_length = 12
        size = struct.unpack_from("<Q", section_bytes, 4)[0]
    if size > len(section_bytes):
        size = len(section_bytes)
    if header_length + 6 > size:
        raise FirmwareParseError("compression section header truncated")
    compression_type = struct.unpack_from("<H", section_bytes, header_length)[0]
    uncompressed_length = struct.unpack_from("<I", section_bytes, header_length + 2)[0]
    compressed_data = section_bytes[header_length + 6 : size]
    return header_length, compression_type, uncompressed_length, compressed_data


def decompress_compression_section(section_bytes: bytes) -> tuple[bytes, int, int, int]:
    header_length, compression_type, uncompressed_length, compressed = parse_compression_section(section_bytes)
    if compression_type == EFI_NOT_COMPRESSED:
        return bytes(compressed), compression_type, uncompressed_length, header_length
    if compression_type == EFI_STANDARD_COMPRESSION:
        data = _decompress_standard(compressed, expected_length=uncompressed_length)
    else:
        codec = _CUSTOM_COMPRESSION_CODECS.get(compression_type)
        if codec is None:
            raise FirmwareMutationError(f"unsupported compression type {compression_type}")
        _, custom_decompress, _ = codec
        try:
            data = custom_decompress(compressed, uncompressed_length)
        except FirmwareParseError as exc:
            raise FirmwareMutationError(str(exc)) from exc
    return data, compression_type, uncompressed_length, header_length

def build_compression_section(
    data: bytes,
    *,
    compression_type: int,
    original_header_length: Optional[int] = None,
    original_section_bytes: Optional[bytes] = None,
) -> bytes:
    """
    For EFI_CUSTOM_COMPRESSION_LZMA (ee4e5898-3914-4259-9d6e-dc7bd79403cf),
    emit a GUID-DEFINED (0x02) section (PROCESSING_REQUIRED) using AMD's
    split-header layout: preamble=first 4 header bytes, body=rest.
    For EFI_CUSTOM_COMPRESSION_AMD_DEFLATE (ce3233f5-2cd6-4d87-9152-4a238bb6d1c4),
    emit a GUID-DEFINED (0x02) section with that GUID and a preamble containing
    the uncompressed length (4-byte LE), and the body as the compressed stream.
    Other compression types: standard EFI_SECTION_COMPRESSION (0x01).
    """
    if compression_type == EFI_CUSTOM_COMPRESSION_LZMA:
        alone = _lzma_alone_encode_known_size_cpython(
            bytes(data), lc=3, lp=0, pb=2, dict_size=1 << 24
        )
        # AMD split-header: DataOffset = 16+2+2+4 = 0x18
        preamble = alone[:4]        # props + dict[0:3] (e.g., 5D 00 00 00)
        body     = alone[4:]        # dict[3] + size[8] + payload
        return build_guid_defined_section(
            guid=EFI_GUIDED_SECTION_LZMA,
            attributes=EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
            preamble=preamble,
            body=body,
            prefer_extended=(original_header_length == 12),
        )

    if compression_type in (
        EFI_CUSTOM_COMPRESSION_AMD_DEFLATE,
        EFI_CUSTOM_COMPRESSION_AMD_DEFLATE1,
    ):
        # Build GUID_DEFINED section for AMD deflate-like GUID.
        # AMD ZLIB format has a specific structure:
        #   - Preamble: 4 bytes (zeros)
        #   - Body starts with padding area where compressed size is at offset +0x10
        #   - Then comes the actual zlib compressed stream
        # The DataOffset field will be 0x18 (24 bytes from GUID start).
        # Detect original FLEVEL (if original section provided) and map to a zlib level
        zlib_level: Optional[int] = None
        target_guid: Optional[UUID] = None
        orig_preamble: Optional[bytes] = None
        orig_body: Optional[bytes] = None
        orig_zoff: Optional[int] = None
        orig_size_off: Optional[int] = None
        if isinstance(original_section_bytes, (bytes, bytearray, memoryview)):
            try:
                # Detect FLEVEL from original
                flevel = _detect_amd_zlib_flevel_from_guid_section(bytes(original_section_bytes))
                if flevel is not None:
                    zlib_level = map_flevel_to_zlib_level(flevel)
            except Exception:
                # fall back silently
                zlib_level = None
            # Try to extract original preamble and analyze original layout
            try:
                sec = bytes(original_section_bytes)
                if len(sec) >= 4 and sec[3] == EFI_SECTION_GUID_DEFINED:
                    base_len = 4
                    total_len = int.from_bytes(sec[0:3] + b"\x00", "little")
                    if total_len == 0xFFFFFF and len(sec) >= 12:
                        base_len = 12
                        total_len = int.from_bytes(sec[4:12], "little")
                    off = base_len
                    if off + 20 <= len(sec):
                        orig_guid = _uuid_from_bytes_le(sec[off:off+16])
                        target_guid = orig_guid
                        data_offset = int.from_bytes(sec[off+16:off+18], "little")
                        pre_start = off + 20
                        pre_end = off + data_offset
                        if pre_start <= pre_end <= len(sec):
                            orig_preamble = sec[pre_start:pre_end]
                            body_start = pre_end
                            body_end = min(len(sec), base_len + total_len)
                            if body_start <= body_end:
                                orig_body = sec[body_start:body_end]
                                # Find original zlib header offset inside body
                                orig_zoff = _find_zlib_header_offset(orig_body)
                                # Guess original compressed size as trailing length
                                if orig_zoff is not None and orig_zoff >= 4:
                                    comp_len_old = len(orig_body) - orig_zoff
                                    pat = comp_len_old.to_bytes(4, "little")
                                    # search for the first occurrence before zlib
                                    window = orig_body[:orig_zoff]
                                    idx = window.find(pat)
                                    if idx != -1:
                                        orig_size_off = idx
            except Exception:
                pass

        compressed = compress_section_payload(
            data,
            compression_type=compression_type,
            zlib_level=zlib_level,
        )
        
        # Create preamble: prefer reusing original (to match vendor pattern), else 4 zeros
        if orig_preamble is not None and len(orig_preamble) == 4:
            preamble = orig_preamble
        else:
            preamble = b"\x00" * 4
        
        # Create padding area for body. If we learned the original offsets, mirror them.
        comp_size_field = len(compressed).to_bytes(4, "little")
        if orig_body is not None and orig_zoff is not None and orig_zoff >= 4:
            pre_zero_len = orig_size_off if (orig_size_off is not None and orig_size_off >= 0) else 0x10
            total_pad_len = orig_zoff
            post_zero_len = max(0, total_pad_len - (pre_zero_len + 4))
            body = (b"\x00" * pre_zero_len) + comp_size_field + (b"\x00" * post_zero_len) + compressed
        else:
            # Default vendor-like layout: size at +0x10 and zlib stream at +0x108
            padding_before_size = b"\x00" * 0x10
            padding_after_size = b"\x00" * (0xFC - 0x10 - 0x04)
            body = padding_before_size + comp_size_field + padding_after_size + compressed
        
        resolved_guid = target_guid
        if resolved_guid is None:
            resolved_guid = (
                EFI_GUIDED_SECTION_ZLIB_AMD2
                if compression_type == EFI_CUSTOM_COMPRESSION_AMD_DEFLATE1
                else EFI_GUIDED_SECTION_ZLIB_AMD
            )
        return build_guid_defined_section(
            guid=resolved_guid,
            attributes=EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
            preamble=preamble,
            body=body,
            prefer_extended=(original_header_length == 12),
        )

    # ---- Normal EFI compressed section (type 0x01) ----
    # (no detection needed here; standard compression ignores zlib level)

    # ---- Normal EFI compressed section (type 0x01) ----
    compressed = compress_section_payload(data, compression_type=compression_type)
    prefer_extended = bool(original_header_length == 12)
    base_header = 12 if prefer_extended else 4
    total_length = base_header + 6 + len(compressed)
    if not prefer_extended and total_length >= 0x1000000:
        base_header = 12

    header = bytearray(base_header + 6)
    if base_header == 4:
        header[:3] = _write_u24(total_length)
        header[3] = EFI_SECTION_COMPRESSION
        extra_offset = 4
    else:
        header[:3] = b"\xFF\xFF\xFF"
        header[3] = EFI_SECTION_COMPRESSION
        header[4:12] = int(total_length).to_bytes(8, "little")
        extra_offset = 12

    struct.pack_into("<H", header, extra_offset, compression_type)
    struct.pack_into("<I", header, extra_offset + 2, len(data))
    return bytes(header) + compressed

def build_guid_defined_section(
    *,
    guid: UUID,
    preamble: bytes,
    body: bytes,
    attributes: int = EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
    prefer_extended: bool = False,
) -> bytes:
    """
    Build a GUID_DEFINED (section type 0x02) section:
      [3B size][1B type=0x02][(optional 8B extended size)]
      [16B GUID][2B DataOffset][2B Attributes][preamble][body]

    DataOffset counts from the start of the GUID-defined header (the GUID),
    so DataOffset = 20 + len(preamble).

    If total size >= 0x1000000, the extended-Size header is used automatically.
    """
    preamble = bytes(preamble or b"")
    body = bytes(body or b"")
    # Bytes after the (4 or 12)-byte section header:
    # 16(GUID) + 2(Off) + 2(Attr) + len(preamble) + len(body)
    gd_payload_len = 16 + 2 + 2 + len(preamble) + len(body)

    # Base section header length: 4 or 12 (extended)
    base_hdr_len = 12 if prefer_extended else 4
    total_len = base_hdr_len + gd_payload_len
    if base_hdr_len == 4 and total_len >= 0x1000000:
        base_hdr_len = 12
        total_len = base_hdr_len + gd_payload_len

    hdr = bytearray(base_hdr_len)
    if base_hdr_len == 4:
        # 3-byte size + type
        hdr[:3] = int(total_len).to_bytes(3, "little")
        hdr[3] = EFI_SECTION_GUID_DEFINED
    else:
        # extended size header
        hdr[:3] = b"\xFF\xFF\xFF"
        hdr[3] = EFI_SECTION_GUID_DEFINED
        hdr[4:12] = int(total_len).to_bytes(8, "little")

    # GUID-defined header (immediately follows the base section header)
    gd = bytearray(16 + 2 + 2)
    gd[:16] = guid.bytes_le
    data_offset = 20 + len(preamble)  # from start of GUID-defined header
    gd[16:18] = int(data_offset).to_bytes(2, "little")
    gd[18:20] = int(attributes).to_bytes(2, "little")

    return bytes(hdr) + bytes(gd) + preamble + body


def _detect_amd_zlib_flevel_from_guid_section(section_bytes: bytes) -> Optional[int]:
    """
    Given a GUID_DEFINED section blob, attempt to extract the body and detect
    the zlib FLEVEL (0..3) by scanning for the zlib header.
    Returns None if detection fails.
    """
    if len(section_bytes) < 4:
        return None
    size_u24 = int.from_bytes(section_bytes[0:3] + b"\x00", "little")
    stype = section_bytes[3]
    base_hdr_len = 4
    total_len = size_u24
    if size_u24 == 0xFFFFFF:
        if len(section_bytes) < 12:
            return None
        total_len = int.from_bytes(section_bytes[4:12], "little")
        base_hdr_len = 12
    if stype != EFI_SECTION_GUID_DEFINED:
        return None
    if base_hdr_len + 20 > len(section_bytes):
        return None
    off = base_hdr_len
    data_offset = int.from_bytes(section_bytes[off+16:off+18], "little")
    preamble_end = off + data_offset
    if preamble_end > len(section_bytes):
        return None
    body = section_bytes[preamble_end: total_len if total_len <= len(section_bytes) else len(section_bytes)]
    return detect_zlib_flevel_from_data(body)


def _find_zlib_header_offset(data: bytes) -> Optional[int]:
    """
    Locate the first valid zlib header (CM=8 and (CMF<<8|FLG)%31==0) in data.
    Returns the byte offset or None if not found within a reasonable scan window.
    """
    if not data:
        return None
    scan = min(len(data), 0x800)
    for i in range(0, max(0, scan - 2)):
        cmf = data[i]
        flg = data[i + 1]
        if (cmf & 0x0F) == 8 and (((cmf << 8) | flg) % 31) == 0:
            return i
    return None


def rebuild_amd_zlib_section_matching(
    original_section_bytes: bytes,
    data: bytes,
    *,
    original_header_length: Optional[int] = None,
) -> bytes:
    """
    Convenience API: Rebuild an AMD ZLIB GUID_DEFINED section for 'data',
    matching the original section's compression rate (zlib FLEVEL) and
    preserving the original header size (4 or 12 bytes) when possible.

    - original_section_bytes: existing GUID_DEFINED section with AMD ZLIB GUID
    - data: uncompressed payload to encode
    - original_header_length: override for base header size (4 or 12); if None,
      derive from the original_section_bytes
    """
    # Determine extended or normal base header by parsing original
    prefer_ext = False
    if original_header_length in (4, 12):
        prefer_ext = (original_header_length == 12)
    else:
        if len(original_section_bytes) >= 4:
            sz = int.from_bytes(original_section_bytes[0:3] + b"\x00", "little")
            prefer_ext = (sz == 0xFFFFFF)

    return build_compression_section(
        data,
        compression_type=EFI_CUSTOM_COMPRESSION_AMD_DEFLATE,
        original_header_length=(12 if prefer_ext else 4),
        original_section_bytes=original_section_bytes,
    )


def rebuild_guid_defined_section_from_existing(
    section_bytes: bytes,
    *,
    new_preamble: bytes | None = None,
    new_body: bytes | None = None,
    match_amd_zlib_rate: bool = True,
) -> bytes:
    """
    Rebuild a GUID_DEFINED section by parsing the existing one and replacing
    preamble/body while preserving GUID and Attributes.

    Accepts either 4-byte or extended (12-byte) section headers.
    """
    if len(section_bytes) < 4:
        raise FirmwareMutationError("GUID_DEFINED section too small")

    # Parse base section header (4 or 12 bytes)
    size_u24 = int.from_bytes(section_bytes[0:3] + b"\x00", "little")
    stype = section_bytes[3]
    if stype != EFI_SECTION_GUID_DEFINED:
        raise FirmwareMutationError("not a GUID_DEFINED section")
    base_hdr_len = 4
    total_len = size_u24
    if size_u24 == 0xFFFFFF:
        if len(section_bytes) < 12:
            raise FirmwareMutationError("extended GUID_DEFINED header truncated")
        total_len = int.from_bytes(section_bytes[4:12], "little")
        base_hdr_len = 12
    if total_len > len(section_bytes):
        total_len = len(section_bytes)  # tolerate truncation

    # GUID-defined header starts after base header
    off = base_hdr_len
    if off + 20 > len(section_bytes):
        raise FirmwareMutationError("GUID_DEFINED header truncated")

    guid = UUID(bytes_le=bytes(section_bytes[off:off+16]))
    data_offset = int.from_bytes(section_bytes[off+16:off+18], "little")
    attributes = int.from_bytes(section_bytes[off+18:off+20], "little")

    # Compute current preamble/body splits
    preamble_start = off + 20
    preamble_end = off + data_offset
    if preamble_end < preamble_start or preamble_end > len(section_bytes):
        raise FirmwareMutationError("invalid DataOffset in GUID_DEFINED header")

    old_preamble = section_bytes[preamble_start:preamble_end]
    old_body = section_bytes[preamble_end: base_hdr_len + total_len]

    preamble_bytes = old_preamble if new_preamble is None else bytes(new_preamble)
    body_bytes = old_body if new_body is None else bytes(new_body)

    # If caller provided a new (uncompressed) body for AMD ZLIB or AMD ZLIB2, rebuild the
    # entire GUID_DEFINED via build_compression_section to preserve the
    # original compression rate (FLEVEL) when possible.
    amd_zlib_guids = {EFI_GUIDED_SECTION_ZLIB_AMD, EFI_GUIDED_SECTION_ZLIB_AMD2}
    if match_amd_zlib_rate and guid in amd_zlib_guids and new_body is not None:
        # Here 'body_bytes' is expected to be the uncompressed payload.
        # Rebuild using AMD ZLIB packer that can detect original FLEVEL.
        rebuilt = build_compression_section(
            body_bytes,
            compression_type=EFI_CUSTOM_COMPRESSION_AMD_DEFLATE,
            original_header_length=(12 if base_hdr_len == 12 else 4),
            original_section_bytes=section_bytes,
        )
        return rebuilt

    return build_guid_defined_section(
        guid=guid,
        preamble=preamble_bytes,
        body=body_bytes,
        attributes=attributes,
        prefer_extended=(base_hdr_len == 12),
    )



def repair_fv_bytes(fv_bytes: bytes) -> bytes:
    """
    Rebuild an inner FV blob:
      - Parse FV
      - For each FFS file, if it contains AMD LZMA GUID_DEFINED (split header),
        decompress to get inner FV, recursively repair it, then recompress
        with explicit 13-byte LZMA-Alone header (no 0xFF) and rebuild section.
      - Rebuild each FFS file with corrected header/file checksums.
      - Reassemble FV body and fix FV header checksum.
    Returns the rebuilt FV bytes (same total FV length as input).
    """
    view = memoryview(fv_bytes)
    info = _parse_firmware_volume_view(view, None, log_callback=None)
    if info is None:
        raise FirmwareMutationError("repair_fv_bytes: not a valid FV")
    header = bytearray(view[:info.header_length])
    assembled = bytearray()
    for f in info.files:
        # Extract file body (sections only)
        body = bytes(view[f.relative_offset + f.header_length : f.relative_offset + f.size])
        # Rebuild sections
        rebuilt_sections = bytearray()
        for s in f.sections:
            rel = s.relative_offset - (f.relative_offset + f.header_length)
            raw = body[rel: rel + s.size]
            if s.type == EFI_SECTION_GUID_DEFINED and s.guid == EFI_GUIDED_SECTION_LZMA:
                # parse GUID_DEFINED payload
                if len(raw) < 4 + 20:
                    raise FirmwareMutationError("GUID_DEFINED too small")
                hdr_len = 4
                sz = _read_u24(raw[:3])
                if sz == 0xFFFFFF:
                    hdr_len = 12
                    sz = struct.unpack_from("<Q", raw, 4)[0]
                fixed = raw[hdr_len:hdr_len+20]
                data_off, attrs = struct.unpack_from("<HH", fixed, 16)
                preamble = raw[hdr_len+20 : hdr_len+data_off]
                body_stream = raw[hdr_len+data_off : sz]
                # Repair split header and decompress
                if len(preamble) == 4 and len(body_stream) >= 10:
                    hdr13 = bytes([preamble[0]]) + preamble[1:4] + body_stream[0:1] + body_stream[1:9]
                    payload = body_stream[9:]
                    inner = lzma.decompress(hdr13 + payload, format=lzma.FORMAT_ALONE)
                else:
                    # fallback
                    inner = _decompress_guid_defined(EFI_GUIDED_SECTION_LZMA, preamble, body_stream) or b""
                # If the inner blob is itself an FV, repair it recursively
                if b"_FVH" in inner:
                    inner = repair_fv_bytes(inner)
                # Recompress with explicit size header; rebuild GUID_DEFINED
                alone = _lzma_alone_encode(inner, lc=3, lp=0, pb=2, dict_size=1<<24)
                new_preamble = alone[:4]
                new_body = alone[4:]
                raw = build_guid_defined_section(
                    guid=EFI_GUIDED_SECTION_LZMA,
                    attributes=EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
                    preamble=new_preamble,
                    body=new_body,
                    prefer_extended=(hdr_len == 12),
                )
            rebuilt_sections += raw
            pad_to = _align(len(rebuilt_sections), ALIGN_SEC)
            if pad_to > len(rebuilt_sections):
                rebuilt_sections += bytes([FF_FILL]) * (pad_to - len(rebuilt_sections))
        # Build new FFS file from rebuilt sections
        new_file = build_ffs_file(
            rebuilt_sections,
            guid=f.guid,
            file_type=f.type,
            attributes=f.attributes,
            state=f.state,
        )
        assembled += _pad_file_bytes(new_file)
    # Reassemble FV: keep header, replace data region; fix checksum
    total_len = info.size
    if info.header_length + len(assembled) > total_len:
        raise FirmwareMutationError("repair_fv_bytes: rebuilt data exceeds FV size")
    # Pad to original FV data length
    assembled += bytes([FF_FILL]) * (total_len - info.header_length - len(assembled))
    # Fix FV header checksum
    fv_hdr = bytearray(header)
    # zero checksum field then compute 16-bit sum
    struct.pack_into("<H", fv_hdr, 0x32, 0)
    if len(fv_hdr) % 2:
        fv_hdr.append(0)
    words = struct.unpack("<" + "H"*(len(fv_hdr)//2), fv_hdr)
    need = (-sum(words)) & 0xFFFF
    struct.pack_into("<H", fv_hdr, 0x32, need)
    return bytes(fv_hdr) + bytes(assembled)




def _parse_ffs_file(
    view: memoryview,
    cursor: int,
    volume_end: int,
    base_offset: Optional[int],
    *,
    log_callback=None,
) -> Optional[FirmwareFileInfo]:
    if cursor + 24 > volume_end:
        return None
    header = view[cursor : cursor + 24]
    if _all_erased(header):
        return None
    guid = _uuid_from_bytes_le(bytes(header[:16]))
    _ = struct.unpack_from("<H", header, 16)[0]  # checksum (unused here)
    file_type = header[18]
    attributes = header[19]
    size = _read_u24(bytes(header[20:23]))
    state = header[23]
    header_len = 24
    if size == 0xFFFFFF:
        if cursor + 32 > volume_end:
            return None
        size = struct.unpack_from("<Q", view, cursor + 24)[0]
        header_len = 32
    if size < header_len or cursor + size > volume_end:
        return None
    abs_off = (base_offset + cursor) if base_offset is not None else None
    sections_data = view[cursor + header_len : cursor + size]
    raw_blob: Optional[bytes] = None
    if base_offset is None:
        try:
            raw_blob = bytes(view[cursor:cursor + size])
        except Exception:
            raw_blob = None
    sections = _parse_sections(
        sections_data,
        (base_offset + cursor + header_len) if base_offset is not None else None,
        relative_base=cursor + header_len,
        log_callback=log_callback,
    )
    
    # Detect special file types for display name
    display_name: Optional[str] = None
    
    # Check for Startup AP data padding file (PAD file with all-FF GUID)
    if file_type == 0xF0 and guid == PAD_FILE_GUID:
        # Get the file payload (data after header)
        file_payload = view[cursor + header_len : cursor + size]
        if _detect_startup_ap_data(file_payload):
            display_name = "Startup AP data padding file"
    
    return FirmwareFileInfo(
        absolute_offset=abs_off,
        relative_offset=cursor,
        size=size,
        header_length=header_len,
        type=file_type,
        type_name=FFS_TYPE_NAMES.get(file_type, f"0x{file_type:02X}"),
        attributes=attributes,
        state=state ^ 0xFF,
        guid=guid,
        raw_data=raw_blob,
        sections=sections,
        display_name=display_name,
    )


def _parse_firmware_volume_view(
    view: memoryview, base_offset: Optional[int], *, log_callback=None
) -> Optional[FirmwareVolumeInfo]:
    if len(view) < 0x38:
        return None
    try:
        zero_vec, fs_guid_bytes, fv_length, signature, attributes, header_len, checksum, ext_hdr_off, reserved, revision = struct.unpack_from(
            "<16s16sQ4sIHHHBB", view, 0
        )
    except struct.error:
        return None
    if signature != FVH_SIGNATURE:
        return None
    filesystem_guid = UUID(bytes_le=bytes(fs_guid_bytes))
    fv_name_guid: Optional[UUID] = None
    try:
        ext_off = int(ext_hdr_off)
    except Exception:
        ext_off = 0
    if ext_off and 0 <= ext_off < len(view):
        if ext_off + 0x14 <= len(view):
            try:
                fv_name_guid = _uuid_from_bytes_le(bytes(view[ext_off : ext_off + 16]))
            except Exception:
                fv_name_guid = None
    blocks = _parse_block_map(header_len, view)
    fv_size = min(len(view), int(fv_length))
    raw_blob: Optional[bytes] = None
    if base_offset is None:
        try:
            raw_blob = bytes(view[:fv_size])
        except Exception:
            raw_blob = None
    data_start = header_len
    if data_start > fv_size:
        return None
    files: List[FirmwareFileInfo] = []
    used = 0
    cursor = data_start
    while cursor + 24 <= fv_size:
        file_info = _parse_ffs_file(
            view, cursor, fv_size, base_offset, log_callback=log_callback
        )
        if file_info is None:
            break
        files.append(file_info)
        used += _align(file_info.size, ALIGN_FILE)
        cursor += _align(file_info.size, ALIGN_FILE)
    data_region = max(0, fv_size - data_start)
    used = min(used, data_region)
    free = max(0, data_region - used)
    return FirmwareVolumeInfo(
        absolute_offset=base_offset,
        relative_offset=0,
        size=fv_size,
        header_length=header_len,
        attributes=attributes,
        revision=revision,
        checksum=checksum,
        filesystem_guid=filesystem_guid,
        raw_data=raw_blob,
        fv_name=fv_name_guid,
        blocks=blocks,
        files=files,
        used_size=used,
        free_size=free,
    )


def parse_firmware_volume_at(buf: bytes, offset: int, *, limit: Optional[int] = None, log_callback=None) -> Optional[FirmwareVolumeInfo]:
    upper = len(buf) if limit is None else min(len(buf), limit)
    if offset < 0 or offset >= upper:
        return None
    view = memoryview(buf)[offset:upper]
    info = _parse_firmware_volume_view(view, offset, log_callback=log_callback)
    if info:
        info.relative_offset = 0
    return info


def parse_firmware_volume_bytes(
    data: bytes, base_offset: Optional[int], log_callback=None
) -> List[FirmwareVolumeInfo]:
    logger = get_logger()
    view = memoryview(data)
    volumes: List[FirmwareVolumeInfo] = []
    search = 0
    data_len = len(data)
    while True:
        pos = data.find(FVH_SIGNATURE, search)
        if pos == -1:
            break
        header_start = pos - 0x28
        if header_start < 0:
            search = pos + 1
            continue
        # Ensure we have enough room for a minimal FV header (0x38 bytes)
        if header_start + 0x38 > data_len:
            search = pos + 1
            continue

        sub_view = view[header_start:]
        info = _parse_firmware_volume_view(
            sub_view,
            None if base_offset is None else base_offset + header_start,
            log_callback=log_callback,
        )
        if info is None:
            search = pos + 1
            continue

        info.relative_offset = header_start
        abs_off = (
            (base_offset + header_start)
            if base_offset is not None
            else header_start
        )
        logger.info(
            f"UEFI volume @ 0x{abs_off:08X}: {info.size:,} bytes, {len(info.files)} files"
        )
        # Log unaligned firmware volumes but still include them
        try:
            if header_start % ALIGN_FILE != 0:
                message = (
                    f"Unaligned volume at 0x{abs_off:08X} (relative 0x{header_start:X})"
                )
                logger.info(message)
        except Exception:
            pass
        volumes.append(info)

        span = max(info.size, 4)
        if span <= 0:
            # Prevent infinite loops on malformed headers by advancing minimally
            span = max(pos + 1 - header_start, 4)
        search = header_start + span
    return volumes


def scan_firmware_volumes(
    buf: bytes, offset: int, size: int, *, log_callback=None
) -> List[FirmwareVolumeInfo]:
    limit = min(len(buf), offset + max(size, 0))
    data = buf[offset:limit]
    volumes = parse_firmware_volume_bytes(data, offset, log_callback)
    for volume in volumes:
        volume.absolute_offset = (offset + volume.relative_offset) if volume.absolute_offset is None else volume.absolute_offset
    return volumes


def build_ffs_file(
    payload: bytes | bytearray | memoryview,
    *,
    guid: UUID,
    file_type: int,
    attributes: int = 0,
    state: int = 0x07,
) -> bytes:
    """Construct raw FFS file bytes (header + payload, without padding)."""
    return _build_ffs_file_bytes(
        guid=guid,
        file_type=file_type,
        attributes=attributes,
        state=state,
        payload=bytes(payload),
    )


def insert_ffs_file(
    buf: bytearray,
    volume: FirmwareVolumeInfo,
    index: int,
    payload: bytes | bytearray | memoryview,
    *,
    guid: UUID,
    file_type: int,
    attributes: int = 0,
    state: int = 0x07,
) -> FirmwareVolumeInfo:
    """Insert a new FFS file into a firmware volume."""
    if not isinstance(buf, bytearray):
        raise TypeError("buffer must be a bytearray to allow in-place mutation")
    if index < 0 or index > len(volume.files):
        raise FirmwareMutationError("insertion index out of range")
    payload_bytes = bytes(payload)
    file_bytes = build_ffs_file(
        payload_bytes,
        guid=guid,
        file_type=file_type,
        attributes=attributes,
        state=state,
    )
    storage = _pad_file_bytes(file_bytes)

    attempts = 0
    compacted = False
    tail_region: bytearray | memoryview
    while True:
        start, data = _extract_volume_data(buf, volume)
        original_length = len(data)
        tail_start = _tail_start(volume)
        tail_region = data[tail_start:]
        if len(storage) <= len(tail_region):
            break
        pad_entry = _find_resizable_pad(volume, data)
        if pad_entry is None:
            if not compacted:
                volume = _compact_volume(volume, buf)
                compacted = True
                continue
            break
        pad_index, _pad_info, _pad_content, _pad_tail = pad_entry
        needed = len(storage) - len(tail_region)
        volume, freed = _shrink_pad_file(buf, volume, pad_index, needed)
        if freed > 0:
            volume = _compact_volume(volume, buf)
            compacted = True
            attempts += 1
            continue
        if pad_index < index:
            index = max(index - 1, 0)
        try:
            volume = remove_ffs_file(buf, volume, pad_index)
        except FirmwareMutationError:
            break
        attempts += 1
        if attempts > len(volume.files) + 4:
            break

    start, data = _extract_volume_data(buf, volume)
    original_length = len(data)
    tail_start = _tail_start(volume)
    tail_region = data[tail_start:]
    if len(storage) > len(tail_region):
        pad_entry = _find_resizable_pad(volume, data)
        if pad_entry is not None:
            pad_index, _pad_info, _pad_content, _pad_tail = pad_entry
            needed = len(storage) - len(tail_region)
            volume, freed = _shrink_pad_file(buf, volume, pad_index, needed)
            if freed > 0:
                volume = _compact_volume(volume, buf)
                compacted = True
                start, data = _extract_volume_data(buf, volume)
                original_length = len(data)
                tail_start = _tail_start(volume)
                tail_region = data[tail_start:]
        if len(storage) > len(tail_region) and not compacted:
            volume = _compact_volume(volume, buf)
            compacted = True
            start, data = _extract_volume_data(buf, volume)
            original_length = len(data)
            tail_start = _tail_start(volume)
            tail_region = data[tail_start:]
        if len(storage) > len(tail_region):
            pad_entry = _find_resizable_pad(volume, data)
            if pad_entry is not None:
                pad_index, _pad_info, _pad_content, _pad_tail = pad_entry
                if pad_index < index:
                    index = max(index - 1, 0)
                try:
                    volume = remove_ffs_file(buf, volume, pad_index)
                except FirmwareMutationError:
                    pass
                start, data = _extract_volume_data(buf, volume)
                original_length = len(data)
                tail_start = _tail_start(volume)
                tail_region = data[tail_start:]
        if len(storage) > len(tail_region):
            needed = len(storage)
            available = len(tail_region)
            shortage = needed - available
            raise FirmwareMutationError(
                f"not enough free space for insertion: need 0x{needed:X} bytes, "
                f"available 0x{available:X} bytes (short by 0x{shortage:X} bytes)"
            )
    if len(storage):
        tail_view = memoryview(tail_region)[-len(storage) :]
        if not _is_uniform_erased(tail_view)[0]:
            raise FirmwareMutationError(
                f"trailing space (0x{len(tail_region):X} bytes) is not erased; cannot insert file"
            )
    
    index = max(0, min(index, len(volume.files)))
    insert_offset = tail_start
    if index < len(volume.files):
        insert_offset = int(volume.files[index].relative_offset)
    insert_offset = _align(insert_offset, ALIGN_FILE)
    data[insert_offset:insert_offset] = storage
    del data[-len(storage):]
    if len(data) != original_length:
        raise FirmwareMutationError("volume size changed during insertion")
    _commit_volume_data(buf, start, data)
    refreshed = _reparse_volume(buf, start, original_length, log_callback=None)
    return _refresh_volume(volume, refreshed)


def replace_ffs_file(
    buf: bytearray,
    volume: FirmwareVolumeInfo,
    index: int,
    payload: bytes | bytearray | memoryview,
    *,
    guid: UUID | None = None,
    file_type: int | None = None,
    attributes: int | None = None,
    state: int | None = None,
) -> FirmwareVolumeInfo:
    """Replace an existing FFS file with a new payload."""
    if not isinstance(buf, bytearray):
        raise TypeError("buffer must be a bytearray to allow in-place mutation")
    if index < 0 or index >= len(volume.files):
        raise FirmwareMutationError("file index out of range")
    payload_bytes = bytes(payload)
    file_info = volume.files[index]
    if file_info.guid is None and guid is None:
        raise FirmwareMutationError("cannot determine GUID for replacement file")
    file_guid = guid or file_info.guid
    new_file_type = file_type if file_type is not None else file_info.type
    new_attributes = attributes if attributes is not None else file_info.attributes
    new_state = state if state is not None else file_info.state
    file_bytes = build_ffs_file(
        payload_bytes,
        guid=file_guid,
        file_type=new_file_type,
        attributes=new_attributes,
        state=new_state,
    )
    storage = _pad_file_bytes(file_bytes)

    attempts = 0
    compacted = False
    while True:
        start, data = _extract_volume_data(buf, volume)
        original_length = len(data)
        tail_start = _tail_start(volume)
        tail_region = data[tail_start:]
        if not volume.files:
            raise FirmwareMutationError("firmware volume contains no files")
        if index >= len(volume.files):
            raise FirmwareMutationError("file index out of range")
        file_info = volume.files[index]
        old_span = _align(file_info.size, ALIGN_FILE)
        new_span = len(storage)
        diff = new_span - old_span
        needs_space = diff > 0 and diff > len(tail_region)
        tail_dirty = False
        if diff > 0 and diff <= len(tail_region):
            tail_slice = memoryview(tail_region)[-diff:]
            tail_dirty = not _is_uniform_erased(tail_slice)[0]
        if not needs_space and not tail_dirty:
            break
        pad_entry = _find_resizable_pad(volume, data)
        if pad_entry is None:
            if not compacted:
                volume = _compact_volume(volume, buf)
                compacted = True
                continue
            break
        pad_index, _pad_info, _pad_content, _pad_tail = pad_entry
        if pad_index == index:
            break
        if pad_index < index:
            index = max(index - 1, 0)
        shrink_need = 0
        if needs_space:
            shrink_need = diff - len(tail_region)
        elif tail_dirty:
            shrink_need = diff
        if shrink_need > 0:
            volume, freed = _shrink_pad_file(buf, volume, pad_index, shrink_need)
            if freed > 0:
                volume = _compact_volume(volume, buf)
                compacted = True
                attempts += 1
                continue
        try:
            volume = remove_ffs_file(buf, volume, pad_index)
        except FirmwareMutationError:
            break
        attempts += 1
        if attempts > len(volume.files) + 4:
            break

    start, data = _extract_volume_data(buf, volume)
    original_length = len(data)
    tail_start = _tail_start(volume)
    tail_region = data[tail_start:]
    if not volume.files:
        raise FirmwareMutationError("firmware volume contains no files")
    index = max(0, min(index, len(volume.files) - 1))
    file_info = volume.files[index]
    old_span = _align(file_info.size, ALIGN_FILE)
    new_span = len(storage)
    diff = new_span - old_span
    if diff > 0:
        if diff > len(tail_region):
            pad_entry = _find_resizable_pad(volume, data)
            if pad_entry is not None:
                pad_index, _pad_info, _pad_content, _pad_tail = pad_entry
                if pad_index != index:
                    shrink_need = diff - len(tail_region)
                    volume, freed = _shrink_pad_file(buf, volume, pad_index, shrink_need)
                    if freed > 0:
                        volume = _compact_volume(volume, buf)
                        compacted = True
                        start, data = _extract_volume_data(buf, volume)
                        original_length = len(data)
                        tail_start = _tail_start(volume)
                        tail_region = data[tail_start:]
                        file_info = volume.files[index]
                        old_span = _align(file_info.size, ALIGN_FILE)
                        diff = len(storage) - old_span
        if diff > len(tail_region) and not compacted:
            volume = _compact_volume(volume, buf)
            compacted = True
            start, data = _extract_volume_data(buf, volume)
            original_length = len(data)
            tail_start = _tail_start(volume)
            tail_region = data[tail_start:]
            file_info = volume.files[index]
            old_span = _align(file_info.size, ALIGN_FILE)
            diff = len(storage) - old_span
        if diff > len(tail_region):
            pad_entry = _find_resizable_pad(volume, data)
            if pad_entry is not None:
                pad_index, _pad_info, _pad_content, _pad_tail = pad_entry
                if pad_index != index and pad_index < len(volume.files):
                    if pad_index < index:
                        index = max(index - 1, 0)
                    try:
                        volume = remove_ffs_file(buf, volume, pad_index)
                    except FirmwareMutationError:
                        pass
                    start, data = _extract_volume_data(buf, volume)
                    original_length = len(data)
                    tail_start = _tail_start(volume)
                    tail_region = data[tail_start:]
                    file_info = volume.files[index]
                    old_span = _align(file_info.size, ALIGN_FILE)
                    diff = len(storage) - old_span
        if diff > len(tail_region):
            needed = diff
            available = len(tail_region)
            shortage = needed - available
            raise FirmwareMutationError(
                f"not enough free space for replacement: need 0x{needed:X} extra bytes, "
                f"available 0x{available:X} bytes (short by 0x{shortage:X} bytes)"
            )
        if diff:
            tail_slice = memoryview(tail_region)[-diff:]
            if not _is_uniform_erased(tail_slice)[0]:
                pad_entry = _find_resizable_pad(volume, data)
                if pad_entry is not None:
                    pad_index, _pad_info, _pad_content, _pad_tail = pad_entry
                    if pad_index != index:
                        volume, freed = _shrink_pad_file(buf, volume, pad_index, diff)
                        if freed > 0:
                            volume = _compact_volume(volume, buf)
                            compacted = True
                            start, data = _extract_volume_data(buf, volume)
                            original_length = len(data)
                            tail_start = _tail_start(volume)
                            tail_region = data[tail_start:]
                            file_info = volume.files[index]
                            old_span = _align(file_info.size, ALIGN_FILE)
                            diff = len(storage) - old_span
        if diff:
            tail_slice = memoryview(tail_region)[-diff:]
            if not _is_uniform_erased(tail_slice)[0]:
                raise FirmwareMutationError(
                    f"trailing space (0x{len(tail_region):X} bytes) is not erased; "
                    f"cannot resize file by 0x{diff:X} bytes"
                )

    rel_start = _align(int(file_info.relative_offset), ALIGN_FILE)
    rel_end = rel_start + old_span
    data[rel_start:rel_end] = storage
    if diff > 0:
        del data[-diff:]
    elif diff < 0:
        data.extend(bytes([FF_FILL]) * (-diff))
    if len(data) != original_length:
        raise FirmwareMutationError("volume size changed during replacement")
    _commit_volume_data(buf, start, data)
    refreshed = _reparse_volume(buf, start, original_length, log_callback=None)
    return _refresh_volume(volume, refreshed)


def remove_ffs_file(
    buf: bytearray,
    volume: FirmwareVolumeInfo,
    index: int,
) -> FirmwareVolumeInfo:
    """Remove an FFS file from a firmware volume."""
    if not isinstance(buf, bytearray):
        raise TypeError("buffer must be a bytearray to allow in-place mutation")
    if index < 0 or index >= len(volume.files):
        raise FirmwareMutationError("file index out of range")
    file_info = volume.files[index]
    start, data = _extract_volume_data(buf, volume)
    original_length = len(data)
    rel_start = _align(int(file_info.relative_offset), ALIGN_FILE)
    span = _align(file_info.size, ALIGN_FILE)
    del data[rel_start : rel_start + span]
    data.extend(bytes([FF_FILL]) * span)
    if len(data) != original_length:
        raise FirmwareMutationError("volume size changed during removal")
    _commit_volume_data(buf, start, data)
    refreshed = _reparse_volume(buf, start, original_length, log_callback=None)
    return _refresh_volume(volume, refreshed)


def parse_ffs_file_bytes(data: bytes | bytearray | memoryview) -> FirmwareFileInfo:
    """Parse an FFS file blob into metadata and nested sections."""
    view = memoryview(data)
    info = _parse_ffs_file(view, 0, len(view), 0)
    if info is None:
        raise FirmwareParseError("invalid FFS file data")
    return info
