# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
UEFI capsule decapsulation utilities.

This module provides:
    - Capsule header parsing (EFI, EFI2, UEFI formats)
    - Capsule detection and extraction
    - IFLASH BIOS image extraction
"""

import ctypes
import struct
from typing import Optional, Tuple, Dict

from ..utils.debug_logger import get_logger


# GUID Constants


EFI_CAPSULE_GUID  = bytes.fromhex("BD86663B760D3040B70EB5519E2FC5A0")  # 3B6686BD-0D76-4030-B70E-B5519E2FC5A0
EFI2_CAPSULE_GUID = bytes.fromhex("8BA63C4A2377FB48803D578CC1FEC44D")  # 4A3CA68B-7723-48FB-803D-578CC1FEC44D
UEFI_CAPSULE_GUID = bytes.fromhex("B9829153B5AB9143B69AE3A943F72FCC")  # 539182B9-ABB5-4391-B69A-E3A943F72FCC

IFLASH_BIOS_SIGNATURE = b"$_IFLASH_BIOSIMG"
IFLASH_HEADER_LEN = 16 + 4 + 4  # signature + FullSize + UsedSize


# ctypes Structure Definitions


uint8_t  = ctypes.c_ubyte
uint32_t = ctypes.c_uint
uint16_t = ctypes.c_ushort

class EfiCapsuleHeader(ctypes.LittleEndianStructure):
    """EFI Capsule Header structure (original format)."""

    _fields_ = [
        ("CapsuleGuid",                 uint8_t*16),
        ("HeaderSize",                  uint32_t),
        ("Flags",                       uint32_t),
        ("CapsuleImageSize",            uint32_t),
        ("SequenceNumber",              uint32_t),
        ("InstanceId",                  uint8_t*16),
        ("OffsetToSplitInformation",    uint32_t),
        ("OffsetToCapsuleBody",         uint32_t),
        ("OffsetToOemDefinedHeader",    uint32_t),
        ("OffsetToAuthorInformation",   uint32_t),
        ("OffsetToRevisionInformation", uint32_t),
        ("OffsetToShortDescription",    uint32_t),
        ("OffsetToLongDescription",     uint32_t),
        ("OffsetToApplicableDevices",   uint32_t),
    ]

class Efi2CapsuleHeader(ctypes.LittleEndianStructure):
    """EFI2 Capsule Header structure (Aptio format)."""

    _fields_ = [
        ("CapsuleGuid",                 uint8_t*16),
        ("HeaderSize",                  uint32_t),
        ("Flags",                       uint32_t),
        ("CapsuleImageSize",            uint32_t),
        ("FwImageOffset",               uint16_t),
        ("OemHdrOffset",                uint16_t),
    ]

class UefiCapsuleHeader(ctypes.LittleEndianStructure):
    """UEFI Capsule Header structure (standard format)."""

    _fields_ = [
        ("CapsuleGuid",                 uint8_t*16),
        ("HeaderSize",                  uint32_t),
        ("Flags",                       uint32_t),
        ("CapsuleImageSize",            uint32_t),
    ]

def _get_struct(buf: bytes, off: int, ty):
    s = ty()
    slen = ctypes.sizeof(s)
    chunk = buf[off: off + slen]
    if len(chunk) < slen:
        raise ValueError("Buffer too small to parse header")
    ctypes.memmove(ctypes.addressof(s), chunk, slen)
    return s

def is_capsule_bytes(buf: bytes, offset: int = 0) -> bool:
    """Check if the buffer contains a capsule header at the given offset."""
    if len(buf) < offset + 16:
        return False
    g = buf[offset:offset+16]
    return g in (EFI_CAPSULE_GUID, EFI2_CAPSULE_GUID, UEFI_CAPSULE_GUID)

def _check_fv(fvdata: bytes) -> bool:
    if len(fvdata) < 0x38:
        return False
    # UEFI FV header: 16s 16s Q 4s L H H 3x B
    try:
        (_zero, _fstype, _lenq, fvsig, _attr, _hdrlen, _chksum, _rev) = struct.unpack(
            "<16s16sQ4sLHHxBx", fvdata[0:0x38]
        )
    except struct.error:
        # The format above is strict; fallback to original-friendly format
        try:
            (_zero, _fstype, _lenq, fvsig, _attr, _hdrlen, _chksum, _rev) = struct.unpack(
                "< 16s 16s Q 4s L H H 3x B", fvdata[0:0x38]
            )
        except struct.error:
            return False
    return fvsig == b"_FVH"


def _extract_iflash_bios_image(buf: bytes) -> Optional[Tuple[bytes, Dict[str, int]]]:
    best: Optional[Tuple[int, int, int, int]] = None  # used_size, full_size, offset, payload_start
    search = 0
    length = len(buf)
    while True:
        idx = buf.find(IFLASH_BIOS_SIGNATURE, search)
        if idx == -1:
            break
        search = idx + 1
        if idx + IFLASH_HEADER_LEN > length:
            continue
        full_size, used_size = struct.unpack_from("<II", buf, idx + 16)
        if used_size == 0 or used_size > full_size:
            continue
        payload_start = idx + IFLASH_HEADER_LEN
        payload_end = payload_start + used_size
        if payload_end > length:
            continue
        if best is None or used_size > best[0]:
            best = (used_size, full_size, idx, payload_start)
    if best is None:
        return None
    used_size, full_size, offset, payload_start = best
    payload = bytes(buf[payload_start:payload_start + used_size])
    return payload, {"offset": offset, "used_size": used_size, "full_size": full_size}

def decapsule_bytes(buf: bytes, offset: int = 0) -> Optional[bytes]:
    if not is_capsule_bytes(buf, offset):
        return None

    g = buf[offset:offset+16]

    if g == EFI_CAPSULE_GUID:
        # Older capsule with extended header fields
        hdr = _get_struct(buf, offset, EfiCapsuleHeader)
        end = offset + (hdr.CapsuleImageSize or 0)
        if end <= offset or end > len(buf):
            end = len(buf)
        # Prefer explicit body offset if present, else header size
        body_off = int(hdr.OffsetToCapsuleBody) or int(hdr.HeaderSize)
        fwstart = offset + body_off
        if fwstart >= end:
            return None
        inner = buf[fwstart:end]
        return inner if inner else None

    if g == EFI2_CAPSULE_GUID:
        hdr = _get_struct(buf, offset, Efi2CapsuleHeader)
        end = offset + (hdr.CapsuleImageSize or 0)
        if end <= offset or end > len(buf):
            end = len(buf)
        fwstart = offset + int(hdr.FwImageOffset)
        if fwstart >= end:
            return None
        inner = buf[fwstart:end]
        return inner if inner else None

    if g == UEFI_CAPSULE_GUID:
        hdr = _get_struct(buf, offset, UefiCapsuleHeader)
        end = offset + (hdr.CapsuleImageSize or 0)
        if end <= offset or end > len(buf):
            end = len(buf)
        fwstart = offset + int(hdr.HeaderSize)
        if fwstart >= end:
            return None
        inner = buf[fwstart:end]
        return inner if inner else None

    return None

def maybe_decapsule_bytes(
    buf: bytes,
    filename: str | None = None,
    *,
    return_info: bool = False,
) -> bytes | tuple[bytes, bool]:
    """
    Attempt to extract firmware from a UEFI capsule or IFLASH image.
    
    Args:
        buf: Raw input bytes
        filename: Optional filename hint for format detection
        return_info: If True, return (bytes, was_decapsulated) tuple
        
    Returns:
        Extracted firmware bytes, or tuple with decapsulation status if return_info=True
    """
    logger = get_logger()
    name_hint = (filename or "").lower()
    
    def _result(data: bytes, decapsulated: bool):
        return (data, decapsulated) if return_info else data
    
    def _log_insyde(source: str, offset: int, used_size: int, has_fv: bool):
        logger.info(f"InsydeFlash BIOS image extracted from {source}")
        logger.debug(f"  Offset: 0x{offset:X}, Used size: {used_size} bytes")
        if has_fv:
            logger.debug("  FV header detected in extracted payload")
    
    def _log_capsule(size: int):
        logger.info(f"UEFI capsule detected ({size} bytes), extracted FV")
    
    # Try direct IFLASH extraction first
    insyde_entry = _extract_iflash_bios_image(buf)
    if insyde_entry is not None:
        bios_blob, meta = insyde_entry
        _log_insyde("input", meta['offset'], meta['used_size'], _check_fv(bios_blob))
        return _result(bios_blob, True)

    # Check if we should attempt capsule decapsulation
    is_capsule = is_capsule_bytes(buf, 0)
    should_try = name_hint.endswith((".rom", ".cap")) or is_capsule
    if not should_try:
        return _result(buf, False)
    
    # Try capsule extraction
    inner = decapsule_bytes(buf, 0)
    if inner and _check_fv(inner):
        _log_capsule(len(buf))
        return _result(inner, True)
    
    # Try IFLASH extraction from capsule payload or original
    for source, data in [("capsule payload", inner), ("input", buf)]:
        if data is None:
            continue
        bios_entry = _extract_iflash_bios_image(data)
        if bios_entry is not None:
            bios_blob, meta = bios_entry
            _log_insyde(source, meta['offset'], meta['used_size'], _check_fv(bios_blob))
            return _result(bios_blob, True)
    
    # Fallback: keep original if it's already an FV
    if _check_fv(buf):
        return _result(buf, False)
    
    # Return inner even if FV check failed (some vendor payloads begin with padding)
    if inner:
        _log_capsule(len(buf))
        return _result(inner, True)
    
    return _result(buf, False)
