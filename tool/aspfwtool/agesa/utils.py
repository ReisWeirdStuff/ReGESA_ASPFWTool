# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Utility functions for AMD firmware parsing and manipulation.

This module provides:
    - ROM pointer normalization and resolution (address modes 0-3, map to SPI NOR image offsets)
    - Entry offset calculation with address mode support
    - Platform name lookup from PSP IDs
    - Type formatting utilities
"""

from .constants import DirKind, ProgramTable, COOKIE_KIND
from typing import Optional, List, Iterable, Tuple
from .entrytypes import lookup_entry_definition



# Compressed Payload Size Resolution



def resolve_compressed_payload_size(actual: Optional[int], declared: int) -> int:
    """
    Normalize compressed entry lengths read from pointer headers:

    Some PSP directory entries store 0xFFFFFFFF in the embedded size field when
    the real length is not provided. Treat that (and zero) as 'unknown' and fall
    back to the directory-declared size.

        Args:
            actual: Size value from the entry header (may be invalid).
            declared: Size value declared in the directory entry.

        Returns:
            Resolved size value to use.
    """

    declared = int(declared or 0)
    if actual is None:
        return declared
    try:
        value = int(actual) & 0xFFFFFFFF
    except Exception:
        return declared
    if value in (0, 0xFFFFFFFF):
        return declared
    return value



# Cookie Detection



def cookie_kind_at(buf: bytes, off: int) -> Optional[DirKind]:
    """
    Get the directory kind for a 4-byte cookie at the given offset.

    Args:
        buf: Firmware image buffer.
        off: Offset to check for a cookie.

    Returns:
        DirKind enum if a valid cookie is found, None otherwise.
    """
    if off < 0 or off + 4 > len(buf):
        return None
    return COOKIE_KIND.get(bytes(buf[off : off + 4]))



# Pointer Normalization



def normalize_rom_ptr(p: int | None) -> int | None:
    """
    Normalize a 32-bit ROM pointer.
    Treats 0xFFxxxxxx as 24-bit addresses by clearing the top byte.

    Args:
        p: Raw pointer value.

    Returns:
        Normalized pointer value or None.
    """
    if p is None:
        return None
    p = int(p) & 0xFFFFFFFF
    if (p & 0xFF000000) == 0xFF000000:
        p &= 0x00FFFFFF
    return p


def is_u32_ptr(x: int, file_size: int) -> bool:
    """Check if a value is a valid 32-bit aligned pointer within file bounds."""
    return 0 < x < file_size and (x & 3) == 0



# Pointer Resolution (Address Mode 62:63)


_ADDR_MASK62 = (1 << 62) - 1


def _direct(off: int, size: int, file_size: int) -> Optional[int]:
    size = max(int(size or 0), 0)
    if 0 <= off <= file_size - size:
        return off
    return None


def _ffmask(off: int, size: int, file_size: int) -> Optional[int]:
    return _direct(off & 0x00FFFFFF, size, file_size)


def _top(off: int, size: int, file_size: int) -> Optional[int]:
    base_phys = (1 << 32) - file_size
    if base_phys <= off < (1 << 32):
        return _direct(off - base_phys, size, file_size)
    return None


def _shift2(ptr64: int, size: int, file_size: int) -> Optional[int]:
    return _direct((ptr64 & _ADDR_MASK62) >> 2, size, file_size)


def resolve_offset(ptr64: int, size: int, file_size: int):
    sz = int(size or 0)
    sz = sz if 0 <= sz <= file_size else 0
    mode = (ptr64 >> 62) & 0x3
    val = ptr64 & _ADDR_MASK62
    if mode == 1:  # BIOS offset
        off = _direct(val, sz, file_size) or _direct(val, 0, file_size)
        return (off, "mode=bios") if off is not None else (None, "unmapped")
    if mode == 0:  # x86 physical
        for fn, tag in (
            (_direct, "mode=x86:direct"),
            (_ffmask, "mode=x86:ffmask"),
            (_top, "mode=x86:top"),
        ):
            off = fn(val, sz, file_size)
            if off is not None:
                return off, tag
        for fn, tag in (
            (_direct, "mode=x86:direct:partial"),
            (_ffmask, "mode=x86:ffmask:partial"),
            (_top, "mode=x86:top:partial"),
        ):
            off = fn(val, 0, file_size)
            if off is not None:
                return off, tag
    # legacy heuristics
    masked = ptr64 & ~0x3
    for fn, tag in (
        (_direct, "legacy:direct"),
        (_ffmask, "legacy:ffmask"),
        (_top, "legacy:top"),
    ):
        off = fn(masked, sz, file_size)
        if off is not None:
            return off, tag
    off = _shift2(ptr64, sz, file_size)
    if off is not None:
        return off, "legacy:shift2"
    return None, "unmapped"


def resolve_entry_offset(
    kind: str,
    d_off: int,
    ptr64: int,
    size: int,
    file_size: int,
    allow_shift2: bool = False,
    *,
    allow_zero_size: bool = False,
    allow_oversize: bool = False,
):
    raw_size = int(size) if size is not None else None
    sz = int(size or 0)
    sz = sz if 0 <= sz <= file_size else 0
    if ptr64 == 0:
        return None, "zero"
    if raw_size == 0 and not allow_zero_size:
        return None, "zero"
    mode = (ptr64 >> 62) & 0x3
    val = ptr64 & _ADDR_MASK62
    seg_base = 0
    if d_off > 0:
        seg_base = (int(d_off) // 0x01000000) * 0x01000000
    seg_partial: Optional[Tuple[int, str]] = None

    def _record_candidate(off: Optional[int], tag: str, *, allow_partial: bool = False):
        nonlocal seg_partial
        if off is None:
            return None
        if 0 <= off <= file_size - sz:
            return off, tag
        if allow_oversize and 0 <= off < file_size:
            return off, f"{tag}:oversize"
        if allow_partial and 0 <= off < file_size and seg_partial is None:
            seg_partial = (off, f"{tag}:partial")
        return None

    def _segment_choice(raw: int, tag: str, allow_partial: bool = False):
        if not seg_base:
            return None
        raw &= 0xFFFFFFFF
        if raw >= 0x01000000:
            return None
        alt = seg_base + raw
        return _record_candidate(alt, f"{tag}+seg", allow_partial=allow_partial)

    if mode == 1:  # direct flash offset (used by compressed BIOS entries like 0x62)
        res = _record_candidate(val, "mode=flash", allow_partial=True)
        if res:
            return res
    elif mode == 2:  # from directory header
        res = _record_candidate(d_off + val, "mode=dir", allow_partial=True)
        if res:
            return res
    elif mode == 3:  # from partition start (approx: dir base if partition unknown)
        res = _record_candidate(d_off + val, "mode=part", allow_partial=True)
        if res:
            return res
    # PL2/BL2 quirk: bit63 set → lower32 offset from dir base
    if kind is not None and kind.is_level2 and (ptr64 & (1 << 63)):
        res = _record_candidate(
            d_off + (ptr64 & 0xFFFFFFFF), "pl2+base", allow_partial=True
        )
        if res:
            return res
    if mode == 0:  # x86 physical
        for fn, tag in (
            (_direct, "mode=x86:direct"),
            (_ffmask, "mode=x86:ffmask"),
            (_top, "mode=x86:top"),
        ):
            seg = _segment_choice(val, tag)
            if seg:
                return seg
            res = _record_candidate(fn(val, sz, file_size), tag)
            if res:
                return res
        for fn, tag in (
            (_direct, "mode=x86:direct:partial"),
            (_ffmask, "mode=x86:ffmask:partial"),
            (_top, "mode=x86:top:partial"),
        ):
            seg = _segment_choice(val, tag, allow_partial=True)
            if seg:
                return seg
            res = _record_candidate(fn(val, 0, file_size), tag, allow_partial=True)
            if res:
                return res

    masked = ptr64 & ~0x3
    for fn, tag in (
        (_direct, "legacy:direct"),
        (_ffmask, "legacy:ffmask"),
        (_top, "legacy:top"),
    ):
        seg = _segment_choice(masked, tag)
        if seg:
            return seg
        res = _record_candidate(fn(masked, sz, file_size), tag)
        if res:
            return res
    for fn, tag in (
        (_direct, "legacy:direct:partial"),
        (_ffmask, "legacy:ffmask:partial"),
        (_top, "legacy:top:partial"),
    ):
        seg = _segment_choice(masked, tag, allow_partial=True)
        if seg:
            return seg
        res = _record_candidate(fn(masked, 0, file_size), tag, allow_partial=True)
        if res:
            return res

    alt, tag = resolve_offset(ptr64, size, file_size)
    if alt is not None:
        seg = _segment_choice(val, tag)
        if seg:
            return seg
        res = _record_candidate(alt, tag)
        if res:
            return res

    if seg_partial is not None:
        return seg_partial

    return None, "unmapped"


def encode_entry_pointer(
    kind: str,
    directory_offset: Optional[int],
    file_size: int,
    target_offset: int,
    *,
    prefer_mode: Optional[int] = None,
) -> Optional[int]:
    """
    Encode a pointer that resolves to "target_offset" within "file_size"

    The encoder attempts to reuse the caller's preferred addressing mode before
    falling back to generic encodings. Any candidate value is validated by
    "resolve_entry_offset" so we only return pointers that decode back to the
    requested offset.
    """

    try:
        toff = int(target_offset)
    except Exception:
        return None
    if toff < 0 or toff >= int(file_size or 0):
        return None

    modes: List[int] = []
    if isinstance(prefer_mode, int) and 0 <= prefer_mode <= 3:
        modes.append(prefer_mode)
    for candidate in (0, 1, 2, 3):
        if candidate not in modes:
            modes.append(candidate)

    mask = _ADDR_MASK62
    d_base = int(directory_offset or 0)

    for mode in modes:
        ptr: Optional[int] = None
        if mode in (2, 3):
            delta = toff - d_base
            if delta < 0:
                continue
            ptr = (mode << 62) | (delta & mask)
        elif mode in (0, 1):
            ptr = (mode << 62) | (toff & mask)
        if ptr is None:
            continue
        resolved, _ = resolve_entry_offset(
            kind,
            d_base,
            int(ptr),
            0,
            int(file_size),
            allow_zero_size=True,
            allow_oversize=True,
        )
        if resolved == toff:
            return int(ptr)
    return None


def resolve_offset_with_mode(
    kind, d_off, ptr64, size, file_size, allow_shift2=False, *, allow_zero_size=False
):
    return resolve_entry_offset(
        kind,
        d_off,
        ptr64,
        size,
        file_size,
        allow_shift2,
        allow_zero_size=allow_zero_size,
    )


def platform_names_for_pspid(pspid: int):
    exact = []
    masked = []
    for name, info in ProgramTable.items():
        idv = info.get("PSPID")
        if idv is None:
            continue
        if pspid == idv:
            exact.append(name)
            continue
        am = info.get("AndMask", 0xFFFFFFFF)
        try:
            if (pspid & am) == idv:
                masked.append(name)
        except Exception:
            pass
    return exact if exact else masked


def labels_from_pspids(pspids: Iterable[int]) -> str:
    # Turn many PSPIDs into a union of platform labels.
    names: List[str] = []
    for pid in pspids or []:
        nm_list = platform_names_for_pspid(int(pid))
        if nm_list:
            names.extend(nm_list)
    uniq = sorted(set(names))
    return ",".join(uniq) if uniq else ""


# Pretty-print helpers


def fmt_type(raw_type: Optional[int], zone: str, mode: bool) -> str:
    if raw_type is None:
        return "Unknown" if mode else "Unknown (0x??)"
    base = int(raw_type) & 0xFF
    definition = lookup_entry_definition(zone, base)
    if mode:
        return definition.name
    return f"{definition.name} (0x{base:02X})"
