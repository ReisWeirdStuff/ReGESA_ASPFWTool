# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
PSP Directory collection operations for AMD firmware images.

This module provides:
    - EFS-based directory discovery
    - Cookie-scan directory discovery
    - Directory validation and parsing helpers
"""

from typing import List, Optional, Tuple
from .constants import Directory, DirKind, COOKIE_KIND
from .utils import resolve_entry_offset, cookie_kind_at, is_u32_ptr
from .ish import try_parse_ish_at
from .efs import find_valid_efs, resolve_efs_pointer
from .directory import dir_header_len, parse_dir_header, entry_span, parse_entry
from ..utils.debug_logger import get_logger

# Helper Functions


def _parse_dir_header_safe(buf: bytes, off: int, kind: DirKind):
    try:
        return parse_dir_header(buf, off, kind)
    except Exception:
        return None


def _valid_dir(buf: bytes, off: int, kind: DirKind) -> bool:
    fs = len(buf)
    hdr = _parse_dir_header_safe(buf, off, kind)
    if not hdr:
        return False
    try:
        cnt = int(getattr(hdr, "Count", 0))
    except Exception:
        return False
    if not (0 <= cnt <= 0x4000):
        return False
    base = off + dir_header_len(kind)
    span = entry_span(kind)
    end = base + cnt * span
    if end > fs:
        return False
    return bytes(buf[off : off + 4]) in COOKIE_KIND


def _try_add_dir(
    buf: bytes,
    out_list: List[Directory],
    seen: set,
    off: int,
    expect_kinds: Tuple[DirKind, ...],
) -> bool:
    if off is None:
        return False
    try:
        off = int(off)
    except Exception:
        return False
    if off < 0 or off + 4 > len(buf):
        return False
    kind = cookie_kind_at(buf, off)
    if kind not in expect_kinds:
        return False
    key = (kind, off)
    if key in seen:
        return True
    try:
        hdr = parse_dir_header(buf, off, kind)
        cnt = int(getattr(hdr, "Count", getattr(hdr, "count", 0)))
    except Exception:
        cnt = 0
    out_list.append(Directory(kind=kind, magic=kind.value, offset=off, count=cnt))
    seen.add(key)
    return True


""" EFS-Based Directory Collection """


def collect_dirs_efs(
    buf: bytes,
    *,
    prefer_offset: int | None = None,
    prefer_index: int | None = None,
) -> List[Directory]:
    efs_off, efs = find_valid_efs(
        buf, prefer_offset=prefer_offset, prefer_index=prefer_index
    )
    if efs is None:
        return []
    fs = len(buf)
    dirs: List[Directory] = []
    seen: set[Tuple[DirKind, int]] = set()

    def _add_if(off: Optional[int], expect: Tuple[DirKind, ...]) -> bool:
        if off is None:
            return False
        return _try_add_dir(buf, dirs, seen, off, expect)

    def _resolve(
        field: str, expect: Tuple[DirKind, ...] | None = None
    ) -> Optional[int]:
        raw = getattr(efs, field, None)
        if raw is None:
            return None
        try:
            raw_val = int(raw)
        except Exception:
            return None
        return resolve_efs_pointer(buf, efs_off, raw_val, expect)

    psp_roots = [
        _resolve("PSP_Directory_Table_Combo", (DirKind.COMBO_PSP, DirKind.PSP_L1)),
        _resolve("PSP_Directory_Table_Legacy", (DirKind.PSP_L1, DirKind.COMBO_PSP)),
        _resolve("PSP_L1_Backup", (DirKind.PSP_L1, DirKind.COMBO_PSP)),
    ]
    bios_roots = [
        _resolve("BIOS_Directory_Combo", (DirKind.COMBO_BHD, DirKind.BHD_L1)),
        _resolve("BIOS_Directory_F17h_M30h", (DirKind.BHD_L1, DirKind.COMBO_BHD)),
        _resolve("BIOS_Directory_F17h_M10h", (DirKind.BHD_L1, DirKind.COMBO_BHD)),
        _resolve("BIOS_Directory_F17h_M00h", (DirKind.BHD_L1, DirKind.COMBO_BHD)),
    ]

    def _add_if_kind(off: Optional[int], expect_kinds: Tuple[DirKind, ...]) -> bool:
        if off is None:
            return False
        return _try_add_dir(buf, dirs, seen, off, expect_kinds)

    for p in psp_roots:
        _add_if_kind(p, (DirKind.COMBO_PSP, DirKind.PSP_L1))
    for p in bios_roots:
        _add_if_kind(p, (DirKind.COMBO_BHD, DirKind.BHD_L1))

    if not dirs:
        return []

    q = list(dirs)
    while q:
        d = q.pop(0)
        head = d.offset
        span = entry_span(d.kind)
        base = head + dir_header_len(d.kind)
        if base + span > fs:
            continue

        if d.kind in (DirKind.COMBO_PSP, DirKind.COMBO_BHD):
            expect_child = (
                DirKind.PSP_L1 if d.kind == DirKind.COMBO_PSP else DirKind.BHD_L1
            )
            for ei in range(d.count):
                eoff = base + ei * span
                if eoff + span > fs:
                    break
                try:
                    ent = parse_entry(buf, d.kind, eoff)
                except Exception:
                    continue
                child_off, _ = resolve_entry_offset(
                    d.kind,
                    d.offset,
                    int(ent.ptr64),
                    0,
                    fs,
                    False,
                    allow_zero_size=True,
                )
                if child_off is None:
                    continue
                if _add_if(child_off, (expect_child,)):
                    q.append(dirs[-1])
            continue

        if d.kind == DirKind.PSP_L1:
            for ei in range(d.count):
                eoff = base + ei * span
                if eoff + span > fs:
                    break
                try:
                    ent = parse_entry(buf, d.kind, eoff)
                except Exception:
                    continue
                low8 = int(ent.type_id) & 0xFF
                if low8 not in (0x40, 0x48, 0x4A):
                    continue
                child_off, _ = resolve_entry_offset(
                    d.kind,
                    d.offset,
                    int(ent.ptr64),
                    0,
                    fs,
                    False,
                    allow_zero_size=True,
                )
                if child_off is None:
                    continue
                if _add_if(child_off, (DirKind.PSP_L2,)):
                    q.append(dirs[-1])
                    continue
                # Treat as ISH stub if not an actual $PL2 header
                ish = try_parse_ish_at(buf, child_off)
                if ish:
                    pl2_off = int(ish.location_pointer)
                    if is_u32_ptr(pl2_off, fs) and _add_if(pl2_off, (DirKind.PSP_L2,)):
                        q.append(dirs[-1])
            continue

        if d.kind == DirKind.BHD_L1:
            for ei in range(d.count):
                eoff = base + ei * span
                if eoff + span > fs:
                    break
                try:
                    ent = parse_entry(buf, d.kind, eoff)
                except Exception:
                    continue
                if (int(ent.type_id) & 0xFF) != 0x70:
                    continue
                child_off, _ = resolve_entry_offset(
                    d.kind,
                    d.offset,
                    int(ent.ptr64),
                    0,
                    fs,
                    False,
                    allow_zero_size=True,
                )
                if child_off is None:
                    continue
                if _add_if(child_off, (DirKind.BHD_L2,)):
                    q.append(dirs[-1])
            continue

        if d.kind == DirKind.PSP_L2:
            for ei in range(d.count):
                eoff = base + ei * span
                if eoff + span > fs:
                    break
                try:
                    ent = parse_entry(buf, d.kind, eoff)
                except Exception:
                    continue
                low8 = int(ent.type_id) & 0xFF
                if low8 != 0x49:
                    continue
                child_off, _ = resolve_entry_offset(
                    d.kind,
                    d.offset,
                    int(ent.ptr64),
                    0,
                    fs,
                    False,
                    allow_zero_size=True,
                )
                if child_off is None:
                    continue
                if _add_if(child_off, (DirKind.BHD_L2,)):
                    q.append(dirs[-1])
                    continue
                ish = try_parse_ish_at(buf, child_off)
                if ish:
                    bl2_off = int(ish.location_pointer)
                    if is_u32_ptr(bl2_off, fs) and _add_if(bl2_off, (DirKind.BHD_L2,)):
                        q.append(dirs[-1])
            continue

    dirs.sort(key=lambda d: d.offset)
    logger = get_logger()
    logger.info(f"Found EFS at 0x{efs_off:08X}")
    return dirs


""" Scan mode (search for cookies) """


def collect_dirs_scan(buf: bytes) -> list[Directory]:
    dirs: list[Directory] = []
    seen: set[tuple[DirKind, int]] = set()
    for ck, kind in COOKIE_KIND.items():
        start = 0
        while True:
            idx = buf.find(ck, start)
            if idx < 0:
                break
            start = idx + 1
            if not _valid_dir(buf, idx, kind):
                continue
            key = (kind, idx)
            if key in seen:
                continue
            hdr = _parse_dir_header_safe(buf, idx, kind)
            cnt = int(getattr(hdr, "Count", 0)) if hdr else 0
            dirs.append(Directory(kind=kind, magic=kind.value, offset=idx, count=cnt))
            seen.add(key)
    dirs.sort(key=lambda d: d.offset)
    return dirs
