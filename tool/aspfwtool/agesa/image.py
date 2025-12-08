# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Firmware image loading and directory discovery utilities.

This module provides:
    - Input file collection and filtering
    - Directory discovery via EFS or scan modes
    - Capsule decapsulation handling
"""

from pathlib import Path
from typing import Optional, Iterable, List, Sequence, Tuple, Dict, Any

from .constants import Directory, DirKind, is_real_bios_dir
from .utils import resolve_entry_offset, resolve_compressed_payload_size
from .directory import (
    dir_header_len,
    parse_entry,
    entry_span,
    list_entry_ranges,
    is_bios_compressed,
)
from .psp_dirs import collect_dirs_scan, collect_dirs_efs
from ..uefi.decapsule import maybe_decapsule_bytes, is_capsule_bytes, decapsule_bytes
from ..utils.debug_logger import get_logger


# Candidate File Helpers (I/O)


_FIRMWARE_SUFFIXES = {".bin", ".rom", ".cap", ".fd", ".bio", ".img", ".fv", ".efi"}


def _is_candidate_file(p: Path) -> bool:
    if not p.is_file():
        return False
    if p.suffix.lower() in _FIRMWARE_SUFFIXES:
        return True
    try:
        return p.stat().st_size >= 64 * 1024
    except OSError:
        return False


def _iter_path_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        if _is_candidate_file(path):
            yield path
        return
    if path.is_dir():
        for f in path.rglob("*"):
            if _is_candidate_file(f):
                yield f


def collect_inputs(
    positional: Sequence[Path] | None, optional: Sequence[Path] | None
) -> List[Path]:
    seen: set[Path] = set()
    result: List[Path] = []

    def add_path(p: Path):
        try:
            rp = p.resolve()
        except Exception:
            rp = p.absolute()
        for f in _iter_path_files(rp):
            if f not in seen:
                seen.add(f)
                result.append(f)

    for src in positional or []:
        add_path(src)
    for src in optional or []:
        add_path(src)

    return result


# Directory Discovery


def collect_dirs(
    buf: bytes,
    mode: str | None,
    *,
    efs_offset: int | None = None,
) -> List[Directory]:
    mode = (mode or "auto").lower()
    logger = get_logger()

    logger.info(f"Image size: {len(buf)} Bytes")
    if mode == "scan":
        logger.info("Mode: Scan for cookies")
        return collect_dirs_scan(buf)
    # EFS or AUTO
    logger.info("Mode: EFS Parsing")
    dirs = collect_dirs_efs(buf, prefer_offset=efs_offset)
    if dirs:
        return dirs
    logger.info("No EFS found, falling back to scan mode")
    return collect_dirs_scan(buf)


# Normalize list_entry_ranges() results
#   Accepts (off, size), (ei, off, size), or (ei, off, size, type_id)


def _normalize_ranges_from_list(
    buf: bytes, d: Directory
) -> List[Tuple[Optional[int], int, int, Optional[int]]]:
    out: List[Tuple[Optional[int], int, int, Optional[int]]] = []
    for item in list_entry_ranges(buf, d):
        try:
            n = len(item)
        except Exception:
            # Try as (off, size)
            try:
                off = int(item[0])
                size = int(item[1])
                out.append((None, off, size, None))
            except Exception:
                continue
            continue

        if n == 4:
            ei, off, size, type_id = item
            out.append(
                (
                    int(ei) if ei is not None else None,
                    int(off),
                    int(size),
                    int(type_id) if type_id is not None else None,
                )
            )
        elif n == 3:
            ei, off, size = item
            out.append((int(ei) if ei is not None else None, int(off), int(size), None))
        elif n == 2:
            off, size = item
            out.append((None, int(off), int(size), None))
        else:
            continue
    return out


# Fallback mapper


def _fallback_entry_ranges(
    buf: bytes, d: Directory, all_dirs: List[Directory]
) -> List[Tuple[int, int, int, int]]:
    file_size = len(buf)

    # Next directory start
    all_sorted = sorted(all_dirs, key=lambda x: x.offset)
    this_idx = all_sorted.index(d)
    next_dir_start = (
        all_sorted[this_idx + 1].offset if this_idx + 1 < len(all_sorted) else file_size
    )

    # Gather per-entry mapping
    mapped: List[Dict[str, Any]] = []
    base = d.offset + dir_header_len(d.kind)
    span = entry_span(d.kind)

    for ei in range(d.count):
        eoff = base + ei * span
        ent = parse_entry(buf, d.kind, eoff)
        type_id = int(ent.type_id)
        size = int(ent.size)
        declared_size = size
        ptr64 = int(ent.ptr64)
        comp = (
            is_bios_compressed(buf, eoff)
            if is_real_bios_dir(d.kind)
            else is_bios_compressed(d.kind, type_id)
        )
        zlib_pointer = comp and is_real_bios_dir(d.kind) and (type_id & 0xFF) == 0x62
        size = declared_size
        chk_size = 0 if comp else declared_size
        off_spi, _how = resolve_entry_offset(
            d.kind,
            d.offset,
            ptr64,
            chk_size,
            file_size,
            allow_shift2=False,
            allow_zero_size=zlib_pointer,
            allow_oversize=zlib_pointer,
        )
        if zlib_pointer and off_spi is not None:
            try:
                actual = int.from_bytes(
                    buf[int(off_spi) + 0x14 : int(off_spi) + 0x18], "little"
                )
            except Exception:
                actual = None
            size = resolve_compressed_payload_size(actual, declared_size)
        if off_spi is None:
            continue
        mapped.append(
            {
                "ei": ei,
                "off": int(off_spi),
                "size_field": size,
                "type": type_id,
                "compressed": bool(comp),
            }
        )

    if not mapped:
        return []

    mapped.sort(key=lambda r: r["off"])

    out: List[Tuple[int, int, int, int]] = []
    for idx, cur in enumerate(mapped):
        off = cur["off"]
        type_id = cur["type"]
        if not cur["compressed"] and cur["size_field"] > 0:
            size = max(0, min(cur["size_field"], file_size - off))
        else:
            next_off = (
                mapped[idx + 1]["off"] if idx + 1 < len(mapped) else next_dir_start
            )
            bound = min(next_off, next_dir_start, file_size)
            size = max(0, bound - off)
        if size <= 0:
            continue
        out.append((cur["ei"], off, size, type_id))

    return out


def _union_ranges(
    a: List[Tuple[Optional[int], int, int, Optional[int]]],
    b: List[Tuple[int, int, int, int]],
    buf: bytes,
    d: Directory,
) -> List[Tuple[Optional[int], int, int, Optional[int]]]:
    # Merge native list_entry_ranges() results (A) with fallback (B).
    # Prefer A where (off) matches; otherwise include B. Fill missing type ids.
    by_off: Dict[int, Tuple[Optional[int], int, int, Optional[int]]] = {}
    for ei, off, size, tid in a:
        by_off[off] = (ei, off, size, tid)

    # type-by-ei map
    base = d.offset + dir_header_len(d.kind)
    span = entry_span(d.kind)
    type_by_ei: Dict[int, int] = {}
    for ei in range(d.count):
        eoff = base + ei * span
        ent = parse_entry(buf, d.kind, eoff)
        type_by_ei[ei] = int(ent.type_id)

    for ei, off, size, tid in b:
        if off in by_off:
            a_ei, a_off, a_size, a_tid = by_off[off]
            if a_ei is None:
                a_ei = ei
            if a_tid is None:
                a_tid = tid
            size_use = size if size and size < a_size else a_size
            by_off[off] = (a_ei, a_off, size_use, a_tid)
        else:
            by_off[off] = (ei, off, size, tid)

    merged = list(by_off.values())
    fixed: List[Tuple[Optional[int], int, int, Optional[int]]] = []
    for ei, off, size, tid in merged:
        if tid is None and ei is not None and ei in type_by_ei:
            tid = type_by_ei[ei]
        fixed.append((ei, off, size, tid))

    fixed.sort(key=lambda t: t[1])
    return fixed


def _iter_entry_ranges(buf: bytes, d: Directory, all_dirs: List[Directory]):
    # Yield normalized, deduplicated ranges as (ei, off, size, type_id).
    a = _normalize_ranges_from_list(buf, d)
    b = _fallback_entry_ranges(buf, d, all_dirs)
    merged = _union_ranges(a, b, buf, d)
    for ei, off, size, tid in merged:
        yield (ei, off, size, tid)


# Read & maybe decapsulate


def _read_image_bytes(path: Path) -> bytes:
    data, _ = _read_image_bytes_with_capsule(path)
    return data


def _read_image_bytes_with_capsule(
    path: Path,
) -> tuple[bytes, bool]:
    data = path.read_bytes()
    suffix = path.suffix.lower()
    decapsulated = False
    # Try decapsulation based on file hints first
    if suffix in (".rom", ".cap"):
        data, decapsulated = maybe_decapsule_bytes(
            data, filename=str(path.name), return_info=True
        )
    else:
        candidate, was_capsule = maybe_decapsule_bytes(
            data, filename=str(path.name), return_info=True
        )
        if was_capsule:
            data = candidate
            decapsulated = True
    # Even without the extension, detect capsules by GUID
    if not decapsulated and is_capsule_bytes(data, 0):
        inner = decapsule_bytes(data, 0)
        if inner:
            return inner, True
    return data, decapsulated
