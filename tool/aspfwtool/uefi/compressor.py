# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
UEFI firmware compression utilities.

This module provides compression support for various UEFI section formats:

    - EFI standard compression (Tiano/EFI1.1)
    - LZMA compression (custom UEFI format)
    - Deflate/zlib compression
"""

from __future__ import annotations

import lzma
import zlib

from .decompressor import FirmwareMutationError, get_efi_compression_backend


_efi_compressor = get_efi_compression_backend()


# Compression Type Constants (UEFI PI + Vendor Custom)


EFI_NOT_COMPRESSED = 0
EFI_STANDARD_COMPRESSION = 1
EFI_CUSTOM_COMPRESSION_LZMA = 0x5898  # ee4e5898-3914-4259-9d6e-dc7bd79403cf
EFI_CUSTOM_COMPRESSION_AMD_DEFLATE = 0x33F5  # ce3233f5-2cd6-4d87-9152-4a238bb6d1c4
EFI_CUSTOM_COMPRESSION_AMD_DEFLATE1 = 0xFAC0  # 991efac0-e260-416b-a4b8-3b153072b804

COMPRESSION_TYPE_NAMES = {
    EFI_NOT_COMPRESSED: "NOT_COMPRESSED",
    EFI_STANDARD_COMPRESSION: "EFI_STANDARD",
    EFI_CUSTOM_COMPRESSION_LZMA: "LZMA_CUSTOM",
    EFI_CUSTOM_COMPRESSION_AMD_DEFLATE: "AMD_DEFLATE",
    EFI_CUSTOM_COMPRESSION_AMD_DEFLATE1: "AMD_DEFLATE",
}


def _compress_deflate_like(data: bytes, *, level: int | None = None) -> bytes:
    """
    Encode data using a standard zlib (deflate) wrapper.
    If 'level' is provided (0-9), use it; otherwise default to 9.
    """
    lvl = 9 if level is None else int(level)
    return zlib.compress(data, level=lvl)


def _compress_standard(data: bytes) -> bytes:
    errors: list[str] = []
    if _efi_compressor is not None:
        for attr in ("EfiCompress", "TianoCompress"):
            func = getattr(_efi_compressor, attr, None)
            if func is None:
                continue
            try:
                return func(data, len(data))
            except Exception as exc:
                errors.append(f"{attr}: {exc}")
    if errors:
        raise FirmwareMutationError("; ".join(errors))
    raise FirmwareMutationError("EFI standard compression unavailable")


def _encode_lzma_props(lc: int, lp: int, pb: int) -> int:
    if not (0 <= lc <= 8 and 0 <= lp <= 4 and 0 <= pb <= 4) or lc + lp > 8:
        raise ValueError("invalid lc/lp/pb")
    return (pb * 5 + lp) * 9 + lc


def _lzma_alone_encode(
    data: bytes,
    *,
    lc: int = 3,
    lp: int = 0,
    pb: int = 2,
    dict_size: int = 1 << 24,
) -> bytes:
    filters = [{
        "id": lzma.FILTER_LZMA1,
        "lc": int(lc), "lp": int(lp), "pb": int(pb),
        "dict_size": int(dict_size),
    }]
    stream = lzma.compress(data, format=lzma.FORMAT_ALONE, filters=filters)

    if len(stream) < 13:
        raise FirmwareMutationError("internal: LZMA-Alone stream too short")

    header = bytearray(stream[:13])
    header[5:13] = len(data).to_bytes(8, "little", signed=False)
    return bytes(header) + stream[13:]


def _compress_lzma_custom(data: bytes) -> bytes:
    try:
        return _lzma_alone_encode(
            data,
            lc=3, lp=0, pb=2,
            dict_size=1 << 24,
        )
    except Exception as exc:
        raise FirmwareMutationError(f"LZMA compression failed: {exc}")


def _lzma_alone_encode_known_size_noeos(
    data: bytes,
    *,
    lc: int = 3,
    lp: int = 0,
    pb: int = 2,
    dict_size: int = 1 << 24,
    nice_len: int = 128,
) -> bytes:
    comp = lzma.LZMACompressor(
        format=lzma.FORMAT_RAW,
        filters=[{
            "id": lzma.FILTER_LZMA1,
            "lc": int(lc),
            "lp": int(lp),
            "pb": int(pb),
            "dict_size": int(dict_size),
            "mode": lzma.MODE_NORMAL,
            "mf": lzma.MF_BT4,
            "nice_len": int(nice_len),
            "end_marker": False,
        }],
    )
    raw = comp.compress(data) + comp.flush()

    props = (pb * 5 + lp) * 9 + lc
    header = bytearray(13)
    header[0] = props & 0xFF
    header[1:5] = int(dict_size).to_bytes(4, "little")
    header[5:13] = len(data).to_bytes(8, "little")
    return bytes(header) + raw


def _lzma_alone_encode_known_size_cpython(
    data: bytes,
    *,
    lc: int = 3,
    lp: int = 0,
    pb: int = 2,
    dict_size: int = 1 << 24,
) -> bytes:
    filters = [{
        "id": lzma.FILTER_LZMA1,
        "lc": int(lc),
        "lp": int(lp),
        "pb": int(pb),
        "dict_size": int(dict_size),
    }]
    stream = lzma.compress(data, format=lzma.FORMAT_ALONE, filters=filters)
    if len(stream) < 13:
        raise FirmwareMutationError("internal: LZMA-Alone stream too short")
    header = bytearray(stream[:13])
    header[5:13] = len(data).to_bytes(8, "little", signed=False)
    return bytes(header) + stream[13:]


def compress_section_payload(
    data: bytes,
    *,
    compression_type: int,
    zlib_level: int | None = None,
) -> bytes:
    """
    Compress a payload according to a UEFI compression type id.

        - EFI_NOT_COMPRESSED: return data as-is
        - EFI_STANDARD_COMPRESSION: use firmware backend (Tiano/Efi)
        - EFI_CUSTOM_COMPRESSION_LZMA: LZMA-Alone with fixed params
        - EFI_CUSTOM_COMPRESSION_AMD_DEFLATE: zlib (deflate) wrapper
    """
    if compression_type == EFI_NOT_COMPRESSED:
        return bytes(data)
    if compression_type == EFI_STANDARD_COMPRESSION:
        return _compress_standard(bytes(data))
    if compression_type == EFI_CUSTOM_COMPRESSION_LZMA:
        return _compress_lzma_custom(bytes(data))
    if compression_type == EFI_CUSTOM_COMPRESSION_AMD_DEFLATE or EFI_CUSTOM_COMPRESSION_AMD_DEFLATE1:
        return _compress_deflate_like(bytes(data), level=zlib_level)
    raise FirmwareMutationError(f"unsupported compression type {compression_type}")


def detect_zlib_flevel_from_data(data: bytes) -> int | None:
    """
    Scan 'data' for a zlib or gzip header and return the 2-bit FLEVEL (0..3),
    or None if not found. Scans up to the first 0x400 bytes.
    """
    scan = min(len(data), 0x400)
    for i in range(0, max(0, scan - 2)):
        if i + 1 >= len(data):
            break
        cmf = data[i]
        flg = data[i + 1]
        # zlib header check: CM=8 (deflate) and (CMF*256+FLG) % 31 == 0
        if (cmf & 0x0F) == 8 and (((cmf << 8) | flg) % 31) == 0:
            return (flg >> 6) & 0x03
        # gzip magic
        if cmf == 0x1F and flg == 0x8B:
            # gzip doesn't expose zlib FLEVEL; return default (None)
            return None
    return None


def map_flevel_to_zlib_level(flevel: int) -> int:
    """
    Map 2-bit zlib FLEVEL to a representative zlib level (0..9).
        - 0: fastest -> level 1
        - 1: fast    -> level 5
        - 2: default -> level 6
        - 3: max     -> level 9
    """
    f = int(flevel) & 0x03
    if f == 0:
        return 1
    if f == 1:
        return 5
    if f == 2:
        return 6
    return 9
