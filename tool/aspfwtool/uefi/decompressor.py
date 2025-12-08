# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
UEFI firmware decompression utilities.

This module provides decompression support for various UEFI section formats:

    - EFI standard compression (Tiano/EFI1.1)
    - LZMA compression (custom and standard)
    - Deflate/zlib compression (including AMD variants)
    - GUID-defined section decompression
"""

from __future__ import annotations

from typing import List, Optional, Tuple
from uuid import UUID
import gzip
import lzma
import zlib

try:
    from ._compression_backend import get_backend as _get_compression_backend  # type: ignore
except Exception:  # pragma: no cover - optional backend
    _get_compression_backend = None  # type: ignore


def _init_backend() -> Optional[object]:
    if _get_compression_backend is None:
        return None
    try:
        return _get_compression_backend()
    except Exception:
        return None


_efi_compressor = _init_backend()


def get_efi_compression_backend() -> Optional[object]:
    """Return the optional EFI compression backend, if available."""
    return _efi_compressor


class FirmwareParseError(RuntimeError):
    """Raised when parsing firmware data fails."""


class FirmwareMutationError(RuntimeError):
    """Raised when mutating firmware data fails."""


def _decompress_deflate_like(data: bytes, expected_length: Optional[int]) -> bytes:
    """Robustly decode deflate-family streams."""

    def _try_members(b: bytes, wbits: int) -> Optional[bytes]:
        remaining = b
        out = bytearray()
        try:
            while remaining:
                d = zlib.decompressobj(wbits)
                out += d.decompress(remaining)
                remaining = d.unused_data or d.unconsumed_tail
                out += d.flush()
                if expected_length and expected_length > 0 and len(out) >= expected_length:
                    return bytes(out[:expected_length])
            return bytes(out)
        except zlib.error as exc:
            msg = str(exc)
            if "NEED_DICT" in msg or "Error -2" in msg:
                raise FirmwareParseError("zlib requires preset dictionary (Z_NEED_DICT)")
            return None

    for w in (zlib.MAX_WBITS, -zlib.MAX_WBITS, 16 + zlib.MAX_WBITS):
        out = _try_members(data, w)
        if out is not None and (not expected_length or len(out) >= 1):
            return out

    candidates: List[int] = []
    scan = min(len(data), 0x200)
    for i in range(0, max(0, scan - 2)):
        cmf = data[i]
        if i + 1 < len(data):
            flg = data[i + 1]
            if (cmf & 0x0F) == 8 and ((cmf << 8) | flg) % 31 == 0:
                candidates.append(i)
            if cmf == 0x1F and flg == 0x8B:
                candidates.append(i)

    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]
    for off in candidates:
        sub = data[off:]
        for w in (zlib.MAX_WBITS, 16 + zlib.MAX_WBITS, -zlib.MAX_WBITS):
            out = _try_members(sub, w)
            if out is not None and (not expected_length or len(out) >= 1):
                return out

    raise FirmwareParseError("zlib decompression failed")


def _decompress_standard(data: bytes, *, expected_length: Optional[int]) -> bytes:
    errors: List[str] = []
    if _efi_compressor is not None:
        for attr in ("EfiDecompress", "TianoDecompress"):
            func = getattr(_efi_compressor, attr, None)
            if func is None:
                continue
            try:
                result = func(data, len(data))
                if expected_length in (None, 0) or len(result) == expected_length:
                    return result
                if expected_length and len(result) > expected_length:
                    return result[:expected_length]
                return result
            except Exception as exc:
                errors.append(f"{attr}: {exc}")
    if errors:
        raise FirmwareParseError("; ".join(errors))
    raise FirmwareParseError("EFI standard decompression unavailable")


def _decompress_gzip(data: bytes) -> bytes:
    try:
        return gzip.decompress(data)
    except OSError:
        pass
    for wbits in (16 + zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            return zlib.decompress(data, wbits)
        except zlib.error:
            continue
    raise FirmwareParseError("gzip decompression failed")


def _decompress_zlib(data: bytes, expected_length: Optional[int] = None) -> bytes:
    last_msgs: List[str] = []
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        remaining = data
        out = bytearray()
        try:
            while remaining:
                d = zlib.decompressobj(wbits)
                out += d.decompress(remaining)
                remaining = d.unused_data or d.unconsumed_tail
                out += d.flush()
                if expected_length and expected_length > 0 and len(out) >= expected_length:
                    return bytes(out[:expected_length])
            if out:
                return bytes(out if not expected_length else out[:expected_length])
        except zlib.error as exc:
            msg = str(exc)
            if "NEED_DICT" in msg or "Error -2" in msg:
                last_msgs.append("requires a preset zlib dictionary (Z_NEED_DICT)")
            else:
                last_msgs.append(msg)
            continue
    raise FirmwareParseError(
        "zlib decompression failed" + (": " + "; ".join(last_msgs) if last_msgs else "")
    )


def _decompress_lzma_custom(data: bytes, expected_length: Optional[int]) -> bytes:
    errors: List[str] = []
    if not data:
        return b""
    seen: set[bytes] = set()
    attempts: List[tuple[str, bytes, Optional[int]]] = []

    def _queue(label: str, stream: bytes, length_hint: Optional[int]) -> None:
        if not stream or stream in seen:
            return
        seen.add(stream)
        attempts.append((label, stream, length_hint))

    _queue("base", data, expected_length)
    for skip in (4, 8, 12, 16, 20, 24, 28, 32):
        if len(data) > skip + 5:
            _queue(f"skip{skip}", data[skip:], expected_length)
    search_limit = min(len(data), 0x40)
    for pos in range(1, search_limit):
        if len(data) - pos <= 5:
            break
        _queue(f"pos{pos}", data[pos:], expected_length)

    for label, stream, _ in attempts:
        local: List[str] = []
        if _efi_compressor is not None:
            fn = getattr(_efi_compressor, "LzmaDecompress", None)
            if fn is not None:
                try:
                    return fn(stream, len(stream))
                except Exception as exc:
                    local.append(f"{label} LzmaDecompress: {exc}")
        for fmt_label, kwargs in (
            ("FORMAT_ALONE", {"format": lzma.FORMAT_ALONE}),
            ("AUTO", {}),
        ):
            try:
                return lzma.decompress(stream, **kwargs)
            except lzma.LZMAError as exc:
                local.append(f"{label} {fmt_label}: {exc}")
        if len(stream) >= 5:
            props = stream[0]
            dict_size = int.from_bytes(stream[1:5], "little", signed=False)
            payload = stream[5:]
            pb = props // 45
            rem = props - pb * 45
            lp = rem // 9
            lc = rem - lp * 9
            if 0 <= lc <= 8 and 0 <= lp <= 4 and 0 <= pb <= 4 and lc + lp <= 8 and dict_size > 0:
                try:
                    dec = lzma.LZMADecompressor(
                        format=lzma.FORMAT_RAW,
                        filters=[{
                            "id": lzma.FILTER_LZMA1,
                            "dict_size": dict_size,
                            "lc": lc, "lp": lp, "pb": pb,
                        }],
                    )
                    out = dec.decompress(payload)
                    if not dec.eof:
                        out += dec.decompress(b"")
                    return out
                except lzma.LZMAError as exc:
                    local.append(f"{label} RAW: {exc}")
        errors.extend(local)
    raise FirmwareParseError(
        "; ".join(dict.fromkeys(errors)) if errors else "LZMA decompress failed"
    )


# --- GUID-defined section decompression ---
# Keep GUID constants here to avoid circular deps from ffs.py
try:
    from .guids import (  # type: ignore
        GUID_AMDCOMP,
        GUID_AMDZLIB,
        GUID_AMDZLIB2,
        GUID_LZMA,
        GUID_LZMAF86,
        EFI_GUIDED_SECTION_CRC32,
        EFI_GUIDED_SECTION_GZIP,
        EFI_GUIDED_SECTION_LZMA,
        EFI_GUIDED_SECTION_LZMA_HP,
        EFI_GUIDED_SECTION_LZMA_MS,
        EFI_GUIDED_SECTION_LZMAF86,
        EFI_GUIDED_SECTION_TIANO,
        EFI_GUIDED_SECTION_ZLIB_AMD,
        EFI_GUIDED_SECTION_ZLIB_AMD2,
    )
except Exception:  # pragma: no cover
    # If GUIDs aren't available, function below will behave conservatively
    GUID_AMDCOMP = GUID_AMDZLIB = GUID_AMDZLIB2 = GUID_LZMA = GUID_LZMAF86 = None  # type: ignore
    EFI_GUIDED_SECTION_CRC32 = EFI_GUIDED_SECTION_GZIP = None  # type: ignore
    EFI_GUIDED_SECTION_LZMA = EFI_GUIDED_SECTION_LZMA_HP = EFI_GUIDED_SECTION_LZMA_MS = EFI_GUIDED_SECTION_LZMAF86 = None  # type: ignore
    EFI_GUIDED_SECTION_TIANO = EFI_GUIDED_SECTION_ZLIB_AMD = EFI_GUIDED_SECTION_ZLIB_AMD2 = None  # type: ignore


def decompress_guid_defined(guid: UUID, preamble: bytes, data: bytes) -> Optional[bytes]:
    """Decompress a GUID-defined section payload.

    Returns uncompressed bytes, or None if GUID is unknown/opaque.
    May raise FirmwareParseError on recognized GUIDs when the payload
    fails to decompress.
    """
    # ---- Non-LZMA helpers ----
    def _candidate_streams() -> List[bytes]:
        if preamble:
            return [preamble + data, data]
        return [data]

    # ---------------- LZMA GUIDs ----------------
    if guid in {
        GUID_LZMA, EFI_GUIDED_SECTION_LZMA, EFI_GUIDED_SECTION_LZMA_HP,
        EFI_GUIDED_SECTION_LZMA_MS, GUID_LZMAF86, EFI_GUIDED_SECTION_LZMAF86
    }:
        errors: List[str] = []
        if not data:
            return b""

        # AMD split-header repair (construct true 13-byte ALONE header)
        if len(preamble) >= 4 and len(data) >= 10:
            def _decode_lzma_props(prop: int) -> Optional[Tuple[int, int, int]]:
                if not (0 <= prop < 225):
                    return None
                pb = prop // 45
                rem = prop - pb * 45
                lp = rem // 9
                lc = rem - lp * 9
                if lc > 8 or lp > 4 or pb > 4 or lc + lp > 8:
                    return None
                return lc, lp, pb

            def _try_alone(stream: bytes) -> Optional[bytes]:
                if not stream:
                    return None
                try:
                    return lzma.decompress(stream, format=lzma.FORMAT_ALONE)
                except lzma.LZMAError:
                    return None

            def _try_raw_with(props_dict: bytes, payload: bytes) -> Optional[bytes]:
                if len(props_dict) < 5:
                    return None
                props = props_dict[0]
                dict_size = int.from_bytes(props_dict[1:5], "little", signed=False)
                decoded = _decode_lzma_props(props)
                if decoded is None:
                    return None
                lc, lp, pb = decoded
                if dict_size <= 0:
                    dict_size = 1 << 20
                try:
                    dec = lzma.LZMADecompressor(
                        format=lzma.FORMAT_RAW,
                        filters=[{
                            "id": lzma.FILTER_LZMA1,
                            "dict_size": dict_size,
                            "lc": lc, "lp": lp, "pb": pb,
                        }],
                    )
                    out = dec.decompress(payload)
                    if not dec.eof:
                        out += dec.decompress(b"")
                    return out
                except lzma.LZMAError:
                    return None

            props = preamble[0]
            if _decode_lzma_props(props) is not None:
                dict_le = preamble[1:4] + data[0:1]
                usize_le = data[1:9]
                header13 = bytes([props]) + dict_le + usize_le

                candidate_offsets: List[int] = [9]
                if len(data) >= 13 and data[9:13] in (b"\x00\x06\x00\x30", b"\x30\x00\x06\x00"):
                    candidate_offsets.append(13)
                candidate_offsets.extend(x for x in range(9, min(len(data), 26)) if x not in candidate_offsets)

                for off in candidate_offsets:
                    out = _try_alone(header13 + data[off:])
                    if out is not None:
                        return out

                props_dict = bytes([props]) + dict_le
                for off in candidate_offsets:
                    maybe = _try_raw_with(props_dict, data[off:])
                    if maybe is not None:
                        return maybe

        # Some vendors pack a full ALONE header in preamble
        if len(preamble) >= 13:
            out = None
            try:
                out = lzma.decompress(preamble[:13] + data, format=lzma.FORMAT_ALONE)
            except lzma.LZMAError:
                out = None
            if out is not None:
                return out

        # Try body as ALONE (non-AMD)
        try:
            out = lzma.decompress(data, format=lzma.FORMAT_ALONE)
            return out
        except lzma.LZMAError:
            pass

        # RAW with body props
        if len(data) >= 5:
            props = data[:5]
            payload = data[5:]
            try:
                dec = lzma.LZMADecompressor(
                    format=lzma.FORMAT_RAW,
                    filters=[{
                        "id": lzma.FILTER_LZMA1,
                        "dict_size": int.from_bytes(props[1:5], "little", signed=False),
                        "lc": props[0] % 9,
                        "lp": (props[0] // 9) % 5,
                        "pb": props[0] // 45,
                    }],
                )
                out = dec.decompress(payload)
                if not dec.eof:
                    out += dec.decompress(b"")
                return out
            except lzma.LZMAError:
                pass

        # Optional vendor backend last
        backend = get_efi_compression_backend()
        if backend is not None:
            func = getattr(backend, "LzmaDecompress", None)
            if func is not None:
                try:
                    return func(data, len(data))
                except Exception:
                    pass

        raise FirmwareParseError("LZMA decompress failed")

    # ---------------- Tiano/standard ----------------
    if guid in {EFI_GUIDED_SECTION_TIANO, GUID_AMDCOMP}:
        for stream in _candidate_streams():
            try:
                return _decompress_standard(stream, expected_length=None)
            except Exception:
                continue
        raise FirmwareParseError("EFI standard decompression unavailable")

    # ---------------- gzip ----------------
    if guid in {EFI_GUIDED_SECTION_GZIP}:
        for stream in _candidate_streams():
            try:
                return _decompress_gzip(stream)
            except Exception:
                continue
        raise FirmwareParseError("gzip decompression failed")

    # ---------------- AMD zlib variants + new GUID (deflate-like) ----------------
    if guid in {
        GUID_AMDZLIB, GUID_AMDZLIB2, EFI_GUIDED_SECTION_ZLIB_AMD, EFI_GUIDED_SECTION_ZLIB_AMD2,
    }:
        def _len_hint_from_preamble(p: bytes) -> Optional[int]:
            for w in (4, 8):
                if len(p) >= w:
                    v = int.from_bytes(p[:w], "little", signed=False)
                    if 0 < v <= 0x40000000:
                        return v
            return None

        size_hint = _len_hint_from_preamble(preamble)
        errors: List[str] = []
        for stream in _candidate_streams():
            try:
                return _decompress_deflate_like(stream, expected_length=size_hint)
            except FirmwareParseError as exc:
                errors.append(f"zlib: {exc}")
        for stream in _candidate_streams():
            try:
                return _decompress_standard(stream, expected_length=size_hint)
            except Exception as exc:
                errors.append(f"efi: {exc}")
        msg = "; ".join(dict.fromkeys(errors)) if errors else "zlib decompression failed"
        raise FirmwareParseError(msg)

    # ---------------- CRC32 pass-through ----------------
    if guid in {EFI_GUIDED_SECTION_CRC32}:
        if len(data) >= 4:
            return data[4:]
        return b""

    # Unknown GUID: treat as opaque
    return None
