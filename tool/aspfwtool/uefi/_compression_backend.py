# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Native EDK2 compression backend loader.

This module provides a ctypes wrapper around the EDK2 compression library
for EFI standard (Tiano) compression and decompression operations.

The backend library is optional; pure Python fallbacks are used when unavailable.
"""

from __future__ import annotations

import ctypes
import platform
from pathlib import Path
from typing import Any, Callable, Optional


class _CtypesCompressor:
    """Minimal wrapper around EDK2 compression routines exposed via ctypes."""

    def __init__(self, library: ctypes.CDLL) -> None:
        self._lib = library
        size_t = ctypes.c_size_t
        status_t = ctypes.c_int

        self._bind_info_decompress("EfiGetInfo", "EfiDecompress", size_t, status_t)
        self._bind_info_decompress("TianoGetInfo", "TianoDecompress", size_t, status_t)

        self._lib.EfiCompress.argtypes = [ctypes.c_void_p, size_t, ctypes.c_void_p, ctypes.POINTER(size_t)]
        self._lib.EfiCompress.restype = status_t
        self._lib.TianoCompress.argtypes = [ctypes.c_void_p, size_t, ctypes.c_void_p, ctypes.POINTER(size_t)]
        self._lib.TianoCompress.restype = status_t

        if hasattr(self._lib, "LzmaDecompress"):
            self._lib.LzmaDecompress.argtypes = [ctypes.c_void_p, size_t]
            self._lib.LzmaDecompress.restype = ctypes.c_void_p
        if hasattr(self._lib, "LzmaCompress"):
            self._lib.LzmaCompress.argtypes = [ctypes.c_void_p, size_t]
            self._lib.LzmaCompress.restype = ctypes.c_void_p

    def _bind_info_decompress(
        self,
        info_name: str,
        decompress_name: str,
        size_type: Any,
        status_type: Any
    ) -> None:
        info = getattr(self._lib, info_name)
        decompress = getattr(self._lib, decompress_name)
        info.argtypes = [ctypes.c_void_p, size_type, ctypes.POINTER(size_type), ctypes.POINTER(size_type)]
        info.restype = status_type
        decompress.argtypes = [
            ctypes.c_void_p,
            size_type,
            ctypes.c_void_p,
            size_type,
            ctypes.c_void_p,
            size_type,
        ]
        decompress.restype = status_type

    def _decompress(
        self,
        data: bytes,
        *,
        info_func: Callable,
        decompress_func: Callable,
    ) -> bytes:
        if not data:
            return b""
        src_buf = ctypes.create_string_buffer(data)
        size_type = ctypes.c_size_t
        dst_size = size_type()
        scratch_size = size_type()
        status = info_func(src_buf, len(data), ctypes.byref(dst_size), ctypes.byref(scratch_size))
        if status != 0:
            raise RuntimeError(f"compression info failure: {status}")
        dst_buf = (ctypes.c_uint8 * dst_size.value)()
        scratch_len = scratch_size.value
        scratch_buf = (ctypes.c_uint8 * scratch_len)() if scratch_len else None
        scratch_ptr = scratch_buf if scratch_buf is not None else ctypes.c_void_p()
        status = decompress_func(
            src_buf,
            len(data),
            dst_buf,
            dst_size.value,
            scratch_ptr,
            scratch_len,
        )
        if status != 0:
            raise RuntimeError(f"compression failure: {status}")
        return bytes(dst_buf)

    def EfiDecompress(self, data: bytes, _length: int) -> bytes:  # noqa: N802
        return self._decompress(
            data,
            info_func=self._lib.EfiGetInfo,
            decompress_func=self._lib.EfiDecompress,
        )

    def TianoDecompress(self, data: bytes, _length: int) -> bytes:  # noqa: N802
        return self._decompress(
            data,
            info_func=self._lib.TianoGetInfo,
            decompress_func=self._lib.TianoDecompress,
        )

    def _compress(self, data: bytes, *, func: Callable) -> bytes:
        if not data:
            return b""
        size_type = ctypes.c_size_t
        dest_len = max(len(data) + 0x200, len(data) * 2)
        while True:
            dst_buf = (ctypes.c_uint8 * dest_len)()
            size_holder = size_type(dest_len)
            status = func(data, len(data), dst_buf, ctypes.byref(size_holder))
            if status == 0:
                return bytes(dst_buf[: size_holder.value])
            if status != 5:  # EFI_BUFFER_TOO_SMALL
                raise RuntimeError(f"compression failure: {status}")
            dest_len *= 2

    def EfiCompress(self, data: bytes, _length: int) -> bytes:  # noqa: N802
        return self._compress(data, func=self._lib.EfiCompress)

    def TianoCompress(self, data: bytes, _length: int) -> bytes:  # noqa: N802
        return self._compress(data, func=self._lib.TianoCompress)

    def LzmaDecompress(self, data: bytes, _length: int) -> bytes:  # noqa: N802
        if not hasattr(self._lib, "LzmaDecompress"):
            raise RuntimeError("LZMA decompression unavailable in fallback library")
        return ctypes.string_at(self._lib.LzmaDecompress(data, len(data)))

    def LzmaCompress(self, data: bytes, _length: int) -> bytes:  # noqa: N802
        if not hasattr(self._lib, "LzmaCompress"):
            raise RuntimeError("LZMA compression unavailable in fallback library")
        return ctypes.string_at(self._lib.LzmaCompress(data, len(data)))


def _load_vendor_library() -> Optional[ctypes.CDLL]:
    system = platform.system().lower()
    arch = platform.machine().lower()
    if system != "linux" or arch not in {"x86_64", "amd64"}:
        return None
    vendor_path = Path(__file__).with_name("_vendor") / "linux_x86_64" / "efi_compressor.so"
    if not vendor_path.exists():
        return None
    try:
        return ctypes.CDLL(str(vendor_path))
    except OSError:
        return None


def get_backend() -> Optional[object]:
    try:
        from uefi_firmware import efi_compressor  # type: ignore

        return efi_compressor
    except Exception:
        pass

    library = _load_vendor_library()
    if library is None:
        return None
    try:
        return _CtypesCompressor(library)
    except Exception:
        return None
