# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""Utilities for parsing AMD microcode patch headers (type 0x66)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

import struct


class MicrocodeParseError(RuntimeError):
    """Raised when a microcode payload cannot be parsed."""


@dataclass(frozen=True)
class MicrocodeHeader:
    """Represents the fixed 0x20-byte header found in microcode patches."""

    year: int
    day: int
    month: int
    update_revision: int
    loader_id: int
    data_size: int
    initialization_flag: int
    data_checksum: int
    northbridge_vendor_id: int
    northbridge_device_id: int
    southbridge_vendor_id: int
    southbridge_device_id: int
    processor_signature: int
    northbridge_revision_id: int
    southbridge_revision_id: int
    bios_api_revision: int
    load_control: int
    reserved_1e: int
    reserved_1f: int

    @property
    def cpuid(self) -> str:
        signature = int(self.processor_signature) & 0xFFFF
        return f"{(signature >> 8) & 0xFF:02X}0F{signature & 0xFF:02X}"

    @property
    def date_tuple(self) -> Tuple[int, int, int]:
        """Return the (year, month, day) tuple for convenience."""

        return (self.year, self.month, self.day)


_HEADER_SIZE = 0x20


def parse_microcode_patch(blob: bytes) -> tuple[MicrocodeHeader, bytes]:
    """
    Parse *blob* into a :class:MicrocodeHeader and payload bytes.
    Parameters:
        blob:
            Raw bytes containing the microcode patch entry.  The first 0x20 bytes
            encode the metadata header.

    Returns:
        tuple
            '(header, body)' where *header* is the decoded
            :class:`MicrocodeHeader` instance and *body* contains the remaining
            payload bytes after the header.
    """

    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError("Microcode payload must be bytes-like")
    data = bytes(blob)
    if len(data) < _HEADER_SIZE:
        raise MicrocodeParseError(
            f"Microcode payload is too small (expected >= 0x{_HEADER_SIZE:02X} bytes)"
        )

    year, day, month = struct.unpack_from("<HBB", data, 0x00)
    update_revision = struct.unpack_from("<I", data, 0x04)[0]
    loader_id, data_size, initialization_flag = struct.unpack_from("<HBB", data, 0x08)
    data_checksum = struct.unpack_from("<I", data, 0x0C)[0]
    northbridge_vendor_id, northbridge_device_id = struct.unpack_from("<HH", data, 0x10)
    southbridge_vendor_id, southbridge_device_id = struct.unpack_from("<HH", data, 0x14)
    processor_signature = struct.unpack_from("<H", data, 0x18)[0]
    (
        northbridge_revision_id,
        southbridge_revision_id,
        bios_api_revision,
        load_control,
        reserved_1e,
        reserved_1f,
    ) = struct.unpack_from("<6B", data, 0x1A)

    header = MicrocodeHeader(
        year=year,
        day=day,
        month=month,
        update_revision=update_revision,
        loader_id=loader_id,
        data_size=data_size,
        initialization_flag=initialization_flag,
        data_checksum=data_checksum,
        northbridge_vendor_id=northbridge_vendor_id,
        northbridge_device_id=northbridge_device_id,
        southbridge_vendor_id=southbridge_vendor_id,
        southbridge_device_id=southbridge_device_id,
        processor_signature=processor_signature,
        northbridge_revision_id=northbridge_revision_id,
        southbridge_revision_id=southbridge_revision_id,
        bios_api_revision=bios_api_revision,
        load_control=load_control,
        reserved_1e=reserved_1e,
        reserved_1f=reserved_1f,
    )

    body = data[_HEADER_SIZE:]
    return header, body
