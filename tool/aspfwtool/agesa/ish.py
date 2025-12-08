# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
ISH (Image Slot Header) parsing for AMD PSP firmware.
"""

import struct
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Mapping, Optional

from .constants import Directory, is_level2_dir
from .utils import platform_names_for_pspid


# ISH support

ISH_LEN = 32


@dataclass(frozen=True)
class ISHEntry:
    """
    ISH entry structure (32 bytes).
        Layout:
        - 0x00: checksum (Fletcher-32 over bytes 0x04-0x1F)
        - 0x04: boot_priority (0xFFFFFFFF=A, 0x00000001=B, 0=unbootable)
        - 0x08: update_retry_count (typically 1 for BIOS)
        - 0x0C: glitch_retry_count (typically 0 for BIOS)
        - 0x0D: reserved_0d (3 bytes)
        - 0x10: location_pointer (ROM offset to $PL2 or $BL2)
        - 0x14: pspid (SoC PSP ID, e.g., 0xBC0D0300 for RPL)
        - 0x18: slot_max_size (max slot size in bytes)
        - 0x1C: reserved_1c (4 bytes)
    """

    checksum: int  # 4 bytes - Fletcher-32
    boot_priority: int  # 4 bytes
    update_retry_count: int  # 4 bytes
    glitch_retry_count: int  # 1 byte
    reserved_0d: bytes  # 3 bytes
    location_pointer: int  # 4 bytes
    pspid: int  # 4 bytes
    slot_max_size: int  # 4 bytes
    reserved_1c: int  # 4 bytes

    _FORMAT: ClassVar[str] = "<III B3s IIII"  # 32 bytes total
    _SIZE: ClassVar[int] = 32

    @classmethod
    def parse(cls, data: bytes) -> "ISHEntry":
        """Parse ISH entry from 32 bytes."""
        (
            checksum,
            boot_priority,
            update_retry_count,
            glitch_retry_count,
            reserved_0d,
            location_pointer,
            pspid,
            slot_max_size,
            reserved_1c,
        ) = struct.unpack(cls._FORMAT, data[: cls._SIZE])
        return cls(
            checksum=checksum,
            boot_priority=boot_priority,
            update_retry_count=update_retry_count,
            glitch_retry_count=glitch_retry_count,
            reserved_0d=reserved_0d,
            location_pointer=location_pointer,
            pspid=pspid,
            slot_max_size=slot_max_size,
            reserved_1c=reserved_1c,
        )

    @classmethod
    def build(cls, fields: Dict) -> bytes:
        """Build ISH entry bytes from field dictionary."""
        reserved_0d = fields.get("reserved_0D", b"\x00\x00\x00")
        if isinstance(reserved_0d, int):
            reserved_0d = reserved_0d.to_bytes(3, "little")
        return struct.pack(
            cls._FORMAT,
            fields.get("checksum", 0) & 0xFFFFFFFF,
            fields.get("boot_priority", 0) & 0xFFFFFFFF,
            fields.get("update_retry_count", 0) & 0xFFFFFFFF,
            fields.get("glitch_retry_count", 0) & 0xFF,
            bytes(reserved_0d[:3]),
            fields.get("location_pointer", 0) & 0xFFFFFFFF,
            fields.get("pspid", 0) & 0xFFFFFFFF,
            fields.get("slot_max_size", 0) & 0xFFFFFFFF,
            fields.get("reserved_1C", 0) & 0xFFFFFFFF,
        )


def _fletcher32_le(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    mod = 0xFFFF
    length = len(data)
    for idx in range(0, length, 2):
        word = data[idx]
        if idx + 1 < length:
            word |= data[idx + 1] << 8
        sum1 = (sum1 + word) % mod
        sum2 = (sum2 + sum1) % mod
    return ((sum2 << 16) | sum1) & 0xFFFFFFFF


def _ish_record_ok(blob: bytes, file_size: int | None = None) -> bool:
    # Be permissive: real-world images sometimes differ on checksum variant
    if len(blob) != 32:
        return False
    loc = int.from_bytes(blob[0x10:0x14], "little", signed=False)
    if file_size is not None and not (0 <= loc < file_size):
        return False
    # PSPID often has 0xBC top byte, but don't require that
    return True


def try_parse_ish_at(buf: bytes, off: int) -> Optional[ISHEntry]:
    """Probe for ISH at an address (used when $PSP/$PL2 entries are ISH stubs)."""
    if off is None or off < 0 or off + ISH_LEN > len(buf):
        return None
    blob = buf[off : off + ISH_LEN]
    if not _ish_record_ok(blob, len(buf)):
        return None
    try:
        rec = ISHEntry.parse(blob)
    except Exception:
        return None
    loc = rec.location_pointer
    if not (0 <= loc < len(buf)):
        return None
    return rec


def parse_ish_bytes(blob: bytes) -> Optional[Dict[str, int]]:
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < ISH_LEN:
        return None
    try:
        rec = ISHEntry.parse(bytes(blob[:ISH_LEN]))
    except Exception:
        return None
    reserved = rec.reserved_0d
    if not isinstance(reserved, (bytes, bytearray)):
        reserved = b"\x00\x00\x00"
    reserved_int = int.from_bytes(bytes(reserved[:3]), "little", signed=False)
    return {
        "checksum": rec.checksum & 0xFFFFFFFF,
        "boot_priority": rec.boot_priority & 0xFFFFFFFF,
        "update_retry_count": rec.update_retry_count & 0xFFFFFFFF,
        "glitch_retry_count": rec.glitch_retry_count & 0xFF,
        "location_pointer": rec.location_pointer & 0xFFFFFFFF,
        "pspid": rec.pspid & 0xFFFFFFFF,
        "slot_max_size": rec.slot_max_size & 0xFFFFFFFF,
        "reserved_0d": reserved_int & 0xFFFFFF,
        "reserved_1c": rec.reserved_1c & 0xFFFFFFFF,
    }


def ish_defaults(slot: int | str | None = None) -> Dict[str, int]:
    slot_code: Optional[int]
    if isinstance(slot, str):
        token = slot.strip().upper()
        if token.endswith("B"):
            slot_code = 0x4A
        elif token.endswith("A"):
            slot_code = 0x48
        else:
            slot_code = None
    elif isinstance(slot, int):
        slot_code = slot & 0xFF
    else:
        slot_code = None
    if slot_code == 0x4A:
        boot_priority = 0x00000001
    else:
        boot_priority = 0xFFFFFFFF
    return {
        "boot_priority": boot_priority,
        "update_retry_count": 1,
        "glitch_retry_count": 0,
        "location_pointer": 0,
        "pspid": 0,
        "slot_max_size": 0,
        "reserved_0d": 0,
        "reserved_1c": 0,
    }


def build_ish_stub(fields: Mapping[str, int]) -> bytes:
    base = ish_defaults(None)
    for key, value in fields.items():
        try:
            base[key] = int(value)
        except Exception:
            continue
    reserved = int(base.get("reserved_0d", 0)) & 0xFFFFFF
    entry = {
        "checksum": 0,
        "boot_priority": int(base.get("boot_priority", 0)) & 0xFFFFFFFF,
        "update_retry_count": int(base.get("update_retry_count", 0)) & 0xFFFFFFFF,
        "glitch_retry_count": int(base.get("glitch_retry_count", 0)) & 0xFF,
        "reserved_0D": reserved.to_bytes(3, "little"),
        "location_pointer": int(base.get("location_pointer", 0)) & 0xFFFFFFFF,
        "pspid": int(base.get("pspid", 0)) & 0xFFFFFFFF,
        "slot_max_size": int(base.get("slot_max_size", 0)) & 0xFFFFFFFF,
        "reserved_1C": int(base.get("reserved_1c", 0)) & 0xFFFFFFFF,
    }
    blob = bytearray(ISHEntry.build(entry))
    blob[0:4] = b"\x00\x00\x00\x00"
    checksum = _fletcher32_le(blob)
    blob[0:4] = int(checksum).to_bytes(4, "little")
    return bytes(blob)


def scan_ish_entries_pointing_to_lv2(buf: bytes, lv2_offsets: List[int]):
    out = []
    for lv2 in lv2_offsets:
        tag = lv2.to_bytes(4, "little")
        start = 0
        while True:
            idx = buf.find(tag, start)
            if idx < 0:
                break
            start = idx + 1
            # Try PSP layout (location at +0x10) and BIOS layout (location at +0x08)
            for delta in (-0x10, -0x08):
                rec_off = idx + delta
                rec = try_parse_ish_at(buf, rec_off)
                if not rec:
                    continue
                loc = int(rec.get("location_pointer", -1))
                pspid = int(rec.get("pspid", 0))
                if loc != lv2:
                    continue
                names = platform_names_for_pspid(pspid)
                if not names:
                    continue
                out.append({"location_pointer": loc, "pspid": pspid, "names": names})
                break  # prefer first valid layout
    # Deduplicate by (location, pspid) so multiple PSPIDs per PL2 survive
    uniq = {}
    for h in out:
        key = (int(h["location_pointer"]), int(h["pspid"]))
        if key not in uniq:
            uniq[key] = h
    # emit one record per (location, pspid)
    return list(uniq.values())


def platform_label_from_ish(buf: bytes, dirs: Optional[list[Directory]]):
    if not dirs:
        return "", {}
    lv2_offsets = [d.offset for d in dirs if is_level2_dir(d.kind)]
    if not lv2_offsets:
        return "", {}

    hits = scan_ish_entries_pointing_to_lv2(buf, lv2_offsets)

    if not hits:
        return "", {}

    def _names_for_pspid(pspid: int) -> list[str]:
        names = platform_names_for_pspid(int(pspid)) or []
        return names if names else [f"0x{int(pspid):08X}"]

    all_pspids: set[int] = set()
    by_lv2_pspids: dict[int, set[int]] = {}

    for h in hits:
        # Defensive key extraction
        pspid = h.get("pspid")
        loc = (
            h.get("location_pointer")
            or h.get("location_ptr")
            or h.get("offset")
            or h.get("loc")
        )
        # Parse PSPID
        try:
            pspid = int(pspid)
        except Exception:
            continue

        # Normalize PL2 location (offset)
        if isinstance(loc, str) and loc.lower().startswith("0x"):
            try:
                loc = int(loc, 16)
            except Exception:
                loc = None

        all_pspids.add(pspid)
        if isinstance(loc, int):
            by_lv2_pspids.setdefault(loc, set()).add(pspid)

    # Build global label
    global_names: set[str] = set()
    for pid in sorted(all_pspids):
        global_names.update(_names_for_pspid(pid))
    global_label = ",".join(sorted(global_names)) if global_names else ""

    # Per-dir labels
    per_dir_labels: dict[int, str] = {}
    for off, pid_set in by_lv2_pspids.items():
        names: set[str] = set()
        for pid in sorted(pid_set):
            names.update(_names_for_pspid(pid))
        per_dir_labels[off] = ",".join(sorted(names))

    return global_label, per_dir_labels
