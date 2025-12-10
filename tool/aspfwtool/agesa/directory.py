# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Directory parsing for AMD PSP/BIOS firmware structures.

Uses native Python struct module with dataclasses for readable binary parsing.
"""

import struct
from dataclasses import dataclass
from typing import ClassVar, Dict, Optional, List, Tuple

from .constants import (
    Directory,
    DirKind,
    COOKIE_KIND,
    is_combo_dir,
)
from .utils import (
    resolve_entry_offset,
    platform_names_for_pspid,
    resolve_compressed_payload_size,
)
from .entrytypes import lookup_entry_definition, POINT_ENTRY, VALUE_ENTRY
from .ish import platform_label_from_ish
from ..utils.debug_logger import get_logger



# Directory Header Structures


@dataclass(frozen=True)
class DirHeaderCombo:
    """Combo directory header (2PSP/2BHD): 32 bytes total."""
    Cookie: bytes       # 4 bytes - "2PSP"/"2BHD"
    CRC32: int          # 4 bytes - Fletcher-32 checksum
    Count: int          # 4 bytes - number of entries
    Reserved: bytes     # 20 bytes

    _FORMAT: ClassVar[str] = "<4sII20s"  # little-endian: 4s, uint32, uint32, 20s
    _SIZE: ClassVar[int] = 0x20  # 32 bytes

    @classmethod
    def parse(cls, data: bytes) -> "DirHeaderCombo":
        """Parse combo header from bytes."""
        cookie, crc32, count, reserved = struct.unpack(cls._FORMAT, data[:cls._SIZE])
        return cls(Cookie=cookie, CRC32=crc32, Count=count, Reserved=reserved)

    def to_bytes(self) -> bytes:
        """Serialize header back to bytes."""
        return struct.pack(self._FORMAT, self.Cookie, self.CRC32, self.Count, self.Reserved)


@dataclass(frozen=True)
class DirHeaderReal:
    """Real directory header ($PSP/$PL2/$BHD/$BL2): 16 bytes + computed fields."""
    Cookie: bytes       # 4 bytes
    CRC32: int          # 4 bytes
    Count: int          # 4 bytes
    Info: int           # 4 bytes - bitfield

    _FORMAT: ClassVar[str] = "<4sIII"  # little-endian: 4s, uint32, uint32, uint32
    _SIZE: ClassVar[int] = 0x10  # 16 bytes

    @classmethod
    def parse(cls, data: bytes) -> "DirHeaderReal":
        """Parse real header from bytes."""
        cookie, crc32, count, info = struct.unpack(cls._FORMAT, data[:cls._SIZE])
        return cls(Cookie=cookie, CRC32=crc32, Count=count, Info=info)

    def to_bytes(self) -> bytes:
        """Serialize header back to bytes."""
        return struct.pack(self._FORMAT, self.Cookie, self.CRC32, self.Count, self.Info)

    # Computed properties from Info bitfield
    # Version bit at [31] determines layout:
    # Version 0: [9:0]Size [13:10]SpiBlockSize [28:14]BaseAddr [30:29]Mode [31]=0
    # Version 1: [15:0]Size [19:16]SpiBlockSize(power) [23:20]HeaderSize [25:24]Mode [27:26]EntryVer [30:28]Rsvd [31]=1

    @property
    def Version(self) -> int:
        return (self.Info >> 31) & 0x1

    @property
    def MaxSize(self) -> int:
        """Directory size in 4KB units."""
        if self.Version == 1:
            return self.Info & 0xFFFF  # 16 bits for version 1
        else:
            return self.Info & 0x3FF   # 10 bits for version 0

    @property
    def SpiBlockSize(self) -> int:
        """SPI block size field (raw value)."""
        if self.Version == 1:
            return (self.Info >> 16) & 0x0F  # 4 bits, encoded as power of 2
        else:
            return (self.Info >> 10) & 0x0F  # 4 bits, direct value

    @property
    def DirHeaderSize(self) -> int:
        """Directory header size in 1KB units (version 1 only)."""
        if self.Version == 1:
            return (self.Info >> 20) & 0x0F
        else:
            return 0  # Not available in version 0

    @property
    def BaseAddressBits(self) -> int:
        """Base address bits (version 0 only)."""
        if self.Version == 1:
            return 0  # Not available in version 1
        else:
            return (self.Info >> 14) & 0x7FFF  # 15 bits for version 0

    @property
    def AddressMode(self) -> int:
        if self.Version == 1:
            return (self.Info >> 24) & 0x03
        else:
            return (self.Info >> 29) & 0x03

    @property
    def EntryVersion(self) -> int:
        """Entry version (version 1 only)."""
        if self.Version == 1:
            return (self.Info >> 26) & 0x03
        else:
            return 0  # Not available in version 0

    @property
    def BaseAddress(self) -> int:
        return self.BaseAddressBits << 12


def parse_dir_header(buf: bytes, off: int, kind: DirKind):
    """Parse directory header based on kind."""
    if is_combo_dir(kind):
        return DirHeaderCombo.parse(buf[off : off + 0x20])
    else:
        return DirHeaderReal.parse(buf[off : off + 0x10])


def describe_directory_at(buf: bytes, off: int):
    """Describe directory at offset."""
    if off is None or off < 0 or off + 4 > len(buf):
        return None
    cookie = bytes(buf[off : off + 4])
    kind = COOKIE_KIND.get(cookie)
    if not kind:
        return None
    try:
        header = parse_dir_header(buf, off, kind)
    except Exception:
        return {"kind": kind, "offset": off, "count": None}
    count = int(getattr(header, "Count", 0)) if hasattr(header, "Count") else None
    return {"kind": kind, "offset": off, "count": count}


def dir_header_len(kind: DirKind) -> int:
    """Return header length for directory kind."""
    if is_combo_dir(kind):
        return 0x20
    else:
        return 0x10



# Entry Structures


@dataclass(frozen=True)
class EntryCombo:
    """Combo entry: 16 bytes.
    
    Used in 2PSP/2BHD combo directories to point to sub-directories.
    """
    id_select: int    # 4 bytes - identifier/selector (often 0)
    pspid: int        # 4 bytes - PSP ID for platform identification
    location: int     # 8 bytes - pointer to sub-directory

    _FORMAT: ClassVar[str] = "<IIQ"  # little-endian: uint32, uint32, uint64
    _SIZE: ClassVar[int] = 0x10  # 16 bytes

    @classmethod
    def parse(cls, data: bytes) -> "EntryCombo":
        """Parse combo entry from bytes."""
        id_select, pspid, location = struct.unpack(cls._FORMAT, data[:cls._SIZE])
        return cls(id_select=id_select, pspid=pspid, location=location)

    def to_bytes(self) -> bytes:
        """Serialize entry back to bytes."""
        return struct.pack(self._FORMAT, self.id_select, self.pspid, self.location)
    
    # Alias for backward compatibility
    @property
    def u0(self) -> int:
        return self.id_select
    
    @property
    def ptr64(self) -> int:
        return self.location


@dataclass(frozen=True)
class EntryPSP:
    """PSP directory entry: 16 bytes.
    
    PSP_DIRECTORY_ENTRY_TYPE (v0) structure:
    - type_attrib[31:0]:
        - Type[7:0]: Entry type (see PspDirectoryEntryName)
        - SubProgram[15:8]: Sub-program specifier
        - RomId[17:16]: ROM ID
        - Writable[18]: 1=writable, 0=read-only
        - Instance[22:19]: Instance number
        - Reserved[31:23]
    """
    type_id: int      # 4 bytes - type and attribute bits (full 32-bit, named for backward compat)
    size: int         # 4 bytes - entry size in bytes
    location: int     # 8 bytes - source address/pointer

    _FORMAT: ClassVar[str] = "<IIQ"  # little-endian: uint32, uint32, uint64
    _SIZE: ClassVar[int] = 0x10  # 16 bytes

    @classmethod
    def parse(cls, data: bytes) -> "EntryPSP":
        """Parse PSP entry from bytes."""
        type_id, size, location = struct.unpack(cls._FORMAT, data[:cls._SIZE])
        return cls(type_id=type_id, size=size, location=location)

    def to_bytes(self) -> bytes:
        """Serialize entry back to bytes."""
        return struct.pack(self._FORMAT, self.type_id, self.size, self.location)
    
    # Alias for the full type attribute word
    @property
    def type_attrib(self) -> int:
        """Full type/attribute word (same as type_id for backward compat)."""
        return self.type_id
    
    # Decoded type_attrib fields
    @property
    def entry_type(self) -> int:
        """Entry type (bits 7:0)."""
        return self.type_id & 0xFF
    
    @property
    def sub_program(self) -> int:
        """Sub-program specifier (bits 15:8)."""
        return (self.type_id >> 8) & 0xFF
    
    @property
    def rom_id(self) -> int:
        """ROM ID (bits 17:16)."""
        return (self.type_id >> 16) & 0x03
    
    @property
    def writable(self) -> bool:
        """Writable flag (bit 18)."""
        return bool((self.type_id >> 18) & 0x01)
    
    @property
    def instance(self) -> int:
        """Instance number (bits 22:19)."""
        return (self.type_id >> 19) & 0x0F
    
    # Alias for backward compatibility
    @property
    def ptr64(self) -> int:
        return self.location


@dataclass(frozen=True)
class EntryBHD:
    """BIOS (BHD) directory entry: 24 bytes.
    
    BIOS directory entry v0 TYPE_ATTRIB structure:
    - type_id[31:0] (raw field, named for backward compatibility):
        - Type[7:0]: Entry type (see BiosDirectoryEntryName)
        - RegionType[15:8]: 0=Normal, 1=TA1, 2=TA2 memory
        - ResetImage[16]: BIOS Reset Image flag (SEC/EL3 FW authenticated by PSP)
        - Copy[17]: 1=copy image from source to dest, 0=set region attributes
        - ReadOnly[18]: 1=read-only, 0=read-write (for ARM TA1/TA2)
        - Compressed[19]: 1=compressed
        - Instance[23:20]: Instance number
        - SubProgram[26:24]: Sub-program specifier
        - RomId[28:27]: ROM ID
        - Writable[29]: 1=writable, 0=read-only
        - Reserved[31:30]
    """
    type_id: int       # 4 bytes - type and attribute bits (full 32-bit, named for backward compat)
    size: int          # 4 bytes - entry size in bytes
    source: int        # 8 bytes - source address (location in flash)
    destination: int   # 8 bytes - destination address in memory

    _FORMAT: ClassVar[str] = "<IIQQ"  # little-endian: uint32, uint32, uint64, uint64
    _SIZE: ClassVar[int] = 0x18  # 24 bytes

    @classmethod
    def parse(cls, data: bytes) -> "EntryBHD":
        """Parse BHD entry from bytes."""
        type_id, size, source, destination = struct.unpack(cls._FORMAT, data[:cls._SIZE])
        return cls(type_id=type_id, size=size, source=source, destination=destination)

    def to_bytes(self) -> bytes:
        """Serialize entry back to bytes."""
        return struct.pack(self._FORMAT, self.type_id, self.size, self.source, self.destination)
    
    # Alias for the full type attribute word
    @property
    def type_attrib(self) -> int:
        """Full type/attribute word (same as type_id for backward compat)."""
        return self.type_id
    
    # Decoded type_attrib fields
    @property
    def entry_type(self) -> int:
        """Entry type (bits 7:0)."""
        return self.type_id & 0xFF
    
    @property
    def region_type(self) -> int:
        """Region type: 0=Normal, 1=TA1, 2=TA2 memory (bits 15:8)."""
        return (self.type_id >> 8) & 0xFF
    
    @property
    def reset_image(self) -> bool:
        """BIOS Reset Image flag (bit 16)."""
        return bool((self.type_id >> 16) & 0x01)
    
    @property
    def copy(self) -> bool:
        """Copy flag: 1=copy to destination (bit 17)."""
        return bool((self.type_id >> 17) & 0x01)
    
    @property
    def read_only(self) -> bool:
        """Read-only flag (bit 18)."""
        return bool((self.type_id >> 18) & 0x01)
    
    @property
    def compressed(self) -> bool:
        """Compressed flag (bit 19)."""
        return bool((self.type_id >> 19) & 0x01)
    
    @property
    def instance(self) -> int:
        """Instance number (bits 23:20)."""
        return (self.type_id >> 20) & 0x0F
    
    @property
    def sub_program(self) -> int:
        """Sub-program specifier (bits 26:24)."""
        return (self.type_id >> 24) & 0x07
    
    @property
    def rom_id(self) -> int:
        """ROM ID (bits 28:27)."""
        return (self.type_id >> 27) & 0x03
    
    @property
    def writable(self) -> bool:
        """Writable flag (bit 29)."""
        return bool((self.type_id >> 29) & 0x01)
    
    # Aliases for backward compatibility
    @property
    def ptr64(self) -> int:
        return self.source
    
    @property
    def u10(self) -> int:
        """Legacy alias: lower 32 bits of destination."""
        return self.destination & 0xFFFFFFFF
    
    @property
    def u14(self) -> int:
        """Legacy alias: upper 32 bits of destination."""
        return (self.destination >> 32) & 0xFFFFFFFF


# Aliases for readability
EntryRealPL2 = EntryPSP   # PL2 uses same 16-byte format as PSP
EntryRealBL2 = EntryBHD   # BL2 uses same 24-byte format as BHD
EntryReal = EntryPSP      # Default 16-byte entry



# Family Labeling


def build_dir_family_map(buf: bytes, dirs: Optional[List[Directory]]) -> Dict[int, str]:
    """Build mapping of directory offsets to family/platform labels."""
    if not dirs:
        return {}
    fams: Dict[int, List[str]] = {}
    fs = len(buf)

    def _add(off: int, names: List[str]):
        if not names:
            return
        fams.setdefault(off, [])
        for nm in names:
            if nm not in fams[off]:
                fams[off].append(nm)

    # 1) 2PSP/2BHD -> $PSP/$BHD by combo PSPID
    for d in dirs:
        if not is_combo_dir(d.kind):
            continue
        base = d.offset + dir_header_len(d.kind)
        span = entry_span(d.kind)
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
            _add(child_off, platform_names_for_pspid(int(ent.pspid)))

    # 2) $BHD -> $BL2 via type 0x70
    for d in dirs:
        if d.kind != DirKind.BHD_L1:
            continue
        parent = fams.get(d.offset)
        if not parent:
            continue
        base = d.offset + dir_header_len(d.kind)
        span = entry_span(d.kind)
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
            if child_off is not None:
                _add(child_off, parent)

    # 3) $PSP -> $PL2 via 0x40/0x48/0x4A
    for d in dirs:
        if d.kind != DirKind.PSP_L1:
            continue
        parent = fams.get(d.offset)
        if not parent:
            continue
        base = d.offset + dir_header_len(d.kind)
        span = entry_span(d.kind)
        for ei in range(d.count):
            eoff = base + ei * span
            if eoff + span > fs:
                break
            try:
                ent = parse_entry(buf, d.kind, eoff)
            except Exception:
                continue
            if (int(ent.type_id) & 0xFF) not in (0x40, 0x48, 0x4A):
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
            if child_off is not None:
                _add(child_off, parent)

    # 4) $PL2 -> $BL2 via 0x49
    for d in dirs:
        if d.kind != DirKind.PSP_L2:
            continue
        parent = fams.get(d.offset)
        if not parent:
            continue
        base = d.offset + dir_header_len(d.kind)
        span = entry_span(d.kind)
        for ei in range(d.count):
            eoff = base + ei * span
            if eoff + span > fs:
                break
            try:
                ent = parse_entry(buf, d.kind, eoff)
            except Exception:
                continue
            if (int(ent.type_id) & 0xFF) != 0x49:
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
            if child_off is not None:
                _add(child_off, parent)

    # Merge ISH labels (prefer A-slot if present)
    ish_label, ish_by_dir = platform_label_from_ish(buf, dirs)
    if ish_by_dir:
        for off, nm in ish_by_dir.items():
            _add(off, [nm])
    if ish_label:
        for d in dirs:
            if d.offset not in fams or not fams[d.offset]:
                _add(d.offset, [ish_label])

    return {off: ",".join(v) for off, v in fams.items()}



# Entry Utilities


def _bhd_is_compressed(buf: bytes, eoff: int) -> bool:
    """Check if BHD entry at offset is compressed."""
    try:
        b = buf[eoff + 0x02]
    except Exception:
        return False
    return bool((b >> 3) & 1)


def entry_span(kind: DirKind) -> int:
    """Return entry size in bytes for directory kind."""
    if kind in (DirKind.PSP_L1, DirKind.PSP_L2, DirKind.COMBO_PSP, DirKind.COMBO_BHD):
        return 16
    if kind in (DirKind.BHD_L1, DirKind.BHD_L2):
        return 24
    return 16


def parse_entry(buf: bytes, kind: DirKind, at: int):
    """Parse entry at offset based on directory kind."""
    if kind == DirKind.PSP_L1:
        return EntryPSP.parse(buf[at : at + 0x10])
    if kind == DirKind.BHD_L1:
        return EntryBHD.parse(buf[at : at + 0x18])
    if kind == DirKind.PSP_L2:
        return EntryRealPL2.parse(buf[at : at + 0x10])
    if kind == DirKind.BHD_L2:
        return EntryRealBL2.parse(buf[at : at + 0x18])
    if is_combo_dir(kind):
        return EntryCombo.parse(buf[at : at + 0x10])
    return EntryReal.parse(buf[at : at + 0x10])


def iter_entries(buf: bytes, d: Directory):
    """Iterate over entries in a directory, yielding parsed info dicts."""
    logger = get_logger()
    fs = len(buf)
    base = d.offset + dir_header_len(d.kind)
    span = entry_span(d.kind)
    for ei in range(d.count):
        eoff = base + ei * span
        if eoff + span > fs:
            logger.warning(f"Entry {ei} in {d.kind.value} truncated (offset 0x{eoff:X} beyond file)")
            break
        try:
            if is_combo_dir(d.kind):
                ent = parse_entry(buf, d.kind, eoff)
                type_id = None
                size = 0
            else:
                ent = parse_entry(buf, d.kind, eoff)
                type_id = int(ent.type_id) if hasattr(ent, "type_id") else None
                size = int(ent.size) if hasattr(ent, "size") else 0
            declared_size = size
            ptr64 = int(ent.ptr64) if hasattr(ent, "ptr64") else 0
        except Exception as ex:
            logger.error(f"Entry {ei} in {d.kind.value} @ 0x{eoff:X}: parse error - {ex}")
            ent = None
            type_id = None
            size = 0
            declared_size = 0
            ptr64 = 0
        pspid_value = None
        if is_combo_dir(d.kind) and ent is not None:
            try:
                pspid_value = int(getattr(ent, "pspid", None))
            except Exception:
                pspid_value = None
        definition = (
            lookup_entry_definition(d.kind, type_id)
            if isinstance(type_id, int)
            else None
        )
        allow_zero = definition.entry_type == POINT_ENTRY if definition else False
        if is_combo_dir(d.kind):
            allow_zero = True
        compressed = False
        if d.kind in (DirKind.BHD_L1, DirKind.BHD_L2):
            compressed = _bhd_is_compressed(buf, eoff)
        allow_oversize = False
        use_zero_size = False
        resolve_size = size
        declared_size = size
        zlib_pointer = (
            compressed
            and d.kind in (DirKind.BHD_L1, DirKind.BHD_L2)
            and isinstance(type_id, int)
            and (type_id & 0xFF) == 0x62
        )
        inline_mode = False
        inline_offset = None
        value_inline_raw = None
        pointer_to_directory = (
            definition
            and definition.entry_type == POINT_ENTRY
            and isinstance(type_id, int)
            and (
                (d.kind == DirKind.PSP_L1 and (type_id & 0xFF) in (0x48, 0x49, 0x4A))
                or (d.kind == DirKind.BHD_L1 and (type_id & 0xFF) == 0x70)
            )
        )
        if (
            definition
            and definition.entry_type == VALUE_ENTRY
            and isinstance(type_id, int)
            and (type_id & 0xFF) == 0x0B
        ):
            inline_mode = True
            inline_offset = eoff + 8
            resolve_size = size = declared_size = 8
            value_inline_raw = ptr64 & 0xFFFFFFFFFFFFFFFF
            ptr64 = 0
        if zlib_pointer:
            resolve_size = 0
            allow_oversize = True
            use_zero_size = True
        if pointer_to_directory:
            resolve_size = 0
            size = declared_size = 0
            allow_oversize = True
        if inline_mode:
            off, mode = inline_offset, "mode=inline"
        else:
            try:
                off, mode = resolve_entry_offset(
                    d.kind,
                    d.offset,
                    ptr64,
                    resolve_size,
                    fs,
                    False,
                    allow_zero_size=(allow_zero or use_zero_size),
                    allow_oversize=allow_oversize,
                )
            except Exception:
                off, mode = None, "unmapped"
        if zlib_pointer and off is not None:
            try:
                actual = int.from_bytes(
                    buf[int(off) + 0x14 : int(off) + 0x18], "little"
                )
            except Exception:
                actual = None
            # The size at offset 0x14 is just the zlib data size, not including
            # the 0x100 byte header. Add it to get the full entry size in flash.
            zlib_size = resolve_compressed_payload_size(actual, declared_size)
            size = zlib_size + 0x100 if zlib_size > 0 else zlib_size
        yield {
            "index": ei,
            "kind": d.kind,
            "entry": ent,
            "pspid": pspid_value,
            "type_id": type_id,
            "raw_type": (type_id & 0xFF) if isinstance(type_id, int) else None,
            "entry_type": definition.entry_type if definition else None,
            "size": size,
            "declared_size": declared_size,
            "ptr64": None if inline_mode else ptr64,
            "resolved_off": off,
            "mode": mode,
            "compressed": compressed,
            "entry_offset": eoff,
            "inline_raw": value_inline_raw,
            "inline_offset": inline_offset,
        }


def list_entry_ranges(buf: bytes, d: Directory):
    """List merged byte ranges occupied by entries in a directory."""
    fs = len(buf)
    spans = []
    for info in iter_entries(buf, d):
        off = info.get("resolved_off")
        sz = int(info.get("size") or 0)
        if off is None or sz <= 0:
            continue
        s = int(off)
        e = s + sz
        if e <= 0 or s >= fs:
            continue
        if s < 0:
            s = 0
        if e > fs:
            e = fs
        if e > s:
            spans.append((s, e))
    spans.sort(key=lambda t: t[0])
    merged = []
    for s, e in spans:
        if not merged or s > merged[-1][1]:
            merged.append([s, e])
        else:
            merged[-1][1] = max(merged[-1][1], e)
    return [(s, e) for s, e in merged]


def is_bios_compressed(a, b=None) -> bool:
    """Check if BIOS entry is compressed.
    
    Supports two call forms:
    - (buf, entry_offset): Check compression flag in buffer
    - (kind, type_id): Check compression bit in type_id
    """
    # (buf, entry_offset) form
    if isinstance(a, (bytes, bytearray, memoryview)) and isinstance(b, int):
        return _bhd_is_compressed(a, b)
    # (kind, type_id) form
    kind, type_id = a, b
    if kind not in (DirKind.BHD_L1, DirKind.BHD_L2) or not isinstance(type_id, int):
        return False
    return bool((type_id >> 19) & 1)



# Directory Checksum Helpers


def _fletcher32_le(data: bytes, seed: Tuple[int, int]) -> int:
    """Compute Fletcher-32 checksum (little-endian) with seed."""
    sum1, sum2 = seed
    mod = 0xFFFF
    length = len(data)
    for idx in range(0, length, 2):
        word = data[idx]
        if idx + 1 < length:
            word |= data[idx + 1] << 8
        sum1 = (sum1 + word) % mod
        sum2 = (sum2 + sum1) % mod
    return ((sum2 << 16) | sum1) & 0xFFFFFFFF


def detect_directory_checksum_seed(
    buf: bytes, directory: Directory
) -> Optional[Tuple[int, int]]:
    """Detect the checksum seed used for a directory."""
    if directory.offset is None:
        return None
    head = int(directory.offset)
    header_len = dir_header_len(directory.kind)
    span = entry_span(directory.kind)
    total_len = header_len + directory.count * span
    if head < 0 or head + total_len > len(buf):
        return None
    blob = bytearray(buf[head : head + total_len])
    stored = int.from_bytes(blob[4:8], "little", signed=False)
    blob[4:8] = b"\x00\x00\x00\x00"
    for seed in ((0, 0), (0xFFFF, 0xFFFF)):
        if _fletcher32_le(blob, seed) == stored:
            return seed
    return (0, 0)


def compute_directory_checksum(
    buf: bytes, directory: Directory, seed: Optional[Tuple[int, int]] = None
) -> Optional[int]:
    """Compute directory checksum."""
    if directory.offset is None:
        return None
    head = int(directory.offset)
    header_len = dir_header_len(directory.kind)
    span = entry_span(directory.kind)
    total_len = header_len + directory.count * span
    if head < 0 or head + total_len > len(buf):
        return None
    blob = bytearray(buf[head : head + total_len])
    blob[4:8] = b"\x00\x00\x00\x00"
    chosen = (
        seed if seed is not None else detect_directory_checksum_seed(buf, directory)
    )
    if chosen is None:
        chosen = (0, 0)
    return _fletcher32_le(blob, chosen)
