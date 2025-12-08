# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
EFS (Embedded Firmware Structure) parsing for AMD firmware images.

Uses native Python struct module with dataclasses for readable binary parsing.
"""

import struct
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional, Sequence, Tuple

from .constants import DirKind
from .utils import normalize_rom_ptr, is_u32_ptr, cookie_kind_at
from ..utils.debug_logger import get_logger


# EFS support

EFS_SIG = 0x55AA55AA
UBU_TABLE_SIG = 0x55425524  # $UBU
# Candidate offsets within a 16MB window
_EFS_WINDOW_OFFSETS = (
    0x00020000,  # 16MB base
    0x00120000,  # special base observed on some images
    0x00820000,  # 8MB base
    0x00C20000,  # 4MB base
    0x00E20000,  # 2MB base
    0x00F20000,  # 1MB base
    0x00FA0000,  # 512KB base
)


@dataclass(frozen=True)
class EFSHeader:
    """
    EFS (Embedded Firmware Structure) header - 0x4B bytes parsed.
        Layout:
        - 0x00: Signature (0x55AA55AA)
        - 0x04: IMC_FW_Address_Legacy
        - 0x08: GBE_FW_Address_Legacy
        - 0x0C: xHCI_FW_Address_Legacy
        - 0x10: PSP_Directory_Table_Legacy
        - 0x14: PSP_Directory_Table_Combo
        - 0x18: BIOS_Directory_F17h_M00h
        - 0x1C: BIOS_Directory_F17h_M10h
        - 0x20: BIOS_Directory_F17h_M30h
        - 0x24: EFS_Generation
        - 0x28: BIOS_Directory_Combo
        - 0x2C: PSP_L1_Backup
        - 0x30: Prom_FW
        - 0x34: LP_Prom_FW
        - 0x38-0x3F: reserved (8 bytes)
        - 0x40: SPI_ReadMode_F15h_M60h
        - 0x41: SPI_FastSpeed_F15h_M60h
        - 0x42: reserved (1 byte)
        - 0x43: SPI_ReadMode_F17h_M00h
        - 0x44: SPI_FastSpeed_F17h_M00h
        - 0x45: QPR_Dummy_Cycle_F17h_M00h
        - 0x46: reserved (1 byte)
        - 0x47: SPI_ReadMode_F17h_M30h
        - 0x48: SPI_FastSpeed_F17h_M30h
        - 0x49: SPI_Micron_Detect_F17h_M30h
        - 0x4A: reserved (1 byte)
    """
    Signature: int
    IMC_FW_Address_Legacy: int
    GBE_FW_Address_Legacy: int
    xHCI_FW_Address_Legacy: int
    PSP_Directory_Table_Legacy: int
    PSP_Directory_Table_Combo: int
    BIOS_Directory_F17h_M00h: int
    BIOS_Directory_F17h_M10h: int
    BIOS_Directory_F17h_M30h: int
    EFS_Generation: int
    BIOS_Directory_Combo: int
    PSP_L1_Backup: int
    Prom_FW: int
    LP_Prom_FW: int
    SPI_ReadMode_F15h_M60h: int
    SPI_FastSpeed_F15h_M60h: int
    SPI_ReadMode_F17h_M00h: int
    SPI_FastSpeed_F17h_M00h: int
    QPR_Dummy_Cycle_F17h_M00h: int
    SPI_ReadMode_F17h_M30h: int
    SPI_FastSpeed_F17h_M30h: int
    SPI_Micron_Detect_F17h_M30h: int

    # Format: 14 uint32s + 8 reserved + 2 bytes + 1 reserved + 3 bytes + 1 reserved + 3 bytes + 1 reserved
    _FORMAT: ClassVar[str] = "<14I 8x BB x BBB x BBB x"
    _SIZE: ClassVar[int] = 0x4B  # 75 bytes

    @classmethod
    def sizeof(cls) -> int:
        """Return the size of the EFS header."""
        return cls._SIZE

    @classmethod
    def parse(cls, data: bytes) -> "EFSHeader":
        """Parse EFS header from bytes."""
        if len(data) < cls._SIZE:
            raise ValueError(f"Data too short: {len(data)} < {cls._SIZE}")
        
        # Parse the 14 uint32 fields first
        uint32_fields = struct.unpack_from("<14I", data, 0)
        
        # Parse the SPI config bytes at their specific offsets
        spi_read_f15 = data[0x40]
        spi_fast_f15 = data[0x41]
        spi_read_f17_00 = data[0x43]
        spi_fast_f17_00 = data[0x44]
        qpr_dummy = data[0x45]
        spi_read_f17_30 = data[0x47]
        spi_fast_f17_30 = data[0x48]
        spi_micron = data[0x49]
        
        return cls(
            Signature=uint32_fields[0],
            IMC_FW_Address_Legacy=uint32_fields[1],
            GBE_FW_Address_Legacy=uint32_fields[2],
            xHCI_FW_Address_Legacy=uint32_fields[3],
            PSP_Directory_Table_Legacy=uint32_fields[4],
            PSP_Directory_Table_Combo=uint32_fields[5],
            BIOS_Directory_F17h_M00h=uint32_fields[6],
            BIOS_Directory_F17h_M10h=uint32_fields[7],
            BIOS_Directory_F17h_M30h=uint32_fields[8],
            EFS_Generation=uint32_fields[9],
            BIOS_Directory_Combo=uint32_fields[10],
            PSP_L1_Backup=uint32_fields[11],
            Prom_FW=uint32_fields[12],
            LP_Prom_FW=uint32_fields[13],
            SPI_ReadMode_F15h_M60h=spi_read_f15,
            SPI_FastSpeed_F15h_M60h=spi_fast_f15,
            SPI_ReadMode_F17h_M00h=spi_read_f17_00,
            SPI_FastSpeed_F17h_M00h=spi_fast_f17_00,
            QPR_Dummy_Cycle_F17h_M00h=qpr_dummy,
            SPI_ReadMode_F17h_M30h=spi_read_f17_30,
            SPI_FastSpeed_F17h_M30h=spi_fast_f17_30,
            SPI_Micron_Detect_F17h_M30h=spi_micron,
        )


@dataclass(frozen=True)
class UBUHeader:
    """
    UBU table header structure.
        Layout:
        - 0x00: Signature ($UBU = 0x55425524)
        - 0x04: Checksum (Fletcher32)
        - 0x08: TableSize (2 bytes)
        - 0x0A: Version (1 byte)
        - 0x0B: Action (1 byte - AfterUBU, LED, Beep flags)
        - 0x0C-0x17: FileName (8.3 DOS format, 12 bytes)
        - 0x18: CapsuleHeaderAddr
        - 0x1C: CapsuleHeaderSize
    """
    Signature: int
    Checksum: int
    TableSize: int
    Version: int
    Action: int
    CapsuleHeaderAddr: int
    CapsuleHeaderSize: int

    _FORMAT: ClassVar[str] = "<II HBB 12x II"  # 32 bytes
    _SIZE: ClassVar[int] = 0x20

    @classmethod
    def parse(cls, data: bytes) -> "UBUHeader":
        """Parse UBU header from bytes."""
        if len(data) < cls._SIZE:
            raise ValueError(f"Data too short: {len(data)} < {cls._SIZE}")
        
        sig, checksum, table_size, version, action, cap_addr, cap_size = struct.unpack(
            cls._FORMAT, data[:cls._SIZE]
        )
        return cls(
            Signature=sig,
            Checksum=checksum,
            TableSize=table_size,
            Version=version,
            Action=action,
            CapsuleHeaderAddr=cap_addr,
            CapsuleHeaderSize=cap_size,
        )


# Backward compatibility alias
EFS_STRUCT = EFSHeader


# Lookup Tables
SPI_FASTSPEED_TABLE: Dict[int, str] = {
    0x00: "66.66MHz",
    0x01: "33.33MHz",
    0x02: "22.22MHz",
    0x03: "16.66MHz",
    0x04: "100MHz",
    0x05: "800kHz",
}

SPI_READMODE_TABLE: Dict[int, str] = {
    0x00: "Normal read (33MHz)",
    0x01: "Reserved",
    0x02: "Dual IO (1-1-2)",
    0x03: "Quad IO (1-1-4)",
    0x04: "Dual IO (1-2-2)",
    0x05: "Quad IO (1-4-4)",
    0x06: "Normal read (66MHz)",
    0x07: "Fast Read",
}

SPI_MICRON_TABLE: Dict[int, str] = {
    0x55: "Force Micron detection",
    0xAA: "Force Micron dummycycle",
}

SPI_QPR_DUMMY_TABLE: Dict[int, str] = {
    0x0A: "Micron SPI chips",
    0xFF: "Non-Micron SPI chips",
}

# eSPI Configuration Tables
ESPI_OFFSET = 0x50  # Relative offset within EFS region (0x20050 from segment base)

ESPI_ALERT_MODE_TABLE: Dict[int, str] = {
    0: "Directly routed",
    1: "Virtual wire",
}

ESPI_DATA_BUS_TABLE: Dict[int, str] = {
    0: "Single data",
    1: "Dual data",
}

ESPI_CLOCK_PIN_TABLE: Dict[int, str] = {
    0: "24MHz",
    1: "48MHz",
}

ESPI_DEVICE_CAP_TABLE: Dict[int, str] = {
    0: "Single IO",
    1: "Dual IO",
}

ESPI_IO_MODE_TABLE: Dict[int, str] = {
    0: "Single IO",
    1: "Dual IO",
    2: "Quad IO",
    3: "Reserved",
}

ESPI_FREQ_TABLE: Dict[int, str] = {
    0: "16.7MHz",
    1: "33MHz",
    2: "66MHz",
    3: "Reserved",
    4: "Reserved",
    5: "Reserved",
    6: "Reserved",
    7: "Reserved",
}

# UBU Table Constants
UBU_PTR_OFFSET = 0x54  # Relative offset within EFS region (0x20054 from segment base)

UBU_ACTION_AFTER_TABLE: Dict[int, str] = {
    0: "Continue boot",
    1: "Reset system",
}

UBU_ACTION_LED_TABLE: Dict[int, str] = {
    0: "Disabled",
    1: "Enabled",
}

UBU_ACTION_BEEP_TABLE: Dict[int, str] = {
    0: "Disabled",
    1: "Enabled",
}


@dataclass
class EspiChannelInfo:
    """eSPI channel configuration (eSPI0 or eSPI1)."""
    valid: bool
    enable_80_port: bool
    alert_mode: int
    alert_mode_str: str
    data_bus: int
    data_bus_str: str
    clock_pin: int
    clock_pin_str: str
    device_capability: int
    device_capability_str: str
    io_mode: int
    io_mode_str: str
    raw_value: int


@dataclass
class EspiConfigInfo:
    """eSPI configuration (eSPI0Config or eSPI1Config)."""
    enhancement: bool
    frequency: int
    frequency_str: str
    raw_value: int


@dataclass
class EspiInfo:
    """Complete eSPI configuration information."""
    offset: int
    espi0: Optional[EspiChannelInfo]
    espi1: Optional[EspiChannelInfo]
    espi0_config: Optional[EspiConfigInfo]
    espi1_config: Optional[EspiConfigInfo]
    raw_bytes: bytes


@dataclass
class UbuProtectedRegion:
    """UBU protected region entry."""
    offset: int
    length: int


@dataclass
class UbuInfo:
    """UBU table information."""
    pointer_offset: int
    table_offset: int
    valid: bool
    signature: int
    checksum: int
    table_size: int
    version: int
    action_after_ubu: int
    action_after_ubu_str: str
    action_led: int
    action_led_str: str
    action_beep: int
    action_beep_str: str
    filename: str
    capsule_header_addr: int
    capsule_header_size: int
    protected_regions: List[UbuProtectedRegion]
    signature_protection: Optional[bytes]
    bios_version_protection: Optional[int]


def _segment_base(offset: int) -> int:
    # Return the 16MB-aligned base for an EFS located at *offset*.
    if offset <= 0:
        return 0
    return (int(offset) // 0x01000000) * 0x01000000


@dataclass
class EfsPointerStatus:
    label: str
    raw_value: int
    normalized: Optional[int]
    expects_directory: bool
    cookie: Optional[str]
    in_range: bool
    valid: bool


@dataclass
class EfsInfo:
    offset: int
    segment_base: int
    header: any
    pointer_status: Dict[str, EfsPointerStatus]
    generation_raw: int
    second_generation: Optional[bool]
    multigen_mask: Optional[int]
    score: int
    spi_config: Dict[str, Tuple[int, str]]
    espi_info: Optional[EspiInfo] = None
    ubu_info: Optional[UbuInfo] = None
    selected: bool = False


_LAST_SCAN: List[EfsInfo] = []
_LAST_SCAN_SIZE: Optional[int] = None
_LAST_SCAN_TOKEN: Optional[Tuple[int, int]] = None
_LAST_SELECTED_OFFSET: Optional[int] = None


# eSPI Parsing Functions

def _parse_espi_channel(data: int) -> EspiChannelInfo:
    """Parse a single eSPI channel byte."""
    return EspiChannelInfo(
        valid=bool(data & 0x01),
        enable_80_port=bool(data & 0x02),
        alert_mode=(data >> 2) & 0x01,
        alert_mode_str=ESPI_ALERT_MODE_TABLE.get((data >> 2) & 0x01, "Unknown"),
        data_bus=(data >> 3) & 0x01,
        data_bus_str=ESPI_DATA_BUS_TABLE.get((data >> 3) & 0x01, "Unknown"),
        clock_pin=(data >> 4) & 0x01,
        clock_pin_str=ESPI_CLOCK_PIN_TABLE.get((data >> 4) & 0x01, "Unknown"),
        device_capability=(data >> 5) & 0x01,
        device_capability_str=ESPI_DEVICE_CAP_TABLE.get((data >> 5) & 0x01, "Unknown"),
        io_mode=(data >> 6) & 0x03,
        io_mode_str=ESPI_IO_MODE_TABLE.get((data >> 6) & 0x03, "Unknown"),
        raw_value=data,
    )


def _parse_espi_config(data: int) -> EspiConfigInfo:
    """Parse a single eSPI config byte."""
    return EspiConfigInfo(
        enhancement=bool(data & 0x01),
        frequency=(data >> 1) & 0x07,
        frequency_str=ESPI_FREQ_TABLE.get((data >> 1) & 0x07, "Unknown"),
        raw_value=data,
    )


def parse_espi_info(buf: bytes, efs_offset: int) -> Optional[EspiInfo]:
    """Parse eSPI configuration from buffer at given EFS offset."""
    segment_base = _segment_base(efs_offset)
    espi_offset = segment_base + 0x20000 + ESPI_OFFSET  # 0x20050 relative to segment
    
    if espi_offset + 4 > len(buf):
        return None
    
    raw_bytes = bytes(buf[espi_offset:espi_offset + 4])
    if len(raw_bytes) < 4:
        return None
    
    # Check if all 0xFF (unprogrammed)
    if raw_bytes == b'\xFF\xFF\xFF\xFF':
        return None
    
    return EspiInfo(
        offset=espi_offset,
        espi0=_parse_espi_channel(raw_bytes[0]),
        espi1=_parse_espi_channel(raw_bytes[1]),
        espi0_config=_parse_espi_config(raw_bytes[2]),
        espi1_config=_parse_espi_config(raw_bytes[3]),
        raw_bytes=raw_bytes,
    )


# UBU Parsing Functions

def _fletcher32(data: bytes) -> int:
    """Calculate Fletcher32 checksum."""
    words = len(data) // 2
    sum1 = 0
    sum2 = 0
    for i in range(words):
        word = data[i * 2] | (data[i * 2 + 1] << 8)
        sum1 = (sum1 + word) % 0xFFFF
        sum2 = (sum2 + sum1) % 0xFFFF
    return (sum2 << 16) | sum1


def parse_ubu_info(buf: bytes, efs_offset: int) -> Optional[UbuInfo]:
    """Parse UBU table from buffer at given EFS offset."""
    segment_base = _segment_base(efs_offset)
    ubu_ptr_offset = segment_base + 0x20000 + UBU_PTR_OFFSET  # 0x20054 relative to segment
    
    if ubu_ptr_offset + 4 > len(buf):
        return None
    
    # Read UBU table pointer
    ubu_ptr_raw = int.from_bytes(buf[ubu_ptr_offset:ubu_ptr_offset + 4], 'little')
    
    # Check if pointer is valid (not 0xFFFFFFFF or 0)
    if ubu_ptr_raw == 0xFFFFFFFF or ubu_ptr_raw == 0:
        return None
    
    # Normalize pointer to file offset
    table_offset = normalize_rom_ptr(ubu_ptr_raw)
    if table_offset is None:
        table_offset = ubu_ptr_raw
    
    # Handle segment-relative offset
    if table_offset < 0x01000000:
        table_offset = segment_base + table_offset
    
    if table_offset + 0x20 > len(buf):
        return None
    
    # Read and verify signature
    signature = int.from_bytes(buf[table_offset:table_offset + 4], 'little')
    if signature != UBU_TABLE_SIG:
        return None
    
    # Parse UBU header
    checksum = int.from_bytes(buf[table_offset + 0x04:table_offset + 0x08], 'little')
    table_size = int.from_bytes(buf[table_offset + 0x08:table_offset + 0x0A], 'little')
    version = buf[table_offset + 0x0A]
    action = buf[table_offset + 0x0B]
    
    # Parse action flags
    action_after_ubu = action & 0x01
    action_led = (action >> 1) & 0x01
    action_beep = (action >> 2) & 0x01
    
    # Parse filename (8.3 DOS format, 12 bytes at 0x0C)
    filename_bytes = buf[table_offset + 0x0C:table_offset + 0x18]
    filename = filename_bytes.rstrip(b'\xFF\x00').decode('ascii', errors='replace')
    
    # Parse capsule header info
    capsule_header_addr = int.from_bytes(buf[table_offset + 0x18:table_offset + 0x1C], 'little')
    capsule_header_size = int.from_bytes(buf[table_offset + 0x1C:table_offset + 0x20], 'little')
    
    # Parse protected regions (10 regions, 8 bytes each starting at 0x20)
    protected_regions: List[UbuProtectedRegion] = []
    if table_offset + 0x70 <= len(buf):
        for i in range(10):
            region_offset = table_offset + 0x20 + (i * 8)
            if region_offset + 8 > len(buf):
                break
            offset_val = int.from_bytes(buf[region_offset:region_offset + 4], 'little')
            length_val = int.from_bytes(buf[region_offset + 4:region_offset + 8], 'little')
            # Only add non-empty regions
            if offset_val != 0xFFFFFFFF and length_val != 0xFFFFFFFF and length_val > 0:
                protected_regions.append(UbuProtectedRegion(offset=offset_val, length=length_val))
    
    # Parse signature protection (16 bytes at 0x70) if table is large enough
    signature_protection: Optional[bytes] = None
    if table_size >= 0x80 and table_offset + 0x80 <= len(buf):
        sig_prot_bytes = buf[table_offset + 0x70:table_offset + 0x80]
        if sig_prot_bytes != b'\xFF' * 16:
            signature_protection = bytes(sig_prot_bytes)
    
    # Parse BIOS version backward protection (2 bytes at 0x80)
    bios_version_protection: Optional[int] = None
    if table_size >= 0x82 and table_offset + 0x82 <= len(buf):
        bvp = int.from_bytes(buf[table_offset + 0x80:table_offset + 0x82], 'little')
        if bvp != 0xFFFF:
            bios_version_protection = bvp
    
    return UbuInfo(
        pointer_offset=ubu_ptr_offset,
        table_offset=table_offset,
        valid=True,
        signature=signature,
        checksum=checksum,
        table_size=table_size,
        version=version,
        action_after_ubu=action_after_ubu,
        action_after_ubu_str=UBU_ACTION_AFTER_TABLE.get(action_after_ubu, "Unknown"),
        action_led=action_led,
        action_led_str=UBU_ACTION_LED_TABLE.get(action_led, "Unknown"),
        action_beep=action_beep,
        action_beep_str=UBU_ACTION_BEEP_TABLE.get(action_beep, "Unknown"),
        filename=filename,
        capsule_header_addr=capsule_header_addr,
        capsule_header_size=capsule_header_size,
        protected_regions=protected_regions,
        signature_protection=signature_protection,
        bios_version_protection=bios_version_protection,
    )


# Entry iteration utilities (used by CLI)



def _candidate_offsets(file_size: int) -> List[int]:
    if file_size <= 0:
        return []
    segments = max(1, (file_size + 0x0FFFFF) // 0x01000000)
    offsets: List[int] = []
    for seg in range(segments):
        base = seg * 0x01000000
        for rel in _EFS_WINDOW_OFFSETS:
            off = base + rel
            if 0 <= off <= file_size - 0x4C:
                offsets.append(off)
    # Deduplicate while preserving order
    seen = set()
    uniq: List[int] = []
    for off in offsets:
        if off not in seen:
            uniq.append(off)
            seen.add(off)
    return uniq


def _describe_spi_field(value: int, table: Dict[int, str]) -> Tuple[int, str]:
    value = int(value) & 0xFF
    return value, table.get(value, f"0x{value:02X}")


def _build_spi_config(header: EFSHeader) -> Dict[str, Tuple[int, str]]:
    return {
        "SPI_ReadMode_F15h_M60h": _describe_spi_field(
            header.SPI_ReadMode_F15h_M60h, SPI_READMODE_TABLE
        ),
        "SPI_FastSpeed_F15h_M60h": _describe_spi_field(
            header.SPI_FastSpeed_F15h_M60h, SPI_FASTSPEED_TABLE
        ),
        "SPI_ReadMode_F17h_M00h": _describe_spi_field(
            header.SPI_ReadMode_F17h_M00h, SPI_READMODE_TABLE
        ),
        "SPI_FastSpeed_F17h_M00h": _describe_spi_field(
            header.SPI_FastSpeed_F17h_M00h, SPI_FASTSPEED_TABLE
        ),
        "QPR_Dummy_Cycle_F17h_M00h": _describe_spi_field(
            header.QPR_Dummy_Cycle_F17h_M00h, SPI_QPR_DUMMY_TABLE
        ),
        "SPI_ReadMode_F17h_M30h": _describe_spi_field(
            header.SPI_ReadMode_F17h_M30h, SPI_READMODE_TABLE
        ),
        "SPI_FastSpeed_F17h_M30h": _describe_spi_field(
            header.SPI_FastSpeed_F17h_M30h, SPI_FASTSPEED_TABLE
        ),
        "SPI_Micron_Detect_F17h_M30h": _describe_spi_field(
            header.SPI_Micron_Detect_F17h_M30h, SPI_MICRON_TABLE
        ),
    }


_POINTER_DEFS: Sequence[Tuple[str, str, Optional[Tuple[DirKind, ...]]]] = (
    ("IMC_FW_Address_Legacy", "IMC FW", None),
    ("GBE_FW_Address_Legacy", "GbE FW", None),
    ("xHCI_FW_Address_Legacy", "xHCI FW", None),
    ("Prom_FW", "Prom FW", None),
    ("LP_Prom_FW", "LP Prom FW", None),
    ("PSP_Directory_Table_Combo", "PSP Combo", (DirKind.COMBO_PSP, DirKind.PSP_L1)),
    ("PSP_Directory_Table_Legacy", "PSP Legacy", (DirKind.PSP_L1, DirKind.COMBO_PSP)),
    ("PSP_L1_Backup", "PSP L1 Backup", (DirKind.PSP_L1, DirKind.COMBO_PSP)),
    ("BIOS_Directory_Combo", "BIOS Combo", (DirKind.COMBO_BHD, DirKind.BHD_L1)),
    ("BIOS_Directory_F17h_M30h", "BIOS F17h M30h", (DirKind.BHD_L1, DirKind.COMBO_BHD)),
    ("BIOS_Directory_F17h_M10h", "BIOS F17h M10h", (DirKind.BHD_L1, DirKind.COMBO_BHD)),
    ("BIOS_Directory_F17h_M00h", "BIOS F17h M00h", (DirKind.BHD_L1, DirKind.COMBO_BHD)),
)


def _evaluate_pointer(
    buf: bytes,
    raw_val: int,
    label: str,
    expect: Optional[Tuple[DirKind, ...]],
    segment_base: int,
) -> EfsPointerStatus:
    raw_val &= 0xFFFFFFFF
    if raw_val == 0:
        return EfsPointerStatus(label, raw_val, None, expect is not None, None, False, False)

    norm = normalize_rom_ptr(raw_val)
    if norm is None:
        return EfsPointerStatus(label, raw_val, None, expect is not None, None, False, False)

    fs = len(buf)

    def _candidate(value: int) -> Tuple[int, bool, Optional[str], bool]:
        in_range = is_u32_ptr(value, fs)
        cookie = cookie_kind_at(buf, value) if in_range else None
        valid = bool(expect and cookie in expect)
        return value, in_range, cookie, valid

    candidates: List[Tuple[int, bool, Optional[str], bool]] = []

    prefer_segment = bool(segment_base) and norm < 0x01000000 and expect is not None
    if prefer_segment:
        candidates.append(_candidate(int(segment_base + norm)))

    candidates.append(_candidate(int(norm)))

    if not prefer_segment and segment_base and norm < 0x01000000:
        candidates.append(_candidate(int(segment_base + norm)))

    deduped: List[Tuple[int, bool, Optional[str], bool]] = []
    seen_values: set[int] = set()
    for entry in candidates:
        val = entry[0]
        if val in seen_values:
            continue
        seen_values.add(val)
        deduped.append(entry)

    chosen: Optional[Tuple[int, bool, Optional[str], bool]] = None
    for entry in deduped:
        val, in_range, _, valid = entry
        if in_range and valid:
            chosen = entry
            break
    if chosen is None:
        for entry in deduped:
            val, in_range, _, _ = entry
            if in_range:
                chosen = entry
                break
    if chosen is None and deduped:
        chosen = deduped[0]

    if chosen is None:
        return EfsPointerStatus(label, raw_val, None, expect is not None, None, False, False)

    value, in_range, cookie, valid = chosen
    return EfsPointerStatus(label, raw_val, value, expect is not None, cookie, in_range, valid)


def _pointer_status_for(
    buf: bytes,
    header,
    name: str,
    label: str,
    expect: Optional[Tuple[str, ...]],
    segment_base: int,
) -> EfsPointerStatus:
    raw_val = int(getattr(header, name, 0)) & 0xFFFFFFFF
    return _evaluate_pointer(buf, raw_val, label, expect, segment_base)


def _collect_infos(buf: bytes) -> List[EfsInfo]:
    global _LAST_SCAN, _LAST_SCAN_SIZE, _LAST_SCAN_TOKEN
    infos: List[EfsInfo] = []
    fs = len(buf)
    for off in _candidate_offsets(fs):
        try:
            header = EFSHeader.parse(buf[off : off + EFSHeader.sizeof()])
        except Exception:
            continue
        if header.Signature != EFS_SIG:
            continue
        segment_base = _segment_base(off)
        pointer_map: Dict[str, EfsPointerStatus] = {}
        for name, label, expect in _POINTER_DEFS:
            pointer_map[label] = _pointer_status_for(
                buf, header, name, label, expect, segment_base
            )
        score = sum(1 for st in pointer_map.values() if st.expects_directory and st.valid)
        raw_gen = header.EFS_Generation & 0xFFFFFFFF
        second_gen: Optional[bool]
        if raw_gen == 0:
            second_gen = None
        else:
            second_gen = (raw_gen & 0x1) == 0
        multigen_mask = raw_gen & 0xFFFF if raw_gen else None
        
        # Parse eSPI and UBU info
        espi_info = parse_espi_info(buf, off)
        ubu_info = parse_ubu_info(buf, off)
        
        info = EfsInfo(
            offset=off,
            segment_base=segment_base,
            header=header,
            pointer_status=pointer_map,
            generation_raw=raw_gen,
            second_generation=second_gen,
            multigen_mask=multigen_mask,
            score=score,
            spi_config=_build_spi_config(header),
            espi_info=espi_info,
            ubu_info=ubu_info,
        )
        infos.append(info)
    _LAST_SCAN = infos
    _LAST_SCAN_SIZE = fs
    _LAST_SCAN_TOKEN = (id(buf), fs)
    return infos


def _mark_selected(offset: Optional[int]):
    global _LAST_SELECTED_OFFSET
    _LAST_SELECTED_OFFSET = offset
    for info in _LAST_SCAN:
        info.selected = offset is not None and info.offset == offset


def get_cached_efs_infos(buf: Optional[bytes] = None) -> List[EfsInfo]:
    if buf is not None:
        token = (id(buf), len(buf))
        if (_LAST_SCAN_TOKEN != token) or (_LAST_SCAN_SIZE != len(buf)):
            _collect_infos(buf)
    if buf is not None and not _LAST_SCAN:
        _collect_infos(buf)
    _mark_selected(_LAST_SELECTED_OFFSET)
    return _LAST_SCAN


def iter_all_efs_headers(buf: bytes):
    """Yield (offset, EFSHeader) for every valid EFS found at fixed slots."""
    for info in _collect_infos(buf):
        yield info.offset, info.header


def find_valid_efs(
    buf: bytes,
    prefer_offset: int | None = None,
    prefer_index: int | None = None,
):
    logger = get_logger()
    infos = _collect_infos(buf)
    if not infos:
        logger.warning("No valid EFS found in image")
        _mark_selected(None)
        return None, None

    logger.info(f"Found {len(infos)} EFS candidate(s)")
    for idx, info in enumerate(infos):
        logger.debug(f"  EFS #{idx}: offset=0x{info.offset:08X}, score={info.score}")

    selected: Optional[EfsInfo] = None
    if prefer_offset is not None:
        target = prefer_offset & 0xFFFFFFFF
        for info in infos:
            if info.offset == target:
                selected = info
                break

    if selected is None and prefer_index is not None:
        try:
            idx = int(prefer_index)
        except Exception:
            idx = -1
        if 0 <= idx < len(infos):
            selected = infos[idx]

    best: Optional[EfsInfo] = None
    for info in infos:
        if best is None:
            best = info
            continue
        if info.score > best.score:
            best = info
            continue
        if info.score == best.score:
            if (info.second_generation is True) and (best.second_generation is not True):
                best = info
                continue
            if (info.second_generation is True) == (best.second_generation is True):
                if info.offset > best.offset:
                    best = info
    if selected is None and best and best.score > 0:
        selected = best

    if selected is None:
        selected = infos[0]

    logger.info(f"Selected EFS @ 0x{selected.offset:08X} (score={selected.score})")
    _mark_selected(selected.offset)
    return selected.offset, selected.header


def pointer_status_from_value(
    buf: bytes,
    efs_offset: int,
    raw_value: int,
    label: str,
    expect: Optional[Tuple[str, ...]] = None,
) -> EfsPointerStatus:
    # Compute the pointer status for a raw EFS field value.

    segment_base = _segment_base(efs_offset)
    return _evaluate_pointer(buf, int(raw_value) & 0xFFFFFFFF, label, expect, segment_base)


def resolve_efs_pointer(
    buf: bytes,
    efs_offset: int,
    raw_value: int,
    expect: Optional[Tuple[str, ...]] = None,
) -> Optional[int]:
    # Return the mapped ROM offset for an EFS pointer if it is in range.

    status = pointer_status_from_value(buf, efs_offset, raw_value, "", expect)
    if status.normalized is None or not status.in_range:
        return None
    return status.normalized
