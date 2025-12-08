# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
PS1 header parsing for AMD PSP firmware entries.

Uses native Python struct module with dataclasses for readable binary parsing.
"""

import struct
from dataclasses import dataclass
from typing import ClassVar, Optional, Tuple


PS1_HEADER_LEN = 0x100


@dataclass(frozen=True)
class PS1Header:
    """Parsed $PS1 header metadata (256 bytes total)."""

    # Raw field offsets and meanings:
    # 0x00-0x0F: reserved
    # 0x10-0x13: magic "$PS1"
    # 0x14: size_signed - Size of signed region
    # 0x18: encrypted - Encryption flag (1=encrypted)
    # 0x1C-0x1F: reserved
    # 0x20-0x2F: iv - Initialization vector for AES decryption (16 bytes)
    # 0x30: signed_flag - Signing flag
    # 0x34: signature_type - 0x0=256B RSA, 0x2=512B RSA
    # 0x38-0x47: signature_fingerprint - 16 bytes
    # 0x48: compressed - Compression flag (1=compressed)
    # 0x4C: unknown_4c
    # 0x50: size_uncompressed - Uncompressed size
    # 0x54: zlib_size - Compressed size
    # 0x58: bitfield - Big-endian bitfield
    # 0x5C-0x5F: reserved
    # 0x60-0x63: version_raw - 4 bytes version
    # 0x64-0x67: reserved
    # 0x68: load_addr - Load address
    # 0x6C: rom_size - ROM size
    # 0x70-0x7F: reserved
    # 0x80-0x8F: wrapped_key - Wrapped AES key for decryption (16 bytes)
    # 0x90-0xCF: reserved
    # 0xD0-0xFF: sha_region - 48 bytes SHA region

    size_signed: int
    encrypted: int
    iv: bytes                    # 16 bytes - AES initialization vector (0x20-0x2F)
    signed_flag: int
    signature_type: int
    signature_fingerprint: bytes
    compressed: int
    unknown_4c: int
    size_uncompressed: int
    zlib_size: int
    bitfield: int
    version_raw: bytes
    load_addr: int
    rom_size: int
    wrapped_key: bytes           # 16 bytes - Wrapped AES key (0x80-0x8F)
    sha_region: bytes

    # Format string for struct parsing (little-endian unless noted)
    # We parse specific fields at known offsets
    _MAGIC_OFFSET: ClassVar[int] = 0x10
    _MAGIC: ClassVar[bytes] = b"$PS1"

    @classmethod
    def parse(cls, data: bytes) -> Optional["PS1Header"]:
        """Parse PS1 header from 256 bytes of data."""
        if len(data) < PS1_HEADER_LEN:
            return None
        if data[cls._MAGIC_OFFSET:cls._MAGIC_OFFSET + 4] != cls._MAGIC:
            return None
        
        try:
            # Parse individual fields at their offsets
            size_signed = struct.unpack_from("<I", data, 0x14)[0]
            encrypted = struct.unpack_from("<I", data, 0x18)[0]
            iv = data[0x20:0x30]  # 16-byte AES IV
            signed_flag = struct.unpack_from("<I", data, 0x30)[0]
            signature_type = struct.unpack_from("<I", data, 0x34)[0]
            signature_fingerprint = data[0x38:0x48]
            compressed = struct.unpack_from("<I", data, 0x48)[0]
            unknown_4c = struct.unpack_from("<I", data, 0x4C)[0]
            size_uncompressed = struct.unpack_from("<I", data, 0x50)[0]
            zlib_size = struct.unpack_from("<I", data, 0x54)[0]
            bitfield = struct.unpack_from(">I", data, 0x58)[0]  # Big-endian
            version_raw = data[0x60:0x64]
            load_addr = struct.unpack_from("<I", data, 0x68)[0]
            rom_size = struct.unpack_from("<I", data, 0x6C)[0]
            wrapped_key = data[0x80:0x90]  # 16-byte wrapped AES key
            sha_region = data[0xD0:0x100]
            
            
            return cls(
                size_signed=size_signed,
                encrypted=encrypted,
                iv=bytes(iv),
                signed_flag=signed_flag,
                signature_type=signature_type,
                signature_fingerprint=bytes(signature_fingerprint),
                compressed=compressed,
                unknown_4c=unknown_4c,
                size_uncompressed=size_uncompressed,
                zlib_size=zlib_size,
                bitfield=bitfield,
                version_raw=bytes(version_raw),
                load_addr=load_addr,
                rom_size=rom_size,
                wrapped_key=bytes(wrapped_key),
                sha_region=bytes(sha_region),
            )
        except Exception:
            return None

    @property
    def is_encrypted(self) -> bool:
        return bool(self.encrypted)

    @property
    def is_compressed(self) -> bool:
        return bool(self.compressed)

    @property
    def has_valid_iv(self) -> bool:
        """Check if IV is non-zero (valid for decryption)."""
        return self.iv != (b'\x00' * 16)

    @property
    def has_valid_wrapped_key(self) -> bool:
        """Check if wrapped key is non-zero (valid for decryption)."""
        return self.wrapped_key != (b'\x00' * 16)

    @property
    def has_encryption_keys(self) -> bool:
        """Check if both IV and wrapped key are present for decryption."""
        return self.is_encrypted and self.has_valid_iv and self.has_valid_wrapped_key

    @property
    def has_sha256_checksum(self) -> bool:
        """Check if SHA256 checksum is present (bitfield bit 0)."""
        return bool(self.bitfield & 0b01)

    @property
    def has_sha384_checksum(self) -> bool:
        """Check if SHA384 checksum is present (bitfield bit 1)."""
        return bool(self.bitfield & 0b10)

    @property
    def signature_length(self) -> int:
        if self.signature_type == 0x0:
            return 0x100
        if self.signature_type == 0x2:
            return 0x200
        return 0

    def resolve_rom_size(self, off: int, total_len: int, size_hint: Optional[int]) -> int:
        rom_size = int(self.rom_size)
        if rom_size <= 0:
            rom_size = int(size_hint or (total_len - off))
        return max(0, min(rom_size, total_len - off))

    def body_range(self, off: int, total_len: int, size_hint: Optional[int]) -> Tuple[int, int]:
        body_start = off + PS1_HEADER_LEN
        rom_size = self.resolve_rom_size(off, total_len, size_hint)
        sig_len = self.signature_length
        body_end = off + max(0, rom_size - sig_len)
        body_end = min(max(body_end, body_start), total_len)
        return body_start, body_end

    def signature_range(self, off: int, total_len: int, size_hint: Optional[int]) -> Optional[Tuple[int, int]]:
        sig_len = self.signature_length
        if sig_len <= 0:
            return None
        rom_size = self.resolve_rom_size(off, total_len, size_hint)
        sig_off = off + max(0, rom_size - sig_len)
        sig_off = max(off, min(sig_off, total_len))
        sig_end = min(sig_off + sig_len, total_len)
        if sig_end <= sig_off:
            return None
        return sig_off, sig_end


def parse_ps1_header(buf: bytes, off: int) -> Optional[PS1Header]:
    """Parse a $PS1 header at ``off`` if present."""
    if off < 0 or off + PS1_HEADER_LEN > len(buf):
        return None
    return PS1Header.parse(buf[off:off + PS1_HEADER_LEN])


def resolve_body_range(
    buf: bytes, off: int, size_hint: Optional[int]
) -> Optional[Tuple[PS1Header, int, int]]:
    # Return (header, body_start, body_end) for a PS1 entry.

    hdr = parse_ps1_header(buf, off)
    if hdr is None:
        return None
    start, end = hdr.body_range(off, len(buf), size_hint)
    return hdr, start, end


def read_ps1_body(
    buf: bytes, off: int, size_hint: Optional[int] = None
) -> Optional[Tuple[PS1Header, bytes]]:
    # Return (header, body_bytes) for a PS1 entry, or ``None``.

    resolved = resolve_body_range(buf, off, size_hint)
    if resolved is None:
        return None
    hdr, start, end = resolved
    return hdr, bytes(memoryview(buf)[start:end])

