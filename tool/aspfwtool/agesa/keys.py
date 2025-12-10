# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Public Key extraction and provenance tracking for AMD PSP firmware.

This module provides:
    - Key source tracking (which directory/entry a key came from)
    - Key ingestion from various PSP entry types
    - Key database parsing and display utilities
"""

import os
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple

from . import constants as _constants
from . import crypto as _crypto
from . import ps1 as _ps1
from ..utils.debug_logger import get_logger

try:
    from cryptography.hazmat.primitives import serialization
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


""" Key Provenance Tracking """
class KeySource(NamedTuple):
    """
    Location context for a key-bearing entry.
        Attributes:
            directory_index: Index of the directory containing the key.
            entry_index: Index of the entry within the directory.
            address: ROM address of the key entry.
            parent_directory_index: Index of parent directory (for L2 dirs, None for L1/combo).
    """

    directory_index: Optional[int]
    entry_index: Optional[int]
    address: Optional[int]
    parent_directory_index: Optional[int] = None


_KEY_SOURCES: Dict[bytes, List[KeySource]] = {}


def _record_key_source(key_id: bytes, source: Optional[KeySource]) -> None:
    if not key_id or source is None:
        return
    locs = _KEY_SOURCES.setdefault(key_id, [])
    if source not in locs:
        locs.append(source)


def iter_key_sources() -> Dict[bytes, List[KeySource]]:
    """Return a copy of the key-to-locations mapping."""
    return {k: list(v) for k, v in _KEY_SOURCES.items()}


@dataclass(frozen=True)
class ParsedKeyEntry:
    """
    Minimal representation of a key parsed from a KEY_DATABASE block.
        Attributes:
            key_id: 16-byte key identifier.
            exponent: RSA public exponent.
            modulus: RSA modulus as raw bytes.
    """

    key_id: bytes
    exponent: int
    modulus: bytes

    @property
    def bits(self) -> int:
        return len(self.modulus) * 8


@dataclass(frozen=True)
class KeyDisplayRecord:
    """
    Snapshot-friendly description of a key in the global keyring.
        Attributes:
            key_id: 16-byte key identifier.
            bits: Key size in bits (e.g., 2048, 4096).
            entry_locations: Formatted string of entry locations.
            address_locations: Formatted string of address locations.
            public_key: The PublicKey instance.
    """

    key_id: bytes
    bits: int
    entry_locations: str
    address_locations: str
    public_key: Any


def clear_key_sources() -> None:
    _KEY_SOURCES.clear()


def get_key_ids_for_directory(
    directory_index: int,
    parent_directory_index: Optional[int] = None,
) -> set:
    """
    Return set of key_ids valid for the specified directory.
        Args:
            directory_index: The directory index to filter by.
            parent_directory_index: Optional parent directory index. If provided
                (and not a combo directory), keys from parent are also included.
                This allows L2 directories to use keys from their L1 parent.

        Returns:
            Set of key_id bytes for keys that can be used by this directory.
    """
    # Build set of allowed directory indices
    allowed_dirs = {directory_index}
    if parent_directory_index is not None:
        allowed_dirs.add(parent_directory_index)
    
    result = set()
    for key_id, sources in _KEY_SOURCES.items():
        for src in sources:
            if src.directory_index in allowed_dirs:
                result.add(key_id)
                break
    return result



""" Utility Functions """


def _le_u32(b: bytes, off: int) -> int:
    """Read a little-endian 32-bit unsigned integer from bytes."""
    return int.from_bytes(b[off:off+4], "little", signed=False)


""" AMD Public Key Ingestion (Type 0x00), No $PS1 Header, Not signed """


def ingest_amd_pubkey_from_entry(
    kind: str, type_id: int, payload: bytes, source: Optional[KeySource] = None
) -> int:
    """
    Parse and ingest AMD public key blobs while tracking provenance.
        Args:
            kind: Directory kind identifier.
            type_id: Entry type ID.
            payload: Raw entry payload bytes.
            source: Optional source location for provenance tracking.

        Returns:
            Number of keys successfully ingested.
    """

    try:
        zone = "bios" if _constants.is_bios_dir(kind) else "psp"
        if zone != "psp" or (type_id & 0xFF) != 0x00:
            return 0

        parser = getattr(_crypto, "_parse_amd_pubkey_bin", None)
        if not callable(parser):
            return 0

        parsed = parser(payload)
        if not parsed:
            return 0

        key_id, pub = parsed
        added = 1 if _crypto.add_public_key(key_id, pub) else 0
        _record_key_source(key_id, source)
        return added
    except Exception:
        return 0


""" 0x50 KEY_DATABASE ingestion & sequencing helpers """


def _parse_kdb_header(b: bytes, off: int = 0) -> Tuple[int, int, int]:
    """
    KDB header (0x50 bytes). Field order differs across images:
        Variant A:
            00 u32 total_len
            04 u32 version (=1)
        Variant B:
            00 u32 version (=1)
            04 u32 total_len

        Accept both; return (total_len, version, data_start).
    """
    if off + 0x50 > len(b):
        raise ValueError("KDB header truncated")

    # Read both ways and pick the plausible one
    a_total = _le_u32(b, off + 0x00)
    a_ver   = _le_u32(b, off + 0x04)

    b_ver   = _le_u32(b, off + 0x00)
    b_total = _le_u32(b, off + 0x04)

    # Prefer the one with version==1 and a sane total_len
    lim = len(b) - off
    def sane_total(n: int) -> bool:
        return 0x60 <= n <= lim

    if a_ver == 1 and sane_total(a_total):
        return a_total, 1, off + 0x50
    if b_ver == 1 and sane_total(b_total):
        return b_total, 1, off + 0x50

    # Fallback: accept either order for total_len if plausible; force version=1
    if sane_total(a_total):
        return a_total, 1, off + 0x50
    if sane_total(b_total):
        return b_total, 1, off + 0x50

    # Last resort: treat the rest of the buffer as the block
    return lim, 1, off + 0x50


def _parse_kdb_entry(b: bytes, off: int):
    """
    Per-key record (two tolerated layouts). Returns dict or None.

    Layout A (length & mod_bits provided):
      00 u32 total_entry_len (~0x150 or 0x250)
      04 u32 version (=1)
      08 u32 reserved
      0C u32 exponent (LE)
      10 16B key_id
      20 u32 mod_bits (0x800 or 0x1000)
      24..4F reserved
      50.. raw modulus (len = total_entry_len-0x50 or mod_bits/8)

    Layout B (compact header):
      00 u16 short_id (BE when printed)
      02 u16 mod_len (0x0100 or 0x0200)
      04 u32 exponent (LE)
      08..0F reserved
      10 16B key_id
      20..4F reserved
      50.. raw modulus (len = mod_len)

    Exponent may be LE or BE; we accept {3, 65537}, else default 65537.
    Modulus endian: prefer LITTLE-ENDIAN (matches 0x00/EK) then BIG-ENDIAN.
    """
    end = len(b)
    if off + 0x50 > end:
        return None

    # Try Layout A first
    total_entry_len = _le_u32(b, off + 0x00)
    ver_a           = _le_u32(b, off + 0x04)
    exp_le_a        = _le_u32(b, off + 0x0C)
    exp_be_a        = int.from_bytes(b[off + 0x0C : off + 0x10], "big")
    key_id_a        = bytes(b[off + 0x10 : off + 0x20])
    mod_bits_a      = _le_u32(b, off + 0x20)

    def _valid_layout_a() -> Tuple[bool, int]:
        if ver_a != 1:
            return (False, 0)
        blob_len = 0
        if 0x50 <= total_entry_len <= 0x4000:
            blob_len = total_entry_len - 0x50
        if blob_len not in (256, 512):
            mb = (mod_bits_a // 8) if mod_bits_a in (0x800, 0x1000) else 0
            blob_len = mb
        ok = blob_len in (256, 512)
        return (ok, blob_len)

    ok_a, blob_len_a = _valid_layout_a()
    if ok_a:
        mod_off = off + 0x50
        mod_end = mod_off + blob_len_a
        if mod_end > end:
            return None
        modulus = bytes(b[mod_off:mod_end])
        e = exp_le_a if exp_le_a in (3, 65537) else (exp_be_a if exp_be_a in (3, 65537) else 65537)
        return {
            "key_id": key_id_a,
            "exp": e,
            "modulus": modulus,
            "bits": blob_len_a * 8,
            "next": off + 0x50 + blob_len_a,  # exact stride
        }

    # Fallback: Layout B
    mod_len_b = int.from_bytes(b[off + 0x02 : off + 0x04], "little")
    if mod_len_b in (0x0100, 0x0200, 256, 512):
        exp_le_b = _le_u32(b, off + 0x04)
        exp_be_b = int.from_bytes(b[off + 0x04 : off + 0x08], "big")
        key_id_b = bytes(b[off + 0x10 : off + 0x20])
        blob_len = 256 if mod_len_b in (0x0100, 256) else 512
        mod_off  = off + 0x50
        mod_end  = mod_off + blob_len
        if mod_end > end:
            return None
        modulus = bytes(b[mod_off:mod_end])
        e = exp_le_b if exp_le_b in (3, 65537) else (exp_be_b if exp_be_b in (3, 65537) else 65537)
        return {
            "key_id": key_id_b,
            "exp": e,
            "modulus": modulus,
            "bits": blob_len * 8,
            "next": off + 0x50 + blob_len,
        }

    return None


# parse one PS1-wrapped KDB payload (may contain multiple KDB blocks)

def _ingest_kdb_block(
    body: memoryview,
    start: int,
    source: Optional[KeySource] = None,
    *,
    usage: _crypto.KeyUsage = _crypto.KeyUsage.ANY,
) -> Tuple[int, int]:
    # Parse one KDB block at 'start' within 'body'.
    # Returns (added_keys, next_offset_after_block). If header is not plausible, returns (0, start).
    total_len, version, i = _parse_kdb_header(body, start)
    # Version already normalized to 1 in _parse_kdb_header
    if total_len < 0x60 or total_len > (len(body) - start):
        return (0, start)

    block_end = start + total_len
    added = 0

    while i + 0x50 <= block_end:
        ent = _parse_kdb_entry(body, i)
        if not ent:
            # slide within the block to re-sync
            i += 0x10
            continue

        key_id = ent["key_id"]
        e = int(ent["exp"])
        mod = ent["modulus"]

        # Prefer LITTLE-ENDIAN modulus; fallback to BIG.
        added_here = False
        for _order in ("little", "big"):
            try:
                n = int.from_bytes(mod, _order, signed=False)
            except Exception:
                continue
            if n <= 0:
                continue
            if _crypto.add_public_key_numbers(key_id, e, n, usage=usage):
                added += 1
                added_here = True
            else:
                added_here = True
            break

        if added_here:
            _record_key_source(key_id, source)

        i = ent["next"]

    return (added, block_end)


def _build_ps1_signed_region(
    hdr: _ps1.PS1Header,
    buf: bytes,
    off_spi: int,
    size_hint: Optional[int],
    signed_body: bytes,
) -> Tuple[bytes, int]:
    header_bytes = bytes(memoryview(buf)[off_spi : off_spi + _ps1.PS1_HEADER_LEN])
    signed_region = (header_bytes + signed_body)[
        : _ps1.PS1_HEADER_LEN + int(hdr.size_signed)
    ]
    rom_size = hdr.resolve_rom_size(off_spi, len(buf), size_hint)
    return signed_region, rom_size


def ingest_keys_from_kdb(
    buf: bytes,
    off_spi: int,
    size_hint: Optional[int] = None,
    source: Optional[KeySource] = None,
    *,
    usage: _crypto.KeyUsage = _crypto.KeyUsage.ANY,
    require_verified: bool = False,
    type_hint: Optional[int] = None,
    log_fail: bool = True,
) -> int:
    # Parse PS1-wrapped KEY_DATABASE and add keys into the keyring.
    # The PS1 body may contain *multiple* KDB blocks back-to-back.
    resolved = _ps1.read_ps1_body(buf, off_spi, size_hint)
    if resolved is None:
        return 0
    hdr, body_raw = resolved

    dec_res = _crypto.decrypt_body_if_needed(body_raw, hdr.encrypted)
    if hdr.is_encrypted and dec_res.method is None:
        # Cannot decrypt -> cannot ingest keys.
        logger = get_logger()
        logger.warning(f"[Keyring] KEY_DATABASE at 0x{off_spi:X} is encrypted and no decryptor is configured;"
        " skipping.")
        return 0

    signed_body = dec_res.body
    if require_verified and not (hdr.is_encrypted and dec_res.method is None):
        signed_region, rom_size = _build_ps1_signed_region(
            hdr,
            buf,
            off_spi,
            size_hint,
            signed_body,
        )
        sig_result = _crypto.verify_ps1_signature(
            buf=buf,
            off_spi=off_spi,
            rom_size=rom_size,
            signature_type=int(hdr.signature_type),
            fingerprint=bytes(hdr.signature_fingerprint),
            signed_region=signed_region,
            entry_type=type_hint,
        )
        if sig_result is not True:
            if log_fail:
                type_txt = (
                    f"type 0x{int(type_hint) & 0xFF:02X} "
                    if isinstance(type_hint, int)
                    else ""
                )
                logger = get_logger()
                logger.warning(
                    f"KEY_DATABASE {type_txt}at 0x{off_spi:X} failed signature verification;"
                    " ignoring keys."
                )
            return 0

    work = _crypto.decompress_body_if_needed(
        signed_body, hdr.is_compressed, hdr.zlib_size
    )
    body = memoryview(work)

    total_added = 0
    cursor = 0
    end = len(body)

    # Iterate across the PS1 body to catch multiple KDB blocks
    while cursor + 0x50 <= end:
        # Quick skip for empty/garbage areas
        if int.from_bytes(body[cursor:cursor+4], "little", signed=False) == 0:
            cursor += 0x10
            continue
        try:
            added, next_off = _ingest_kdb_block(
                body,
                cursor,
                source,
                usage=usage,
            )
        except Exception:
            added, next_off = (0, cursor)

        if added > 0 and next_off > cursor:
            total_added += added
            cursor = next_off
            continue

        # Not a KDB header here; slide forward on 16B boundaries
        cursor += 0x10

    return total_added


def extract_kdb_entries(
    buf: bytes,
    off_spi: int,
    size_hint: Optional[int] = None,
) -> List[ParsedKeyEntry]:
    # Return parsed KEY_DATABASE entries without mutating the keyring.

    resolved = _ps1.read_ps1_body(buf, off_spi, size_hint)
    if resolved is None:
        return []

    hdr, body_raw = resolved
    dec_res = _crypto.decrypt_body_if_needed(body_raw, hdr.encrypted)
    if hdr.is_encrypted and dec_res.method is None:
        return []

    work = dec_res.body
    work = _crypto.decompress_body_if_needed(work, hdr.is_compressed, hdr.zlib_size)
    body = memoryview(work)

    entries: List[ParsedKeyEntry] = []
    cursor = 0
    end = len(body)

    while cursor + 0x50 <= end:
        ent = _parse_kdb_entry(body, cursor)
        if ent:
            modulus = bytes(ent["modulus"])
            entry = ParsedKeyEntry(
                key_id=bytes(ent["key_id"]),
                exponent=int(ent["exp"]),
                modulus=modulus,
            )
            entries.append(entry)
            next_cursor = int(ent.get("next", cursor))
            if next_cursor <= cursor:
                cursor += 0x10
            else:
                cursor = next_cursor
            continue
        cursor += 0x10

    return entries


# directory pre-load helper (fixes key loading sequence)

def _field(e: Any, *names: str):
    # Best-effort getter for dir-entry fields (dicts or objects).
    for n in names:
        if isinstance(e, dict) and n in e:
            return e[n]
        if hasattr(e, n):
            return getattr(e, n)
    return None


def _normalize_kind(kind: Optional[Any], fallback: Optional[Any] = None) -> Any:
    """Normalize directory kind, preserving DirKind enums."""
    raw = kind if kind is not None else fallback
    if raw is None:
        return None
    # Preserve DirKind enum objects as-is
    if hasattr(raw, 'value') and hasattr(raw, 'is_bios'):
        return raw
    if isinstance(raw, bytes):
        try:
            return raw.decode("ascii", "ignore")
        except Exception:
            return raw.hex().upper()
    return raw


def _zone_for_kind(kind: Optional[Any]) -> str:
    """Determine zone (psp/bios) from directory kind."""
    if kind is None:
        return "psp"
    # Handle DirKind enum directly
    if hasattr(kind, 'is_bios'):
        return "bios" if kind.is_bios else "psp"
    # Handle string fallback
    normalized = str(kind).strip().upper()
    if any(x in normalized for x in ("BHD", "BIOS", "$BHD", "$BL2", "2BHD")):
        return "bios"
    return "psp"


_BIOS_KEY_TYPES = {0x07, 0x74}


def preload_kdb_keys_for_directory(
    fw_bytes: bytes,
    dir_entries: Iterable[Any],
    directory_index: Optional[int] = None,
    *,
    directory_kind: Optional[Any] = None,
) -> int:
    """
    Preload keys from key-bearing entries in a directory.
    
    Call this ONCE at the top of your per-directory processing BEFORE verifying any entries.
    It scans the directory for key-bearing entries and ingests all keys first.
    
    Args:
        fw_bytes: Full firmware image bytes
        dir_entries: Iterable of entry dicts from iter_entries()
        directory_index: Optional directory index for provenance tracking
        directory_kind: Directory kind (DirKind enum or string)
    
    Returns:
        Number of keys successfully ingested
    """
    logger = get_logger()
    entries_list = list(dir_entries)
    total = 0
    ordered_candidates: List[Tuple[int, dict]] = []
    
    zone = _zone_for_kind(directory_kind)
    allowed = _BIOS_KEY_TYPES if zone == "bios" else _constants.PSP_KEY_TYPES
    logger.debug(f"[keys] Scanning directory {directory_index} ({directory_kind}) zone={zone} for key types {allowed}")
    
    for order, ent in enumerate(entries_list):
        tid_raw = _field(
            ent, "type_id", "TypeId", "Type_Id", "Type Id", "type", "Type"
        )
        try:
            tid = int(tid_raw)
        except Exception:
            continue
        # Use entry's own kind if available, fallback to directory_kind
        entry_kind = _normalize_kind(_field(ent, "kind", "directory_kind"), directory_kind)
        entry_zone = _zone_for_kind(entry_kind)
        entry_allowed = _BIOS_KEY_TYPES if entry_zone == "bios" else _constants.PSP_KEY_TYPES
        low = tid & 0xFF
        if low not in entry_allowed:
            continue
        logger.debug(f"[keys] Found key candidate: type 0x{low:02X} in entry {order}")
        off_val = _field(
            ent,
            "resolved_off",
            "payload_offset",
            "offset",
            "Address",
            "address",
        )
        if off_val is None:
            off_val = _field(ent, "entry_offset")
        try:
            off_int = int(off_val)
        except Exception:
            continue
        size_val = _field(
            ent,
            "size",
            "payload_size",
            "declared_size",
            "length",
            "Length",
            "DeclaredSize",
        )
        try:
            size_int = int(size_val) if size_val is not None else None
        except Exception:
            size_int = None
        if size_int is not None and size_int <= 0:
            size_int = None
        entry_index_val = _field(ent, "index", "Entry#", "entry_index", "Entry")
        try:
            entry_index_int = (
                int(entry_index_val) if entry_index_val is not None else None
            )
        except Exception:
            entry_index_int = None

        if off_int < 0 or off_int >= len(fw_bytes):
            continue

        ordered_candidates.append(
            (
                order,
                {
                    "type": low,
                    "full_type": tid,
                    "offset": off_int,
                    "size": size_int,
                    "source": KeySource(directory_index, entry_index_int, off_int),
                    "kind": entry_kind,
                },
            )
        )

    def _iter_candidates(match: Iterable[int]) -> Iterable[dict]:
        wanted = set(match)
        for _, info in sorted(ordered_candidates, key=lambda kv: kv[0]):
            if info["type"] in wanted:
                yield info

    # Phase 1: raw AMD public keys (0x00)
    for info in _iter_candidates({0x00}):
        size_int = info.get("size")
        off_int = info.get("offset")
        if not isinstance(off_int, int):
            continue
        if size_int is None or size_int <= 0:
            logger.debug(f"[keys] Skipping type 0x00 at 0x{off_int:X}: invalid size {size_int}")
            continue
        end = min(len(fw_bytes), off_int + size_int)
        if end <= off_int:
            continue
        payload = bytes(memoryview(fw_bytes)[off_int:end])
        try:
            added = ingest_amd_pubkey_from_entry(
                info.get("kind") or directory_kind or "",
                int(info.get("full_type", 0)),
                payload,
                info.get("source"),
            )
        except Exception as e:
            logger.debug(f"[keys] Failed to ingest AMD pubkey at 0x{off_int:X}: {e}")
            added = 0
        if added:
            logger.debug(f"[keys] Ingested {added} AMD pubkey(s) from 0x{off_int:X}")
            total += int(added)

    # Phase 2: key databases that must verify against AMD key (0x50, 0x51)
    for info in _iter_candidates({0x50, 0x51}):
        off_int = info.get("offset")
        if not isinstance(off_int, int):
            continue
        usage = _crypto.KeyUsage.TEE_ONLY if info["type"] in _constants.TEE_KEY_DB_TYPES else _crypto.KeyUsage.ANY
        try:
            added = ingest_keys_from_kdb(
                fw_bytes,
                off_int,
                info.get("size"),
                info.get("source"),
                usage=usage,
                require_verified=True,
                type_hint=info["type"],
                log_fail=True,
            )
        except Exception as e:
            logger.debug(f"[keys] Failed to ingest KDB at 0x{off_int:X}: {e}")
            added = 0
        if added:
            logger.debug(f"[keys] Ingested {added} key(s) from KDB at 0x{off_int:X}")
            total += int(added)

    # Phase 3: remaining key-bearing entries (load after databases)
    for _, info in sorted(ordered_candidates, key=lambda kv: kv[0]):
        if info["type"] in {0x00, 0x50, 0x51}:
            continue
        off_int = info.get("offset")
        if not isinstance(off_int, int):
            continue
        usage = _crypto.KeyUsage.TEE_ONLY if info["type"] in _constants.TEE_KEY_DB_TYPES else _crypto.KeyUsage.ANY
        try:
            added = ingest_keys_from_kdb(
                fw_bytes,
                off_int,
                info.get("size"),
                info.get("source"),
                usage=usage,
                require_verified=False,
                type_hint=info["type"],
                log_fail=False,
            )
        except Exception:
            added = 0
        if added:
            total += int(added)
    
    if total > 0:
        logger.debug(f"[keys] Directory {directory_index}: loaded {total} key(s) total")
    return total



def maybe_ingest(
    kind: str,
    type_id: int,
    buf: bytes,
    off_spi: int,
    size_hint: Optional[int],
    source: Optional[KeySource] = None,
) -> int:
    # Ingest keys if the entry is a known key container (0x00, 0x50, 0x51).
    # Returns count of keys added.
    t = (type_id & 0xFF)
    if t == 0x00:
        payload = (
            bytes(buf[off_spi : off_spi + (size_hint or 0)])
            if size_hint
            else bytes(buf[off_spi:])
        )
        return ingest_amd_pubkey_from_entry(kind, type_id, payload, source)
    if t in (0x50, 0x51):
        usage = _crypto.KeyUsage.TEE_ONLY if t in _constants.TEE_KEY_DB_TYPES else _crypto.KeyUsage.ANY
        return ingest_keys_from_kdb(
            buf,
            off_spi,
            size_hint,
            source,
            usage=usage,
            require_verified=True,
            type_hint=t,
            log_fail=False,
        )
    return 0


def _format_locations(locs: Iterable[KeySource]) -> Tuple[str, str]:
    entries: List[str] = []
    addresses: List[str] = []
    for loc in locs:
        label = ""
        if loc.directory_index is not None:
            if loc.entry_index is not None:
                label = f"d{int(loc.directory_index)}e{int(loc.entry_index)}"
            else:
                label = f"d{int(loc.directory_index)}"
        elif loc.entry_index is not None:
            label = f"e{int(loc.entry_index)}"
        if label:
            entries.append(label)
        if loc.address is not None:
            addresses.append(f"0x{int(loc.address):X}")

    def _dedupe(values: List[str]) -> List[str]:
        seen: Dict[str, None] = {}
        for v in values:
            if v and v not in seen:
                seen[v] = None
        return list(seen.keys())

    entry_txt = ", ".join(_dedupe(entries))
    addr_txt = ", ".join(_dedupe(addresses))
    return entry_txt, addr_txt


def collect_key_display_records() -> List[KeyDisplayRecord]:
    # Return sorted keyring entries with display-friendly metadata.
    sources_map = iter_key_sources()
    records: List[KeyDisplayRecord] = []
    for key_id, pub in sorted(_crypto.keyring_iter(), key=lambda kv: kv[0]):
        entry_txt, addr_txt = _format_locations(sources_map.get(key_id, []))
        records.append(
            KeyDisplayRecord(
                key_id=bytes(key_id),
                bits=int(pub.key_size),
                entry_locations=entry_txt,
                address_locations=addr_txt,
                public_key=pub,
            )
        )
    return records


def dump_keyring_summary() -> None:
    """Log keyring summary via debug logger."""
    logger = get_logger()
    total = _crypto.keyring_size()
    items = sorted(_crypto.keyring_iter(), key=lambda kv: kv[0])
    
    logger.debug(f"[Keyring] Total public keys: {total}")
    if not items:
        return
    
    logger.debug("[Keyring] Keyring contents:")
    sources_map = iter_key_sources()
    for key_id, pub in items:
        short = key_id[:2].hex().upper()
        bits = pub.key_size or "?"
        entry_txt, addr_txt = _format_locations(sources_map.get(key_id, []))
        loc_bits = f"entries={entry_txt}" if entry_txt else ""
        addr_bits = f"address={addr_txt}" if addr_txt else ""
        logger.debug(f"[Keyring] {short:>4} id={key_id.hex().upper()} length={bits}bits {loc_bits} {addr_bits}")


def export_public_keys(target_dir: Path) -> List[Path]:
    # Write all known public keys to PEM files within target_dir.
    exported: List[Path] = []
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return []
    for key_id, pub in sorted(_crypto.keyring_iter(), key=lambda kv: kv[0]):
        try:
            pem = _crypto.public_key_to_pem(pub)
        except Exception:
            continue
        file_name = f"{key_id.hex().upper()}.pem"
        path = target_dir / file_name
        try:
            path.write_bytes(pem)
        except Exception:
            continue
        exported.append(path)
    return exported


def ingest_env_pem() -> int:
    # Load a PEM public key from PSP_PUBKEY and store under a synthetic id (all zeros).
    path = os.environ.get("PSP_PUBKEY")
    if not path or not os.path.isfile(path) or not HAVE_CRYPTO:
        return 0
    try:
        with open(path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        return 1 if _crypto.add_public_key(b"\x00"*16, pub) else 0
    except Exception:
        return 0
