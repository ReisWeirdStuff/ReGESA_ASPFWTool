# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Cryptographic utilities for AMD PSP firmware verification.

This module provides:
    - RSA public key management and keyring operations
    - Signature verification for PSP firmware entries
    - AMD public key parsing from firmware blobs
    - AES decryption support for encrypted entries
"""

import base64
import os
import zlib
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, NamedTuple, Optional, Tuple, Union

from . import constants as _constants

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

"""RSA key usage restrictions for PSP firmware verification."""
class KeyUsage(Enum):

    ANY = "any"           # Key can be used for any entry type
    TEE_ONLY = "tee-only" # Key restricted to TEE-related entries


""" 
Public Key Keyring Management:
    - The keyring stores RSA public keys indexed by their 16-byte key ID.
    - Keys are used to verify signatures on PSP firmware entries.
"""
@dataclass(frozen=True)
class PublicKey:
    """
    RSA public key representation.

    Attributes:
        modulus: The RSA modulus N.
        exponent: The RSA public exponent e (typically 65537).
    """

    modulus: int
    exponent: int

    @property
    def key_size(self) -> int:
        bits = int(self.modulus).bit_length()
        # Align to the next byte boundary so callers get canonical sizes.
        return ((bits + 7) // 8) * 8

    @property
    def key_size_bytes(self) -> int:
        return self.key_size // 8 if self.key_size else 0


_KEYRING: Dict[bytes, PublicKey] = {}
# Key usage restrictions
_KEY_USAGE: Dict[bytes, KeyUsage] = {}


def keyring_clear() -> None:
    """Remove all keys from the global keyring."""
    _KEYRING.clear()
    _KEY_USAGE.clear()


def keyring_size() -> int:
    """Return the number of keys currently in the keyring."""
    return len(_KEYRING)


def keyring_iter() -> Iterable[Tuple[bytes, PublicKey]]:
    """Yield (key_id, public_key) pairs from the keyring."""
    return list(_KEYRING.items())


def _ensure_public_key(pub: Union[PublicKey, Tuple[int, int], Dict[str, int], object]) -> Optional[PublicKey]:
    """
    Normalize various public-key representations into PublicKey.

    Accepts:
        - PublicKey instance (returned as-is)
        - Tuple (exponent, modulus)
        - Dict with 'modulus' and 'exponent' keys
        - Cryptography library public key objects

    Returns:
        Normalized PublicKey or None if conversion fails.
    """
    if isinstance(pub, PublicKey):
        return pub
    if isinstance(pub, tuple) and len(pub) == 2:
        e, n = pub
        return PublicKey(int(n), int(e))
    if isinstance(pub, dict) and {"modulus", "exponent"} <= set(pub.keys()):
        return PublicKey(int(pub["modulus"]), int(pub["exponent"]))
    if HAVE_CRYPTO:
        try:
            nums = pub.public_numbers()  # type: ignore[attr-defined]
            return PublicKey(int(nums.n), int(nums.e))
        except Exception:
            return None
    return None


def add_public_key(key_id: bytes, pub, *, usage: KeyUsage = KeyUsage.ANY) -> bool:
    """
    Add or replace a key in the global keyring.

    Args:
        key_id: 16-byte key identifier.
        pub: Public key in any supported format.
        usage: Key usage restriction (KeyUsage.ANY or KeyUsage.TEE_ONLY).

    Returns:
        True if the key was newly added, False if replaced.
    """
    if not key_id or pub is None:
        return False
    normalized = _ensure_public_key(pub)
    if normalized is None:
        return False
    new = key_id not in _KEYRING
    _KEYRING[key_id] = normalized
    existing_usage = _KEY_USAGE.get(key_id)
    if existing_usage == KeyUsage.ANY or usage == KeyUsage.ANY:
        _KEY_USAGE[key_id] = KeyUsage.ANY
    elif usage:
        _KEY_USAGE[key_id] = usage
    elif existing_usage:
        _KEY_USAGE[key_id] = existing_usage
    else:
        _KEY_USAGE[key_id] = KeyUsage.ANY
    return new


def add_public_key_numbers(
    key_id: bytes,
    exponent: int,
    modulus: int,
    *,
    usage: KeyUsage = KeyUsage.ANY,
) -> bool:
    """
    Store a key described by raw RSA numbers.

    Args:
        key_id: 16-byte key identifier.
        exponent: RSA public exponent.
        modulus: RSA modulus.
        usage: Key usage restriction.

    Returns:
        True if successful, False otherwise.
    """
    if not key_id:
        return False
    if int(modulus) <= 0 or int(exponent) <= 0:
        return False
    return add_public_key(
        key_id,
        PublicKey(int(modulus), int(exponent)),
        usage=usage,
    )


def get_public_key_by_id(key_id: bytes) -> Optional[PublicKey]:
    return _KEYRING.get(key_id)


def _usage_allows_entry(usage: KeyUsage, entry_type: Optional[int]) -> bool:
    if not usage or usage == KeyUsage.ANY:
        return True
    if usage == KeyUsage.TEE_ONLY:
        return entry_type in _constants.TEE_ENTRY_TYPES if entry_type is not None else False
    return True


def get_candidate_public_keys(
    fingerprint: Optional[bytes],
    entry_type: Optional[int] = None,
    directory_index: Optional[int] = None,
    parent_directory_index: Optional[int] = None,
) -> Iterable[PublicKey]:
    """
    Yield candidate RSA public keys for signature verification.

    Keys are returned in priority order:
        1. Exact fingerprint match (if any)
        2. All other keys passing usage restrictions

    Args:
        fingerprint: Optional 16-byte key fingerprint to prioritize.
        entry_type: Optional entry type for usage filtering.
        directory_index: Optional directory index to scope keys. If provided,
            only keys that originated from this directory will be returned.
        parent_directory_index: Optional parent directory index. If provided,
            keys from the parent directory are also included (for L2 dirs).

    Yields:
        PublicKey instances that may be used for verification.
    """
    # Get allowed key_ids if directory scoping is enabled
    allowed_key_ids: Optional[set] = None
    if directory_index is not None:
        from . import keys as _keys
        allowed_key_ids = _keys.get_key_ids_for_directory(
            directory_index,
            parent_directory_index=parent_directory_index,
        )
        if not allowed_key_ids:
            return  # No keys from this directory tree

    seen = set()
    if fingerprint and fingerprint in _KEYRING:
        # Check directory scope
        if allowed_key_ids is not None and fingerprint not in allowed_key_ids:
            pass  # Skip this key, not from the same directory tree
        else:
            k = _KEYRING[fingerprint]
            usage = _KEY_USAGE.get(fingerprint, KeyUsage.ANY)
            if _usage_allows_entry(usage, entry_type):
                seen.add(id(k))
                yield k
    for key_id, k in _KEYRING.items():
        # Check directory scope
        if allowed_key_ids is not None and key_id not in allowed_key_ids:
            continue
        ik = id(k)
        if ik in seen:
            continue
        usage = _KEY_USAGE.get(key_id, KeyUsage.ANY)
        if not _usage_allows_entry(usage, entry_type):
            continue
        seen.add(ik)
        yield k



"""AMD Public Key Parsing (Type 0x00 Entries)"""


def _parse_amd_pubkey_bin(payload: bytes) -> Optional[Tuple[bytes, PublicKey]]:
    """
    Parse AMD public key blob (type 0x00 entry, NOT wrapped in $PS1 header).

    Layout:
        0x00: u32 version (=1)
        0x04: 16B this_key_id
        0x14: 16B (unused/other id)
        0x38: u32 exp_size
        0x3C: u32 mod_bits (2048 or 4096)
        0x40..: exponent region (padded)
        ...last N: modulus (N = mod_bits/8), little-endian

    Args:
        payload: Raw bytes of the public key entry.

    Returns:
        Tuple of (key_id, PublicKey) or None if parsing fails.
    """
    if len(payload) < 0x100:
        return None
    key_id = payload[0x04:0x14]
    mod_bits = int.from_bytes(payload[0x3C:0x40], "little", signed=False)
    if mod_bits not in (2048, 4096):
        return None
    mod_size = mod_bits // 8
    if len(payload) < 0x40 + mod_size:
        return None

    mod_region = payload[-mod_size:] # LE modulus in practice
    exp_region = payload[0x40: len(payload) - mod_size]

    # exponent from region (prefer LE, fallback BE)
    e_le = int.from_bytes(exp_region, "little", signed=False)
    e_be = int.from_bytes(exp_region, "big", signed=False)
    e = e_le if 0 < e_le < (1 << 64) else (e_be if e_be else 65537)

    n = int.from_bytes(mod_region, "little", signed=False)
    return key_id, PublicKey(n, e)


def ingest_amd_pubkey_from_entry(kind: str, type_id: int, payload: bytes) -> int:
    # Add 0x00 AMD public key into the keyring (psp zone only).
    # Returns 1 if added, else 0.
    zone = "bios" if _constants.is_bios_dir(kind) else "psp"
    if zone != "psp":
        return 0
    if (type_id & 0xFF) != 0x00:
        return 0
    parsed = _parse_amd_pubkey_bin(payload)
    if not parsed:
        return 0
    key_id, pub = parsed
    return 1 if add_public_key(key_id, pub) else 0


# Hash/helpers 

def decompress_body_if_needed(body_raw: bytes, compressed: bool, zlib_size: int) -> bytes:
    if not compressed:
        return body_raw
    if zlib_size and zlib_size <= len(body_raw):
        try:
            return zlib.decompress(body_raw[:zlib_size])
        except Exception:
            pass
    try:
        return zlib.decompress(body_raw)
    except Exception:
        return body_raw


def check_sha256(body: bytes, expected32: bytes) -> bool:
    return bool(expected32) and hashlib.sha256(body).digest() == expected32[:32]


def check_sha384(body: bytes, expected48: bytes) -> bool:
    return bool(expected48) and hashlib.sha384(body).digest() == expected48[:48]


# Decryption helpers

class DecryptResult(NamedTuple):
    body: bytes
    used: bool
    method: Optional[str]
    error: Optional[str]


def _env_hex_bytes(name: str) -> Optional[bytes]:
    val = os.environ.get(name)
    if not val:
        return None
    try:
        cleaned = val.replace(" ", "").replace(":", "")
        if cleaned.startswith("0x") or cleaned.startswith("0X"):
            cleaned = cleaned[2:]
        return bytes.fromhex(cleaned)
    except Exception:
        return None


def decrypt_body_if_needed(body: bytes, encrypted_flag: int) -> DecryptResult:
    if not encrypted_flag:
        return DecryptResult(body, False, None, None)
    if not HAVE_CRYPTO:
        return DecryptResult(body, True, None, "cryptography unavailable")

    key = _env_hex_bytes("PSP_AES_KEY")
    if key and len(key) in (16, 24, 32):
        mode = (os.environ.get("PSP_AES_MODE") or "ECB").strip().upper()
        # Default to ECB if mode unset/unknown.
        if mode in ("", "ECB"):
            if len(body) % 16 == 0:
                try:
                    cipher = Cipher(algorithms.AES(key), modes.ECB())
                    decryptor = cipher.decryptor()
                    dec = decryptor.update(body) + decryptor.finalize()
                    return DecryptResult(dec, True, "AES-ECB", None)
                except Exception:
                    pass
        elif mode == "CBC":
            iv = _env_hex_bytes("PSP_AES_IV")
            if iv and len(iv) == 16 and len(body) % 16 == 0:
                try:
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                    decryptor = cipher.decryptor()
                    dec = decryptor.update(body) + decryptor.finalize()
                    return DecryptResult(dec, True, "AES-CBC", None)
                except Exception:
                    pass

    return DecryptResult(body, True, None, "no decryptor matched")


# Signature verify


def _pss_params_for_key(pub: PublicKey) -> Tuple[str, int]:
    # Return (hash_name, salt_len) tuned for PSP signatures.
    bits = pub.key_size
    if bits >= 4096:
        return "sha384", 48
    return "sha256", 32


def _mgf1(seed: bytes, mask_len: int, hash_name: str) -> bytes:
    counter = 0
    out = bytearray()
    while len(out) < mask_len:
        c = counter.to_bytes(4, "big")
        out.extend(hashlib.new(hash_name, seed + c).digest())
        counter += 1
    return bytes(out[:mask_len])


def _pss_verify(pub: PublicKey, signature: bytes, message: bytes) -> bool:
    if not signature:
        return False
    hash_name, salt_len = _pss_params_for_key(pub)
    k = pub.key_size_bytes
    if k <= 0:
        return False
    sig_int = int.from_bytes(signature, "big", signed=False)
    if sig_int <= 0 or sig_int >= pub.modulus:
        return False
    em_int = pow(sig_int, pub.exponent, pub.modulus)
    em = em_int.to_bytes(k, "big")
    if not em or em[-1] != 0xBC:
        return False
    hlen = hashlib.new(hash_name).digest_size
    if k < hlen + salt_len + 2:
        return False
    db = bytearray(em[: k - hlen - 1])
    h = em[k - hlen - 1 : k - 1]
    em_bits = pub.modulus.bit_length() - 1
    leading_mask_bits = (8 * k) - em_bits
    if leading_mask_bits > 0:
        db[0] &= (0xFF >> leading_mask_bits)
    db_mask = _mgf1(h, len(db), hash_name)
    db = bytearray(x ^ y for x, y in zip(db, db_mask))
    if leading_mask_bits > 0:
        db[0] &= (0xFF >> leading_mask_bits)
    ps_end = len(db) - salt_len - 1
    if ps_end < 0:
        return False
    if any(db[:ps_end]):
        return False
    if db[ps_end] != 0x01:
        return False
    salt = bytes(db[-salt_len:]) if salt_len > 0 else b""
    m_hash = hashlib.new(hash_name, message).digest()
    h_prime = hashlib.new(hash_name, b"\x00" * 8 + m_hash + salt).digest()
    return h_prime == h


def _try_verify(pub: PublicKey, signature: bytes, message: bytes) -> bool:
    if _pss_verify(pub, signature, message):
        return True
    # fallback: try reversed signature bytes (some dumps store LE sig)
    return _pss_verify(pub, signature[::-1], message)


def verify_ps1_signature(
    buf: bytes,
    off_spi: int,
    rom_size: int,
    signature_type: int,
    fingerprint: Optional[bytes],
    signed_region: bytes,
    *,
    entry_type: Optional[int] = None,
    directory_index: Optional[int] = None,
    parent_directory_index: Optional[int] = None,
) -> Optional[bool]:
    # Verify RSASSA-PSS over 'signed_region'.
    # Returns True/False if keys were tried, None if no keys available or malformed.
    sig_len = 0x100 if signature_type == 0x0 else 0x200 if signature_type == 0x2 else 0
    if sig_len <= 0:
        return None
    sig_off = off_spi + max(0, rom_size - sig_len)
    if sig_off + sig_len > len(buf):
        return None
    signature = bytes(buf[sig_off: sig_off + sig_len])

    tried = False
    for pub in get_candidate_public_keys(
        fingerprint,
        entry_type=entry_type,
        directory_index=directory_index,
        parent_directory_index=parent_directory_index,
    ):
        tried = True
        if _try_verify(pub, signature, signed_region):
            return True

    # allow a PEM fallback via env (PSP_PUBKEY)
    path = os.environ.get("PSP_PUBKEY")
    if path and os.path.isfile(path):
        try:
            with open(path, "rb") as f:
                data = f.read()
            env_pub = _ensure_public_key(serialization.load_pem_public_key(data)) if HAVE_CRYPTO else None
        except Exception:
            env_pub = None
        if env_pub is not None:
            tried = True
            if _try_verify(env_pub, signature, signed_region):
                return True

    return None if not tried else False


# Public-key export


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    payload = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(payload)]) + payload


def _der_int(value: int) -> bytes:
    if value < 0:
        raise ValueError("INTEGER must be non-negative")
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + _der_len(len(body)) + body


def _der_sequence(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + _der_len(len(body)) + body


def _der_bit_string(body: bytes) -> bytes:
    # Prepend 0 unused bits byte
    payload = b"\x00" + body
    return b"\x03" + _der_len(len(payload)) + payload


_OID_RSA_ENC = b"\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"
_DER_NULL = b"\x05\x00"


def public_key_to_der(pub: PublicKey) -> bytes:
    alg = _der_sequence(_OID_RSA_ENC, _DER_NULL)
    rsa_body = _der_sequence(_der_int(pub.modulus), _der_int(pub.exponent))
    bit_string = _der_bit_string(rsa_body)
    return _der_sequence(alg, bit_string)


def public_key_to_pem(pub: PublicKey) -> bytes:
    der = public_key_to_der(pub)
    b64 = base64.b64encode(der)
    lines = [b"-----BEGIN PUBLIC KEY-----"]
    for i in range(0, len(b64), 64):
        lines.append(b64[i : i + 64])
    lines.append(b"-----END PUBLIC KEY-----")
    return b"\n".join(lines) + b"\n"



    
