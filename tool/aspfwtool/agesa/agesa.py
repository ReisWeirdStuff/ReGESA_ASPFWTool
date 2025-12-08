# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Utilities for matching firmware components to AGESA versions.

This module is intentionally lightweight so it can be imported by both the
GUI layer and lower-level helpers without pulling in Qt dependencies.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

"""Constants and Globals"""

_DB_CACHE: Optional[Dict[str, Any]] = None
_DB_PATH: Optional[Path] = None

_TEMPLATE: Dict[str, Any] = {
    "metadata": {"version": "1"},
    "psp_entries": {},
    "bios_entries": {}
}

_COLLECTION_KEYS = (
    "variants",
    "artifacts",
    "records",
    "entries",
    "hashes",
    "matches",
    "versions",
)

_VARIANT_FIELDS = ("hashes", "variants", "entries")

_SKIP_KEYS = set(_COLLECTION_KEYS + ("hash", "digest"))


def _get_split_db_paths() -> tuple[Path, Path]:
    """Return paths to the split AGESA PSP and UEFI version JSON files."""
    package_root = Path(__file__).resolve().parent.parent
    updatable_dir = package_root / "updatable"
    return (
        updatable_dir / "agesa_psp_versions.json",
        updatable_dir / "agesa_uefi_versions.json",
    )


def _load_from_path(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            return loaded
    except Exception:
        pass
    return dict(_TEMPLATE)


def _ensure_iterable(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _collect_base_fields(record: dict, skip: Iterable[str]) -> dict:
    return {k: v for k, v in record.items() if k not in skip}


def _normalize_variant_items(value: Any) -> list:
    if isinstance(value, dict):
        normalized = []
        for digest, data in value.items():
            if isinstance(data, dict):
                entry = dict(data)
            else:
                entry = {"version": data}
            entry.setdefault("hash", digest)
            normalized.append(entry)
        return normalized
    return _ensure_iterable(value)


def _iter_version_values(value: Any):
    if value is None:
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_version_values(item)
        return
    yield value


def _merge_versions_into_record(record: dict, *extra_values: Any) -> None:
    collected: list[Any] = []

    def _collect(value: Any) -> None:
        if value is None:
            return
        collected.append(value)

    _collect(record.pop("versions", None))
    _collect(record.pop("version", None))
    _collect(record.get("agesa_version"))
    for value in extra_values:
        _collect(value)

    unique: list[str] = []
    seen: set[str] = set()
    for candidate in collected:
        for variant in _iter_version_values(candidate):
            text = _stringify_version_value(variant)
            if not text or text in seen:
                continue
            unique.append(text)
            seen.add(text)

    if unique:
        record["versions"] = unique
        record["version"] = unique[0]
    else:
        record.pop("versions", None)
        record.pop("version", None)


def _merge_indexed_record(indexed: Dict[str, dict], combined: dict) -> None:
    digest = combined.get("hash")
    if not digest:
        return
    _merge_versions_into_record(combined)
    existing = indexed.get(digest)
    if existing is None:
        indexed[digest] = combined
        return
    _merge_versions_into_record(
        existing,
        combined.get("versions") or combined.get("version"),
    )
    for key, value in combined.items():
        if key in {"hash", "version", "versions"}:
            continue
        if key not in existing or existing[key] in (None, "", []):
            existing[key] = value


def _ingest_variants(indexed: Dict[str, dict], base_fields: dict, variants: Any) -> None:
    for variant in _normalize_variant_items(variants):
        if isinstance(variant, dict):
            digest = variant.get("hash") or variant.get("digest")
        else:
            digest = variant
        normalized = _normalize_digest(digest)
        if not normalized:
            continue
        combined = dict(base_fields)
        if isinstance(variant, dict):
            for key, value in variant.items():
                if key in _SKIP_KEYS:
                    continue
                combined[key] = value
        combined["hash"] = normalized
        _merge_indexed_record(indexed, combined)


def _flatten_records(raw: Any, *, label_field: Optional[str] = None) -> Dict[str, dict]:
    indexed: Dict[str, dict] = {}
    if isinstance(raw, dict):
        for key, record in raw.items():
            if isinstance(record, dict):
                variants = None
                for field in _VARIANT_FIELDS:
                    value = record.get(field)
                    if value:
                        variants = value
                        break
                if variants is not None:
                    base_fields = _collect_base_fields(record, _VARIANT_FIELDS)
                    if label_field and label_field not in base_fields:
                        base_fields[label_field] = key
                    _ingest_variants(indexed, base_fields, variants)
                    continue
            normalized = _normalize_digest(key)
            if not normalized:
                continue
            if isinstance(record, dict):
                combined = dict(record)
                combined.setdefault("hash", normalized)
            else:
                combined = {"hash": normalized, "version": record}
            _merge_indexed_record(indexed, combined)
        return indexed
    if not isinstance(raw, list):
        return indexed
    for block in raw:
        if not isinstance(block, dict):
            continue
        matches_value = None
        for key in _COLLECTION_KEYS:
            value = block.get(key)
            if value:
                matches_value = value
                break
        if matches_value is None:
            match_items = [block]
        else:
            match_items = _normalize_variant_items(matches_value)
        base_fields = {k: v for k, v in block.items() if k not in _SKIP_KEYS}
        for match in match_items:
            if isinstance(match, str):
                match_dict = {"hash": match}
            elif isinstance(match, dict):
                match_dict = match
            else:
                try:
                    text = str(match).strip()
                except Exception:
                    continue
                if not text:
                    continue
                match_dict = {"hash": text}
            digest = match_dict.get("hash") or match_dict.get("digest")
            normalized = _normalize_digest(digest)
            if not normalized:
                continue
            combined = dict(base_fields)
            for key, value in match_dict.items():
                if key in _SKIP_KEYS:
                    continue
                combined[key] = value
            combined["hash"] = normalized
            _merge_indexed_record(indexed, combined)
    return indexed


def _flatten_psp_entries(raw: Any) -> Dict[str, dict]:
    """
    Flatten PSP/BIOS entries from { type_id: { hash: version } } structure.
    
    Returns a dict indexed by hash with version information.
    """
    indexed: Dict[str, dict] = {}
    if not isinstance(raw, dict):
        return indexed
    for type_id, hashes_dict in raw.items():
        if not isinstance(hashes_dict, dict):
            continue
        for digest, version_data in hashes_dict.items():
            normalized = _normalize_digest(digest)
            if not normalized:
                continue
            combined = {
                "hash": normalized,
                "type_id": type_id,
            }
            _merge_versions_into_record(combined, version_data)
            _merge_indexed_record(indexed, combined)
    return indexed


def _normalize_database(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raw = dict(_TEMPLATE)
    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        metadata = dict(_TEMPLATE["metadata"])
    normalized = {
        "metadata": metadata,
        "psp_entries": _flatten_psp_entries(raw.get("psp_entries")),
        "bios_entries": _flatten_psp_entries(raw.get("bios_entries")),
        "modules": _flatten_records(raw.get("modules"), label_field="module_name"),
    }
    return normalized


def _load_split_databases() -> Dict[str, Any]:
    """Load from the split agesa_psp_versions.json and agesa_uefi_versions.json files."""
    psp_path, uefi_path = _get_split_db_paths()
    combined: Dict[str, Any] = dict(_TEMPLATE)

    if psp_path.exists():
        psp_data = _load_from_path(psp_path)
        if "psp_entries" in psp_data:
            combined["psp_entries"] = psp_data["psp_entries"]
        if "bios_entries" in psp_data:
            combined["bios_entries"] = psp_data["bios_entries"]
        if "metadata" in psp_data:
            combined["metadata"] = psp_data["metadata"]

    if uefi_path.exists():
        uefi_data = _load_from_path(uefi_path)
        if "modules" in uefi_data:
            combined["modules"] = uefi_data["modules"]

    return combined


def load_database(force: bool = False) -> Dict[str, Any]:
    global _DB_CACHE, _DB_PATH
    if _DB_CACHE is not None and not force:
        return _DB_CACHE

    psp_path, uefi_path = _get_split_db_paths()
    _DB_CACHE = _normalize_database(_load_split_databases())
    _DB_PATH = psp_path.parent  # Store the directory
    return _DB_CACHE


def _normalize_digest(digest: str | bytes | bytearray | memoryview) -> Optional[str]:
    if digest is None:
        return None
    if isinstance(digest, (bytes, bytearray, memoryview)):
        hex_digest = bytes(digest).hex()
    else:
        text = str(digest).strip()
        if not text:
            return None
        hex_digest = text
    hex_digest = hex_digest.lower()
    if not hex_digest:
        return None
    return hex_digest


def lookup_entry(digest: str | bytes | bytearray | memoryview) -> Optional[dict]:
    normalized = _normalize_digest(digest)
    if not normalized:
        return None
    db = load_database()
    # Search both psp_entries and bios_entries
    result = db.get("psp_entries", {}).get(normalized)
    if result is not None:
        return result
    return db.get("bios_entries", {}).get(normalized)


def lookup_module(digest: str | bytes | bytearray | memoryview) -> Optional[dict]:
    normalized = _normalize_digest(digest)
    if not normalized:
        return None
    db = load_database()
    return db.get("modules", {}).get(normalized)


def hash_bytes(blob: bytes | bytearray | memoryview) -> str:
    view = memoryview(blob)
    return hashlib.sha256(view).hexdigest()


def hash_buffer_slice(
    buf: bytes | bytearray | memoryview,
    start: int,
    length: int,
) -> Optional[str]:
    if start is None or length is None:
        return None
    try:
        offset = int(start)
        size = int(length)
    except Exception:
        return None
    if size <= 0:
        return None
    view = memoryview(buf)
    end = offset + size
    if offset < 0 or end > len(view):
        return None
    return hashlib.sha256(view[offset:end]).hexdigest()


def _stringify_version_value(value: Any) -> Optional[str]:
    """Return a friendly string for the supplied AGESA version field."""

    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple, set)):
        parts: list[str] = []
        seen: set[str] = set()
        for item in value:
            text = _stringify_version_value(item)
            if not text or text in seen:
                continue
            parts.append(text)
            seen.add(text)
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0]
        return ", ".join(parts)
    if isinstance(value, dict):
        # Common structure: {"pi": "ComboAM4v2", "version": "1.2.0.7"}
        parts: list[str] = []
        for key in ("pi", "pi_name", "family", "name"):
            text = _stringify_version_value(value.get(key))
            if text:
                parts.append(text)
                break
        for key in ("version", "pi_version", "build", "revision", "number"):
            text = _stringify_version_value(value.get(key))
            if text:
                parts.append(text)
                break
        if not parts:
            # Look for a generic string-ish field before falling back to the
            # first value.
            for key in ("label", "string", "text"):
                text = _stringify_version_value(value.get(key))
                if text:
                    return text
        if parts:
            return " ".join(parts).strip()
        for candidate in value.values():
            text = _stringify_version_value(candidate)
            if text:
                return text
        return None
    return str(value)


def extract_version(record: Optional[dict]) -> Optional[str]:
    if not isinstance(record, dict):
        return None
    value = (
        record.get("version")
        or record.get("agesa_version")
        or record.get("versions")
    )
    return _stringify_version_value(value)

