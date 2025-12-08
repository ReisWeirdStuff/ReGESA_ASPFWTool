# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Diff utilities for comparing firmware tree items.

This module provides:
    - Tree item iteration helpers
    - Payload hash computation for change detection
    - Diff key generation for PSP and UEFI items
    - Diff status computation between tree models
"""

from __future__ import annotations

import hashlib
from typing import Dict, Optional, Iterable

from PySide6.QtGui import QStandardItem, QStandardItemModel
from .roles import PAYLOAD_ROLE


def iter_tree_items(model: Optional[QStandardItemModel]) -> Iterable[QStandardItem]:
    if model is None:
        return []

    def walk(item: Optional[QStandardItem]):
        if item is None:
            return
        yield item
        for row in range(item.rowCount()):
            child = item.child(row, 0)
            if child is not None:
                yield from walk(child)

    for row in range(model.rowCount()):
        item = model.item(row, 0)
        if item is not None:
            yield from walk(item)


def _compute_payload_hash(payload: dict, loaded_images: list) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    try:
        image_index = int(payload.get("image_index"))
    except Exception:
        return None
    if not (0 <= image_index < len(loaded_images)):
        return None
    blob = payload.get("hex_blob")
    data_bytes: Optional[bytes] = None
    if blob is not None:
        try:
            data_bytes = bytes(blob)
        except Exception:
            data_bytes = None
    if data_bytes is None:
        off = payload.get("offset")
        size = payload.get("size") or payload.get("declared_size")
        try:
            start = int(off) if off is not None else None
            length = int(size) if size is not None else None
        except Exception:
            start = length = None
        if start is not None and length and length > 0:
            image_data = loaded_images[image_index].data
            end = start + length
            if 0 <= start < end <= len(image_data):
                data_bytes = bytes(image_data[start:end])
    if not data_bytes:
        return None
    return hashlib.sha256(data_bytes).hexdigest()


def _psp_diff_key(payload: dict) -> Optional[tuple]:
    if not isinstance(payload, dict):
        return None
    if payload.get("is_directory"):
        return ("psp_dir", payload.get("directory_index"))
    if "directory_index" in payload or "entry_index" in payload:
        return ("psp_entry", payload.get("directory_index"), payload.get("entry_index"))
    return None


def _uefi_diff_key(payload: dict) -> Optional[tuple]:
    if not isinstance(payload, dict):
        return None
    kind = payload.get("uefi_kind")
    if not kind:
        return None
    base: list = [kind]
    if kind == "root":
        base.append(payload.get("root_index"))
    elif kind == "volume":
        base.extend([payload.get("root_index"), payload.get("volume_index")])
    elif kind == "file":
        base.extend([payload.get("root_index"), payload.get("volume_index"), payload.get("file_index")])
    elif kind == "section":
        base.extend([payload.get("root_index"), payload.get("volume_index"), payload.get("file_index")])
        path = payload.get("uefi_section_path")
        if isinstance(path, (list, tuple)):
            base.extend(list(path))
    else:
        base.append(payload.get("label"))
    return tuple(base)


def _collect_diff_map(
    model: Optional[QStandardItemModel],
    *,
    kind: str,
    loaded_images: list,
) -> dict[tuple, dict[int, tuple[QStandardItem, Optional[str]]]]:
    mapping: dict[tuple, dict[int, tuple[QStandardItem, Optional[str]]]] = {}
    if model is None:
        return mapping
    key_fn = _psp_diff_key if kind == "psp" else _uefi_diff_key
    for item in iter_tree_items(model):
        payload = item.data(PAYLOAD_ROLE)
        if not isinstance(payload, dict):
            continue
        key = key_fn(payload)
        if key is None:
            continue
        try:
            img_idx = int(payload.get("image_index"))
        except Exception:
            continue
        digest = _compute_payload_hash(payload, loaded_images)
        by_image = mapping.setdefault(key, {})
        by_image[img_idx] = (item, digest)
    return mapping


def compute_diff_statuses(
    psp_model: Optional[QStandardItemModel],
    uefi_model: Optional[QStandardItemModel],
    loaded_images: list,
) -> Dict[int, tuple[QStandardItem, str]]:
    statuses: Dict[int, tuple[QStandardItem, str]] = {}
    image_count = len(loaded_images)
    if image_count < 2:
        return statuses

    for kind, model in (("psp", psp_model), ("uefi", uefi_model)):
        mapping = _collect_diff_map(model, kind=kind, loaded_images=loaded_images)
        digest_index: list[Dict[Optional[str], set]] = [dict() for _ in range(image_count)]
        for key, per_image in mapping.items():
            for img_idx, (_item, digest) in per_image.items():
                bucket = digest_index[img_idx].setdefault(digest, set())
                bucket.add(key)

        for key, per_image in mapping.items():
            digests = {digest for _, digest in per_image.values()}
            if len(per_image) == image_count and len(digests) <= 1:
                continue
            status = "not present in all images"
            if len(digests) > 1:
                status = "content differs between images"
            else:
                digest_val = next(iter(digests)) if digests else None
                moved = False
                if digest_val is not None:
                    for idx in range(image_count):
                        if idx in per_image:
                            continue
                        keys_with_digest = digest_index[idx].get(digest_val, set())
                        if keys_with_digest and key not in keys_with_digest:
                            moved = True
                            break
                if moved:
                    status = "relocated to different position"
            for item, _ in per_image.values():
                if status:
                    statuses[id(item)] = (item, status)
    return statuses
