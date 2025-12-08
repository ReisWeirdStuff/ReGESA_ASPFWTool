# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
UEFI firmware tree tab management utilities.

This module provides:
    - UEFI volume/file tree operations
    - Item location and navigation
    - GUID catalog export functionality
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

from PySide6.QtGui import QStandardItem
from PySide6.QtWidgets import QFileDialog, QMessageBox, QTreeView

from ..utils.roles import PAYLOAD_ROLE

from ...uefi import (
    EnumeratedFirmwareFile,
    EnumeratedFirmwareSection,
    EnumeratedFirmwareVolume,
    lookup_guid_name,
)


def _format_optional_hex(value: Optional[int]) -> str:
    if value is None:
        return "-"
    try:
        return f"0x{int(value):X}"
    except Exception:
        return "-"


# UEFI Tab Controller



class UefiTabController:
    """Encapsulates operations tied to the UEFI tree tab."""

    def __init__(self, window) -> None:
        self.window = window

    def find_item(
        self,
        image_index: Optional[int],
        offset: Optional[int],
        size: Optional[int],
        guid: Optional[str],
        *,
        volume_index: Optional[int] = None,
        root_index: Optional[int] = None,
    ) -> Optional[QStandardItem]:
        """Locate the tree item corresponding to the given UEFI payload."""

        model = getattr(self.window, "uefi_model", None)
        if model is None:
            return None
        target_guid = guid.lower() if isinstance(guid, str) else None

        def _walk(item: Optional[QStandardItem]) -> Optional[QStandardItem]:
            if item is None:
                return None
            payload = item.data(PAYLOAD_ROLE)
            if isinstance(payload, dict):
                payload_image = payload.get("image_index")
                if (
                    image_index is None
                    or payload_image == image_index
                    or (
                        isinstance(payload_image, int)
                        and image_index is not None
                        and payload_image == image_index
                    )
                ):
                    matches = True
                    if offset is not None:
                        try:
                            payload_offset = int(payload.get("offset"))
                        except Exception:
                            payload_offset = None
                        matches = matches and payload_offset == offset
                    if matches and size is not None:
                        try:
                            payload_size = int(payload.get("size"))
                        except Exception:
                            payload_size = None
                        matches = matches and payload_size == size
                    if matches and target_guid is not None:
                        item_guid = payload.get("guid")
                        try:
                            guid_text = str(item_guid).lower()
                        except Exception:
                            guid_text = None
                        matches = matches and guid_text == target_guid
                    # Match volume_index and root_index if provided
                    if matches and volume_index is not None:
                        payload_vol = payload.get("volume_index")
                        matches = matches and payload_vol == volume_index
                    if matches and root_index is not None:
                        payload_root = payload.get("root_index")
                        matches = matches and payload_root == root_index
                    if matches:
                        return item
            for row in range(item.rowCount()):
                found = _walk(item.child(row, 0))
                if found is not None:
                    return found
            return None

        for row in range(model.rowCount()):
            found_item = _walk(model.item(row, 0))
            if found_item is not None:
                return found_item
        return None

    def focus_item(
        self,
        image_index: Optional[int],
        offset: Optional[int],
        size: Optional[int],
        guid: Optional[str],
        *,
        volume_index: Optional[int] = None,
        root_index: Optional[int] = None,
    ) -> None:
        """Focus the UEFI tree on the requested payload."""

        tree: QTreeView = getattr(self.window, "uefi_tree", None)
        if tree is None:
            return
        item = self.find_item(
            image_index, offset, size, guid,
            volume_index=volume_index, root_index=root_index
        )
        self.window._focus_tree_item(tree, item)

    def mark_items_by_range(self, image_index: int, start: int, length: int) -> None:
        """Mark UEFI tree items that overlap a modified byte range."""

        window = self.window
        if not getattr(window, "include_uefi", False):
            return
        model = getattr(window, "uefi_model", None)
        tree = getattr(window, "uefi_tree", None)
        if model is None or tree is None or model.rowCount() == 0:
            return
        try:
            begin = int(start)
            span = int(length)
        except Exception:
            return
        if span <= 0:
            return
        end = begin + span

        def overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
            return a_start < b_end and b_start < a_end

        def _walk(item: Optional[QStandardItem]) -> None:
            if item is None:
                return
            payload = item.data(PAYLOAD_ROLE)
            marked = False
            if isinstance(payload, dict) and payload.get("image_index") == image_index:
                off = payload.get("offset")
                size = payload.get("size")
                if off is not None and size:
                    try:
                        item_start = int(off)
                        item_end = item_start + int(size)
                    except Exception:
                        item_start = item_end = None
                    if item_start is not None and overlaps(
                        begin, end, item_start, item_end
                    ):
                        window._set_tree_item_action(
                            tree, item, 3, "modify"
                        )
                        marked = True
            for row in range(item.rowCount()):
                _walk(item.child(row, 0))
            if marked and item.parent() is not None:
                window._set_tree_item_action(
                    tree, item.parent(), 3, "modify"
                )

        for row in range(model.rowCount()):
            _walk(model.item(row, 0))

    def capture_selection(self) -> Optional[dict]:
        """Return the current UEFI tree selection locator."""

        model = getattr(self.window, "uefi_model", None)
        tree: QTreeView = getattr(self.window, "uefi_tree", None)
        if model is None or tree is None or not model.rowCount():
            return None
        selection = tree.selectionModel()
        if selection is None:
            return None
        current = selection.currentIndex()
        if not current.isValid():
            return None
        item = model.itemFromIndex(current.sibling(current.row(), 0))
        if item is None:
            return None
        payload = item.data(PAYLOAD_ROLE)
        if not isinstance(payload, dict):
            return None
        locator = {
            "image_index": payload.get("image_index"),
            "offset": payload.get("offset"),
            "size": payload.get("size"),
            "guid": payload.get("guid"),
        }
        return locator

    def restore_selection(self, locator: Optional[dict]) -> None:
        """Restore the UEFI tree selection from a locator."""

        if not locator:
            return
        self.focus_item(
            locator.get("image_index"),
            locator.get("offset"),
            locator.get("size"),
            locator.get("guid"),
        )

    def export_guid_catalog(self) -> None:
        """Export the UEFI GUID catalog for the loaded images."""

        window = self.window
        images = getattr(window, "loaded_images", [])
        if not images or not any(img.uefi_roots for img in images):
            QMessageBox.information(
                window,
                "No GUIDs",
                "Load a firmware image with UEFI parsing enabled before exporting.",
            )
            return
        file_path, _ = QFileDialog.getSaveFileName(
            window,
            "Export GUID catalog",
            str(Path.cwd() / "guid_catalog.csv"),
            "CSV files (*.csv);;All files (*)",
        )
        if not file_path:
            return
        lines: list[str] = ["GUID,Name,Type"]
        for image in images:
            guid_map = window._collect_guid_map(image)
            for guid in sorted(guid_map.keys(), key=lambda g: str(g).upper()):
                guid_text = str(guid).upper()
                name = lookup_guid_name(guid) or "Unknown"
                contexts = sorted(guid_map[guid], key=lambda item: item[0])
                guid_type = self._infer_guid_type(name, contexts)
                safe_name = name.replace(",", " ").strip() or "Unknown"
                safe_type = guid_type.replace(",", " ").strip() or "Unknown"
                lines.append(f"{guid_text},{safe_name},{safe_type}")
        try:
            Path(file_path).write_text(
                "\n".join(lines).rstrip() + "\n", encoding="utf-8"
            )
        except Exception as exc:
            QMessageBox.critical(window, "Export failed", str(exc))
            return
        window._status_message(f"Exported GUID catalog to {file_path}")

    def _infer_guid_type(
        self,
        friendly_name: Optional[str],
        contexts: Sequence[Tuple[str, str]],
    ) -> str:
        type_from_name = self._type_from_name(friendly_name)
        if type_from_name:
            return type_from_name
        for _context, hint in contexts:
            normalized = self._normalize_type_hint(hint)
            if normalized:
                return normalized
        return "Unknown"

    def _type_from_name(self, name: Optional[str]) -> Optional[str]:
        if not name:
            return None
        text = name.strip().lower()
        if not text:
            return None
        suffix_map = [
            ("dxe", "Dxe"),
            ("peim", "Pei"),
            ("pei", "Pei"),
            ("smm", "Smm"),
            ("mm", "Mm"),
            ("app", "App"),
        ]
        for suffix, label in suffix_map:
            if text.endswith(suffix):
                return label
        return None

    def _normalize_type_hint(self, hint: Optional[str]) -> Optional[str]:
        if not hint:
            return None
        value = str(hint).strip()
        if not value:
            return None
        lower = value.lower()
        alias_map = {
            "fv": "FV",
            "ffs": "FFS",
            "driver": "Dxe",
            "combined_peim_driver": "Dxe",
            "application": "App",
            "raw": "Raw",
            "pad": "Pad",
            "freeform": "Freeform",
            "freeform_subtype_guid": "Freeform",
            "section": "Section",
            "firmware_volume_image": "FV",
            "peim": "Pei",
            "pei_core": "Pei",
            "pei_apriori": "Pei",
            "dxe_core": "Dxe",
            "dxe_apriori": "Dxe",
            "smm": "Smm",
            "mm": "Smm",
            "mm_core": "Smm",
            "mm_core_standalone": "Smm",
            "mm_standalone": "Smm",
        }
        mapped = alias_map.get(lower)
        if mapped:
            return mapped
        if "dxe" in lower:
            return "Dxe"
        if "pei" in lower:
            return "Pei"
        if "smm" in lower or "mm" in lower:
            return "Smm"
        if lower.startswith("fv"):
            return "FV"
        if lower.startswith("ffs"):
            return "FFS"
        return value.title()

    # GUID collection helpers -------------------------------------------------

    def collect_guid_from_volume(
        self,
        volume: EnumeratedFirmwareVolume,
        store: Dict[object, set[Tuple[str, str]]],
    ) -> None:
        info = volume.info
        label = f"FV[{volume.index if volume.index is not None else '?'}]"
        label += f" @{_format_optional_hex(info.absolute_offset)}"
        self._add_guid_context(store, info.filesystem_guid, label, "FV")
        for firmware_file in volume.files:
            self.collect_guid_from_file(firmware_file, store)

    def collect_guid_from_file(
        self,
        firmware_file: EnumeratedFirmwareFile,
        store: Dict[object, set[Tuple[str, str]]],
    ) -> None:
        info = firmware_file.info
        label = f"FFS[{firmware_file.index if firmware_file.index is not None else '?'}]"
        label += f" {info.type_name}"
        label += f" @{_format_optional_hex(info.absolute_offset)}"
        type_hint = info.type_name or "FFS"
        self._add_guid_context(store, info.guid, label, type_hint)
        for section in firmware_file.sections:
            self.collect_guid_from_section(section, store)

    def collect_guid_from_section(
        self,
        section: EnumeratedFirmwareSection,
        store: Dict[object, set[Tuple[str, str]]],
    ) -> None:
        info = section.info
        label = f"Section {info.type_name}"
        if info.name:
            label += f" '{info.name}'"
        label += f" @{_format_optional_hex(info.absolute_offset)}"
        type_hint = info.type_name or "Section"
        self._add_guid_context(store, info.guid, label, type_hint)
        for nested_volume in section.volumes:
            self.collect_guid_from_volume(nested_volume, store)
        for nested_section in section.sections:
            self.collect_guid_from_section(nested_section, store)

    def _add_guid_context(
        self,
        store: Dict[object, set[Tuple[str, str]]],
        guid,
        context: str,
        type_hint: Optional[str] = None,
    ) -> None:
        if guid is None:
            return
        store.setdefault(guid, set()).add((context, type_hint or ""))
