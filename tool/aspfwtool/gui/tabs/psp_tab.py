# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
PSP firmware tree tab management utilities.

This module provides:
    - PSP directory tree operations
    - Entry validation and pointer checking
    - Structure export functionality
    - Entry modification tracking
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from PySide6.QtGui import QStandardItem
from PySide6.QtWidgets import QFileDialog, QMessageBox, QTreeView

from ..utils.roles import ENTRY_LOC_ROLE, PENDING_ACTION_ROLE

from ...agesa.constants import (
    DirKind,
    COOKIE_KIND,
    is_combo_dir,
    is_real_psp_dir,
    is_real_bios_dir,
)
from ...agesa import constants as _constants
from ...agesa.directory import dir_header_len, entry_span, iter_entries
from ...agesa.entrytypes import POINT_ENTRY
from ...agesa.ish import ISH_LEN
from ...agesa.utils import encode_entry_pointer, fmt_type, resolve_entry_offset
from ...utils import get_logger


# Constants


PSP_LOCATION_COLUMN = 1
PSP_ACTION_COLUMN = 3



# PSP Tab Controller



class PspTabController:
    """Encapsulates operations tied to the PSP tree tab."""

    def __init__(self, window) -> None:
        self.window = window

    def _validate_combo_pointer(
        self,
        directory,
        pointer_value: int,
        pointer_text: Optional[str],
        image,
        *,
        entry_type: Optional[int] = None,
    ) -> bool:
        """Ensure a combo directory pointer references a valid header."""

        window = self.window
        data = getattr(image, "data", None)
        if not isinstance(data, (bytes, bytearray)) or len(data) < 4:
            QMessageBox.warning(
                window,
                "Invalid address",
                "Firmware image is too small to validate the combo pointer.",
            )
            return False

        raw = int(pointer_value) & 0xFFFFFFFFFFFFFFFF
        pointer_display = pointer_text or f"0x{raw:016X}"
        max_index = len(data) - 4
        candidates: List[int] = []
        for candidate in (raw, raw & 0xFFFFFFFF, raw & 0x00FFFFFF):
            if candidate < 0 or candidate > max_index:
                continue
            if candidate not in candidates:
                candidates.append(candidate)

        entry_type_low = (int(entry_type) & 0xFF) if entry_type is not None else None
        if entry_type_low in (0x48, 0x4A):
            if not candidates and raw != 0:
                QMessageBox.warning(
                    window,
                    "Invalid address",
                    f"{pointer_display} is outside the firmware image.",
                )
                return False
            return True

        if directory.kind == DirKind.COMBO_PSP:
            expected_tags = (b"$PSP", b"$PL2")
            expected_label = "$PSP/$PL2"
        else:
            expected_tags = (b"$BHD", b"$BL2")
            expected_label = "$BHD/$BL2"

        for candidate in candidates:
            header = bytes(data[candidate : candidate + 4])
            if header in expected_tags:
                return True

        if not candidates:
            QMessageBox.warning(
                window,
                "Invalid address",
                f"{pointer_display} is outside the firmware image.",
            )
            return False

        candidate = candidates[0]
        header = bytes(data[candidate : candidate + 4])
        ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in header)
        header_hex = header.hex().upper()
        if candidate == raw:
            location_text = f"Offset 0x{candidate:X}"
        else:
            location_text = f"Normalized offset 0x{candidate:X}"
        QMessageBox.warning(
            window,
            "Invalid address",
            (
                f"{pointer_display} does not reference a valid directory. "
                f"{location_text} contains {ascii_view} (0x{header_hex}); "
                f"expected {expected_label}."
            ),
        )
        return False

    def find_item(
        self,
        image_index: int,
        directory_index: Optional[int],
        entry_index: Optional[int],
    ) -> Optional[QStandardItem]:
        """Locate the tree item corresponding to the given PSP entry."""

        model = getattr(self.window, "psp_model", None)
        if model is None:
            return None

        def _search(item: Optional[QStandardItem]) -> Optional[QStandardItem]:
            if item is None:
                return None
            data = item.data(ENTRY_LOC_ROLE)
            if isinstance(data, dict):
                matches = (
                    data.get("image_index") == image_index
                    and data.get("directory_index") == directory_index
                    and data.get("entry_index") == entry_index
                )
                if matches:
                    return item
            for row in range(item.rowCount()):
                child = item.child(row, 0)
                found = _search(child)
                if found is not None:
                    return found
            return None

        for row in range(model.rowCount()):
            root_item = model.item(row, 0)
            found = _search(root_item)
            if found is not None:
                return found
        return None

    def focus_item(
        self,
        image_index: Optional[int],
        directory_index: Optional[int],
        entry_index: Optional[int],
    ) -> None:
        """Focus the PSP tree on the requested entry."""

        if image_index is None or directory_index is None:
            return
        tree: QTreeView = getattr(self.window, "psp_tree", None)
        if tree is None:
            return
        item = self.find_item(image_index, directory_index, entry_index)
        self.window._focus_tree_item(tree, item)

    def record_modification(
        self,
        image_index: int,
        directory_index: Optional[int],
        entry_index: Optional[int] = None,
        *,
        action_text: str = "modify",
        mark_directory: bool = True,
    ) -> None:
        """Track a modification for the given PSP entry."""

        window = self.window
        images = getattr(window, "loaded_images", [])
        if not (0 <= image_index < len(images)):
            return
        try:
            dir_idx = int(directory_index)
        except Exception:
            return
        image = images[image_index]
        image.psp_modified_entries.add((dir_idx, entry_index))
        if action_text:
            image.psp_entry_actions[(dir_idx, entry_index)] = action_text
        tree = getattr(window, "psp_tree", None)
        item = self.find_item(image_index, dir_idx, entry_index)
        if tree is not None and item is not None:
            window._set_tree_item_action(
                tree, item, PSP_ACTION_COLUMN, action_text or "modify"
            )
            # Set pending action role so undo option appears in context menu
            pending_info = image.pending_entry_actions.get((dir_idx, entry_index))
            if pending_info is not None:
                item.setData(pending_info, PENDING_ACTION_ROLE)
        if entry_index is not None and mark_directory:
            image.psp_modified_entries.add((dir_idx, None))
            image.psp_entry_actions.setdefault((dir_idx, None), "modify")
            dir_item = self.find_item(image_index, dir_idx, None)
            if tree is not None:
                window._set_tree_item_action(
                    tree, dir_item, PSP_ACTION_COLUMN, "modify"
                )

    def clear_modification(
        self,
        image_index: int,
        directory_index: Optional[int],
        entry_index: Optional[int],
    ) -> None:
        """Remove any modification markers for the PSP entry."""

        window = self.window
        images = getattr(window, "loaded_images", [])
        if not (0 <= image_index < len(images)):
            return
        try:
            dir_idx = int(directory_index)
        except Exception:
            return
        image = images[image_index]
        image.psp_modified_entries.discard((dir_idx, entry_index))
        image.psp_entry_actions.pop((dir_idx, entry_index), None)
        tree = getattr(window, "psp_tree", None)
        item = self.find_item(image_index, dir_idx, entry_index)
        if tree is not None and item is not None:
            window._set_tree_item_action(tree, item, PSP_ACTION_COLUMN, "")
            # Clear pending action role so undo option disappears from context menu
            item.setData(None, PENDING_ACTION_ROLE)
        if entry_index is not None and (dir_idx, None) in image.psp_modified_entries:
            has_other = any(
                key_dir == dir_idx and key_entry is not None
                for (key_dir, key_entry) in image.psp_modified_entries
                if (key_dir, key_entry) != (dir_idx, None)
            )
            if not has_other:
                image.psp_modified_entries.discard((dir_idx, None))
                image.psp_entry_actions.pop((dir_idx, None), None)
                dir_item = self.find_item(image_index, dir_idx, None)
                if tree is not None:
                    window._set_tree_item_action(
                        tree, dir_item, PSP_ACTION_COLUMN, ""
                    )

    def shift_pending_entry_indices(
        self,
        image,
        directory_index: int,
        start_index: int,
        delta: int,
        *,
        skip: Optional[Set[Tuple[int, Optional[int]]]] = None,
    ) -> None:
        """Shift queued PSP entry indices after an insertion or removal."""

        if delta == 0:
            return
        if skip is None:
            skip = set()
        updated_pending: Dict[Tuple[int, Optional[int]], dict] = {}
        for key, info in image.pending_entry_actions.items():
            dir_idx, entry_idx = key
            if (
                dir_idx == directory_index
                and entry_idx is not None
                and entry_idx >= start_index
                and key not in skip
            ):
                new_entry_idx = entry_idx + delta
                updated = dict(info)
                updated["entry_index"] = new_entry_idx
                updated_pending[(dir_idx, new_entry_idx)] = updated
            else:
                updated_pending[key] = info
        image.pending_entry_actions = updated_pending

        updated_actions: Dict[Tuple[int, Optional[int]], str] = {}
        new_modified: Set[Tuple[int, Optional[int]]] = set()
        for key, text in image.psp_entry_actions.items():
            dir_idx, entry_idx = key
            if (
                dir_idx == directory_index
                and entry_idx is not None
                and entry_idx >= start_index
                and key not in skip
            ):
                new_entry_idx = entry_idx + delta
                updated_actions[(dir_idx, new_entry_idx)] = text
                new_modified.add((dir_idx, new_entry_idx))
            else:
                updated_actions[key] = text
                new_modified.add(key)
        image.psp_entry_actions = updated_actions
        for key in image.psp_modified_entries:
            dir_idx, entry_idx = key
            if (
                dir_idx == directory_index
                and entry_idx is not None
                and entry_idx >= start_index
                and key not in skip
            ):
                new_modified.add((dir_idx, entry_idx + delta))
            else:
                new_modified.add(key)
        image.psp_modified_entries = new_modified

    def capture_selection(self) -> Optional[dict]:
        """Return the current PSP tree selection locator."""

        model = getattr(self.window, "psp_model", None)
        tree = getattr(self.window, "psp_tree", None)
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
        locator = item.data(ENTRY_LOC_ROLE)
        return locator if isinstance(locator, dict) else None

    def restore_selection(self, locator: Optional[dict]) -> None:
        """Restore the PSP tree selection from a locator."""

        if not locator:
            return
        model = getattr(self.window, "psp_model", None)
        tree = getattr(self.window, "psp_tree", None)
        if model is None or tree is None:
            return

        def _search(item: QStandardItem):
            if item is None:
                return None
            data = item.data(ENTRY_LOC_ROLE)
            if isinstance(data, dict):
                matches = all(
                    data.get(key) == locator.get(key)
                    for key in ("image_index", "directory_index", "entry_index")
                )
                if matches:
                    return item.index()
            for row in range(item.rowCount()):
                found = _search(item.child(row, 0))
                if found is not None:
                    return found
            return None

        for row in range(model.rowCount()):
            item = model.item(row, 0)
            result = _search(item)
            if result is not None:
                tree.setCurrentIndex(result)
                break

    def export_structure(self) -> None:
        """Export the PSP tree to a text file."""

        model = getattr(self.window, "psp_model", None)
        if model is None or model.rowCount() == 0:
            QMessageBox.information(
                self.window,
                "No data",
                "Load a firmware image before exporting the PSP tree.",
            )
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self.window,
            "Export PSP tree",
            str(Path.cwd() / "psp_tree.txt"),
            "Text files (*.txt);;All files (*)",
        )
        if not file_path:
            return
        lines: List[str] = []
        for row in range(model.rowCount()):
            item = model.item(row, 0)
            if item is not None:
                self.window._collect_tree_lines(item, 0, lines)
                lines.append("")
        try:
            Path(file_path).write_text(
                "\n".join(lines).rstrip() + "\n", encoding="utf-8"
            )
        except Exception as exc:
            QMessageBox.critical(self.window, "Export failed", str(exc))
            return
        self.window._status_message(f"Exported PSP tree to {file_path}")

    def remove_entry(
        self,
        image_index: int,
        directory_index: int,
        entry_index: int,
        *,
        rebuild: bool = False,
    ) -> None:
        """Queue removal of the specified PSP entry."""

        window = self.window
        images = getattr(window, "loaded_images", [])
        if not (0 <= image_index < len(images)):
            QMessageBox.warning(
                window, "Invalid selection", "Image index is out of range."
            )
            return
        image = images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            QMessageBox.warning(
                window, "Invalid selection", "Directory index is out of range."
            )
            return
        directory = image.directories[directory_index]
        try:
            entry_idx = int(entry_index)
        except Exception:
            QMessageBox.warning(window, "Invalid selection", "Entry index is not valid.")
            return
        original_count = int(directory.count)
        if not (0 <= entry_idx < original_count):
            QMessageBox.warning(
                window,
                "Invalid selection",
                "Entry index is outside the directory bounds.",
            )
            return
        entries = list(iter_entries(image.data, directory))
        entry_info = next(
            (info for info in entries if info.get("index") == entry_idx), None
        )
        if entry_info is None:
            QMessageBox.warning(window, "Not found", "Unable to locate the selected entry.")
            return
        entry_offset = entry_info.get("entry_offset")
        if entry_offset is None or directory.offset is None:
            QMessageBox.warning(
                window,
                "Unsupported entry",
                "Entry offset could not be resolved for removal.",
            )
            return
        context = window._builder._describe_entry(
            image_index, directory_index, directory, entry_info, image.data
        )
        span = int(entry_span(directory.kind))
        header_len = int(dir_header_len(directory.kind))
        table_start = int(directory.offset) + header_len
        table_end = table_start + original_count * span
        if entry_offset < table_start or entry_offset + span > table_end:
            QMessageBox.warning(
                window,
                "Out of range",
                "Entry location does not fall within the directory table.",
            )
            return
        table_bytes = bytes(image.data[table_start:table_end])
        before = table_bytes[: entry_idx * span]
        after = table_bytes[(entry_idx + 1) * span :]
        new_table = before + after + (b"\xff" * span)
        entry_bytes = bytes(image.data[entry_offset : entry_offset + span])
        payload_bytes: Optional[bytes] = None
        payload_offset = entry_info.get("resolved_off")
        size = int(entry_info.get("size") or 0)
        inline_offset = entry_info.get("inline_offset")
        if payload_offset is not None and size > 0:
            start = int(payload_offset)
            end = start + size
            if 0 <= start < end <= len(image.data):
                payload_bytes = bytes(image.data[start:end])
        elif inline_offset is not None and size > 0:
            start = int(inline_offset)
            end = start + size
            if 0 <= start < end <= len(image.data):
                payload_bytes = bytes(image.data[start:end])
                payload_offset = start
        image.data[table_start:table_end] = new_table

        new_count = max(original_count - 1, 0)
        count_off = int(directory.offset) + 8
        image.data[count_off : count_off + 4] = int(new_count).to_bytes(4, "little")
        directory.count = new_count

        resolved_off = entry_info.get("resolved_off")
        size = int(entry_info.get("size") or 0)
        if resolved_off is not None and size > 0:
            start = int(resolved_off)
            end = start + size
            if 0 <= start < end <= len(image.data):
                image.data[start:end] = b"\xff" * (end - start)
                window._record_modified_range(image_index, start, end - start)

        window._record_modified_range(image_index, table_start, len(new_table))
        window._record_modified_range(image_index, count_off, 4)
        window._update_directory_checksum(image, directory)
        if directory.offset is not None:
            window._record_modified_range(image_index, int(directory.offset) + 4, 4)

        image.needs_reparse = True
        window._mark_image_dirty(image_index)

        self.shift_pending_entry_indices(image, directory_index, entry_idx + 1, -1)
        image.pending_entry_actions.pop((directory_index, entry_idx), None)

        type_label = fmt_type(entry_info.get("type_id"), directory.kind, mode=False)
        change_desc = (
            f"d{directory_index:02X}-e{entry_idx:02X} removed "
            f"({type_label}, 0x{size:X} bytes)"
        )
        action_id = window._allocate_action_id()
        context_payload = {
            "label": context.get("label") or change_desc,
            "detail": "\n".join(context.get("detail_lines", [])),
            "summary": context.get("summary") or f"Removed {type_label}",
            "size_display": context.get("size_display"),
            "metadata": context.get("metadata"),
            "location_display": context.get("location_display"),
        }
        image.pending_entry_actions[(directory_index, entry_idx)] = {
            "action": "remove",
            "action_id": action_id,
            "image_index": image_index,
            "directory_index": directory_index,
            "entry_index": entry_idx,
            "span": span,
            "table_start": table_start,
            "count_offset": count_off,
            "entry_bytes": entry_bytes,
            "payload_bytes": payload_bytes,
            "payload_offset": payload_offset,
            "payload_size": size,
            "change_desc": change_desc,
            "action_text": "Remove",
            "context": context_payload,
        }
        image.change_log.append(change_desc)
        self.record_modification(
            image_index, directory_index, entry_idx, action_text="Remove"
        )
        self.record_modification(image_index, directory_index, None, action_text="modify")
        window._append_console(f"Queued removal: {change_desc}")
        window._status_message(f"Removed entry {entry_idx} from {directory.kind.value} d{directory_index:02X}")
        if rebuild:
            window._rebuild_from_loaded_images()

    def replace_entry(
        self, image_index: int, directory_index: int, entry_index: int,
        *, rebuild: bool = False,
    ) -> None:
        """Queue replacement of a PSP entry."""

        window = self.window
        images = getattr(window, "loaded_images", [])
        if not (0 <= image_index < len(images)):
            QMessageBox.warning(
                window, "Invalid selection", "Image index is out of range."
            )
            return
        image = images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            QMessageBox.warning(
                window, "Invalid selection", "Directory index is out of range."
            )
            return
        directory = image.directories[directory_index]
        is_combo = _constants.is_combo_dir(directory.kind)
        try:
            entry_idx = int(entry_index)
        except Exception:
            QMessageBox.warning(window, "Invalid selection", "Entry index is not valid.")
            return
        entries = list(iter_entries(image.data, directory))
        entry_info = next(
            (info for info in entries if info.get("index") == entry_idx), None
        )
        if entry_info is None:
            QMessageBox.warning(window, "Not found", "Unable to locate the selected entry.")
            return
        if entry_info.get("inline_offset") is not None:
            QMessageBox.information(
                window,
                "Inline entry",
                "Inline value entries should be edited through the Soft Fuse pane.",
            )
            return
        entry_offset = entry_info.get("entry_offset")
        if entry_offset is None or directory.offset is None:
            QMessageBox.warning(
                window,
                "Unsupported entry",
                "Entry offset could not be resolved for replacement.",
            )
            return
        span = int(entry_span(directory.kind))
        require_data = not is_combo
        if (
            entry_info.get("entry_type") == POINT_ENTRY
            and int(entry_info.get("size") or 0) <= 0
        ):
            require_data = False
        config = window._prompt_entry_configuration(
            image_index,
            directory_index,
            directory,
            entry_info,
            title="Replace entry",
            require_data=require_data,
        )
        if not config:
            return

        data = image.data
        file_size = len(data)
        old_size = int(entry_info.get("size") or 0)
        original_offset = entry_info.get("resolved_off")
        original_offset_int = (
            int(original_offset) if original_offset is not None else None
        )
        entry_bytes_before = bytes(data[int(entry_offset) : int(entry_offset) + span])
        payload_bytes_before: Optional[bytes] = None
        if original_offset_int is not None and old_size > 0:
            start = int(original_offset_int)
            end = start + old_size
            if 0 <= start < end <= len(data):
                payload_bytes_before = bytes(data[start:end])
        if is_combo:
            pointer_value = config.get("combo_pointer")
            pointer_text = config.get("combo_pointer_text")
            if pointer_value is None:
                QMessageBox.warning(
                    window,
                    "Invalid address",
                    "Enter a directory address for the combo entry.",
                )
                return
            pointer_int = int(pointer_value) & 0xFFFFFFFFFFFFFFFF
            new_type_value = int(config.get("type_value") or 0) & 0xFFFFFFFF
            if not self._validate_combo_pointer(
                directory,
                pointer_int,
                pointer_text,
                image,
                entry_type=new_type_value,
            ):
                return
            entry_bytes = bytearray(entry_bytes_before)
            match_value = int(config.get("combo_pspid") or 0) & 0xFFFFFFFF
            entry_bytes[0:4] = new_type_value.to_bytes(4, "little")
            entry_bytes[4:8] = match_value.to_bytes(4, "little")
            entry_bytes[8:16] = pointer_int.to_bytes(8, "little")
            data[int(entry_offset) : int(entry_offset) + span] = entry_bytes

            window._record_modified_range(image_index, int(entry_offset), span)
            window._update_directory_checksum(image, directory)
            if directory.offset is not None:
                window._record_modified_range(
                    image_index, int(directory.offset) + 4, 4
                )

            image.needs_reparse = True
            window._mark_image_dirty(image_index)
            pointer_display = (
                pointer_text
                if isinstance(pointer_text, str) and pointer_text.strip()
                else f"0x{pointer_int:016X}"
            )
            change_desc = (
                f"d{directory_index:02X}-e{entry_idx:02X} replaced "
                f"(match=0x{match_value:08X}, ptr={pointer_display})"
            )
            action_id = window._allocate_action_id()
            image.pending_entry_actions[(directory_index, entry_idx)] = {
                "action": "replace",
                "action_id": action_id,
                "image_index": image_index,
                "directory_index": directory_index,
                "entry_index": entry_idx,
                "span": span,
                "entry_offset": int(entry_offset),
                "entry_bytes": entry_bytes_before,
                "original_entry_bytes": entry_bytes_before,
                "payload_offset": None,
                "payload_size": 0,
                "payload_bytes": payload_bytes_before,
                "original_payload_bytes": payload_bytes_before,
                "original_payload_offset": original_offset_int,
                "new_payload_offset": original_offset_int,
                "new_payload_size": 0,
                "previous_pointer": original_offset_int,
                "moved": False,
                "change_desc": change_desc,
                "action_text": "Replace",
            }
            image.change_log.append(change_desc)
            self.record_modification(
                image_index, directory_index, entry_idx, action_text="Replace"
            )
            window._append_console(f"Queued replacement: {change_desc}")
            window._status_message(
                f"Replaced entry {entry_idx} in {directory.kind.value} d{directory_index:02X}"
            )
            if rebuild:
                window._rebuild_from_loaded_images()
            return

        new_blob = config.get("data", b"")
        if require_data and not new_blob:
            QMessageBox.warning(
                window, "Replacement failed", "Replacement file does not contain data."
            )
            return

        declared_override_value = config.get("declared_size")
        size_override_value = config.get("size_override")
        if declared_override_value is not None:
            try:
                declared_size = int(declared_override_value)
            except Exception:
                declared_size = 0
        elif size_override_value is not None:
            try:
                declared_size = int(size_override_value)
            except Exception:
                declared_size = len(new_blob)
        else:
            declared_size = len(new_blob)
        declared_size = max(int(declared_size), 0)
        payload_length = len(new_blob)
        final_offset = original_offset_int
        moved = False
        allocate_size = max(declared_size, payload_length)

        if original_offset_int is not None:
            if declared_size > old_size:
                extend_end = original_offset_int + declared_size
                has_space = extend_end <= file_size and all(
                    byte == 0xFF
                    for byte in data[
                        original_offset_int + old_size : min(extend_end, file_size)
                    ]
                )
                if not has_space:
                    candidate = window._find_free_region(
                        data, original_offset_int + old_size, allocate_size
                    )
                    if candidate is not None:
                        final_offset = candidate
                        moved = True
                    else:
                        if extend_end > file_size:
                            QMessageBox.warning(
                                window,
                                "No space",
                                "The image does not have enough free space to extend the entry.",
                            )
                            return
                        overlap_bytes = data[
                            original_offset_int + old_size : extend_end
                        ]
                        if any(byte != 0xFF for byte in overlap_bytes):
                            result = QMessageBox.question(
                                window,
                                "Overwrite data?",
                                "Extending the entry will overwrite non-blank bytes. Continue?",
                            )
                            if result != QMessageBox.Yes:
                                return
            elif declared_size < old_size:
                truncate_start = original_offset_int + declared_size
                truncate_end = original_offset_int + old_size
                data[truncate_start:truncate_end] = b"\xff" * (truncate_end - truncate_start)
        else:
            candidate = window._find_free_region(
                data,
                int(directory.offset) + int(dir_header_len(directory.kind)),
                allocate_size,
            )
            if candidate is None:
                QMessageBox.warning(
                    window, "No space", "Unable to locate free space for the replacement."
                )
                return
            final_offset = candidate
            moved = True

        if final_offset is None:
            QMessageBox.warning(
                window,
                "Pointer error",
                "Unable to resolve a new payload location for the entry.",
            )
            return

        if payload_length:
            data[final_offset : final_offset + payload_length] = new_blob
        if declared_size > payload_length:
            pad_start = final_offset + payload_length
            pad_end = final_offset + declared_size
            data[pad_start:pad_end] = b"\xff" * (pad_end - pad_start)

        prefer_mode = config.get("address_mode")
        pointer = encode_entry_pointer(
            directory.kind,
            int(directory.offset),
            file_size,
            final_offset,
            prefer_mode=prefer_mode,
        )
        if pointer is None:
            QMessageBox.warning(
                window,
                "Pointer error",
                "Unable to encode a pointer for the new entry location.",
            )
            if payload_length:
                data[final_offset : final_offset + payload_length] = b"\xff" * payload_length
            return

        entry_bytes = bytearray(entry_bytes_before)
        new_type_value = int(config.get("type_value") or 0) & 0xFFFFFFFF
        match_value = int(config.get("combo_pspid") or 0) & 0xFFFFFFFF
        entry_bytes[0:4] = new_type_value.to_bytes(4, "little")
        if is_combo:
            entry_bytes[4:8] = match_value.to_bytes(4, "little")
        else:
            entry_bytes[4:8] = int(declared_size).to_bytes(4, "little")
        entry_bytes[8:16] = int(pointer).to_bytes(8, "little")
        data[int(entry_offset) : int(entry_offset) + span] = entry_bytes

        window._record_modified_range(image_index, int(entry_offset), span)
        window._record_modified_range(image_index, final_offset, allocate_size)
        window._update_directory_checksum(image, directory)
        if directory.offset is not None:
            window._record_modified_range(image_index, int(directory.offset) + 4, 4)

        image.needs_reparse = True
        window._mark_image_dirty(image_index)
        if is_combo:
            change_desc = (
                f"d{directory_index:02X}-e{entry_idx:02X} replaced "
                f"(match=0x{match_value:08X})"
            )
        else:
            change_desc = (
                f"d{directory_index:02X}-e{entry_idx:02X} replaced with "
                f"0x{declared_size:X} bytes"
            )
        action_id = window._allocate_action_id()
        image.pending_entry_actions[(directory_index, entry_idx)] = {
            "action": "replace",
            "action_id": action_id,
            "image_index": image_index,
            "directory_index": directory_index,
            "entry_index": entry_idx,
            "span": span,
            "entry_offset": int(entry_offset),
            "entry_bytes": entry_bytes_before,
            "original_entry_bytes": entry_bytes_before,
            "payload_offset": final_offset,
            "payload_size": allocate_size,
            "payload_bytes": payload_bytes_before,
            "original_payload_bytes": payload_bytes_before,
            "original_payload_offset": original_offset_int,
            "new_payload_offset": final_offset,
            "new_payload_size": allocate_size,
            "previous_pointer": original_offset_int,
            "moved": moved,
            "change_desc": change_desc,
            "action_text": "Replace",
        }
        image.change_log.append(change_desc)
        self.record_modification(
            image_index, directory_index, entry_idx, action_text="Replace"
        )
        window._append_console(f"Queued replacement: {change_desc}")
        window._status_message(f"Replaced entry {entry_idx} in {directory.kind.value} d{directory_index:02X}")
        if rebuild:
            window._rebuild_from_loaded_images()

    def edit_entry(
        self, image_index: int, directory_index: int, entry_index: int
    ) -> None:
        """Queue an in-place metadata update for a PSP entry."""

        window = self.window
        images = getattr(window, "loaded_images", [])
        if not (0 <= image_index < len(images)):
            QMessageBox.warning(
                window, "Invalid selection", "Image index is out of range."
            )
            return
        image = images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            QMessageBox.warning(
                window, "Invalid selection", "Directory index is out of range."
            )
            return
        directory = image.directories[directory_index]
        try:
            entry_idx = int(entry_index)
        except Exception:
            QMessageBox.warning(window, "Invalid selection", "Entry index is not valid.")
            return
        entries = list(iter_entries(image.data, directory))
        entry_info = next(
            (info for info in entries if info.get("index") == entry_idx), None
        )
        if entry_info is None:
            QMessageBox.warning(window, "Not found", "Unable to locate the selected entry.")
            return
        if entry_info.get("inline_offset") is not None:
            QMessageBox.information(
                window,
                "Inline entry",
                "Inline value entries should be edited through the Soft Fuse pane.",
            )
            return
        entry_offset = entry_info.get("entry_offset")
        if entry_offset is None:
            QMessageBox.warning(
                window,
                "Unsupported entry",
                "Entry offset could not be resolved for editing.",
            )
            return
        lock_entry_type = (
            is_real_psp_dir(directory.kind)
            and entry_info.get("entry_type") == POINT_ENTRY
        )
        config = window._prompt_entry_configuration(
            image_index,
            directory_index,
            directory,
            entry_info,
            title="Edit entry",
            require_data=False,
            allow_file_selection=False,
            lock_entry_type=lock_entry_type,
        )
        if not config:
            return
        try:
            changed = self._apply_entry_metadata_update(
                image_index,
                directory_index,
                entry_idx,
                directory,
                entry_info,
                config,
                rebuild=False,
                quiet=False,
            )
        except ValueError as exc:
            QMessageBox.warning(window, "Edit failed", str(exc))
            return
        if not changed:
            return

    def _apply_entry_metadata_update(
        self,
        image_index: int,
        directory_index: int,
        entry_idx: int,
        directory,
        entry_info: dict,
        config: dict,
        *,
        rebuild: bool,
        quiet: bool,
    ) -> bool:
        """Apply metadata updates to an entry and queue the change."""
        get_logger().debug(f"_apply_entry_metadata_update: entry={entry_idx}, config={config}")

        window = self.window
        images = getattr(window, "loaded_images", [])
        if not (0 <= image_index < len(images)):
            raise ValueError("Image index is out of range.")
        image = images[image_index]
        data = image.data
        entry_offset = entry_info.get("entry_offset")
        if entry_offset is None:
            raise ValueError("Entry offset could not be resolved for editing.")
        span = int(entry_span(directory.kind))
        start = int(entry_offset)
        end = start + span
        entry_bytes_before = bytes(data[start:end])
        entry_bytes = bytearray(entry_bytes_before)
        is_combo = _constants.is_combo_dir(directory.kind)

        payload_offset = entry_info.get("resolved_off")
        try:
            payload_offset_int = int(payload_offset)
        except Exception:
            payload_offset_int = None
        payload_size = max(int(entry_info.get("size") or 0), 0)
        pointer_display = ""
        payload_bytes_before: Optional[bytes] = None
        payload_changed = False

        if is_combo:
            existing_type = int.from_bytes(entry_bytes_before[0:4], "little")
            existing_match = int.from_bytes(entry_bytes_before[4:8], "little")
            existing_ptr = int.from_bytes(entry_bytes_before[8:16], "little")

            new_type_value = config.get("type_value")
            if new_type_value is None:
                new_type_value = existing_type
            new_type_value = int(new_type_value) & 0xFFFFFFFF

            match_value = config.get("combo_pspid")
            if match_value is None:
                match_value = existing_match
            match_value = int(match_value) & 0xFFFFFFFF

            pointer_value = config.get("combo_pointer")
            pointer_text = config.get("combo_pointer_text")
            if pointer_value is None:
                pointer_value = existing_ptr
            else:
                pointer_value = int(pointer_value) & 0xFFFFFFFFFFFFFFFF
                if not self._validate_combo_pointer(
                    directory,
                    pointer_value,
                    pointer_text,
                    image,
                    entry_type=new_type_value,
                ):
                    raise ValueError("Enter a valid directory address for the combo entry.")
            pointer_display = (
                pointer_text.strip() if isinstance(pointer_text, str) else ""
            )
            if not pointer_display:
                pointer_display = f"0x{pointer_value:016X}"

            entry_bytes[0:4] = new_type_value.to_bytes(4, "little")
            entry_bytes[4:8] = match_value.to_bytes(4, "little")
            entry_bytes[8:16] = pointer_value.to_bytes(8, "little")
            payload_offset_int = None
            payload_size = 0
            change_desc = (
                f"d{directory_index:02X}-e{entry_idx:02X} edited "
                f"(match=0x{match_value:08X}, ptr={pointer_display})"
            )
        else:
            existing_type = int.from_bytes(entry_bytes_before[0:4], "little")
            existing_declared = int.from_bytes(entry_bytes_before[4:8], "little")
            existing_ptr = int.from_bytes(entry_bytes_before[8:16], "little")

            # Handle BHD/BL2 entries with individual bit fields
            if is_real_bios_dir(directory.kind):
                # Check if we have a full type_value from EntryEditDialog
                full_type_value = config.get("type_value")
                if full_type_value is not None:
                    # EntryEditDialog provides the full 32-bit type_id
                    new_type_value = int(full_type_value) & 0xFFFFFFFF
                    entry_type = new_type_value & 0xFF
                else:
                    # DirectoryEditDialog provides individual bit fields
                    # Parse existing type_id into bit fields
                    ex_entry_type = existing_type & 0xFF
                    ex_region_type = (existing_type >> 8) & 0xFF
                    ex_reset_image = (existing_type >> 16) & 0x1
                    ex_copy_image = (existing_type >> 17) & 0x1
                    ex_read_only = (existing_type >> 18) & 0x1
                    ex_compressed = (existing_type >> 19) & 0x1
                    ex_instance = (existing_type >> 20) & 0xF
                    ex_subprogram = (existing_type >> 24) & 0x7
                    ex_rom_id = (existing_type >> 27) & 0x3
                    ex_writable = (existing_type >> 29) & 0x1
                    ex_reserved = (existing_type >> 30) & 0x3
                    
                    # Get updated values from config or use existing
                    entry_type = config.get("entry_type", ex_entry_type) & 0xFF
                    region_type = config.get("region_type", ex_region_type) & 0xFF
                    reset_image = config.get("reset_image", ex_reset_image) & 0x1
                    copy_image = config.get("copy_image", ex_copy_image) & 0x1
                    read_only = config.get("read_only", ex_read_only) & 0x1
                    compressed = config.get("compressed", ex_compressed) & 0x1
                    instance = config.get("instance", ex_instance) & 0xF
                    subprogram = config.get("subprogram", ex_subprogram) & 0x7
                    rom_id = config.get("rom_id", ex_rom_id) & 0x3
                    writable = config.get("writable", ex_writable) & 0x1
                    reserved = config.get("reserved", ex_reserved) & 0x3
                    
                    # Rebuild type_id from bit fields
                    new_type_value = (
                        (entry_type) |
                        (region_type << 8) |
                        (reset_image << 16) |
                        (copy_image << 17) |
                        (read_only << 18) |
                        (compressed << 19) |
                        (instance << 20) |
                        (subprogram << 24) |
                        (rom_id << 27) |
                        (writable << 29) |
                        (reserved << 30)
                    )
                
                # Size - check both 'declared_size' and 'size' keys
                declared_override = config.get("declared_size")
                if declared_override is None:
                    declared_override = config.get("size")
                if declared_override is None:
                    declared_size = existing_declared
                else:
                    declared_size = max(int(declared_override), 0)
                
                # Source address and mode
                ex_source_addr = existing_ptr & ((1 << 62) - 1)
                ex_addr_mode = (existing_ptr >> 62) & 0x3
                
                source_address = config.get("source_address")
                if source_address is None:
                    source_address = ex_source_addr
                else:
                    source_address = int(source_address) & ((1 << 62) - 1)
                
                address_mode = config.get("address_mode")
                if address_mode is None:
                    address_mode = ex_addr_mode
                else:
                    address_mode = int(address_mode) & 0x3
                
                pointer_value = source_address | (address_mode << 62)
                pointer_display = f"0x{source_address:X} (mode {address_mode})"
                
                # Destination
                existing_destination = int.from_bytes(entry_bytes_before[16:24], "little")
                destination = config.get("destination")
                if destination is None:
                    destination = existing_destination
                else:
                    destination = int(destination) & 0xFFFFFFFFFFFFFFFF
                
                # Write all fields
                entry_bytes[0:4] = new_type_value.to_bytes(4, "little")
                entry_bytes[4:8] = int(declared_size).to_bytes(4, "little")
                entry_bytes[8:16] = pointer_value.to_bytes(8, "little")
                entry_bytes[16:24] = int(destination).to_bytes(8, "little")
                
                change_desc = (
                    f"d{directory_index:02X}-e{entry_idx:02X} edited metadata "
                    f"(type=0x{entry_type:02X}, size=0x{int(declared_size):X})"
                )
            else:
                # PSP/PL2 entries (16 bytes)
                # Check if we have a full type_value from EntryEditDialog
                full_type_value = config.get("type_value")
                if full_type_value is not None:
                    # EntryEditDialog provides the full 32-bit type_id
                    new_type_value = int(full_type_value) & 0xFFFFFFFF
                    entry_type = new_type_value & 0xFF
                else:
                    # DirectoryEditDialog provides individual bit fields
                    # Parse existing type_id into bit fields
                    ex_entry_type = existing_type & 0xFF
                    ex_subprogram = (existing_type >> 8) & 0xFF
                    ex_rom_id = (existing_type >> 16) & 0x3
                    ex_writable = (existing_type >> 18) & 0x1
                    ex_instance = (existing_type >> 19) & 0xF
                    ex_reserved = (existing_type >> 23) & 0x1FF
                    
                    # Get updated values from config or use existing
                    entry_type = config.get("entry_type", ex_entry_type) & 0xFF
                    subprogram = config.get("subprogram", ex_subprogram) & 0xFF
                    rom_id = config.get("rom_id", ex_rom_id) & 0x3
                    writable = config.get("writable", ex_writable) & 0x1
                    instance = config.get("instance", ex_instance) & 0xF
                    reserved = config.get("reserved", ex_reserved) & 0x1FF
                    
                    # Rebuild type_id from bit fields
                    new_type_value = (
                        (entry_type) |
                        (subprogram << 8) |
                        (rom_id << 16) |
                        (writable << 18) |
                        (instance << 19) |
                        (reserved << 23)
                    )

                # Handle size - check both 'declared_size' and 'size' keys
                declared_override = config.get("declared_size")
                if declared_override is None:
                    declared_override = config.get("size")
                if declared_override is None:
                    declared_size = existing_declared
                else:
                    declared_size = max(int(declared_override), 0)

                # Address and mode
                ex_address = existing_ptr & ((1 << 62) - 1)
                ex_addr_mode = (existing_ptr >> 62) & 0x3
                
                address = config.get("address")
                if address is None:
                    address = ex_address
                else:
                    address = int(address) & ((1 << 62) - 1)
                
                address_mode = config.get("address_mode")
                if address_mode is None:
                    address_mode = ex_addr_mode
                else:
                    address_mode = int(address_mode) & 0x3
                
                pointer_value = address | (address_mode << 62)
                pointer_display = f"0x{address:X} (mode {address_mode})"

                entry_bytes[0:4] = new_type_value.to_bytes(4, "little")
                entry_bytes[4:8] = int(declared_size).to_bytes(4, "little")
                entry_bytes[8:16] = pointer_value.to_bytes(8, "little")

                type_label = fmt_type(new_type_value, directory.kind, mode=False)
                change_desc = (
                    f"d{directory_index:02X}-e{entry_idx:02X} edited metadata "
                    f"(type=0x{entry_type:02X}, size=0x{int(declared_size):X})"
                )

                # ISH handling for PSP entries only
                type_low = new_type_value & 0xFF
                ish_blob = config.get("data", b"")
                if ish_blob and type_low in (0x48, 0x4A):
                    ish_blob = bytes(ish_blob)
                    if len(ish_blob) != ISH_LEN:
                        raise ValueError(
                            f"ISH stubs must be exactly 0x{ISH_LEN:02X} bytes long."
                        )
                    pointer_changed = int(pointer_value) != int(existing_ptr)
                    target_offset = payload_offset_int
                    if pointer_changed or target_offset is None:
                        base_off = getattr(directory, "offset", None)
                        try:
                            base_int = int(base_off) if base_off is not None else None
                        except Exception:
                            base_int = None
                        resolved_off: Optional[int] = None
                        if base_int is not None:
                            resolved_off, _ = resolve_entry_offset(
                                directory.kind,
                                base_int,
                                int(pointer_value),
                                int(declared_size),
                                len(data),
                                allow_zero_size=True,
                                allow_oversize=True,
                            )
                        if resolved_off is not None:
                            target_offset = resolved_off
                        else:
                            raise ValueError(
                                "Unable to resolve the pointer target for this ISH entry."
                            )
                    start_ish = int(target_offset)
                    end_ish = start_ish + len(ish_blob)
                    if start_ish < 0 or end_ish > len(data):
                        raise ValueError("ISH stub target is outside the firmware image bounds.")
                    existing_blob = bytes(data[start_ish:end_ish])
                    if existing_blob != ish_blob:
                        data[start_ish:end_ish] = ish_blob
                        window._record_modified_range(image_index, start_ish, len(ish_blob))
                        payload_changed = True
                    payload_bytes_before = existing_blob
                    payload_offset_int = target_offset
                    payload_size = len(ish_blob)

        table_changed = bytes(entry_bytes) != entry_bytes_before
        get_logger().debug(f"table_changed={table_changed}, payload_changed={payload_changed}")
        get_logger().debug(f"entry_bytes_before={entry_bytes_before.hex()}")
        get_logger().debug(f"entry_bytes      ={bytes(entry_bytes).hex()}")
        if not table_changed and not payload_changed:
            if not quiet:
                QMessageBox.information(
                    window, "No changes", "No metadata changes were made."
                )
            return False

        if table_changed:
            data[start:end] = entry_bytes
            window._record_modified_range(image_index, start, span)
            window._update_directory_checksum(image, directory)
            if directory.offset is not None:
                window._record_modified_range(image_index, int(directory.offset) + 4, 4)

        if payload_changed and not table_changed:
            change_desc = (
                f"d{directory_index:02X}-e{entry_idx:02X} updated ISH stub data"
            )
        elif payload_changed:
            change_desc = f"{change_desc} + updated ISH stub"

        image.needs_reparse = True
        window._mark_image_dirty(image_index)

        action_id = window._allocate_action_id()
        previous_pointer = entry_info.get("resolved_off")
        try:
            previous_pointer = int(previous_pointer)
        except Exception:
            previous_pointer = None
        image.pending_entry_actions[(directory_index, entry_idx)] = {
            "action": "replace",
            "action_id": action_id,
            "image_index": image_index,
            "directory_index": directory_index,
            "entry_index": entry_idx,
            "span": span,
            "entry_offset": start,
            "entry_bytes": entry_bytes_before,
            "original_entry_bytes": entry_bytes_before,
            "payload_offset": payload_offset_int,
            "payload_size": payload_size,
            "payload_bytes": payload_bytes_before,
            "original_payload_bytes": payload_bytes_before,
            "original_payload_offset": payload_offset_int,
            "new_payload_offset": payload_offset_int,
            "new_payload_size": payload_size,
            "previous_pointer": previous_pointer,
            "moved": False,
            "change_desc": change_desc,
            "action_text": "Edit",
        }
        image.change_log.append(change_desc)
        self.record_modification(
            image_index, directory_index, entry_idx, action_text="Edit"
        )
        window._append_console(f"Queued edit: {change_desc}")
        window._status_message(f"Edited entry {entry_idx} in {directory.kind.value} directory {directory_index:02X}")

        if rebuild:
            window._rebuild_from_loaded_images()
        return True

    def bulk_edit_directory(
        self,
        image_index: int,
        directory_index: int,
        edits: List[dict],
        removals: List[int],
        reorder: Optional[List[int]] = None,
        header_update: Optional[dict] = None,
    ) -> None:
        """Apply multiple metadata updates and removals to a directory."""

        window = self.window
        images = getattr(window, "loaded_images", [])
        if not (0 <= image_index < len(images)):
            QMessageBox.warning(
                window, "Invalid selection", "Image index is out of range."
            )
            return
        image = images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            QMessageBox.warning(
                window, "Invalid selection", "Directory index is out of range."
            )
            return
        directory = image.directories[directory_index]

        header_changed = False
        reordered = False
        reorder_mapping: Optional[Dict[int, int]] = None

        if header_update:
            offset = getattr(directory, "offset", None)
            if offset is None:
                QMessageBox.warning(
                    window, "Header update failed", "Directory offset is unavailable."
                )
            else:
                try:
                    off_int = int(offset)
                except Exception:
                    off_int = None
                header_len = int(dir_header_len(directory.kind))
                if off_int is None or off_int < 0 or off_int + header_len > len(image.data):
                    QMessageBox.warning(
                        window,
                        "Header update failed",
                        "Directory header is outside the firmware image bounds.",
                    )
                else:
                    header_bytes = bytearray(image.data[off_int : off_int + header_len])
                    
                    # Handle cookie update (if provided)
                    cookie_bytes = header_update.get("cookie")
                    if isinstance(cookie_bytes, (bytes, bytearray)) and len(cookie_bytes) == 4:
                        new_kind = COOKIE_KIND.get(bytes(cookie_bytes))
                        if new_kind:
                            new_header_len = int(dir_header_len(new_kind))
                            if new_header_len != header_len:
                                QMessageBox.warning(
                                    window,
                                    "Header update failed",
                                    "Changing the cookie would alter the directory header size, "
                                    "which is not supported.",
                                )
                                new_kind = None
                            else:
                                directory.kind = new_kind
                                directory.magic = new_kind
                        header_bytes[0:4] = bytes(cookie_bytes)
                        header_changed = True
                    
                    # Handle count update
                    count_value = header_update.get("count")
                    if count_value is not None and isinstance(count_value, int):
                        header_bytes[0x08:0x0C] = int(count_value & 0xFFFFFFFF).to_bytes(4, "little")
                        directory.count = count_value
                        header_changed = True
                    
                    # Handle info field update (PSP/BHD only, not combo)
                    info_value = header_update.get("info")
                    if (
                        info_value is not None
                        and not _constants.is_combo_dir(directory.kind)
                        and isinstance(info_value, int)
                    ):
                        header_bytes[0x0C:0x10] = int(info_value & 0xFFFFFFFF).to_bytes(
                            4, "little"
                        )
                        header_changed = True
                    if header_changed:
                        image.data[off_int : off_int + header_len] = header_bytes
                        window._record_modified_range(image_index, off_int, header_len)
                        window._update_directory_checksum(image, directory)
                        if directory.offset is not None:
                            window._record_modified_range(
                                image_index, int(directory.offset) + 4, 4
                            )
                        image.needs_reparse = True
                        window._mark_image_dirty(image_index)
                        self.record_modification(
                            image_index, directory_index, None, action_text="modify"
                        )
                        change_desc = f"d{directory_index:02X} header updated"
                        image.change_log.append(change_desc)
                        window._append_console(f"Updated directory header: {change_desc}")

        entry_map = {
            info.get("index"): info
            for info in iter_entries(image.data, directory)
            if isinstance(info.get("index"), int)
        }

        changes = 0
        error_occurred = False
        for edit in edits:
            entry_idx = edit.get("entry_index")
            if not isinstance(entry_idx, int):
                continue
            entry_info = edit.get("entry_info")
            if not isinstance(entry_info, dict):
                entry_info = entry_map.get(entry_idx)
            if entry_info is None:
                QMessageBox.warning(
                    window, "Edit failed", f"Entry {entry_idx} could not be located."
                )
                error_occurred = True
                break
            config = edit.get("config") or {}
            if not config:
                continue
            try:
                changed = self._apply_entry_metadata_update(
                    image_index,
                    directory_index,
                    entry_idx,
                    directory,
                    entry_info,
                    config,
                    rebuild=False,
                    quiet=True,
                )
            except ValueError as exc:
                QMessageBox.warning(window, "Edit failed", str(exc))
                error_occurred = True
                break
            if changed:
                changes += 1

        if error_occurred:
            if changes:
                window._rebuild_from_loaded_images()
                window._status_message(
                    "Partial directory edits were applied before an error occurred."
                )
            return

        if reorder:
            count = int(directory.count)
            span = int(entry_span(directory.kind))
            header_len = int(dir_header_len(directory.kind))
            offset = getattr(directory, "offset", None)
            if offset is None:
                QMessageBox.warning(
                    window, "Reorder failed", "Directory offset is unavailable."
                )
            elif len(reorder) != count:
                QMessageBox.warning(
                    window,
                    "Reorder failed",
                    "The number of reordered entries does not match the directory count.",
                )
            else:
                try:
                    table_start = int(offset) + header_len
                except Exception:
                    table_start = None
                if (
                    table_start is None
                    or table_start < 0
                    or table_start + count * span > len(image.data)
                ):
                    QMessageBox.warning(
                        window,
                        "Reorder failed",
                        "Directory table is outside the firmware image bounds.",
                    )
                else:
                    new_table = bytearray(count * span)
                    valid = True
                    for new_pos, original_index in enumerate(reorder):
                        if not isinstance(original_index, int) or not (0 <= original_index < count):
                            valid = False
                            break
                        src_start = table_start + original_index * span
                        src_end = src_start + span
                        new_start = new_pos * span
                        new_table[new_start:new_start + span] = image.data[src_start:src_end]
                    if not valid:
                        QMessageBox.warning(
                            window,
                            "Reorder failed",
                            "One or more entries could not be relocated due to invalid indices.",
                        )
                    else:
                        image.data[table_start : table_start + len(new_table)] = new_table
                        reorder_mapping = {
                            original_index: new_pos
                            for new_pos, original_index in enumerate(reorder)
                        }
                        reordered = True
                        window._record_modified_range(
                            image_index, table_start, len(new_table)
                        )
                        window._update_directory_checksum(image, directory)
                        if directory.offset is not None:
                            window._record_modified_range(
                                image_index, int(directory.offset) + 4, 4
                            )
                        image.needs_reparse = True
                        window._mark_image_dirty(image_index)
                        self.record_modification(
                            image_index, directory_index, None, action_text="modify"
                        )
                        change_desc = f"Directory {directory_index:02X} entries reordered"
                        image.change_log.append(change_desc)
                        window._append_console(f"Reordered directory entries: {change_desc}")

                        # Update pending actions and markers to reflect new indices.
                        mapping = reorder_mapping
                        if mapping is not None:
                            new_pending: Dict[Tuple[int, Optional[int]], dict] = {}
                            for key, info in image.pending_entry_actions.items():
                                dir_idx, entry_idx = key
                                if dir_idx != directory_index or entry_idx is None:
                                    new_pending[key] = info
                                    continue
                                new_pos = mapping.get(int(entry_idx))
                                if new_pos is None:
                                    continue
                                updated = dict(info)
                                updated["entry_index"] = new_pos
                                if "entry_offset" in updated:
                                    updated["entry_offset"] = table_start + new_pos * span
                                new_pending[(dir_idx, new_pos)] = updated
                            image.pending_entry_actions = new_pending

                            new_actions: Dict[Tuple[int, Optional[int]], str] = {}
                            for key, action_text in image.psp_entry_actions.items():
                                dir_idx, entry_idx = key
                                if dir_idx != directory_index or entry_idx is None:
                                    new_actions[key] = action_text
                                    continue
                                new_pos = mapping.get(int(entry_idx))
                                if new_pos is None:
                                    continue
                                new_actions[(dir_idx, new_pos)] = action_text
                            image.psp_entry_actions = new_actions

                            updated_marks: Set[Tuple[int, Optional[int]]] = set()
                            for dir_idx, entry_idx in image.psp_modified_entries:
                                if dir_idx != directory_index or entry_idx is None:
                                    updated_marks.add((dir_idx, entry_idx))
                                    continue
                                new_pos = mapping.get(int(entry_idx))
                                if new_pos is not None:
                                    updated_marks.add((dir_idx, new_pos))
                            image.psp_modified_entries = updated_marks

        removed = 0
        removal_targets: List[int] = []
        if removals:
            if reorder_mapping is not None:
                for entry_idx in removals:
                    if not isinstance(entry_idx, int):
                        continue
                    mapped = reorder_mapping.get(entry_idx)
                    if mapped is None:
                        continue
                    removal_targets.append(mapped)
            else:
                removal_targets = [idx for idx in removals if isinstance(idx, int)]

        if removal_targets:
            for entry_idx in sorted(set(removal_targets), reverse=True):
                self.remove_entry(
                    image_index,
                    directory_index,
                    entry_idx,
                    rebuild=False,
                )
                removed += 1

        if changes or removed or header_changed or reordered:
            window._rebuild_from_loaded_images()
            parts: List[str] = []
            if changes:
                parts.append(
                    f"updated {changes} entr{'y' if changes == 1 else 'ies'}"
                )
            if removed:
                parts.append(
                    f"removed {removed} entr{'y' if removed == 1 else 'ies'}"
                )
            if reordered:
                parts.append("reordered entries")
            if header_changed:
                parts.append("updated header")
            summary = "; ".join(parts) if parts else "Applied directory changes"
            window._status_message(f"{summary} in {directory.kind.value}")
        else:
            window._status_message("No directory changes were applied.")

    def insert_entry(
        self,
        image_index: int,
        directory_index: int,
        after_entry: Optional[int] = None,
        *,
        rebuild: bool = False,
    ) -> None:
        """Queue insertion of a new PSP entry."""

        window = self.window
        images = getattr(window, "loaded_images", [])
        if not (0 <= image_index < len(images)):
            QMessageBox.warning(
                window, "Invalid selection", "Image index is out of range."
            )
            return
        image = images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            QMessageBox.warning(
                window, "Invalid selection", "Directory index is out of range."
            )
            return
        directory = image.directories[directory_index]
        is_combo = _constants.is_combo_dir(directory.kind)
        if directory.offset is None:
            QMessageBox.warning(
                window,
                "Unavailable",
                "Directory offset could not be resolved.",
            )
            return
        config = window._prompt_entry_configuration(
            image_index,
            directory_index,
            directory,
            None,
            title="Insert entry",
            require_data=not is_combo,
            allow_address_mode_edit=not is_combo,
        )
        if not config:
            return
        data = image.data
        file_size = len(data)
        header_len = int(dir_header_len(directory.kind))
        span = int(entry_span(directory.kind))
        table_start = int(directory.offset) + header_len
        current_count = int(directory.count)
        insert_index = current_count
        if after_entry is not None:
            try:
                target_idx = int(after_entry)
            except Exception:
                target_idx = current_count
            if current_count > 0:
                target_idx = max(0, min(target_idx, current_count))
            else:
                target_idx = 0
            insert_index = target_idx
        new_slot_off = table_start + current_count * span
        new_slot_end = new_slot_off + span
        if new_slot_end > len(data):
            QMessageBox.warning(
                window,
                "No space",
                "Directory table does not have room for an additional entry.",
            )
            return
        slot = data[new_slot_off:new_slot_end]
        if any(byte != 0xFF for byte in slot):
            QMessageBox.warning(
                window,
                "Slot occupied",
                "Directory table slot is not empty; cannot insert a new entry.",
            )
            return
        moving: Optional[bytes] = None
        if insert_index < current_count:
            block_start = table_start + insert_index * span
            block_end = table_start + current_count * span
            moving = bytes(data[block_start:block_end])
            data[block_start + span : block_end + span] = moving
        else:
            block_start = block_end = table_start + current_count * span
        new_entry_off = table_start + insert_index * span
        new_entry_end = new_entry_off + span

        def _restore_table() -> None:
            if insert_index < current_count and moving is not None:
                data[block_start:block_end] = moving
                data[block_end:block_end + span] = b"\xff" * span

        if is_combo:
            pointer_value = config.get("combo_pointer")
            pointer_text = config.get("combo_pointer_text")
            if pointer_value is None:
                QMessageBox.warning(
                    window, "Invalid address", "Enter a directory address for the combo entry."
                )
                _restore_table()
                return
            pointer_int = int(pointer_value) & 0xFFFFFFFFFFFFFFFF
            new_type_value = int(config.get("type_value") or 0) & 0xFFFFFFFF
            if not self._validate_combo_pointer(
                directory,
                pointer_int,
                pointer_text,
                image,
                entry_type=new_type_value,
            ):
                _restore_table()
                return
            entry_bytes = bytearray(b"\xff" * span)
            match_value = int(config.get("combo_pspid") or 0) & 0xFFFFFFFF
            entry_bytes[0:4] = new_type_value.to_bytes(4, "little")
            entry_bytes[4:8] = match_value.to_bytes(4, "little")
            entry_bytes[8:16] = pointer_int.to_bytes(8, "little")
            data[new_entry_off:new_entry_end] = entry_bytes

            count_off = int(directory.offset) + 8
            directory.count = current_count + 1
            data[count_off : count_off + 4] = int(directory.count).to_bytes(4, "little")

            window._update_directory_checksum(image, directory)
            crc_off = int(directory.offset) + 4
            window._record_modified_range(image_index, crc_off, 4)
            if insert_index < current_count:
                window._record_modified_range(
                    image_index,
                    table_start + insert_index * span,
                    (current_count - insert_index + 1) * span,
                )
            else:
                window._record_modified_range(image_index, new_entry_off, span)
            window._record_modified_range(image_index, count_off, 4)

            image.needs_reparse = True
            window._mark_image_dirty(image_index)
            pointer_display = (
                pointer_text
                if isinstance(pointer_text, str) and pointer_text.strip()
                else f"0x{pointer_int:016X}"
            )
            change_desc = (
                f"d{directory_index:02X}-e{insert_index:02X} inserted ptr {pointer_display} "
                f"(match=0x{match_value:08X})"
            )
            self.shift_pending_entry_indices(image, directory_index, insert_index, 1)
            action_id = window._allocate_action_id()
            image.pending_entry_actions[(directory_index, insert_index)] = {
                "action": "insert",
                "action_id": action_id,
                "image_index": image_index,
                "directory_index": directory_index,
                "entry_index": insert_index,
                "span": span,
                "table_start": table_start,
                "count_offset": count_off,
                "payload_offset": None,
                "payload_size": 0,
                "change_desc": change_desc,
                "action_text": "Insert",
            }
            image.change_log.append(change_desc)
            self.record_modification(
                image_index, directory_index, insert_index, action_text="Insert"
            )
            window._append_console(f"Queued insert: {change_desc}")
            window._status_message(
                f"Inserted entry {insert_index} into {directory.kind.value}"
            )
            if rebuild:
                window._rebuild_from_loaded_images()
            return

        new_blob = config.get("data", b"")
        if not new_blob:
            QMessageBox.warning(
                window, "Insert failed", "Select a payload file for the new entry."
            )
            _restore_table()
            return
        payload_length = len(new_blob)
        declared_override_value = config.get("declared_size")
        size_override_value = config.get("size_override")
        if declared_override_value is not None:
            try:
                declared_size = int(declared_override_value)
            except Exception:
                declared_size = 0
        elif size_override_value is not None:
            try:
                declared_size = int(size_override_value)
            except Exception:
                declared_size = payload_length
        else:
            declared_size = payload_length
        declared_size = max(int(declared_size), 0)
        allocate_size = max(declared_size, payload_length)

        candidate = window._find_free_region(data, int(directory.offset), allocate_size)
        if candidate is None:
            QMessageBox.warning(
                window,
                "No space",
                "Unable to locate free space for the new entry payload.",
            )
            _restore_table()
            return
        final_offset = candidate
        if final_offset + allocate_size > file_size:
            QMessageBox.warning(
                window,
                "Out of bounds",
                "Payload for the new entry would exceed image bounds.",
            )
            _restore_table()
            return
        data[final_offset : final_offset + payload_length] = new_blob
        if allocate_size > payload_length:
            pad_start = final_offset + payload_length
            pad_end = final_offset + allocate_size
            data[pad_start:pad_end] = b"\xff" * (pad_end - pad_start)
        prefer_mode = config.get("address_mode")
        pointer = encode_entry_pointer(
            directory.kind,
            int(directory.offset),
            file_size,
            final_offset,
            prefer_mode=prefer_mode,
        )
        if pointer is None:
            QMessageBox.warning(
                window,
                "Pointer error",
                "Unable to encode a pointer for the new entry location.",
            )
            data[final_offset : final_offset + allocate_size] = b"\xff" * allocate_size
            _restore_table()
            return
        new_type_value = int(config.get("type_value") or 0)
        entry_bytes = bytearray(b"\xff" * span)
        entry_bytes[0:4] = int(new_type_value & 0xFFFFFFFF).to_bytes(4, "little")
        entry_bytes[4:8] = int(declared_size).to_bytes(4, "little")
        entry_bytes[8:16] = int(pointer).to_bytes(8, "little")
        # For BHD/BL2 entries, initialize destination field (16-24) to 0
        if is_real_bios_dir(directory.kind):
            destination = int(config.get("destination") or 0) & 0xFFFFFFFFFFFFFFFF
            entry_bytes[16:24] = destination.to_bytes(8, "little")
        data[new_entry_off:new_entry_end] = entry_bytes

        count_off = int(directory.offset) + 8
        directory.count = current_count + 1
        data[count_off : count_off + 4] = int(directory.count).to_bytes(4, "little")

        window._update_directory_checksum(image, directory)
        crc_off = int(directory.offset) + 4
        window._record_modified_range(image_index, crc_off, 4)
        if insert_index < current_count:
            window._record_modified_range(
                image_index,
                table_start + insert_index * span,
                (current_count - insert_index + 1) * span,
            )
        else:
            window._record_modified_range(image_index, new_entry_off, span)
        window._record_modified_range(image_index, count_off, 4)
        window._record_modified_range(image_index, final_offset, allocate_size)

        image.needs_reparse = True
        window._mark_image_dirty(image_index)
        file_name = Path(config.get("file_path") or "<buffer>").name
        change_desc = (
            f"d{directory_index:02X}-e{insert_index:02X} inserted {file_name} "
            f"(0x{declared_size:X} bytes)"
        )
        self.shift_pending_entry_indices(image, directory_index, insert_index, 1)
        action_id = window._allocate_action_id()
        image.pending_entry_actions[(directory_index, insert_index)] = {
            "action": "insert",
            "action_id": action_id,
            "image_index": image_index,
            "directory_index": directory_index,
            "entry_index": insert_index,
            "span": span,
            "table_start": table_start,
            "count_offset": count_off,
            "payload_offset": final_offset,
            "payload_size": allocate_size,
            "change_desc": change_desc,
            "action_text": "Insert",
        }
        image.change_log.append(change_desc)
        self.record_modification(
            image_index, directory_index, insert_index, action_text="Insert"
        )
        window._append_console(f"Queued insert: {change_desc}")
        window._status_message(f"Inserted entry {insert_index} into {directory.kind.value} d{directory_index:02X}")
        if rebuild:
            window._rebuild_from_loaded_images()
