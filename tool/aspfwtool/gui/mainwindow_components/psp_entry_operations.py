# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
PSP entry manipulation mixin for MainWindow.

This module provides:
    - Entry replacement queuing and execution
    - Free region finding for new entries
    - Undo operations for remove, replace, and insert actions
    - PSP location title formatting
    - Entry configuration dialogs
    - Directory editing support
"""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Set

from .qt import QApplication, QDialog, QMessageBox, QPoint, Qt

from ..dialogs.psp_directory_editor import DirectoryEditDialog
from .dialogs import EntryEditDialog

from ...agesa.directory import (
    Directory,
    dir_header_len,
    entry_span,
    iter_entries,
)
from ...agesa import constants as _constants
from ...agesa.entrytypes import POINT_ENTRY
from ...agesa.ish import ISH_LEN, ish_defaults, parse_ish_bytes
from ...agesa.utils import encode_entry_pointer, fmt_type
from ...agesa.constants import DirKind
from ...utils import get_logger

if TYPE_CHECKING:
    from .controller import MainWindow
    from .models import LoadedImage


class PspEntryOperationsMixin:
    """Mixin providing PSP entry operations."""

    def _find_free_region(
        self: "MainWindow", data: bytearray, start: int, length: int
    ) -> Optional[int]:
        """Find a free (0xFF-filled) region in the data buffer."""
        try:
            begin = max(int(start), 0)
            span = int(length)
        except Exception:
            return None
        if span <= 0:
            return None
        end = len(data)
        run_start: Optional[int] = None
        run_length = 0
        for idx in range(begin, end):
            if data[idx] == 0xFF:
                if run_start is None:
                    run_start = idx
                    run_length = 1
                else:
                    run_length += 1
                if run_length >= span:
                    return run_start
            else:
                run_start = None
                run_length = 0
        return None

    def _queue_psp_entry_replacement(
        self: "MainWindow",
        image_index: int,
        directory_index: int,
        entry_index: int,
        new_blob: bytes,
        *,
        declared_size: Optional[int] = None,
        change_desc: Optional[str] = None,
        rebuild: bool = False,
    ) -> bool:
        """Queue a PSP entry replacement operation."""
        if not (0 <= image_index < len(self.loaded_images)):
            QMessageBox.warning(self, "Invalid selection", "Image index is out of range.")
            return False
        image = self.loaded_images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            QMessageBox.warning(self, "Invalid selection", "Directory index is out of range.")
            return False
        directory = image.directories[directory_index]
        try:
            entry_idx = int(entry_index)
        except Exception:
            QMessageBox.warning(self, "Invalid selection", "Entry index is not valid.")
            return False
        entries = list(iter_entries(bytes(image.data), directory))
        entry_info = next(
            (info for info in entries if info.get("index") == entry_idx), None
        )
        if entry_info is None:
            QMessageBox.warning(self, "Not found", "Unable to locate the selected entry.")
            return False
        if entry_info.get("inline_offset") is not None:
            QMessageBox.warning(
                self,
                "Inline entry",
                "Inline value entries must be edited through the Soft Fuse pane.",
            )
            return False
        entry_offset = entry_info.get("entry_offset")
        if entry_offset is None or directory.offset is None:
            QMessageBox.warning(
                self,
                "Unsupported entry",
                "Entry offset could not be resolved for replacement.",
            )
            return False
        span = int(entry_span(directory.kind))
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

        declared = int(declared_size) if declared_size is not None else len(new_blob)
        declared = max(declared, 0)
        payload_length = len(new_blob)
        allocate_size = max(declared, payload_length)
        final_offset = original_offset_int
        moved = False

        if original_offset_int is not None:
            if declared > old_size:
                extend_end = original_offset_int + declared
                has_space = extend_end <= file_size and all(
                    byte == 0xFF
                    for byte in data[
                        original_offset_int + old_size : min(extend_end, file_size)
                    ]
                )
                if not has_space:
                    candidate = self._find_free_region(
                        data, original_offset_int + old_size, allocate_size
                    )
                    if candidate is not None:
                        final_offset = candidate
                        moved = True
                    else:
                        if extend_end > file_size:
                            QMessageBox.warning(
                                self,
                                "No space",
                                "The image does not have enough free space to extend the entry.",
                            )
                            return False
                        overlap_bytes = data[
                            original_offset_int + old_size : extend_end
                        ]
                        if any(byte != 0xFF for byte in overlap_bytes):
                            result = QMessageBox.question(
                                self,
                                "Overwrite data?",
                                "Extending the entry will overwrite non-blank bytes. Continue?",
                            )
                            if result != QMessageBox.Yes:
                                return False
            elif declared < old_size:
                truncate_start = original_offset_int + declared
                truncate_end = original_offset_int + old_size
                if 0 <= truncate_start < truncate_end <= len(data):
                    data[truncate_start:truncate_end] = b"\xFF" * (
                        truncate_end - truncate_start
                    )
        else:
            candidate = self._find_free_region(
                data,
                int(directory.offset) + int(dir_header_len(directory.kind)),
                allocate_size,
            )
            if candidate is None:
                QMessageBox.warning(
                    self, "No space", "Unable to locate free space for the replacement."
                )
                return False
            final_offset = candidate
            moved = True

        if final_offset is None:
            QMessageBox.warning(
                self,
                "Pointer error",
                "Unable to resolve a new payload location for the entry.",
            )
            return False

        if final_offset + allocate_size > len(data):
            QMessageBox.warning(
                self,
                "No space",
                "The replacement does not fit within the firmware image bounds.",
            )
            return False

        if payload_length:
            data[final_offset : final_offset + payload_length] = new_blob
        if declared > payload_length:
            pad_start = final_offset + payload_length
            pad_end = final_offset + declared
            data[pad_start:pad_end] = b"\xFF" * (pad_end - pad_start)

        prefer_mode = None
        ptr_value = entry_info.get("ptr64")
        if isinstance(ptr_value, int):
            prefer_mode = (int(ptr_value) >> 62) & 0x3
        pointer = encode_entry_pointer(
            directory.kind,
            int(directory.offset),
            file_size,
            final_offset,
            prefer_mode=prefer_mode,
        )
        if pointer is None:
            QMessageBox.warning(
                self,
                "Pointer error",
                "Unable to encode a pointer for the new entry location.",
            )
            if payload_length:
                data[final_offset : final_offset + payload_length] = b"\xFF" * payload_length
            return False

        entry_bytes = bytearray(entry_bytes_before)
        raw_type = entry_info.get("type_id")
        if isinstance(raw_type, int):
            entry_bytes[0:4] = int(raw_type).to_bytes(4, "little")
        entry_bytes[4:8] = int(declared).to_bytes(4, "little")
        entry_bytes[8:16] = int(pointer).to_bytes(8, "little")
        data[int(entry_offset) : int(entry_offset) + span] = entry_bytes

        self._record_modified_range(image_index, int(entry_offset), span)
        self._record_modified_range(image_index, int(final_offset), allocate_size)
        self._update_directory_checksum(image, directory)
        if directory.offset is not None:
            self._record_modified_range(image_index, int(directory.offset) + 4, 4)

        image.needs_reparse = True
        self._mark_image_dirty(image_index)

        if not change_desc:
            change_desc = (
                f"d{directory_index:02X}-e{entry_idx:02X} replaced with "
                f"0x{declared:X} bytes"
            )
        action_id = self._allocate_action_id()
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
        self.psp_tab_controller.record_modification(
            image_index, directory_index, entry_idx, action_text="Replace"
        )
        get_logger().debug(f"Queued replacement: {change_desc}")
        self._status_message(f"Replaced entry {entry_idx} in {directory.kind.value}")
        if rebuild:
            self._rebuild_from_loaded_images()
        return True

    def _undo_entry_action(self: "MainWindow", action: dict) -> None:
        """Undo a queued entry action."""
        if not isinstance(action, dict):
            raise ValueError("No queued action information available")
        image_index = action.get("image_index")
        directory_index = action.get("directory_index")
        if not isinstance(image_index, int):
            raise ValueError("Invalid image index for undo")
        if not (0 <= image_index < len(self.loaded_images)):
            raise ValueError("Image index is out of range")
        try:
            dir_idx = int(directory_index)
        except Exception as exc:
            raise ValueError("Invalid directory index for undo") from exc
        image = self.loaded_images[image_index]
        stored_action: Optional[dict] = None
        action_id = action.get("action_id")
        if isinstance(action_id, int):
            for info in image.pending_entry_actions.values():
                if isinstance(info, dict) and info.get("action_id") == action_id:
                    stored_action = info
                    break
        if stored_action is None:
            entry_index = action.get("entry_index")
            key = (dir_idx, entry_index if isinstance(entry_index, int) else entry_index)
            stored_action = image.pending_entry_actions.get(key)
        if stored_action is None:
            raise ValueError("No queued action found for this entry")

        # Check if this is a 0x62 BIOS entry edit
        if stored_action.get("is_0x62_edit"):
            self._undo_0x62_action(image_index, dir_idx, stored_action)
            return

        kind = stored_action.get("action")
        if kind == "remove":
            self._undo_remove_action(image_index, dir_idx, stored_action)
        elif kind == "replace":
            self._undo_replace_action(image_index, dir_idx, stored_action)
        elif kind == "insert":
            self._undo_insert_action(image_index, dir_idx, stored_action)
        else:
            raise ValueError("Unsupported queued action type")

    def _undo_remove_action(
        self: "MainWindow",
        image_index: int,
        directory_index: int,
        action: dict,
    ) -> None:
        """Undo a remove action."""
        image = self.loaded_images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            raise ValueError("Directory index is out of range")
        directory = image.directories[directory_index]
        entry_index = action.get("entry_index")
        if not isinstance(entry_index, int):
            raise ValueError("Queued removal is missing the entry index")
        span = int(action.get("span") or entry_span(directory.kind))
        table_start = int(action.get("table_start") or 0)
        count_off = int(action.get("count_offset") or 0)
        entry_bytes = action.get("entry_bytes")
        if not isinstance(entry_bytes, (bytes, bytearray)):
            raise ValueError("Queued removal is missing table data")
        data = image.data

        # Get current count to know the table size
        current_count = int.from_bytes(data[count_off : count_off + 4], "little")
        
        # To undo removal: shift entries at entry_index and after down by one,
        # then insert the original entry bytes at entry_index position
        if table_start and len(entry_bytes) == span:
            # Calculate positions
            entry_offset = table_start + entry_index * span
            # Read entries from entry_index to end (these were shifted up during remove)
            after_bytes = bytes(data[entry_offset : table_start + current_count * span])
            # Write the restored entry at its original position
            data[entry_offset : entry_offset + span] = entry_bytes
            # Write the shifted entries after the restored entry
            if after_bytes:
                after_start = entry_offset + span
                data[after_start : after_start + len(after_bytes)] = after_bytes

        # Restore payload if available
        payload_bytes = action.get("payload_bytes")
        payload_offset = action.get("payload_offset")
        if (
            payload_bytes
            and isinstance(payload_bytes, (bytes, bytearray))
            and payload_offset is not None
        ):
            try:
                off = int(payload_offset)
                data[off : off + len(payload_bytes)] = payload_bytes
            except Exception:
                pass

        # Increment directory count
        if count_off > 0:
            try:
                new_count = current_count + 1
                data[count_off : count_off + 4] = new_count.to_bytes(4, "little")
                directory.count = new_count
            except Exception:
                pass

        self._update_directory_checksum(image, directory)

        # Remove from pending actions
        key = (directory_index, entry_index)
        image.pending_entry_actions.pop(key, None)

        # Remove from change log
        change_desc = action.get("change_desc")
        if change_desc:
            self._remove_change_log_entry(image, change_desc)

        self._clear_psp_modification(image_index, directory_index, entry_index)
        self._refresh_image_dirty_state(image_index)
        image.needs_reparse = True
        self._status_message(f"Undid removal of entry {entry_index}")

    def _undo_replace_action(
        self: "MainWindow",
        image_index: int,
        directory_index: int,
        action: dict,
    ) -> None:
        """Undo a replace action."""
        image = self.loaded_images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            raise ValueError("Directory index is out of range")
        directory = image.directories[directory_index]
        entry_index = action.get("entry_index")
        if not isinstance(entry_index, int):
            raise ValueError("Queued replacement is missing the entry index")
        span = int(action.get("span") or entry_span(directory.kind))
        entry_offset = action.get("entry_offset")
        original_entry_bytes = action.get("original_entry_bytes")
        original_payload_bytes = action.get("original_payload_bytes")
        original_payload_offset = action.get("original_payload_offset")
        new_payload_offset = action.get("new_payload_offset")
        new_payload_size = action.get("new_payload_size")

        data = image.data

        # Restore original entry bytes
        if (
            entry_offset is not None
            and original_entry_bytes
            and isinstance(original_entry_bytes, (bytes, bytearray))
        ):
            try:
                off = int(entry_offset)
                data[off : off + span] = original_entry_bytes
            except Exception:
                pass

        # Restore original payload
        if (
            original_payload_bytes
            and isinstance(original_payload_bytes, (bytes, bytearray))
            and original_payload_offset is not None
        ):
            try:
                off = int(original_payload_offset)
                data[off : off + len(original_payload_bytes)] = original_payload_bytes
            except Exception:
                pass

        # Clear new payload location if moved
        if action.get("moved") and new_payload_offset is not None and new_payload_size:
            try:
                off = int(new_payload_offset)
                size = int(new_payload_size)
                data[off : off + size] = b"\xFF" * size
            except Exception:
                pass

        self._update_directory_checksum(image, directory)

        # Remove from pending actions
        key = (directory_index, entry_index)
        image.pending_entry_actions.pop(key, None)

        # Remove from change log
        change_desc = action.get("change_desc")
        if change_desc:
            self._remove_change_log_entry(image, change_desc)

        self._clear_psp_modification(image_index, directory_index, entry_index)
        self._refresh_image_dirty_state(image_index)
        image.needs_reparse = True
        self._status_message(f"Undid replacement of entry {entry_index}")

    def _undo_insert_action(
        self: "MainWindow",
        image_index: int,
        directory_index: int,
        action: dict,
    ) -> None:
        """Undo an insert action."""
        image = self.loaded_images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            raise ValueError("Directory index is out of range")
        directory = image.directories[directory_index]
        entry_index = action.get("entry_index")
        if not isinstance(entry_index, int):
            raise ValueError("Queued insertion is missing the entry index")
        span = int(action.get("span") or entry_span(directory.kind))
        entry_offset = action.get("entry_offset")
        count_off = action.get("count_offset")
        payload_offset = action.get("payload_offset")
        payload_size = action.get("payload_size")

        data = image.data

        # Clear entry bytes
        if entry_offset is not None:
            try:
                off = int(entry_offset)
                data[off : off + span] = b"\xFF" * span
            except Exception:
                pass

        # Clear payload
        if payload_offset is not None and payload_size:
            try:
                off = int(payload_offset)
                size = int(payload_size)
                data[off : off + size] = b"\xFF" * size
            except Exception:
                pass

        # Decrement directory count
        if count_off:
            try:
                off = int(count_off)
                current_count = int.from_bytes(data[off : off + 4], "little")
                if current_count > 0:
                    new_count = current_count - 1
                    data[off : off + 4] = new_count.to_bytes(4, "little")
                    directory.count = new_count
            except Exception:
                pass

        self._update_directory_checksum(image, directory)

        # Remove from pending actions
        key = (directory_index, entry_index)
        image.pending_entry_actions.pop(key, None)

        # Remove from change log
        change_desc = action.get("change_desc")
        if change_desc:
            self._remove_change_log_entry(image, change_desc)

        # Shift indices for subsequent entries
        self._shift_pending_entry_indices(
            image, directory_index, entry_index + 1, -1,
            skip={(directory_index, entry_index)},
        )

        self._clear_psp_modification(image_index, directory_index, entry_index)
        self._refresh_image_dirty_state(image_index)
        image.needs_reparse = True
        self._status_message(f"Undid insertion of entry {entry_index}")

    def _undo_0x62_action(
        self: "MainWindow",
        image_index: int,
        directory_index: int,
        action: dict,
    ) -> None:
        """Undo a 0x62 compressed BIOS entry action.

        This restores the original compressed blob and directory entry bytes
        that were captured before the modification was applied.
        """
        image = self.loaded_images[image_index]
        original_state = action.get("original_state")
        if not original_state:
            raise ValueError("No original state found for 0x62 undo")

        entry_index = action.get("entry_index")
        if not isinstance(entry_index, int):
            raise ValueError("Missing entry index for 0x62 undo")

        # Restore original blob data
        source_offset = original_state.get("source_offset", 0)
        original_blob = original_state.get("original_blob")
        actual_blob_size = original_state.get("actual_blob_size", 0)

        if original_blob and actual_blob_size > 0:
            # Write original blob back to original location
            image.data[source_offset:source_offset + actual_blob_size] = original_blob

        # If the entry was relocated, fill the new location with 0xFF
        if action.get("relocated"):
            new_source_offset = action.get("new_source_offset")
            new_compressed_size = action.get("new_compressed_size", 0)
            if new_source_offset is not None and new_compressed_size > 0:
                image.data[new_source_offset:new_source_offset + new_compressed_size] = (
                    b'\xFF' * new_compressed_size
                )

        # Restore original directory entry bytes
        entry_offset = original_state.get("entry_offset")
        original_entry_bytes = original_state.get("original_entry_bytes")
        if entry_offset is not None and original_entry_bytes:
            image.data[entry_offset:entry_offset + len(original_entry_bytes)] = original_entry_bytes

        # Update directory checksum
        if 0 <= directory_index < len(image.directories):
            directory = image.directories[directory_index]
            self._update_directory_checksum(image, directory)

        # Remove from pending actions
        key = (directory_index, entry_index)
        image.pending_entry_actions.pop(key, None)

        # Remove from change log
        change_desc = action.get("change_desc")
        if change_desc:
            self._remove_change_log_entry(image, change_desc)

        self._clear_psp_modification(image_index, directory_index, entry_index)
        self._refresh_image_dirty_state(image_index)
        image.needs_reparse = True

        action_type = action.get("action", "edit")
        self._status_message(f"Undid {action_type} of 0x62 BIOS entry")

        # Re-parse and rebuild the tree to reflect the restored state
        self._reprocess_image(image_index)
        self._rebuild_from_loaded_images()

    # -------------------------------------------------------------------------
    # Simple wrapper methods that delegate to psp_tab_controller
    # -------------------------------------------------------------------------

    def _remove_psp_entry(
        self: "MainWindow", image_index: int, directory_index: int, entry_index: int
    ) -> None:
        """Remove a PSP entry (delegates to psp_tab_controller)."""
        self.psp_tab_controller.remove_entry(
            image_index, directory_index, entry_index
        )

    def _replace_psp_entry(
        self: "MainWindow", image_index: int, directory_index: int, entry_index: int
    ) -> None:
        """Replace a PSP entry (delegates to psp_tab_controller)."""
        self.psp_tab_controller.replace_entry(
            image_index, directory_index, entry_index
        )

    def _edit_psp_entry(
        self: "MainWindow", image_index: int, directory_index: int, entry_index: int
    ) -> None:
        """Edit a PSP entry (delegates to psp_tab_controller)."""
        self.psp_tab_controller.edit_entry(
            image_index, directory_index, entry_index
        )

    def _insert_psp_entry(
        self: "MainWindow", image_index: int, directory_index: int, after_entry: Optional[int] = None
    ) -> None:
        """Insert a PSP entry (delegates to psp_tab_controller)."""
        self.psp_tab_controller.insert_entry(
            image_index, directory_index, after_entry
        )

    # -------------------------------------------------------------------------
    # PSP location formatting methods
    # -------------------------------------------------------------------------

    def _format_psp_location_title(
        self: "MainWindow",
        image_index: int,
        directory_index: int,
        entry_index: Optional[int],
        *,
        directory: Optional[Directory] = None,
        type_id: Optional[int] = None,
        type_label: Optional[str] = None,
    ) -> str:
        """Format a descriptive title string for a PSP location."""
        parts: List[str] = []
        images = getattr(self, "loaded_images", None)
        image: Optional[LoadedImage] = None
        if isinstance(images, Sequence) and 0 <= image_index < len(images):
            image = images[image_index]

        # Only show image info if more than one image is loaded
        if isinstance(images, Sequence) and len(images) > 1:
            if image is not None:
                image_label = f"Image {image_index}"
                image_path = getattr(image, "path", None)
                image_name: Optional[str] = None
                if isinstance(image_path, Path):
                    image_name = image_path.name
                elif image_path:
                    try:
                        image_name = Path(str(image_path)).name
                    except Exception:
                        image_name = None
                if image_name:
                    image_label += f" ({image_name})"
                parts.append(image_label)
            else:
                parts.append(f"Image {image_index}")

        directory_obj = directory
        if directory_obj is None and image is not None:
            directories = getattr(image, "directories", None)
            if isinstance(directories, Sequence) and 0 <= directory_index < len(directories):
                directory_obj = directories[directory_index]
        if directory_obj is not None:
            dir_label = f"{directory_obj.kind.value} Dir {directory_index}"
            parts.append(dir_label)
        else:
            parts.append(f"Dir {directory_index}")

        entry_label: Optional[str] = None
        entry_value: Optional[int] = None
        if entry_index is not None:
            try:
                entry_value = int(entry_index)
            except Exception:
                entry_value = None
        descriptor = type_label.strip() if isinstance(type_label, str) else ""
        if type_id is not None and not isinstance(type_id, int):
            try:
                type_id = int(type_id)
            except Exception:
                type_id = None
        if entry_value is not None and entry_value >= 0:
            entry_label = f"Entry {entry_value}"
            if descriptor:
                entry_label += f" ({descriptor})"
            elif isinstance(type_id, int):
                entry_label += f" (0x{int(type_id) & 0xFFFFFFFF:08X})"
        elif descriptor:
            entry_label = descriptor

        if entry_label:
            parts.append(entry_label)

        return " | ".join(part for part in parts if part)

    def _format_payload_location(self: "MainWindow", payload: Optional[dict]) -> str:
        """Format a location string from a payload dict."""
        if not isinstance(payload, dict):
            return ""
        image_index = payload.get("image_index")
        directory_index = payload.get("directory_index")
        if image_index is None or directory_index is None:
            return ""
        try:
            image_idx_int = int(image_index)
            directory_idx_int = int(directory_index)
        except Exception:
            return ""
        entry_index = payload.get("entry_index")
        directory_obj: Optional[Directory] = None
        images = getattr(self, "loaded_images", None)
        if (
            isinstance(images, Sequence)
            and 0 <= image_idx_int < len(images)
        ):
            image = images[image_idx_int]
            directories = getattr(image, "directories", None)
            if (
                isinstance(directories, Sequence)
                and 0 <= directory_idx_int < len(directories)
            ):
                directory_obj = directories[directory_idx_int]
        # Don't pass type_id/type_label here since label is already shown separately
        return self._format_psp_location_title(
            image_idx_int,
            directory_idx_int,
            entry_index,
            directory=directory_obj,
        )

    # -------------------------------------------------------------------------
    # PSP entry configuration and editing methods
    # -------------------------------------------------------------------------

    def _prompt_entry_configuration(
        self: "MainWindow",
        image_index: int,
        directory_index: int,
        directory: Directory,
        entry_info: Optional[dict],
        *,
        title: str,
        require_data: bool,
        allow_file_selection: bool = True,
        allow_address_mode_edit: bool = False,
        lock_entry_type: bool = False,
    ) -> Optional[dict]:
        """Show a dialog to configure a PSP entry and return the result."""
        initial_type = entry_info.get("type_id") if entry_info else 0
        initial_size = int(entry_info.get("size") or 0) if entry_info else 0
        if entry_info and _constants.is_combo_dir(directory.kind):
            entry_obj = entry_info.get("entry")
            if hasattr(entry_obj, "u0"):
                try:
                    initial_type = int(entry_obj.u0)
                except Exception:
                    pass
            try:
                initial_size = int(entry_info.get("pspid") or 0)
            except Exception:
                initial_size = 0
        pointer_value = entry_info.get("ptr64") if entry_info else None
        address_mode: Optional[int] = None
        address_value: Optional[int] = None
        initial_pointer: Optional[int] = None
        if isinstance(pointer_value, int):
            initial_pointer = int(pointer_value) & 0xFFFFFFFFFFFFFFFF
            if _constants.is_combo_dir(directory.kind):
                address_value = initial_pointer
            else:
                address_mode = (int(pointer_value) >> 62) & 0x3
                address_value = int(pointer_value) & ((1 << 62) - 1)
        allow_override = False
        if not _constants.is_combo_dir(directory.kind):
            if entry_info is None:
                allow_override = True
            else:
                entry_type = entry_info.get("entry_type") if isinstance(entry_info, dict) else None
                allow_override = entry_type == POINT_ENTRY
                if not allow_override:
                    raw_type = (
                        entry_info.get("type_id") if isinstance(entry_info, dict) else None
                    )
                    if isinstance(raw_type, int):
                        low_byte = raw_type & 0xFF
                        if low_byte in (0x40, 0x48, 0x49, 0x4A, 0x70):
                            allow_override = True
        ish_presets = self._collect_ish_presets(
            image_index, directory, entry_info
        )
        enable_ish_builder = directory.kind == DirKind.PSP_L1
        dialog = EntryEditDialog(
            self,
            directory_kind=directory.kind,
            title=title,
            initial_type=initial_type,
            initial_size=initial_size,
            address_mode=address_mode,
            address_value=address_value,
            initial_pointer=initial_pointer,
            require_data=require_data,
            allow_size_override=allow_override,
            allow_file_selection=allow_file_selection,
            allow_address_mode_edit=allow_address_mode_edit,
            ish_presets=ish_presets or None,
            enable_ish_builder=enable_ish_builder,
            lock_entry_type=lock_entry_type,
        )
        entry_index_value = entry_info.get("index") if isinstance(entry_info, dict) else None
        type_id_value = entry_info.get("type_id") if isinstance(entry_info, dict) else initial_type
        type_label_text: Optional[str]
        try:
            type_label_text = (
                fmt_type(type_id_value, directory.kind, mode=True)
                if type_id_value is not None and entry_info is not None
                else None
            )
        except Exception:
            type_label_text = None
        location_title = self._format_psp_location_title(
            image_index,
            directory_index,
            entry_index_value,
            directory=directory,
            type_id=type_id_value,
            type_label=type_label_text,
        )
        if location_title:
            dialog.setWindowTitle(f"{title} - {location_title}")
        else:
            dialog.setWindowTitle(title)
        if dialog.exec_() == QDialog.Accepted:
            return dialog.result_config()
        return None

    def _collect_ish_presets(
        self: "MainWindow",
        image_index: int,
        directory: Directory,
        entry_info: Optional[dict],
    ) -> Dict[int, Dict[str, int]]:
        """Collect ISH presets for a PSP entry dialog."""
        if directory.kind != DirKind.PSP_L1:
            return {}
        presets: Dict[int, Dict[str, int]] = {
            0x48: ish_defaults(0x48),
            0x4A: ish_defaults(0x4A),
        }
        images = getattr(self, "loaded_images", None)
        if not isinstance(images, Sequence) or not (0 <= image_index < len(images)):
            return presets
        if not entry_info:
            return presets
        type_id = entry_info.get("type_id")
        if not isinstance(type_id, int):
            return presets
        type_low = type_id & 0xFF
        if type_low not in (0x48, 0x4A):
            return presets
        resolved = entry_info.get("resolved_off")
        try:
            target = int(resolved)
        except Exception:
            return presets
        data = images[image_index].data
        if target < 0 or target + ISH_LEN > len(data):
            return presets
        blob = bytes(data[target : target + ISH_LEN])
        parsed = parse_ish_bytes(blob)
        if parsed:
            presets[type_low].update(parsed)
        return presets

    def _collect_directory_entry_snapshots(
        self: "MainWindow", image_index: int, directory_index: int
    ) -> Dict[int, Dict[str, int]]:
        """Collect entry snapshots for directory editing."""
        snapshots: Dict[int, Dict[str, int]] = {}
        records: List[dict] = []
        builder_cache = getattr(self._builder, "_psp_entry_cache", None)
        if isinstance(builder_cache, dict):
            records.extend(builder_cache.get(image_index, []) or [])
        image = self.loaded_images[image_index]
        extra_records = getattr(image, "psp_entries", None)
        if isinstance(extra_records, list):
            records.extend(extra_records)
        for record in records:
            if not isinstance(record, dict):
                continue
            if record.get("directory_index") != directory_index:
                continue
            snapshot = record.get("entry_snapshot")
            if not isinstance(snapshot, dict):
                continue
            index = snapshot.get("index")
            try:
                idx = int(index)
            except Exception:
                continue
            normalized: Dict[int, int] = {}
            for key, value in snapshot.items():
                if key == "index":
                    continue
                normalized[key] = value
            normalized["index"] = idx
            snapshots[idx] = normalized
        return snapshots

    def _edit_psp_directory(
        self: "MainWindow", image_index: int, directory_index: int
    ) -> None:
        """Open the directory editor dialog for a PSP directory."""
        if not (0 <= image_index < len(self.loaded_images)):
            QMessageBox.warning(self, "Invalid selection", "Image index is out of range.")
            return
        image = self.loaded_images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            QMessageBox.warning(self, "Invalid selection", "Directory index is out of range.")
            return
        directory = image.directories[directory_index]
        try:
            entries = list(iter_entries(image.data, directory))
        except Exception as exc:
            entries = []
            self._status_message(
                f"Directory parsing failed; using cached entries instead ({exc})"
            )
        snapshots = self._collect_directory_entry_snapshots(
            image_index, directory_index
        )
        get_logger().debug(
            f"Preparing editor for {directory.kind.value}: offset={directory.offset}, count={directory.count}, parsed entries={len(entries)}, snapshots={len(snapshots)}"
        )
        if entries:
            seen: Set[int] = set()
            for entry in entries:
                idx = entry.get("index")
                try:
                    idx_int = int(idx)
                except Exception:
                    continue
                seen.add(idx_int)
                snapshot = snapshots.get(idx_int)
                if not snapshot:
                    continue
                for key, value in snapshot.items():
                    if key == "index":
                        continue
                    if key not in entry or entry.get(key) is None:
                        entry[key] = value
            for idx, snapshot in snapshots.items():
                if idx in seen:
                    continue
                entries.append(dict(snapshot))
            entries.sort(key=lambda record: int(record.get("index", 0)))
        elif snapshots:
            entries = [dict(snapshot) for _, snapshot in sorted(snapshots.items())]
        try:
            dialog = DirectoryEditDialog(self, directory, entries, bytes(image.data))
        except Exception as exc:
            details = str(exc).strip()
            if not details:
                details = repr(exc)
            tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            get_logger().debug(f"Directory editor initialization failed:\n{tb_text}")
            QMessageBox.critical(
                self,
                "Directory editor failed",
                f"Unable to open the directory editor:\n{details}",
            )
            return
        self._status_message(f"Opening editor for {directory.kind.value} directory...")
        dialog.setWindowModality(Qt.ApplicationModal)
        dialog.setModal(True)
        dialog.ensurePolished()
        dialog.adjustSize()
        if dialog.width() <= 0 or dialog.height() <= 0:
            dialog.resize(900, 560)
        else:
            dialog.resize(max(dialog.width(), 600), max(dialog.height(), 400))
        parent_geom = self.geometry()
        half = QPoint(dialog.width() // 2, dialog.height() // 2)
        if parent_geom.width() > 0 and parent_geom.height() > 0:
            dialog.move(parent_geom.center() - half)
        else:
            screen = QApplication.primaryScreen()
            if screen is not None:
                dialog.move(screen.availableGeometry().center() - half)
        exec_fn = getattr(dialog, "exec", None) or getattr(dialog, "exec_", None)
        result = exec_fn() if callable(exec_fn) else QDialog.Rejected
        get_logger().debug(f"Directory editor exec result: {result}")
        if result != QDialog.Accepted:
            self._status_message("Directory edit cancelled.")
            return
        edits, removals, reorder, header_update = dialog.result_operations()
        self.psp_tab_controller.bulk_edit_directory(
            image_index,
            directory_index,
            edits,
            removals,
            reorder,
            header_update,
        )
