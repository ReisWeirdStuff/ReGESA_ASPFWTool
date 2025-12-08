# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
File I/O operation mixin for MainWindow.

This module provides:
    - Save As operations for modified firmware images
    - Directory extraction to files
    - Payload extraction with naming
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

from .qt import (
    QApplication,
    QFileDialog,
    QInputDialog,
    QMessageBox,
)
from .common import _sanitize_filename, extract_entry_bytes, get_ps1_flags

from ...agesa.directory import iter_entries
from ...agesa.utils import fmt_type

if TYPE_CHECKING:
    from .controller import MainWindow
    from .models import LoadedImage


class FileOperationsMixin:
    """Mixin providing file I/O operations."""

    def _save_as(self: "MainWindow") -> None:
        """Save the current firmware image to a file."""
        if not self.loaded_images:
            QMessageBox.information(
                self, "No data", "Load a firmware image before saving."
            )
            return

        dirty_indices = [i for i, img in enumerate(self.loaded_images) if img.dirty]
        if len(self.loaded_images) == 1:
            target_index = 0
        elif len(dirty_indices) == 1:
            target_index = dirty_indices[0]
        else:
            items = [
                f"{idx}: {img.path.name}{' *' if img.dirty else ''}"
                for idx, img in enumerate(self.loaded_images)
            ]
            choice, ok = QInputDialog.getItem(
                self,
                "Select image to save",
                "Firmware image:",
                items,
                0,
                False,
            )
            if not ok or not choice:
                return
            try:
                target_index = int(choice.split(":", 1)[0])
            except Exception:
                QMessageBox.warning(
                    self, "Invalid selection", "Unable to parse selection."
                )
                return

        if not (0 <= target_index < len(self.loaded_images)):
            QMessageBox.warning(
                self, "Invalid selection", "Image index is out of range."
            )
            return

        image = self.loaded_images[target_index]
        default_name = image.path.name or "firmware.bin"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save firmware image",
            str(Path.cwd() / default_name),
            "Firmware images (*.bin *.rom *.cap *.fd *.bio *.img *.fv *.efi);;All files (*)",
        )
        if not file_path:
            return
        
        # Execute any staged UEFI actions before saving
        self._apply_staged_uefi_actions(image, target_index)
        
        changes = list(image.change_log)
        try:
            Path(file_path).write_bytes(bytes(image.data))
        except Exception as exc:
            QMessageBox.critical(self, "Save failed", str(exc))
            return

        # Update image path to the new saved location
        image.path = Path(file_path)
        self._mark_image_dirty(target_index, False)
        self._update_window_title()
        if changes:
            summary = "\n".join(f"- {entry}" for entry in changes)
            QMessageBox.information(
                self,
                "Changes saved",
                f"Saved {len(changes)} change(s):\n{summary}",
            )
            for entry in changes:
                self._append_console(f"Saved: {entry}")
            image.change_log.clear()
        else:
            image.change_log.clear()

        # Clear pending action markers since changes are now persisted
        if hasattr(image, "pending_uefi_actions"):
            image.pending_uefi_actions.clear()
        if hasattr(image, "pending_entry_actions"):
            image.pending_entry_actions.clear()
        if hasattr(image, "psp_entry_actions"):
            image.psp_entry_actions.clear()

        rebuild_error: Optional[Exception] = None
        if image.needs_reparse:
            try:
                bar = self.summary_scroll.verticalScrollBar()
                self._pending_summary_scroll = bar.value() if bar is not None else None
            except Exception:
                self._pending_summary_scroll = None
            try:
                bar = self.efs_scroll.verticalScrollBar()
                self._pending_efs_scroll = bar.value() if bar is not None else None
            except Exception:
                self._pending_efs_scroll = None
            try:
                self._reprocess_image(target_index)
                image.needs_reparse = False
                self._rebuild_from_loaded_images()
            except Exception as exc:  # pragma: no cover - unexpected parsing failure
                rebuild_error = exc
        if rebuild_error is not None:
            QMessageBox.warning(
                self,
                "Rebuild failed",
                f"Saved image, but reloading failed: {rebuild_error}",
            )
        else:
            self._status_message(f"Saved image to {file_path}")

    def _apply_staged_uefi_actions(self: "MainWindow", image: "LoadedImage", image_idx: int) -> None:
        """Apply any staged UEFI actions (like pending removals) before save."""
        if not hasattr(image, "pending_uefi_actions"):
            return
        
        # Collect staged removal actions
        staged_removals = [
            (key, action) for key, action in image.pending_uefi_actions.items()
            if action.get("staged") and action.get("action") == "remove"
        ]
        
        if not staged_removals:
            return
        
        self._append_console(f"Applying {len(staged_removals)} staged UEFI removal(s)...")
        
        # Sort by file index descending to avoid index shifts during removal
        staged_removals.sort(key=lambda x: x[1].get("file_index", 0), reverse=True)
        
        applied_keys = []
        for key, action in staged_removals:
            guid_text = action.get("guid", "unknown")
            try:
                success = self._execute_uefi_removal(action)
                if success:
                    applied_keys.append(key)
                    self._append_console(f"Applied staged removal: {guid_text}")
                else:
                    self._append_console(f"Failed to apply staged removal: {guid_text}")
            except Exception as exc:
                self._append_console(f"Error applying staged removal of {guid_text}: {exc}")
        
        # Remove applied actions from pending
        for key in applied_keys:
            image.pending_uefi_actions.pop(key, None)
        
        # Reparse UEFI roots after modifications and mark for reparse
        if applied_keys:
            image.needs_reparse = True
            try:
                image.uefi_roots = self._builder._collect_uefi_roots(
                    image_idx, bytes(image.data)
                )
            except Exception:
                image.uefi_roots = []

    def _extract_directory(self: "MainWindow", image_index: int, directory_index: int) -> None:
        """Extract all entries from a PSP directory."""
        if not (0 <= image_index < len(self.loaded_images)):
            QMessageBox.warning(
                self, "Invalid selection", "Image index is out of range."
            )
            return
        image = self.loaded_images[image_index]
        if not (0 <= directory_index < len(image.directories)):
            QMessageBox.warning(
                self, "Invalid selection", "Directory index is out of range."
            )
            return
        directory = image.directories[directory_index]
        entries = list(iter_entries(image.data, directory))
        if not entries:
            QMessageBox.information(
                self,
                "No entries",
                "The selected directory does not contain any extractable entries.",
            )
            return
        dest_dir = QFileDialog.getExistingDirectory(
            self,
            "Select output folder",
            str(Path.cwd()),
        )
        if not dest_dir:
            return
        target = Path(dest_dir)
        written = 0
        for entry in entries:
            # Use shared extraction function
            data = extract_entry_bytes(image.data, entry)
            if not data:
                continue
            
            # Get offset for PS1 flag checking
            offset = entry.get("resolved_off")
            
            # Determine compressed/encrypted/signed flags using shared function
            compressed_flag = bool(entry.get("compressed", False))
            ps1_compressed, encrypted_flag, signed_flag = get_ps1_flags(image.data, offset)
            if ps1_compressed:
                compressed_flag = True

            payload_meta: Dict[str, object] = {
                "image_index": image_index,
                "directory_index": directory_index,
                "directory_kind": directory.kind,
                "type_id": entry.get("type_id"),
                "type_label": fmt_type(entry.get("type_id"), directory.kind, mode=True),
                "compressed": compressed_flag,
                "encrypted": encrypted_flag,
                "signed": signed_flag,
            }
            entry_pspid = entry.get("pspid")
            if entry_pspid is not None:
                payload_meta["pspid"] = entry_pspid
            resolved_off = entry.get("resolved_off")
            if resolved_off is not None:
                try:
                    payload_meta["offset"] = int(resolved_off)
                except Exception:
                    pass
            payload_meta["size"] = len(data)
            export_path = self._derive_payload_export_path(
                target,
                payload_meta,
                include_directory_folder=True,
                payload_bytes=data,
            )
            try:
                export_path.parent.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                QMessageBox.warning(
                    self,
                    "Extraction error",
                    f"Failed to prepare output folder {export_path.parent}: {exc}",
                )
                continue
            final_path = self._resolve_export_collision(export_path, payload_meta)
            try:
                final_path.write_bytes(data)
                written += 1
                QApplication.processEvents()
            except Exception as exc:
                QMessageBox.warning(
                    self,
                    "Extraction error",
                    f"Failed to write {final_path.name}: {exc}",
                )
        if written:
            self._status_message(
                f"Extracted {written} item(s) from {directory.kind.value} to {target}"
            )
        else:
            QMessageBox.information(
                self, "No data", "No extractable entries were found in the directory."
            )

    def _extract_payload(self: "MainWindow", payload: dict) -> None:
        """Extract a single payload to a file."""
        offset = payload.get("offset")
        # For compressed entries (like 0x62), size may be decompressed size
        # Use declared_size (compressed size in flash) if it's smaller and valid
        size = payload.get("size") or 0
        declared_size = payload.get("declared_size") or 0
        if declared_size > 0 and (size == 0 or declared_size < size):
            size = declared_size
        image_index = payload.get("image_index")
        stored_hex_blob = payload.get("hex_blob")

        blob: Optional[bytes] = None
        if isinstance(stored_hex_blob, (bytes, bytearray)):
            blob = bytes(stored_hex_blob)
        elif (
            offset is not None
            and size
            and image_index is not None
            and 0 <= image_index < len(self.loaded_images)
        ):
            try:
                start = int(offset)
                end = start + int(size)
                data = self.loaded_images[image_index].data
                # Clamp to available data if end extends beyond
                if 0 <= start < len(data):
                    end = min(end, len(data))
                    if start < end:
                        blob = bytes(data[start:end])
            except Exception:
                blob = None

        if not blob:
            QMessageBox.warning(
                self, "No data", "Unable to resolve payload bytes for extraction."
            )
            return

        images = getattr(self, "loaded_images", None)
        image = None
        if isinstance(images, list) and isinstance(image_index, int):
            try:
                image = images[image_index]
            except Exception:
                pass
        base_dir = image.path.parent if image and image.path else Path.cwd()

        export_path = self._derive_payload_export_path(
            base_dir,
            payload,
            include_directory_folder=False,
            payload_bytes=blob,
        )
        # Use "All files" as default to prevent OS from appending .bin to other extensions
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export payload",
            str(export_path),
            "All files (*)",
        )
        if not file_path:
            return
        try:
            Path(file_path).write_bytes(blob)
            self._status_message(f"Exported {len(blob)} bytes to {Path(file_path).name}")
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))

    # Key entry types that should use .tkn/.stkn extension (except KEY_DATABASE 0x50/0x51)
    _KEY_ENTRY_TYPES = {0x00, 0x07, 0x09, 0x21, 0x0A, 0x0D, 0x43, 0x51, 0x74, 0x8D, 0x97}

    def _infer_payload_extension(
        self: "MainWindow",
        payload: dict,
        payload_bytes: Optional[bytes] = None,
    ) -> str:
        """
        Infer an appropriate file extension for a payload.
        
        For PSP entries with encryption/compression/signing, special suffixes are used:
        - encrypted: .ebin
        - compressed + encrypted: .ecbin
        - signed + compressed + encrypted: .ecsbin
        For key type entries (except KEY_DATABASE): .tkn
        """
        uefi_kind = payload.get("uefi_kind")
        if uefi_kind == "file":
            return ".ffs"
        if uefi_kind == "volume":
            return ".fv"
        if uefi_kind == "section":
            section_type = payload.get("section_type")
            if section_type == 0x10:  # PE32
                return ".efi"
            if section_type == 0x12:  # TE
                return ".te"
            if section_type == 0x19:  # Raw
                return ".raw"
            return ".sec"

        # Check magic bytes
        if payload_bytes and len(payload_bytes) >= 4:
            magic = payload_bytes[:4]
            if magic[:2] == b"MZ":
                return ".efi"
            if magic == b"$PS1":
                return ".ps1"
            if magic == b"$PS2":
                return ".ps2"

        # Check for encrypted/compressed/signed PSP entries
        encrypted = payload.get("encrypted", False)
        compressed = payload.get("compressed", False)
        signed = payload.get("signed", False)
        
        if encrypted or compressed or signed:
            # Build extension based on flags: e=encrypted, c=compressed, s=signed
            ext = "."
            if encrypted:
                ext += "e"
            if compressed:
                ext += "c"
            if signed:
                ext += "s"
            ext += "bin"
            return ext

        # Check for key type entries (use .tkn for 0x00, .stkn for other keys, except KEY_DATABASE 0x50)
        type_id = payload.get("type_id")
        if type_id is not None:
            type_id_low = int(type_id) & 0xFF
            if type_id_low == 0x00:
                return ".tkn"
            if type_id_low in self._KEY_ENTRY_TYPES:
                return ".stkn"

        directory_kind = payload.get("directory_kind")
        if directory_kind:
            return ".bin"
        return ".bin"

    def _derive_payload_export_path(
        self: "MainWindow",
        root: Path,
        payload: dict,
        *,
        include_directory_folder: bool = True,
        payload_bytes: Optional[bytes] = None,
        extension: Optional[str] = None,
    ) -> Path:
        """Derive an export path for a payload."""
        directory_kind = payload.get("directory_kind")
        type_id = payload.get("type_id")
        type_label = payload.get("type_label")
        offset = payload.get("offset")
        guid = payload.get("guid")
        label = payload.get("label")

        parts: List[str] = []

        if include_directory_folder and directory_kind:
            # Handle both DirKind enum and string values
            kind_str = directory_kind.value if hasattr(directory_kind, 'value') else str(directory_kind)
            parts.append(_sanitize_filename(kind_str, "dir"))

        ext = extension or self._infer_payload_extension(payload, payload_bytes)

        # For PSP/BIOS entries, use cleaner naming: TypeId0x{id}_{label}.ext
        if directory_kind and type_id is not None:
            type_id_hex = f"0x{int(type_id) & 0xFF:02X}"
            # Prefer type_label, fall back to label
            name_label = None
            if type_label:
                safe_label = _sanitize_filename(str(type_label), "")
                if safe_label:
                    name_label = safe_label
            if not name_label and label:
                safe_label = _sanitize_filename(str(label), "")
                if safe_label:
                    name_label = safe_label
            if name_label:
                filename = f"TypeId{type_id_hex}_{name_label}{ext}"
            else:
                filename = f"TypeId{type_id_hex}{ext}"
            filename = _sanitize_filename(filename, "payload.bin")
            if parts:
                return root / "/".join(parts) / filename
            return root / filename

        # For UEFI or other entries, use original logic
        # For UEFI files, prefer decoded GUID name over raw GUID
        from ...uefi import lookup_guid_name
        
        name_parts: List[str] = []
        if type_id is not None:
            name_parts.append(f"0x{int(type_id):02X}")
        if type_label:
            safe_label = _sanitize_filename(str(type_label), "entry")
            if safe_label and safe_label != "entry":
                name_parts.append(safe_label)
        if guid:
            # Try to get decoded name for GUID
            decoded_name = lookup_guid_name(guid)
            if decoded_name:
                name_parts.append(_sanitize_filename(decoded_name, str(guid)))
            else:
                name_parts.append(str(guid))
        if label and not guid:
            safe_label = _sanitize_filename(str(label), "item")
            if safe_label and safe_label != "item":
                name_parts.append(safe_label)
        if offset is not None:
            try:
                name_parts.append(f"0x{int(offset):X}")
            except Exception:
                pass

        if not name_parts:
            name_parts.append("payload")

        filename = "_".join(name_parts) + ext
        filename = _sanitize_filename(filename, "payload.bin")

        if parts:
            return root / "/".join(parts) / filename
        return root / filename

    def _resolve_export_collision(self: "MainWindow", export_path: Path, payload: dict) -> Path:
        """Resolve filename collisions by appending a counter."""
        if not export_path.exists():
            return export_path
        stem = export_path.stem
        suffix = export_path.suffix
        parent = export_path.parent
        counter = 1
        while True:
            candidate = parent / f"{stem}_{counter}{suffix}"
            if not candidate.exists():
                return candidate
            counter += 1
            if counter > 9999:
                # Fallback with offset
                offset = payload.get("offset")
                if offset is not None:
                    return parent / f"{stem}_0x{int(offset):X}{suffix}"
                return parent / f"{stem}_fallback{suffix}"
