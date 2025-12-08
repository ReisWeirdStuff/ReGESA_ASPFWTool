# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Tree view operation mixin for MainWindow.

This module provides:
    - Selection handling and restoration
    - Tree filtering by image
    - Context menu handling
    - Tree column management
    - Expanded state persistence
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Set

from .qt import (
    QAction,
    QGuiApplication,
    QMenu,
    QModelIndex,
    QStandardItem,
    QTreeView,
    Qt,
)

from .common import (
    EDITABLE_DIRECTORY_KINDS,
    SUPPORTED_UEFI_COMPRESSION_TYPES,
)
from ..utils.roles import (
    HEX_ROLE,
    OFFSET_ROLE,
    PAYLOAD_ROLE,
    PENDING_ACTION_ROLE,
)
from ...agesa import constants as _constants
from ...uefi import EFI_SECTION_COMPRESSION

if TYPE_CHECKING:
    from .controller import MainWindow


class TreeOperationsMixin:
    """Mixin providing tree view operations."""

    def _capture_tree_expanded_state(self: "MainWindow", tree: QTreeView) -> Set[str]:
        """Capture which items are expanded in a tree view by their path."""
        expanded: Set[str] = set()
        model = tree.model()
        if model is None:
            return expanded

        def _collect_expanded(parent_index: QModelIndex, path_parts: List[str]) -> None:
            row_count = model.rowCount(parent_index)
            for row in range(row_count):
                index = model.index(row, 0, parent_index)
                if not index.isValid():
                    continue
                item_text = model.data(index, Qt.DisplayRole) or ""
                current_path = path_parts + [f"{row}:{item_text[:30]}"]
                if tree.isExpanded(index):
                    expanded.add("/".join(current_path))
                    _collect_expanded(index, current_path)

        _collect_expanded(QModelIndex(), [])
        return expanded

    def _restore_tree_expanded_state(
        self: "MainWindow", tree: QTreeView, expanded: Set[str]
    ) -> None:
        """Restore expanded state of items in a tree view."""
        if not expanded:
            return
        model = tree.model()
        if model is None:
            return

        def _restore_expanded(parent_index: QModelIndex, path_parts: List[str]) -> None:
            row_count = model.rowCount(parent_index)
            for row in range(row_count):
                index = model.index(row, 0, parent_index)
                if not index.isValid():
                    continue
                item_text = model.data(index, Qt.DisplayRole) or ""
                current_path = path_parts + [f"{row}:{item_text[:30]}"]
                path_str = "/".join(current_path)
                if path_str in expanded:
                    tree.setExpanded(index, True)
                    _restore_expanded(index, current_path)

        _restore_expanded(QModelIndex(), [])

    def _apply_uefi_tree_filter(self: "MainWindow") -> None:
        """Filter UEFI tree to show only active image entries."""
        if not self.include_uefi:
            return
        tree = getattr(self, "uefi_tree", None)
        model = getattr(self, "uefi_model", None)
        if tree is None or model is None or not model.rowCount():
            return
        root_index = QModelIndex()
        active = self._active_image_index
        for row in range(model.rowCount()):
            item = model.item(row, 0)
            payload = item.data(PAYLOAD_ROLE) if item is not None else None
            image_idx = payload.get("image_index") if isinstance(payload, dict) else None
            hide = (
                active is not None
                and image_idx is not None
                and image_idx != active
            )
            try:
                tree.setRowHidden(row, root_index, hide)
            except Exception:
                pass

    def _apply_psp_tree_filter(self: "MainWindow") -> None:
        """Filter PSP tree to show only active image entries."""
        tree = getattr(self, "psp_tree", None)
        model = getattr(self, "psp_model", None)
        if tree is None or model is None or not model.rowCount():
            return
        root_index = QModelIndex()
        active = self._active_image_index
        for row in range(model.rowCount()):
            item = model.item(row, 0)
            payload = item.data(PAYLOAD_ROLE) if item is not None else None
            image_idx = payload.get("image_index") if isinstance(payload, dict) else None
            hide = (
                active is not None
                and image_idx is not None
                and image_idx != active
            )
            try:
                tree.setRowHidden(row, root_index, hide)
            except Exception:
                pass

    def _remember_active_psp_selection(self: "MainWindow") -> None:
        """Remember current PSP selection for the active image."""
        if self._active_image_index is None:
            return
        locator = self._capture_psp_selection()
        if (
            locator
            and locator.get("image_index") is not None
            and locator.get("image_index") == self._active_image_index
        ):
            self._psp_selection_by_image[self._active_image_index] = locator

    def _remember_active_uefi_selection(self: "MainWindow") -> None:
        """Remember current UEFI selection for the active image."""
        if not (self.include_uefi and self._active_image_index is not None):
            return
        locator = self.uefi_tab_controller.capture_selection()
        if (
            locator
            and locator.get("image_index") is not None
            and locator.get("image_index") == self._active_image_index
        ):
            self._uefi_selection_by_image[self._active_image_index] = locator

    def _restore_active_uefi_selection(
        self: "MainWindow", fallback_locator: Optional[dict] = None
    ) -> None:
        """Restore saved UEFI selection for the active image."""
        if not self.include_uefi:
            return
        active = self._active_image_index
        if active is None:
            return
        locator = self._uefi_selection_by_image.get(active)
        if (
            locator is None
            and fallback_locator
            and fallback_locator.get("image_index") == active
        ):
            locator = fallback_locator
        if locator:
            self.uefi_tab_controller.restore_selection(locator)
        else:
            self._select_first_visible_uefi_item()

    def _select_first_visible_uefi_item(self: "MainWindow") -> None:
        """Select the first visible item in the UEFI tree."""
        model = getattr(self, "uefi_model", None)
        tree = getattr(self, "uefi_tree", None)
        if model is None or tree is None or not model.rowCount():
            return
        root_index = QModelIndex()
        for row in range(model.rowCount()):
            if tree.isRowHidden(row, root_index):
                continue
            index = model.index(row, 0)
            if index.isValid():
                tree.setCurrentIndex(index)
                return
        try:
            tree.clearSelection()
        except Exception:
            pass

    def _restore_active_psp_selection(
        self: "MainWindow", fallback_locator: Optional[dict] = None
    ) -> None:
        """Restore saved PSP selection for the active image."""
        active = self._active_image_index
        if active is None:
            return
        locator = self._psp_selection_by_image.get(active)
        if (
            locator is None
            and fallback_locator
            and fallback_locator.get("image_index") == active
        ):
            locator = fallback_locator
        if locator:
            self._restore_psp_selection(locator)
        else:
            self._select_first_visible_psp_item()

    def _select_first_visible_psp_item(self: "MainWindow") -> None:
        """Select the first visible item in the PSP tree."""
        model = getattr(self, "psp_model", None)
        tree = getattr(self, "psp_tree", None)
        if model is None or tree is None or not model.rowCount():
            return
        root_index = QModelIndex()
        for row in range(model.rowCount()):
            if tree.isRowHidden(row, root_index):
                continue
            index = model.index(row, 0)
            if index.isValid():
                tree.setCurrentIndex(index)
                return
        try:
            tree.clearSelection()
        except Exception:
            pass

    def _focus_tree_item(
        self: "MainWindow", tree: QTreeView, item: Optional[QStandardItem]
    ) -> None:
        """Focus and expand to a specific tree item."""
        if item is None:
            return
        if tree is getattr(self, "uefi_tree", None) or tree is getattr(self, "psp_tree", None):
            payload = item.data(PAYLOAD_ROLE)
            image_idx = payload.get("image_index") if isinstance(payload, dict) else None
            try:
                image_idx_int = int(image_idx) if image_idx is not None else None
            except Exception:
                image_idx_int = None
            if image_idx_int is not None and image_idx_int != self._active_image_index:
                self._set_active_image(image_idx_int)
        parent = item.parent()
        while parent is not None:
            index = parent.index()
            if index.isValid():
                tree.expand(index)
            parent = parent.parent()
        index = item.index()
        if index.isValid():
            tree.setCurrentIndex(index)
            try:
                tree.scrollTo(index)
            except Exception:
                pass
        tree.setFocus(Qt.OtherFocusReason)

    def _on_tree_double_clicked(
        self: "MainWindow", tree: QTreeView, index
    ) -> None:
        """Handle double-click on tree item to open hex view."""
        if not index.isValid():
            return
        model = tree.model()
        if model is None:
            return
        item = (
            model.itemFromIndex(index.sibling(index.row(), 0))
            if hasattr(model, "itemFromIndex")
            else None
        )
        if item is None:
            return
        payload = item.data(PAYLOAD_ROLE)
        if isinstance(payload, dict):
            if payload.get("is_directory") and item.data(HEX_ROLE):
                self._open_directory_table_hex(item)
                return
            size = payload.get("size") or payload.get("declared_size")
            if payload.get("offset") is not None and size:
                self._open_hex_view(payload)
                return
        if item.data(HEX_ROLE):
            self._open_directory_table_hex(item)

    def _on_tree_expanded(
        self: "MainWindow", tree: QTreeView, index
    ) -> None:
        """Auto-resize columns to fit content when a tree node is expanded."""
        if not index.isValid():
            return
        header = tree.header()
        if header is None:
            return
        try:
            # Resize all columns except the last (which stretches)
            for section in range(header.count() - 1):
                tree.resizeColumnToContents(section)
        except Exception:
            pass

    def _show_context_menu(self: "MainWindow", tree: QTreeView, pos) -> None:
        """Show context menu for tree item."""
        index = tree.indexAt(pos)
        if not index.isValid():
            return
        index0 = index.sibling(index.row(), 0)
        model = tree.model()
        item = model.itemFromIndex(index0) if hasattr(model, "itemFromIndex") else None
        if item is None:
            return
        payload = item.data(PAYLOAD_ROLE)
        if not isinstance(payload, dict):
            payload = {}
        pending_action = item.data(PENDING_ACTION_ROLE)
        if not isinstance(pending_action, dict):
            pending_action = None
        is_placeholder = bool(pending_action.get("placeholder")) if pending_action else False
        modifiers = QGuiApplication.keyboardModifiers()
        shift_override = bool(modifiers & Qt.ShiftModifier)
        menu = QMenu(tree)
        context_tag = tree.property("context")
        copy_name_action = menu.addAction("Copy Name")
        copy_metadata_action = menu.addAction("Copy Metadata")
        copy_addr_action = None
        address_value = payload.get("offset")
        if address_value is None:
            addr_data = item.data(OFFSET_ROLE)
            if addr_data is not None:
                address_value = addr_data
        if address_value is not None:
            copy_addr_action = menu.addAction("Copy Address (Hex)")
        copy_guid_action = None
        if payload.get("guid"):
            copy_guid_action = menu.addAction("Copy GUID")
        directory_index = payload.get("directory_index")
        image_index = payload.get("image_index")
        entry_index_value = payload.get("entry_index")
        is_directory = bool(payload.get("is_directory"))
        directory_kind = payload.get("directory_kind")

        operations_spec: List[tuple[str, str]] = []
        if pending_action is not None and pending_action.get("action"):
            pass
        elif (
            context_tag == "psp"
            and directory_index is not None
            and image_index is not None
        ):
            if is_directory:
                operations_spec.extend(
                    [
                        ("extract_dir", "Extract Directory…"),
                        (
                            "edit_directory",
                            "Edit Directory…",
                        )
                        if directory_kind in EDITABLE_DIRECTORY_KINDS
                        else None,
                        ("insert_entry", "Insert Entry…"),
                    ]
                )
            elif entry_index_value is not None:
                operations_spec.extend(
                    [
                        ("edit_entry", "Edit Entry…"),
                        ("extract_entry", "Extract"),
                        ("replace_entry", "Replace Entry…"),
                        ("insert_entry", "Insert Entry…"),
                        ("remove_entry", "Remove Entry"),
                    ]
                )
                raw_type = payload.get("type_id")
                if (
                    isinstance(raw_type, int)
                    and raw_type in (0x60, 0x68)
                    and payload.get("offset") is not None
                ):
                    operations_spec.append(
                        ("view_apcb_tokens", "View APCB Tokens…")
                    )
                base_type = raw_type & 0xFF if isinstance(raw_type, int) else None
                if (
                    isinstance(raw_type, int)
                    and _constants.is_real_bios_dir(directory_kind)
                    and base_type == 0x66
                    and payload.get("offset") is not None
                ):
                    operations_spec.append(
                        ("microcode_details", "Show microcode details…")
                    )
        # Handle UEFI items inside PSP context (e.g., files/volumes inside compressed BIOS 0x62)
        elif context_tag == "psp" and payload.get("uefi_kind") is not None:
            uefi_kind = payload.get("uefi_kind")
            has_bios_info = payload.get("compressed_bios_info") is not None
            has_hex_blob = payload.get("hex_blob") is not None
            
            # Extract is always available if we have data
            if payload.get("offset") is not None or has_hex_blob:
                operations_spec.append(("extract_entry", "Extract"))
            
            # Allow UEFI operations for any BIOS entry (0x62), compressed or not
            if has_bios_info and not is_placeholder:
                if uefi_kind == "volume":
                    operations_spec.append(("uefi_insert_append", "Insert Entry…"))
                elif uefi_kind == "file":
                    operations_spec.extend([
                        ("uefi_replace_entry", "Replace Entry…"),
                        ("uefi_remove_entry", "Remove Entry"),
                        ("uefi_insert_before", "Insert Entry Before…"),
                    ])
        elif context_tag == "uefi":
            uefi_kind = payload.get("uefi_kind")
            has_virtual_context = bool(payload.get("uefi_file_chain")) or bool(
                payload.get("uefi_volume_chain")
            )
            has_virtual_data = payload.get("virtual") and payload.get("hex_blob") is not None
            if payload.get("offset") is not None or has_virtual_data:
                operations_spec.append(("extract_entry", "Extract"))
            if (
                uefi_kind == "section"
                and payload.get("section_depth") == 0
                and payload.get("section_type") == EFI_SECTION_COMPRESSION
                and payload.get("compression_type") in SUPPORTED_UEFI_COMPRESSION_TYPES
                and not is_placeholder
            ):
                operations_spec.append(
                    ("uefi_edit_compressed", "Edit Decompressed Payload…")
                )
            if not is_placeholder:
                if uefi_kind == "volume" and (
                    payload.get("offset") is not None or has_virtual_context
                ):
                    operations_spec.append(
                        ("uefi_insert_append", "Insert Entry…")
                    )
                elif uefi_kind == "file" and (
                    payload.get("offset") is not None or has_virtual_context
                ):
                    operations_spec.extend(
                        [
                            ("uefi_replace_entry", "Replace Entry…"),
                            ("uefi_remove_entry", "Remove Entry"),
                            ("uefi_insert_before", "Insert Entry Before…"),
                        ]
                    )
        elif payload.get("offset") is not None:
            operations_spec.append(("extract_entry", "Extract"))

        action_map: Dict[str, "QAction"] = {}
        if operations_spec:
            seen: set[str] = set()
            menu.addSeparator()
            for spec in operations_spec:
                if spec is None:
                    continue
                key, label = spec
                if key is None or label is None:
                    continue
                if key in seen:
                    continue
                seen.add(key)
                action_map[key] = menu.addAction(label)

        payload_size = payload.get("size") or payload.get("declared_size")
        stored_hex_blob = payload.get("hex_blob")
        has_virtual_blob = isinstance(stored_hex_blob, (bytes, bytearray))
        has_payload = payload.get("offset") is not None and payload_size
        hex_blob = item.data(HEX_ROLE)
        hex_actions: List[tuple[str, str]] = []
        if (has_payload or has_virtual_blob) and not is_directory and not is_placeholder:
            hex_actions.append(("hex", "HEX View"))
            if has_payload and (payload.get("compressed") or shift_override):
                hex_actions.append(("hex_decomp", "HEX View (Compressed)"))
        if hex_blob and is_directory and not is_placeholder:
            hex_actions.append(("hex_table", "HEX View (Directory Table)"))
        if hex_actions:
            menu.addSeparator()
            for key, label in hex_actions:
                action_map[key] = menu.addAction(label)
        undo_action = None
        if pending_action is not None:
            menu.addSeparator()
            undo_action = menu.addAction("Undo queued action")
        global_pos = tree.viewport().mapToGlobal(pos)
        exec_fn = getattr(menu, "exec", None) or getattr(menu, "exec_", None)
        chosen = exec_fn(global_pos) if exec_fn else None

        # Handle menu selection
        self._handle_context_menu_action(
            tree, item, payload, pending_action, chosen,
            copy_name_action, copy_metadata_action, copy_addr_action,
            copy_guid_action, undo_action, action_map, address_value,
            image_index, directory_index, entry_index_value, context_tag,
            has_payload, shift_override, hex_blob, model, index0,
        )

    def _handle_context_menu_action(
        self: "MainWindow",
        tree: QTreeView,
        item: QStandardItem,
        payload: dict,
        pending_action: Optional[dict],
        chosen,
        copy_name_action,
        copy_metadata_action,
        copy_addr_action,
        copy_guid_action,
        undo_action,
        action_map: Dict[str, "QAction"],
        address_value,
        image_index,
        directory_index,
        entry_index_value,
        context_tag: str,
        has_payload: bool,
        shift_override: bool,
        hex_blob,
        model,
        index0,
    ) -> None:
        """Handle context menu action selection."""
        # Early return if no action was selected (user clicked outside menu)
        if chosen is None:
            return
        if chosen == copy_name_action:
            QGuiApplication.clipboard().setText(str(item.text()))
        elif chosen == copy_metadata_action:
            metadata_index = index0.sibling(index0.row(), 4)
            metadata_item = model.itemFromIndex(metadata_index) if hasattr(model, "itemFromIndex") else None
            metadata_text = metadata_item.text() if metadata_item else ""
            if metadata_text:
                QGuiApplication.clipboard().setText(metadata_text)
        elif chosen == copy_addr_action:
            try:
                addr = int(address_value)
                QGuiApplication.clipboard().setText(f"0x{addr:X}")
            except Exception:
                pass
        elif chosen == copy_guid_action:
            guid_val = payload.get("guid")
            if guid_val is not None:
                QGuiApplication.clipboard().setText(str(guid_val))
        elif chosen == undo_action and pending_action is not None:
            try:
                # Check if this is a UEFI staged action or PSP entry action
                if pending_action.get("staged") and pending_action.get("action") == "remove":
                    # UEFI staged removal - just remove from pending actions
                    self._undo_uefi_staged_action(pending_action)
                else:
                    self._undo_entry_action(pending_action)
            except Exception as exc:
                self._status_message(str(exc))
        elif (
            chosen == action_map.get("extract_dir")
            and image_index is not None
            and directory_index is not None
        ):
            self._extract_directory(int(image_index), int(directory_index))
        elif (
            chosen == action_map.get("edit_directory")
            and image_index is not None
            and directory_index is not None
        ):
            self._edit_psp_directory(int(image_index), int(directory_index))
        elif chosen == action_map.get("hex"):
            self._open_hex_view(payload)
        elif (
            chosen == action_map.get("hex_decomp")
            and has_payload
            and (payload.get("compressed") or shift_override)
        ):
            self._open_decompressed_hex(
                payload,
                force=shift_override and not payload.get("compressed"),
            )
        elif chosen == action_map.get("extract_entry"):
            # Allow extraction if we have offset OR hex_blob (for decompressed UEFI content)
            offset = payload.get("offset")
            has_hex_blob = payload.get("hex_blob") is not None
            has_virtual = payload.get("virtual") and has_hex_blob
            if offset is not None or has_hex_blob or has_virtual:
                self._extract_payload(payload)
            else:
                # Show debug info when extraction can't proceed
                self._status_message(
                    f"Extract failed: offset={offset}, virtual={payload.get('virtual')}, "
                    f"hex_blob={'yes' if has_hex_blob else 'no'}, "
                    f"size={payload.get('size')}, declared={payload.get('declared_size')}"
                )
        elif (
            chosen == action_map.get("uefi_edit_compressed")
            and (context_tag == "uefi" or payload.get("compressed_bios_info"))
            and payload.get("uefi_kind") == "section"
        ):
            try:
                payload["context_tag"] = context_tag
                self._edit_uefi_compressed_section(payload)
            except Exception as exc:
                self._status_message(str(exc))
        elif (
            chosen == action_map.get("uefi_replace_entry")
            and (context_tag == "uefi" or payload.get("compressed_bios_info"))
        ):
            try:
                payload["context_tag"] = context_tag
                self._replace_uefi_file(payload)
            except Exception as exc:
                self._status_message(str(exc))
        elif (
            chosen == action_map.get("uefi_insert_before")
            and (context_tag == "uefi" or payload.get("compressed_bios_info"))
        ):
            try:
                payload["context_tag"] = context_tag
                self._insert_uefi_file(payload, insert_before=True)
            except Exception as exc:
                self._status_message(str(exc))
        elif (
            chosen == action_map.get("uefi_insert_append")
            and (context_tag == "uefi" or payload.get("compressed_bios_info"))
        ):
            try:
                payload["context_tag"] = context_tag
                self._insert_uefi_file(payload, insert_before=False)
            except Exception as exc:
                self._status_message(str(exc))
        elif (
            chosen == action_map.get("uefi_remove_entry")
            and (context_tag == "uefi" or payload.get("compressed_bios_info"))
        ):
            try:
                payload["context_tag"] = context_tag
                self._remove_uefi_file(payload)
            except Exception as exc:
                self._status_message(str(exc))
        elif chosen == action_map.get("hex_table") and hex_blob:
            self._open_directory_table_hex(item)
        elif (
            chosen == action_map.get("remove_entry")
            and image_index is not None
            and directory_index is not None
            and entry_index_value is not None
        ):
            try:
                self._remove_psp_entry(
                    int(image_index), int(directory_index), int(entry_index_value)
                )
            except Exception as exc:
                self._status_message(str(exc))
        elif (
            chosen == action_map.get("replace_entry")
            and image_index is not None
            and directory_index is not None
            and entry_index_value is not None
        ):
            try:
                self._replace_psp_entry(
                    int(image_index), int(directory_index), int(entry_index_value)
                )
            except Exception as exc:
                self._status_message(str(exc))
        elif (
            chosen == action_map.get("edit_entry")
            and image_index is not None
            and directory_index is not None
            and entry_index_value is not None
        ):
            try:
                self._edit_psp_entry(
                    int(image_index), int(directory_index), int(entry_index_value)
                )
            except Exception as exc:
                self._status_message(str(exc))
        elif (
            chosen == action_map.get("view_apcb_tokens")
            and payload.get("offset") is not None
        ):
            try:
                self._show_apcb_tokens(payload)
            except Exception as exc:
                self._status_message(str(exc))
        elif (
            chosen == action_map.get("microcode_details")
            and payload.get("offset") is not None
        ):
            try:
                self._show_microcode_details(payload)
            except Exception as exc:
                self._status_message(str(exc))
        elif (
            chosen == action_map.get("insert_entry")
            and image_index is not None
            and directory_index is not None
        ):
            try:
                self._insert_psp_entry(
                    int(image_index), int(directory_index), entry_index_value
                )
            except Exception as exc:
                self._status_message(str(exc))
