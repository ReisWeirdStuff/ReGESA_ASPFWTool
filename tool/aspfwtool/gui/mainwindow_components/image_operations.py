# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Image modification tracking mixin for MainWindow.

This module provides:
    - Dirty state management for modified images
    - Modification recording and undo support
    - Checksum recalculation
    - Modified range tracking
    - Image reprocessing after edits
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional, Set, Tuple

from .qt import QApplication

from ..utils.diff_utils import compute_diff_statuses, iter_tree_items

from ...agesa.directory import (
    Directory,
    compute_directory_checksum,
)

if TYPE_CHECKING:
    from .controller import MainWindow
    from .models import LoadedImage


PSP_DIFF_COLUMN = 5
UEFI_DIFF_COLUMN = 5


class ImageModificationMixin:
    """Mixin providing image modification operations."""

    def _record_psp_modification(
        self: "MainWindow",
        image_index: int,
        directory_index: Optional[int],
        entry_index: Optional[int] = None,
        *,
        action_text: str = "modify",
        mark_directory: bool = True,
    ) -> None:
        """Record a PSP modification in the tree."""
        self.psp_tab_controller.record_modification(
            image_index,
            directory_index,
            entry_index,
            action_text=action_text,
            mark_directory=mark_directory,
        )

    def _clear_psp_modification(
        self: "MainWindow",
        image_index: int,
        directory_index: Optional[int],
        entry_index: Optional[int],
    ) -> None:
        """Clear a PSP modification marker."""
        self.psp_tab_controller.clear_modification(
            image_index, directory_index, entry_index
        )

    def _shift_pending_entry_indices(
        self: "MainWindow",
        image: "LoadedImage",
        directory_index: int,
        start_index: int,
        delta: int,
        *,
        skip: Optional[Set[Tuple[int, Optional[int]]]] = None,
    ) -> None:
        """Shift pending entry indices after insert/remove."""
        self.psp_tab_controller.shift_pending_entry_indices(
            image, directory_index, start_index, delta, skip=skip
        )

    def _remove_change_log_entry(
        self: "MainWindow", image: "LoadedImage", change_desc: str
    ) -> None:
        """Remove a specific entry from the change log."""
        try:
            image.change_log.remove(change_desc)
        except ValueError:
            pass

    def _refresh_image_dirty_state(self: "MainWindow", image_index: int) -> None:
        """Refresh the dirty state for an image based on pending changes."""
        if not (0 <= image_index < len(self.loaded_images)):
            return
        image = self.loaded_images[image_index]
        dirty = bool(
            image.change_log
            or image.pending_entry_actions
            or image.modified_ranges
        )
        self._mark_image_dirty(image_index, dirty)

    def _record_modified_range(
        self: "MainWindow", image_index: int, start: int, length: int
    ) -> None:
        """Record a modified byte range in the image."""
        if length is None or length <= 0:
            return
        if not (0 <= image_index < len(self.loaded_images)):
            return
        try:
            begin = int(start)
            span = int(length)
        except Exception:
            return
        if span <= 0:
            return
        end = begin + span
        image = self.loaded_images[image_index]
        merged: List[Tuple[int, int]] = []
        new_start, new_end = begin, end
        for existing_start, existing_end in getattr(image, "modified_ranges", []):
            if existing_end < new_start or existing_start > new_end:
                merged.append((existing_start, existing_end))
            else:
                new_start = min(new_start, existing_start)
                new_end = max(new_end, existing_end)
        merged.append((new_start, new_end))
        merged.sort()
        collapsed: List[Tuple[int, int]] = []
        for rng_start, rng_end in merged:
            if collapsed and collapsed[-1][1] >= rng_start:
                collapsed[-1] = (collapsed[-1][0], max(collapsed[-1][1], rng_end))
            else:
                collapsed.append((rng_start, rng_end))
        image.modified_ranges = collapsed
        self.uefi_tab_controller.mark_items_by_range(
            image_index, new_start, new_end - new_start
        )

    def _update_directory_checksum(
        self: "MainWindow", image: "LoadedImage", directory: Optional[Directory]
    ) -> None:
        """Update the checksum for a directory in the image data."""
        if directory is None or directory.offset is None:
            return
        checksum = compute_directory_checksum(image.data, directory)
        if checksum is None:
            return
        crc_off = int(directory.offset) + 4
        if 0 <= crc_off <= len(image.data) - 4:
            image.data[crc_off : crc_off + 4] = checksum.to_bytes(4, "little")

    def _apply_modified_markers(self: "MainWindow") -> None:
        """Apply modification markers to tree items based on pending actions."""
        for image_index, image in enumerate(self.loaded_images):
            for action in image.pending_entry_actions.values():
                directory_index = action.get("directory_index")
                entry_index = action.get("entry_index")
                # Use action_text if available (e.g. "Remove"), else fall back to action (e.g. "remove")
                action_name = action.get("action_text") or action.get("action", "modify")
                if directory_index is not None:
                    self._record_psp_modification(
                        image_index,
                        directory_index,
                        entry_index,
                        action_text=action_name,
                        mark_directory=True,
                    )

    def _mark_image_dirty(
        self: "MainWindow", image_index: int, dirty: bool = True
    ) -> None:
        """Mark an image as dirty (modified)."""
        if not (0 <= image_index < len(self.loaded_images)):
            return
        image = self.loaded_images[image_index]
        image.dirty = dirty
        if self._save_as_action is not None:
            any_dirty = any(img.dirty for img in self.loaded_images)
            self._save_as_action.setEnabled(any_dirty)
        self._update_window_title()

    def _update_capsule_export_state(self: "MainWindow") -> None:
        """Update the capsule export action enabled state."""
        if self._export_capsule_action is None:
            return
        enabled = any(img.was_capsule for img in self.loaded_images)
        self._export_capsule_action.setEnabled(enabled)

    def _update_window_title(self: "MainWindow") -> None:
        """Update the window title to reflect loaded files and dirty state."""
        names = [str(img.path.name) for img in self.loaded_images if img.path]
        title = self._base_title
        if names:
            joined = ", ".join(names)
            if len(joined) > 60:
                joined = joined[:57] + "..."
            title = f"{joined} - {self._base_title}"
        if any(img.dirty for img in self.loaded_images):
            title = f"- {title}"
        self.setWindowTitle(title)

    def _reprocess_image(self: "MainWindow", image_index: int) -> None:
        """Re-parse an image after modifications."""
        if not (0 <= image_index < len(self.loaded_images)):
            return
        image = self.loaded_images[image_index]

        # Preserve 0x62 pending actions across reprocess
        preserved_0x62_actions = {
            key: action for key, action in image.pending_entry_actions.items()
            if isinstance(action, dict) and action.get("is_0x62_edit")
        }
        
        # Debug logging
        from ...utils.debug_logger import get_logger
        logger = get_logger()
        logger.debug(f"_reprocess_image: preserving {len(preserved_0x62_actions)} 0x62 actions (from {len(image.pending_entry_actions)} total)")
        for key, action in preserved_0x62_actions.items():
            logger.debug(f"  preserving key={key}, action={action.get('action')}")

        refreshed = self._builder.process_image_bytes(
            image.path,
            bytes(image.data),
            image_index,
            log_callback=self._relay_loader_message,
        )
        image.directories = refreshed.directories
        image.efs_infos = refreshed.efs_infos
        image.prom_infos = refreshed.prom_infos
        image.uefi_roots = refreshed.uefi_roots
        image.psp_entries = refreshed.psp_entries
        image.psp_modified_entries.clear()
        image.modified_ranges.clear()
        image.pending_entry_actions.clear()
        image.psp_entry_actions.clear()

        # Restore preserved 0x62 pending actions
        if preserved_0x62_actions:
            image.pending_entry_actions.update(preserved_0x62_actions)
            # Also restore the visual markers
            for (dir_idx, entry_idx), action in preserved_0x62_actions.items():
                action_text = action.get("action_text", "modify")
                image.psp_modified_entries.add((dir_idx, entry_idx))
                image.psp_entry_actions[(dir_idx, entry_idx)] = action_text
            logger.debug(f"Restored {len(preserved_0x62_actions)} 0x62 actions after reprocess")
            for key in preserved_0x62_actions:
                logger.debug(f"  Restored key: {key}")

    # -------------------------------------------------------------------------
    # Diff operations
    # -------------------------------------------------------------------------

    def _set_diff_column_visibility(self: "MainWindow") -> None:
        """Show/hide diff columns based on diff mode and loaded images."""
        diff_visible = self.diff_mode and len(self.loaded_images) > 1
        for tree, column in (
            (self.psp_tree, PSP_DIFF_COLUMN),
            (self.uefi_tree, UEFI_DIFF_COLUMN),
        ):
            if tree is None:
                continue
            try:
                tree.setColumnHidden(column, not diff_visible)
            except Exception:
                pass
        if diff_visible:
            self._initialize_tree_columns()

    def _toggle_diff_mode(self: "MainWindow", checked: bool) -> None:
        """Toggle diff mode on/off."""
        desired = bool(checked) and len(self.loaded_images) > 1
        self.diff_mode = desired
        if self._diff_action and self._diff_action.isChecked() != desired:
            try:
                self._diff_action.blockSignals(True)
                self._diff_action.setChecked(desired)
            finally:
                try:
                    self._diff_action.blockSignals(False)
                except Exception:
                    pass
        self._set_diff_column_visibility()
        self._apply_diff_highlights()

    def _clear_diff_highlights(self: "MainWindow") -> None:
        """Clear all diff highlight text from tree items."""
        for model in (self.psp_model, self.uefi_model):
            if model is None:
                continue
            for item in iter_tree_items(model):
                idx = item.index()
                diff_col = (
                    PSP_DIFF_COLUMN if model is self.psp_model else UEFI_DIFF_COLUMN
                )
                model_item = model.itemFromIndex(idx.sibling(idx.row(), diff_col))
                if model_item is not None:
                    model_item.setText("")

    def _apply_diff_highlights(self: "MainWindow") -> None:
        """Apply diff status highlights to tree items."""
        if not self.diff_mode or len(self.loaded_images) < 2:
            self._clear_diff_highlights()
            self._set_diff_column_visibility()
            return
        statuses = compute_diff_statuses(
            self.psp_model, self.uefi_model, self.loaded_images
        )
        self._clear_diff_highlights()
        for item, status in statuses.values():
            model = item.model()
            if model is None:
                continue
            idx = item.index()
            diff_col = (
                PSP_DIFF_COLUMN if model is self.psp_model else UEFI_DIFF_COLUMN
            )
            diff_item = model.itemFromIndex(idx.sibling(idx.row(), diff_col))
            if diff_item is not None:
                diff_item.setText(status)
        self._set_diff_column_visibility()

    def _update_diff_action_state(self: "MainWindow") -> None:
        """Update the diff action enabled state based on loaded images."""
        if self._diff_action is None:
            return
        enabled = len(self.loaded_images) > 1
        self._diff_action.setEnabled(enabled)
        if not enabled and self.diff_mode:
            try:
                self._diff_action.blockSignals(True)
                self._diff_action.setChecked(False)
            except Exception:
                pass
            finally:
                try:
                    self._diff_action.blockSignals(False)
                except Exception:
                    pass
            self.diff_mode = False
            self._clear_diff_highlights()
            self._set_diff_column_visibility()
        if enabled and self._diff_action.isChecked() != self.diff_mode:
            self._diff_action.setChecked(self.diff_mode)

    # -------------------------------------------------------------------------
    # Image tab management
    # -------------------------------------------------------------------------

    def _sync_uefi_image_tab_selection(self: "MainWindow") -> None:
        """Sync the UEFI image tab bar to the active image index."""
        bar = getattr(self, "uefi_image_bar", None)
        if bar is None:
            return
        target = -1
        active = self._active_image_index
        if active is not None:
            for idx in range(bar.count()):
                if bar.tabData(idx) == active:
                    target = idx
                    break
        try:
            previous = bar.blockSignals(True)
        except Exception:
            previous = False
        if target >= 0:
            bar.setCurrentIndex(target)
        try:
            bar.blockSignals(previous)
        except Exception:
            bar.blockSignals(False)

    def _refresh_uefi_image_tabs(
        self: "MainWindow", fallback_locator: Optional[dict] = None
    ) -> None:
        """Refresh the UEFI image tab bar with loaded images."""
        bar = getattr(self, "uefi_image_bar", None)
        if bar is None:
            return
        try:
            previous = bar.blockSignals(True)
        except Exception:
            previous = False
        try:
            while bar.count() > 0:
                bar.removeTab(0)
        except Exception:
            pass
        for idx, image in enumerate(self.loaded_images):
            label = image.path.name if image.path else f"Image {idx + 1}"
            bar.addTab(label)
            bar.setTabData(idx, idx)
        try:
            bar.blockSignals(previous)
        except Exception:
            bar.blockSignals(False)

        if not self.loaded_images:
            self._active_image_index = None
            bar.setVisible(False)
            self._apply_psp_tree_filter()
            self._apply_uefi_tree_filter()
            return

        preferred = self._active_image_index
        if preferred is None and fallback_locator is not None:
            locator_idx = fallback_locator.get("image_index")
            try:
                preferred = int(locator_idx) if locator_idx is not None else None
            except Exception:
                pass
        if preferred is None or not (0 <= preferred < len(self.loaded_images)):
            preferred = 0
        self._active_image_index = preferred
        self._sync_uefi_image_tab_selection()
        self._apply_psp_tree_filter()
        self._apply_uefi_tree_filter()
        self._restore_active_psp_selection()
        self._restore_active_uefi_selection(fallback_locator=fallback_locator)
        bar.setVisible(bar.count() > 1)

    def _set_active_image(
        self: "MainWindow", image_index: Optional[int], *, from_tab: bool = False
    ) -> None:
        """Set the active image index and update UI accordingly."""
        if image_index is None or not (0 <= image_index < len(self.loaded_images)):
            return
        if image_index == self._active_image_index:
            return
        self._remember_active_psp_selection()
        self._remember_active_uefi_selection()
        self._active_image_index = image_index
        if not from_tab:
            self._sync_uefi_image_tab_selection()
        self._apply_psp_tree_filter()
        self._apply_uefi_tree_filter()
        self._restore_active_psp_selection()
        self._restore_active_uefi_selection()
        self.summary_controller.refresh_summary()
        self.efs_tab_controller.refresh()

    def _on_uefi_image_tab_changed(self: "MainWindow", tab_index: int) -> None:
        """Handle UEFI image tab bar selection change."""
        bar = getattr(self, "uefi_image_bar", None)
        if bar is None:
            return
        data = bar.tabData(tab_index)
        try:
            image_index = int(data)
        except Exception:
            image_index = None
        self._set_active_image(image_index, from_tab=True)

    # -------------------------------------------------------------------------
    # Model reload operations
    # -------------------------------------------------------------------------

    def _rebuild_from_loaded_images(self: "MainWindow") -> None:
        """Rebuild tree models from loaded images."""
        # Capture expanded state before rebuilding
        psp_expanded = self._capture_tree_expanded_state(self.psp_tree)
        uefi_expanded = self._capture_tree_expanded_state(self.uefi_tree) if self.include_uefi else set()
        
        locator = self._capture_psp_selection()
        uefi_locator = self.uefi_tab_controller.capture_selection()
        self._remember_active_psp_selection()
        self._remember_active_uefi_selection()
        self.psp_model.removeRows(0, self.psp_model.rowCount())
        self.uefi_model.removeRows(0, self.uefi_model.rowCount())
        psp_rows = self._builder.build_psp_rows(self.loaded_images)
        for row in psp_rows:
            self.psp_model.appendRow(row)
        # Restore expanded state
        self._restore_tree_expanded_state(self.psp_tree, psp_expanded)

        if self.include_uefi:
            uefi_rows = self._builder.build_uefi_rows(self.loaded_images)
            for row in uefi_rows:
                self.uefi_model.appendRow(row)
            # Restore expanded state
            self._restore_tree_expanded_state(self.uefi_tree, uefi_expanded)
            self._restore_active_uefi_selection(fallback_locator=uefi_locator)
        else:
            self._apply_uefi_tree_filter()
        self._apply_psp_tree_filter()
        self._restore_active_psp_selection(fallback_locator=locator)
        self._update_uefi_tab_state()
        self.summary_controller.refresh_summary()
        self.efs_tab_controller.refresh()
        self._restore_efs_focus()
        self._initialize_tree_columns()
        self._apply_modified_markers()
        self._update_action_column_visibility()
        self._set_diff_column_visibility()
        self._update_diff_action_state()
        self._apply_diff_highlights()

    def _reload_model(self: "MainWindow") -> None:
        """Reload the model from current inputs."""
        uefi_locator = self.uefi_tab_controller.capture_selection()
        psp_locator = self._capture_psp_selection()
        self._remember_active_psp_selection()
        self._remember_active_uefi_selection()
        self.psp_model.removeRows(0, self.psp_model.rowCount())
        self.uefi_model.removeRows(0, self.uefi_model.rowCount())
        self.psp_detail.clear()
        self.uefi_detail.clear()
        self.efs_tab_controller.clear_field_widgets()
        self._psp_columns_initialized = False
        self._uefi_columns_initialized = False
        self.loaded_images = []
        self._update_capsule_export_state()
        if not self.current_inputs:
            self._active_image_index = None
            self._uefi_selection_by_image.clear()
            self._psp_selection_by_image.clear()
            self._refresh_uefi_image_tabs()
        else:
            self._apply_psp_tree_filter()
            self._apply_uefi_tree_filter()

        if not self.current_inputs:
            self.summary_controller.refresh_summary()
            self.efs_tab_controller.refresh()
            self.statusBar().showMessage("No input selected")
            self._update_window_title()
            self._update_diff_action_state()
            return

        if hasattr(self, "progress_bar") and self.progress_bar is not None:
            total_hint = len(self.current_inputs)
            if total_hint <= 0:
                self.progress_bar.setRange(0, 0)
            else:
                self.progress_bar.setRange(0, total_hint)
                self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
            QApplication.processEvents()

        try:
            images = self._builder.load_images(
                self.current_inputs,
                self._loading_progress,
                log_callback=self._relay_loader_message,
                max_images=2,
            )
        except Exception as exc:
            from .qt import QMessageBox
            QMessageBox.critical(self, "Failed to load", str(exc))
            self.statusBar().showMessage("Failed to load inputs")
            self.summary_controller.refresh_summary()
            self.efs_tab_controller.refresh()
            if hasattr(self, "progress_bar") and self.progress_bar is not None:
                self.progress_bar.setVisible(False)
            self._update_capsule_export_state()
            return

        self.loaded_images = images
        self._update_window_title()
        self._update_capsule_export_state()
        self._update_diff_action_state()

        if hasattr(self, "progress_bar") and self.progress_bar is not None:
            self.progress_bar.setVisible(False)

        psp_rows = self._builder.build_psp_rows(images)
        for row in psp_rows:
            self.psp_model.appendRow(row)
        if psp_rows:
            self._select_first_item(self.psp_tree, self.psp_model)
            self.psp_tree.collapseAll()

        if self.include_uefi:
            uefi_rows = self._builder.build_uefi_rows(images)
        else:
            uefi_rows = []
        for row in uefi_rows:
            self.uefi_model.appendRow(row)
        if self.include_uefi and uefi_rows:
            self.uefi_tree.collapseAll()
        fallback_locator = uefi_locator or psp_locator
        self._refresh_uefi_image_tabs(fallback_locator=fallback_locator)

        self._update_uefi_tab_state()
        self.summary_controller.refresh_summary()
        self.efs_tab_controller.refresh()
        self._initialize_tree_columns()
        self._set_diff_column_visibility()
        self._apply_diff_highlights()

        if images:
            self.statusBar().showMessage(
                f"Loaded {len(images)} file(s) using {self.discovery_mode.upper()} mode"
            )
        else:
            self.statusBar().showMessage("No directories discovered")
