# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Actions mixin for MainWindow.

This module provides:
    - Menu bar creation and action setup
    - Keyboard shortcut handling
    - Simple event handlers and dialogs
    - AGESA version matching utilities
"""

import json
import re
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Any, Union

from .qt import (
    QAction,
    QActionGroup,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QInputDialog,
    QKeySequence,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSplitter,
    QStackedWidget,
    QTextBrowser,
    QVBoxLayout,
    Qt,
)
from ..widgets.console_search import show_search_dialog
from ..utils.roles import METADATA_ROLE
from ...agesa import agesa as _agesa
from ...agesa import constants as _constants
from ...uefi import lookup_guid_name


def _parse_version_key(version_str: str) -> Tuple[str, List[Union[int, str]]]:
    """
    Parse a version string into (prefix, version_parts) for sorting.
    
    Examples:
        "ComboAM5 1.2.0.3e" -> ("ComboAM5", [1, 2, 0, 3, "e"])
        "ComboAM5 1.2.0.3"  -> ("ComboAM5", [1, 2, 0, 3])
        "1.2.0.3a"          -> ("", [1, 2, 0, 3, "a"])
    """
    # Match prefix (letters/digits) and version part
    match = re.match(r'^([A-Za-z0-9_-]*)\s*([\d.]+)([a-zA-Z]?)$', version_str.strip())
    if not match:
        return (version_str, [])
    
    prefix = match.group(1) or ""
    version_nums = match.group(2)
    suffix_letter = match.group(3)
    
    parts: List[Union[int, str]] = []
    for segment in version_nums.split('.'):
        try:
            parts.append(int(segment))
        except ValueError:
            parts.append(segment)
    
    if suffix_letter:
        parts.append(suffix_letter.lower())
    
    return (prefix, parts)


def _version_sort_key(version_str: str) -> Tuple[str, List[Union[int, str]]]:
    """Return a sort key for version strings (smallest first)."""
    prefix, parts = _parse_version_key(version_str)
    # Convert parts for proper sorting: ints sort naturally, letters come after numbers
    sortable_parts: List[Any] = []
    for p in parts:
        if isinstance(p, int):
            sortable_parts.append((0, p))  # (0, n) for numbers
        else:
            sortable_parts.append((1, p))  # (1, letter) for letters (sorts after numbers)
    return (prefix, sortable_parts)


def _sort_version_list(versions: List[str]) -> List[str]:
    """Sort a list of version strings by version number (smallest first)."""
    return sorted(versions, key=_version_sort_key)


def _sort_hash_versions(entries: Dict[str, Any]) -> Dict[str, Any]:
    """Sort all version lists within a hash -> version(s) mapping.
    
    Handles both single version strings and lists of versions.
    """
    sorted_entries: Dict[str, Any] = {}
    for type_key, hashes in entries.items():
        if isinstance(hashes, dict):
            sorted_hashes: Dict[str, Any] = {}
            for sha, versions in hashes.items():
                if isinstance(versions, list):
                    sorted_hashes[sha] = _sort_version_list(versions)
                else:
                    sorted_hashes[sha] = versions
            sorted_entries[type_key] = sorted_hashes
        else:
            sorted_entries[type_key] = hashes
    return sorted_entries

class ActionsMixin:
    """
    Mixin class providing menu and action creation.
    
        Requires the host class to have:
        - menuBar() method
        - statusBar() method
        - close() method
        - maintenance_mode attribute
        - include_uefi attribute
        - discovery_mode attribute
        - _display_scale attribute
        - _override_system_theme attribute
        - detail_dock, hex_dock, console_dock widgets
        - Various handler methods for actions
    """

    # Action-related attributes
    _save_as_action: Optional[QAction]
    _export_capsule_action: Optional[QAction]
    _diff_action: Optional[QAction]
    _scale_actions: Dict[int, QAction]
    _scale_group: Optional[QActionGroup]
    _theme_group: Optional[QActionGroup]
    _dark_theme_action: Optional[QAction]
    _light_theme_action: Optional[QAction]
    _system_theme_action: Optional[QAction]
    include_uefi_action: Optional[QAction]
    search_action: Optional[QAction]
    mode_group: Optional[QActionGroup]
    mode_actions: Dict[str, QAction]

    def _create_actions(self) -> None:
        """Create all menu actions and menus."""
        self._create_file_menu()
        self._create_view_menu()
        self._create_discovery_mode_menu()
        self._create_help_menu()

    def _create_file_menu(self) -> None:
        """Create the File menu and its actions."""
        file_menu = self.menuBar().addMenu("&File")

        open_action = QAction("&Open File...", self)
        open_action.triggered.connect(self._open_files)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        self._save_as_action = QAction("Save &As...", self)
        self._save_as_action.setEnabled(False)
        self._save_as_action.triggered.connect(self._save_as)
        file_menu.addAction(self._save_as_action)

        self._export_capsule_action = QAction("Export capsule to &BIN...", self)
        self._export_capsule_action.setEnabled(False)
        self._export_capsule_action.triggered.connect(self._export_capsule_image)
        file_menu.addAction(self._export_capsule_action)

        file_menu.addSeparator()

        efs_action = QAction("Set &EFS offset...", self)
        efs_action.triggered.connect(self._prompt_efs_offset)
        file_menu.addAction(efs_action)

        export_guid_action = QAction("Export GUID &catalog...", self)
        export_guid_action.triggered.connect(self._export_guid_catalog)
        file_menu.addAction(export_guid_action)

        export_psp_action = QAction("Export &PSP tree...", self)
        export_psp_action.triggered.connect(self._export_psp_structure)
        file_menu.addAction(export_psp_action)

        export_xml_action = QAction("Export firmware and generate &XML...", self)
        export_xml_action.triggered.connect(self._export_firmware_xml)
        file_menu.addAction(export_xml_action)

        if self.maintenance_mode:
            load_guid_action = QAction("Load GUID &CSV...", self)
            load_guid_action.triggered.connect(self._load_guid_csv)
            file_menu.addAction(load_guid_action)

            export_amd_action = QAction("Export &AMD modules...", self)
            export_amd_action.triggered.connect(self._export_amd_modules)
            file_menu.addAction(export_amd_action)

            append_agesa_action = QAction("Append AGESA &version...", self)
            append_agesa_action.triggered.connect(self._show_append_agesa_dialog)
            file_menu.addAction(append_agesa_action)

        file_menu.addSeparator()

        search_menu = file_menu.addMenu("&Search")
        self.search_action = QAction("&Find...", self)
        self.search_action.setShortcut(QKeySequence.Find)
        self.search_action.triggered.connect(self._show_search_dialog)
        search_menu.addAction(self.search_action)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def _create_view_menu(self) -> None:
        """Create the View menu and its actions."""
        view_menu = self.menuBar().addMenu("&View")
        
        if getattr(self, "detail_dock", None) is not None:
            detail_toggle = self.detail_dock.toggleViewAction()
            detail_toggle.setText("Details Panel")
            view_menu.addAction(detail_toggle)
        if getattr(self, "hex_dock", None) is not None:
            hex_toggle = self.hex_dock.toggleViewAction()
            hex_toggle.setText("Hex View Panel")
            view_menu.addAction(hex_toggle)
        if getattr(self, "console_dock", None) is not None:
            console_toggle = self.console_dock.toggleViewAction()
            console_toggle.setText("Console / Search")
            view_menu.addAction(console_toggle)
        if view_menu.actions():
            view_menu.addSeparator()
            
        self._diff_action = QAction("Diff mode", self, checkable=True)
        self._diff_action.setEnabled(False)
        self._diff_action.toggled.connect(self._toggle_diff_mode)
        view_menu.addAction(self._diff_action)
        view_menu.addSeparator()
        
        self.include_uefi_action = QAction("Include UEFI parsing", self, checkable=True)
        self.include_uefi_action.setChecked(self.include_uefi)
        self.include_uefi_action.toggled.connect(self._toggle_include_uefi)
        view_menu.addAction(self.include_uefi_action)

        self._create_scale_menu(view_menu)
        self._create_theme_menu(view_menu)

    def _create_scale_menu(self, parent_menu) -> None:
        """Create the Display Scale submenu."""
        scale_menu = parent_menu.addMenu("Display &Scale")
        self._scale_group = QActionGroup(self)
        self._scale_group.setExclusive(True)
        for pct in (100, 125, 150, 175, 200, 250, 300):
            action = QAction(f"{pct}%", self, checkable=True)
            if pct == int(round(self._display_scale * 100)):
                action.setChecked(True)
            action.triggered.connect(
                lambda checked, factor=pct / 100.0: self._set_display_scale(factor)
                if checked
                else None
            )
            self._scale_group.addAction(action)
            scale_menu.addAction(action)
            self._scale_actions[pct] = action

    def _create_theme_menu(self, parent_menu) -> None:
        """Create the Theme submenu with explicit Dark/Light/System options."""
        theme_menu = parent_menu.addMenu("&Theme")
        self._theme_group = QActionGroup(self)
        self._theme_group.setExclusive(True)
        
        # Dark Theme option
        self._dark_theme_action = QAction("Dark", self, checkable=True)
        self._dark_theme_action.triggered.connect(
            lambda checked: self._set_theme_mode("dark") if checked else None
        )
        self._theme_group.addAction(self._dark_theme_action)
        theme_menu.addAction(self._dark_theme_action)
        
        # Light Theme option
        self._light_theme_action = QAction("Light", self, checkable=True)
        self._light_theme_action.triggered.connect(
            lambda checked: self._set_theme_mode("light") if checked else None
        )
        self._theme_group.addAction(self._light_theme_action)
        theme_menu.addAction(self._light_theme_action)
        
        # Follow System option
        self._system_theme_action = QAction("Follow System", self, checkable=True)
        self._system_theme_action.triggered.connect(
            lambda checked: self._set_theme_mode("system") if checked else None
        )
        self._theme_group.addAction(self._system_theme_action)
        theme_menu.addAction(self._system_theme_action)
        
        # Set initial state based on current theme settings
        self._sync_theme_menu()

    def _create_discovery_mode_menu(self) -> None:
        """Create the Discovery Mode menu."""
        mode_menu = self.menuBar().addMenu("&Discovery Mode")
        self.mode_group = QActionGroup(self)
        self.mode_actions = {}
        for mode in ("auto", "efs", "scan"):
            action = QAction(mode.upper(), self, checkable=True)
            action.setChecked(mode == self.discovery_mode)
            action.triggered.connect(
                lambda checked, m=mode: self._set_mode(m) if checked else None
            )
            self.mode_group.addAction(action)
            mode_menu.addAction(action)
            self.mode_actions[mode] = action

    def _create_help_menu(self) -> None:
        """Create the Help menu."""
        help_menu = self.menuBar().addMenu("&Help")
        qrh_action = QAction("&QRH", self)
        qrh_action.setShortcut(QKeySequence("F1"))
        qrh_action.triggered.connect(self._show_qrh_handbook)
        help_menu.addAction(qrh_action)
        help_menu.addSeparator()
        about_action = QAction("About this tool", self)
        about_action.triggered.connect(self._show_about_dialog)
        help_menu.addAction(about_action)
        about_pyside_action = QAction("About PySide", self)
        about_pyside_action.triggered.connect(self._show_about_pyside_dialog)
        help_menu.addAction(about_pyside_action)
        licenses_action = QAction("Software licenses", self)
        licenses_action.triggered.connect(self._show_license_dialog)
        help_menu.addAction(licenses_action)

    # Event handlers for dialogs

    def _show_about_dialog(self) -> None:
        """Show the About dialog with release info loaded from HTML template."""
        psp_path, _ = _agesa._get_split_db_paths()
        release_info_path = psp_path.parent / "release_info.json"
        
        info = {}
        if release_info_path.exists():
            try:
                with release_info_path.open("r", encoding="utf-8") as f:
                    info = json.load(f)
            except Exception:
                pass
        
        version = info.get("version", "Unknown")
        build_date = info.get("build_date", "Unknown")
        authors = ", ".join(info.get("authors", []))
        repository = info.get("repository", "https://kolabo.dev/")
        
        # Load HTML template and substitute placeholders
        html = _load_help_html("about.html", {
            "{version}": version,
            "{build_date}": build_date,
            "{authors}": authors,
            "{repository}": repository,
        })
        
        # Show in a dialog with QTextBrowser for proper rendering
        dialog = QDialog(self)
        dialog.setWindowTitle("About this tool")
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        
        layout = QVBoxLayout(dialog)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        # Inject inline CSS with theme-appropriate colors
        dark = getattr(self, "dark_theme_enabled", False)
        styled = _inject_inline_css(html, dark)
        browser.setHtml(styled)
        layout.addWidget(browser)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(dialog.accept)
        layout.addWidget(button_box)
        
        dialog.resize(600, 480)
        dialog.exec()

    def _show_license_dialog(self) -> None:
        """Show the Software licenses dialog loaded from HTML."""
        html = _load_help_html("licenses.html")
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Software Licenses")
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        
        layout = QVBoxLayout(dialog)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        dark = getattr(self, "dark_theme_enabled", False)
        styled = _inject_inline_css(html, dark)
        browser.setHtml(styled)
        layout.addWidget(browser)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(dialog.accept)
        layout.addWidget(button_box)
        
        dialog.resize(550, 400)
        dialog.exec()

    def _show_about_pyside_dialog(self) -> None:
        """Show the About PySide dialog loaded from HTML."""
        html = _load_help_html("about_pyside.html")
        
        dialog = QDialog(self)
        dialog.setWindowTitle("About PySide")
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        
        layout = QVBoxLayout(dialog)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        dark = getattr(self, "dark_theme_enabled", False)
        styled = _inject_inline_css(html, dark)
        browser.setHtml(styled)
        layout.addWidget(browser)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(dialog.accept)
        layout.addWidget(button_box)
        
        dialog.resize(600, 450)
        dialog.exec()

    def _show_qrh_handbook(self) -> None:
        """Show the built-in Quick Reference Handbook."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Quick Reference Handbook - PSP/BIOS Structures")
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(6, 6, 6, 6)
        
        splitter = QSplitter(Qt.Horizontal, dialog)
        
        # Navigation list
        nav_list = QListWidget()
        nav_list.setMaximumWidth(200)
        nav_list.setMinimumWidth(150)
        
        # Content stack
        content_stack = QStackedWidget()
        
        # Define handbook pages
        pages = _get_qrh_pages()
        
        for title, html_content, file_path in pages:
            # Add navigation item
            item = QListWidgetItem(title)
            nav_list.addItem(item)
            
            # Add content page with security hardening
            browser = QTextBrowser()
            browser.setOpenExternalLinks(False)  # Disable external links for security
            browser.setOpenLinks(False)  # Disable all link navigation
            # Sanitize HTML and inject inline CSS with theme-appropriate colors
            safe_html = _sanitize_html(html_content)
            dark = getattr(self, "dark_theme_enabled", False)
            styled = _inject_inline_css(safe_html, dark)
            browser.setHtml(styled)
            content_stack.addWidget(browser)
        
        # Connect navigation
        nav_list.currentRowChanged.connect(content_stack.setCurrentIndex)
        nav_list.setCurrentRow(0)
        
        splitter.addWidget(nav_list)
        splitter.addWidget(content_stack)
        splitter.setSizes([180, 820])
        
        layout.addWidget(splitter)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Close, dialog)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        dialog.resize(1100, 750)
        dialog.show()

    def _show_search_dialog(self) -> None:
        """Show the search dialog."""
        show_search_dialog(self)

    def _open_files(self) -> None:
        """Open file selection dialog and load selected files."""
        current_inputs = getattr(self, "current_inputs", [])
        base_dir = current_inputs[0].parent if current_inputs else Path.cwd()
        file_paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select firmware image(s)",
            str(base_dir),
            "Firmware images (*.bin *.rom *.cap *.fd *.bio *.img *.fv *.efi);;All files (*)",
        )
        if not file_paths:
            return
        if len(file_paths) > 2:
            QMessageBox.information(
                self,
                "Too many files",
                "Please select up to two firmware images. Loading the first two.",
            )
            file_paths = file_paths[:2]
        self.load_inputs([Path(path) for path in file_paths])

    def _toggle_include_uefi(self, checked: bool) -> None:
        """Toggle UEFI parsing inclusion."""
        if self.include_uefi == checked:
            return
        self.include_uefi = checked
        self._builder.include_uefi = checked
        self._update_uefi_tab_state()
        self._reload_model()

    def _set_mode(self, mode: str) -> None:
        """Set the discovery mode."""
        if mode == self.discovery_mode:
            return
        self.discovery_mode = mode
        self._builder.discovery_mode = mode
        self._reload_model()

    def _export_capsule_image(self) -> None:
        """Export capsule contents to a binary file."""
        loaded_images = getattr(self, "loaded_images", [])
        if not any(img.was_capsule for img in loaded_images):
            QMessageBox.information(
                self,
                "No capsule detected",
                "The currently loaded image was not opened from a capsule.",
            )
            return
        target_image = next(
            (img for img in loaded_images if img.was_capsule), None
        )
        if target_image is None:
            return
        base_dir = target_image.path.parent if target_image.path else Path.cwd()
        default_name = (
            target_image.path.with_suffix(".bin").name
            if target_image.path
            else "firmware.bin"
        )
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export capsule contents",
            str(base_dir / default_name),
            "Binary images (*.bin *.rom *.img);;All files (*)",
        )
        if not file_path:
            return
        try:
            Path(file_path).write_bytes(bytes(target_image.data))
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        self._status_message(f"Exported capsule contents to {file_path}")

    def _prompt_efs_offset(self) -> None:
        """Prompt user to set EFS offset."""
        efs_offset = getattr(self, "efs_offset", None)
        current = "" if efs_offset is None else f"0x{int(efs_offset):X}"
        value, ok = QInputDialog.getText(
            self,
            "Set EFS offset",
            "Enter an absolute EFS offset in bytes (leave blank for auto, e.g. 0x1020000):",
            text=current,
        )
        if not ok:
            return
        value = value.strip()
        if not value:
            self.efs_offset = None
        else:
            try:
                parsed = int(value, 0)
            except ValueError:
                QMessageBox.warning(
                    self, "Invalid value", "Please enter a valid hexadecimal or decimal offset."
                )
                return
            if parsed < 0:
                QMessageBox.warning(
                    self, "Invalid value", "Offset must be non-negative."
                )
                return
            self.efs_offset = parsed
        self._builder.efs_offset = self.efs_offset
        self._reload_model()

    def _show_append_agesa_dialog(self) -> None:
        """Show dialog to append AGESA version to discovered hashes."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Append AGESA Version")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout(dialog)

        form_layout = QFormLayout()
        version_edit = QLineEdit(dialog)
        version_edit.setPlaceholderText("e.g. ComboAM5 1.2.0.2a")
        form_layout.addRow("AGESA Version:", version_edit)
        layout.addLayout(form_layout)

        psp_checkbox = QCheckBox("PSP/BIOS entries (agesa_psp_versions.json)", dialog)
        psp_checkbox.setChecked(True)
        layout.addWidget(psp_checkbox)

        uefi_checkbox = QCheckBox("UEFI modules (agesa_uefi_versions.json)", dialog)
        uefi_checkbox.setChecked(False)
        layout.addWidget(uefi_checkbox)

        info_label = QLabel(
            "This will collect hashes from all loaded images and append them to the selected JSON file(s).",
            dialog,
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel, dialog
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.Accepted:
            return

        version_str = version_edit.text().strip()
        if not version_str:
            QMessageBox.warning(self, "Empty Version", "Please enter an AGESA version string.")
            return

        do_psp = psp_checkbox.isChecked()
        do_uefi = uefi_checkbox.isChecked()
        if not do_psp and not do_uefi:
            QMessageBox.warning(self, "No Selection", "Please select at least PSP or UEFI.")
            return

        if do_psp:
            self._append_psp_hashes(version_str)
        if do_uefi:
            self._append_uefi_hashes(version_str)

    def _get_release_version(self) -> str:
        """Get the version string from release_info.json."""
        psp_path, _ = _agesa._get_split_db_paths()
        release_info_path = psp_path.parent / "release_info.json"
        if release_info_path.exists():
            try:
                with release_info_path.open("r", encoding="utf-8") as f:
                    info = json.load(f)
                    return info.get("version", "0.0.0")
            except Exception:
                pass
        return "0.0.0"

    def _append_psp_hashes(self, version_str: str) -> None:
        """Collect PSP/BIOS hashes from loaded images and append to agesa_psp_versions.json."""
        psp_path, _ = _agesa._get_split_db_paths()
        release_version = self._get_release_version()

        if psp_path.exists():
            try:
                with psp_path.open("r", encoding="utf-8") as f:
                    db = json.load(f)
            except Exception as e:
                QMessageBox.warning(self, "Load Error", f"Failed to load agesa_psp_versions.json: {e}")
                return
        else:
            db = {"metadata": {"version": release_version, "description": "AGESA PSP/BIOS Entry Version <-> Hash Map"}, "psp_entries": {}, "bios_entries": {}}

        # Update metadata version to current release version
        if "metadata" in db:
            db["metadata"]["version"] = release_version

        # Load tracking.json to get whitelist of types to track
        tracking_path = psp_path.parent / "tracking.json"
        psp_whitelist: set = set()
        bios_whitelist: set = set()
        if tracking_path.exists():
            try:
                with tracking_path.open("r", encoding="utf-8") as f:
                    tracking = json.load(f)
                    for t in tracking.get("psp_types", []):
                        try:
                            psp_whitelist.add(int(t, 16) & 0xFF)
                        except (ValueError, TypeError):
                            pass
                    for t in tracking.get("bios_types", []):
                        try:
                            bios_whitelist.add(int(t, 16) & 0xFF)
                        except (ValueError, TypeError):
                            pass
            except Exception:
                pass

        psp_entries = db.setdefault("psp_entries", {})
        bios_entries = db.setdefault("bios_entries", {})
        collected_count = 0

        model = getattr(self, "psp_model", None)
        if model is None:
            QMessageBox.warning(self, "No Model", "PSP tree model not available.")
            return

        def _collect_from_item(item, is_bios_dir: bool = False) -> None:
            nonlocal collected_count
            if item is None:
                return
            
            # Check if this is a BIOS or PSP directory node from item text
            # Directory labels are formatted as "{index}: {kind} @ {offset}"
            # e.g., "00: $PSP @ 0x123" or "01: $BHD @ 0x456"
            item_text = item.text() if item.text() else ""
            if "$BHD" in item_text or "2BHD" in item_text or "$BL2" in item_text:
                is_bios_dir = True
            elif "$PSP" in item_text or "2PSP" in item_text or "$PL2" in item_text:
                is_bios_dir = False
            
            metadata = item.data(METADATA_ROLE)
            if isinstance(metadata, dict):
                # Also check Directory field in metadata for entry nodes
                dir_kind = metadata.get("Directory", "")
                if _constants.is_bios_dir(dir_kind):
                    is_bios_dir = True
                elif _constants.is_psp_dir(dir_kind):
                    is_bios_dir = False
                
                sha256 = metadata.get("Payload SHA256")
                # Type value is stored as "0x00000001" format
                type_value = metadata.get("Type value")
                if sha256 and type_value:
                    # Extract low byte for type key (e.g., "0x00000001" -> "0x01")
                    try:
                        type_int = int(type_value, 16)
                        type_low = type_int & 0xFF
                        type_key = f"0x{type_low:02X}"
                    except (ValueError, TypeError):
                        type_key = type_value
                        type_low = None
                    
                    # Select target entries dict and whitelist based on directory type
                    if is_bios_dir:
                        target_entries = bios_entries
                        whitelist = bios_whitelist
                    else:
                        target_entries = psp_entries
                        whitelist = psp_whitelist
                    
                    # Only track types in whitelist (from tracking.json)
                    if type_low is not None and (not whitelist or type_low in whitelist):
                        # Get or create entry for this type (simple hash -> version mapping)
                        if type_key not in target_entries:
                            target_entries[type_key] = {}
                        hashes = target_entries[type_key]
                        sha_upper = sha256.upper()
                        if sha_upper not in hashes:
                            hashes[sha_upper] = version_str
                            collected_count += 1
                        elif isinstance(hashes[sha_upper], list):
                            if version_str not in hashes[sha_upper]:
                                hashes[sha_upper].append(version_str)
                                collected_count += 1
                        elif hashes[sha_upper] != version_str:
                            hashes[sha_upper] = [hashes[sha_upper], version_str]
                            collected_count += 1
            for row in range(item.rowCount()):
                child = item.child(row, 0)
                _collect_from_item(child, is_bios_dir)

        for row in range(model.rowCount()):
            item = model.item(row, 0)
            _collect_from_item(item)

        if collected_count == 0:
            QMessageBox.information(
                self, "No Hashes", "No new PSP/BIOS entry hashes were found to add."
            )
            return

        # Sort entries by type ID numerically (0x00, 0x01, ..., 0xFF)
        def _type_sort_key(key: str) -> int:
            try:
                return int(key, 16)
            except (ValueError, TypeError):
                return 0xFFFFFFFF
        
        sorted_psp = dict(sorted(psp_entries.items(), key=lambda x: _type_sort_key(x[0])))
        sorted_bios = dict(sorted(bios_entries.items(), key=lambda x: _type_sort_key(x[0])))
        
        # Sort version lists within each hash entry (smallest version first)
        db["psp_entries"] = _sort_hash_versions(sorted_psp)
        db["bios_entries"] = _sort_hash_versions(sorted_bios)

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save AGESA Versions JSON",
            str(psp_path),
            "JSON Files (*.json);;All Files (*)",
        )
        if not save_path:
            return

        try:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(db, f, indent=2)
            QMessageBox.information(
                self, "Success", f"Added {collected_count} PSP/BIOS hash entries.\nSaved to: {save_path}"
            )
        except Exception as e:
            QMessageBox.warning(self, "Save Error", f"Failed to save: {e}")

    def _append_uefi_hashes(self, version_str: str) -> None:
        """Collect UEFI module hashes from loaded images and append to agesa_uefi_versions.json."""
        _, uefi_path = _agesa._get_split_db_paths()
        release_version = self._get_release_version()

        if uefi_path.exists():
            try:
                with uefi_path.open("r", encoding="utf-8") as f:
                    db = json.load(f)
            except Exception as e:
                QMessageBox.warning(self, "Load Error", f"Failed to load agesa_uefi_versions.json: {e}")
                return
        else:
            db = {"metadata": {"version": release_version, "description": "AGESA UEFI Module Version <-> Hash Map"}, "modules": {}}

        # Update metadata version to current release version
        if "metadata" in db:
            db["metadata"]["version"] = release_version

        # Load tracking.json to get whitelist of GUIDs to track
        tracking_path = uefi_path.parent / "tracking.json"
        uefi_guid_whitelist: set = set()
        if tracking_path.exists():
            try:
                with tracking_path.open("r", encoding="utf-8") as f:
                    tracking = json.load(f)
                    for guid in tracking.get("uefi_guids", []):
                        uefi_guid_whitelist.add(str(guid).upper())
            except Exception:
                pass

        modules = db.setdefault("modules", {})
        collected_count = 0

        loaded_images = getattr(self, "loaded_images", [])
        if not loaded_images:
            QMessageBox.warning(self, "No Images", "No images are loaded.")
            return

        for image in loaded_images:
            for uefi_root in getattr(image, "uefi_roots", []):
                for volume in getattr(uefi_root, "volumes", []):
                    for ffs in getattr(volume, "files", []):
                        count_before = self._count_modules(modules)
                        self._process_uefi_ffs_for_hash(
                            image, ffs, modules, version_str, uefi_guid_whitelist
                        )
                        collected_count += self._count_modules(modules) - count_before
                        # Process nested sections if any
                        for section in getattr(ffs, "sections", []):
                            count_before = self._count_modules(modules)
                            self._process_uefi_section_for_hash(
                                image, section, modules, version_str, uefi_guid_whitelist
                            )
                            collected_count += self._count_modules(modules) - count_before

        if collected_count == 0:
            QMessageBox.information(
                self, "No Hashes", "No AMD UEFI module hashes were found to add."
            )
            return

        # Sort version lists within each module's hashes (smallest version first)
        for module_data in modules.values():
            hashes = module_data.get("hashes", {})
            for sha, versions in list(hashes.items()):
                if isinstance(versions, list):
                    hashes[sha] = _sort_version_list(versions)

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save UEFI Versions JSON",
            str(uefi_path),
            "JSON Files (*.json);;All Files (*)",
        )
        if not save_path:
            return

        try:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(db, f, indent=2)
            QMessageBox.information(
                self, "Success", f"Added {collected_count} UEFI module hash entries.\nSaved to: {save_path}"
            )
        except Exception as e:
            QMessageBox.warning(self, "Save Error", f"Failed to save: {e}")

    def _count_modules(self, modules: Dict) -> int:
        """Count total hash entries in modules dict."""
        count = 0
        for mod in modules.values():
            hashes = mod.get("hashes", {})
            count += len(hashes)
        return count

    def _process_uefi_ffs_for_hash(
        self, image, ffs, modules: Dict, version_str: str, guid_whitelist: set
    ) -> None:
        """Process a firmware file system file for AMD module hash."""
        info = getattr(ffs, "info", None)
        if info is None:
            return
        guid = getattr(info, "guid", None)
        if guid is None:
            return
        guid_str = str(guid).upper()
        if guid_str not in guid_whitelist:
            return
        name = lookup_guid_name(guid) or guid_str
        
        # Get hash either from image buffer (if offset available) or from raw_data
        offset = getattr(info, "absolute_offset", None)
        size = getattr(info, "size", None)
        raw_data = getattr(info, "raw_data", None)
        
        digest = None
        if offset is not None and size is not None and size > 0:
            # Hash from image buffer
            digest = _agesa.hash_buffer_slice(image.data, offset, size)
        elif raw_data is not None and len(raw_data) > 0:
            # Hash from raw_data (for nested FFS in decompressed sections)
            digest = _agesa.hash_bytes(raw_data)
        
        if digest is None:
            return
        module_entry = modules.setdefault(name, {
            "guid": guid_str,
            "hashes": {},
        })
        hashes = module_entry.setdefault("hashes", {})
        sha_upper = digest.upper()
        if sha_upper not in hashes:
            hashes[sha_upper] = version_str
        elif isinstance(hashes[sha_upper], list):
            if version_str not in hashes[sha_upper]:
                hashes[sha_upper].append(version_str)
        elif hashes[sha_upper] != version_str:
            hashes[sha_upper] = [hashes[sha_upper], version_str]

    def _process_uefi_section_for_hash(
        self, image, section, modules: Dict, version_str: str, guid_whitelist: set
    ) -> None:
        """Process UEFI section for nested encapsulation sections."""
        # Process nested volumes that contain FFS files
        for nested_volume in getattr(section, "volumes", []):
            for nested_ffs in getattr(nested_volume, "files", []):
                self._process_uefi_ffs_for_hash(image, nested_ffs, modules, version_str, guid_whitelist)
                # Recursively process sections within the FFS file
                for ffs_section in getattr(nested_ffs, "sections", []):
                    self._process_uefi_section_for_hash(image, ffs_section, modules, version_str, guid_whitelist)
        # Process nested sections recursively
        for nested_section in getattr(section, "sections", []):
            self._process_uefi_section_for_hash(image, nested_section, modules, version_str, guid_whitelist)


# QRH Handbook pages - auto-loaded from Docs/qrh directory
_QRH_DOCS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "Docs" / "qrh"

# Help pages - loaded from Docs/help directory
_HELP_DOCS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "Docs" / "help"

# Shared styles directory
_DOCS_STYLE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "Docs" / "style"

# Regex patterns for HTML sanitization (compiled once)
_SCRIPT_TAG_RE = re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
_EVENT_HANDLER_RE = re.compile(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', re.IGNORECASE)
_JAVASCRIPT_URL_RE = re.compile(r'(href|src)\s*=\s*["\']javascript:[^"\']*["\']', re.IGNORECASE)
_STYLE_EXPRESSION_RE = re.compile(r'expression\s*\([^)]*\)', re.IGNORECASE)
_IFRAME_TAG_RE = re.compile(r'<iframe[^>]*>.*?</iframe>', re.IGNORECASE | re.DOTALL)
_OBJECT_TAG_RE = re.compile(r'<object[^>]*>.*?</object>', re.IGNORECASE | re.DOTALL)
_EMBED_TAG_RE = re.compile(r'<embed[^>]*/?>', re.IGNORECASE)


def _sanitize_html(html: str) -> str:
    """Sanitize HTML content to prevent JavaScript/XSS attacks.
    
    Removes:
    - <script> tags and content
    - Event handlers (onclick, onload, onerror, etc.)
    - javascript: URLs
    - CSS expressions
    - <iframe>, <object>, <embed> tags
    """
    # Remove dangerous tags
    html = _SCRIPT_TAG_RE.sub('', html)
    html = _IFRAME_TAG_RE.sub('', html)
    html = _OBJECT_TAG_RE.sub('', html)
    html = _EMBED_TAG_RE.sub('', html)
    
    # Remove event handlers
    html = _EVENT_HANDLER_RE.sub('', html)
    
    # Remove javascript: URLs
    html = _JAVASCRIPT_URL_RE.sub('', html)
    
    # Remove CSS expressions (IE vulnerability)
    html = _STYLE_EXPRESSION_RE.sub('', html)
    
    return html


def _get_inline_css(dark: bool) -> str:
    """Generate inline CSS for QTextBrowser (no CSS variable support).
    
    Returns CSS with colors appropriate for the given theme.
    """
    if dark:
        return """
<style>
html, body {
  background-color: #1e1e1e;
  color: #d4d4d4;
  font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
  font-size: 14px;
  line-height: 1.6;
  margin: 0;
  padding: 20px;
}
h1, h2, h3 { color: #e06060; margin-top: 0; }
h1 { border-bottom: 2px solid #e06060; padding-bottom: 6px; }
p { margin: 10px 0; }
a { color: #569cd6; text-decoration: none; }
a:hover { text-decoration: underline; color: #77bdf2; }
ul, ol { margin: 10px 0; padding-left: 25px; }
li { margin: 5px 0; }
code { background-color: #2d2d2d; color: #ce9178; padding: 2px 6px; border-radius: 3px; font-family: Consolas, 'Courier New', monospace; }
.placeholder { color: #888888; font-style: italic; }
table { border-collapse: collapse; margin: 10px 0; background: #252526; }
table th, table td { border: 1px solid #404040; padding: 6px 10px; text-align: left; }
table th { background: #333333; color: #4fc3f7; }
table td { color: #d4d4d4; }
.offset { font-family: Consolas, 'Courier New', monospace; color: #b5cea8; }
.note { background: #3d3d00; border-left: 4px solid #daa520; padding: 10px; margin: 10px 0; color: #e0e0a0; }
.info-table { border-collapse: collapse; margin: 15px 0; border: none; background: transparent; }
.info-table td { padding: 4px 12px 4px 0; vertical-align: top; border: none; }
.info-table td b { color: #4fc3f7; }
strong { color: #4fc3f7; }
</style>
"""
    else:
        return """
<style>
html, body {
  background-color: #f8f8f8;
  color: #191919;
  font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
  font-size: 14px;
  line-height: 1.6;
  margin: 0;
  padding: 20px;
}
h1, h2, h3 { color: #c04040; margin-top: 0; }
h1 { border-bottom: 2px solid #c04040; padding-bottom: 6px; }
p { margin: 10px 0; }
a { color: #0066cc; text-decoration: none; }
a:hover { text-decoration: underline; color: #2d7dd2; }
ul, ol { margin: 10px 0; padding-left: 25px; }
li { margin: 5px 0; }
code { background-color: #eaeaea; color: #a31515; padding: 2px 6px; border-radius: 3px; font-family: Consolas, 'Courier New', monospace; }
.placeholder { color: #666666; font-style: italic; }
table { border-collapse: collapse; margin: 10px 0; background: #ffffff; }
table th, table td { border: 1px solid #c0c0c0; padding: 6px 10px; text-align: left; }
table th { background: #e0e0e0; color: #333333; }
table td { color: #191919; }
.offset { font-family: Consolas, 'Courier New', monospace; color: #1a5a30; }
.note { background: #fef6e0; border-left: 4px solid #c49000; padding: 10px; margin: 10px 0; color: #5a4500; }
.info-table { border-collapse: collapse; margin: 15px 0; border: none; background: transparent; }
.info-table td { padding: 4px 12px 4px 0; vertical-align: top; border: none; }
.info-table td b { color: #005599; }
strong { color: #005599; }
</style>
"""


def _inject_inline_css(html: str, dark: bool) -> str:
    """Replace external stylesheet link with inline CSS and inject into <head>.
    
    QTextBrowser doesn't reliably load external CSS or support CSS variables,
    so we inline theme-appropriate styles directly.
    """
    css = _get_inline_css(dark)
    # Remove any <link rel="stylesheet" ...> tags
    html = re.sub(r'<link\s+[^>]*rel\s*=\s*["\']stylesheet["\'][^>]*/?>\s*', '', html, flags=re.IGNORECASE)
    # Insert CSS after <head> or at start of <body>
    if re.search(r'<head[^>]*>', html, re.IGNORECASE):
        html = re.sub(r'(<head[^>]*>)', r'\1' + css, html, count=1, flags=re.IGNORECASE)
    elif re.search(r'<body[^>]*>', html, re.IGNORECASE):
        html = re.sub(r'(<body[^>]*>)', css + r'\1', html, count=1, flags=re.IGNORECASE)
    else:
        html = css + html
    return html


def _inject_theme_attr(html: str, dark: bool) -> str:
    """Inject or update data-theme attribute on the <html> element.
    If no <html> tag is present, returns the original html.
    """
    try:
        # Ensure we target the opening <html ...> tag
        m = re.search(r"<html\b[^>]*>", html, re.IGNORECASE)
        if not m:
            return html
        start, end = m.span()
        tag = m.group(0)
        # Remove existing data-theme if present
        tag_new = re.sub(r"\sdata-theme\s*=\s*\"(dark|light)\"", "", tag, flags=re.IGNORECASE)
        # Inject attribute before closing '>'
        theme_val = "dark" if dark else "light"
        tag_new = tag_new[:-1] + f' data-theme="{theme_val}">'  # safe, tag ends with '>'
        return html[:start] + tag_new + html[end:]
    except Exception:
        return html


def _load_help_html(filename: str, substitutions: dict = None) -> str:
    """Load HTML content from Help docs directory.
    
    Args:
        filename: Name of the HTML file (e.g., '01_about.html')
        substitutions: Optional dict of {placeholder: value} for template substitution
        
    Returns:
        Sanitized HTML content, or error message if file not found
    """
    file_path = _HELP_DOCS_DIR / filename
    if not file_path.exists():
        return f"<html><body><h1>Error</h1><p>Help file '{filename}' not found</p></body></html>"
    
    try:
        html = file_path.read_text(encoding="utf-8")
        if substitutions:
            for placeholder, value in substitutions.items():
                html = html.replace(placeholder, str(value))
        return _sanitize_html(html)
    except Exception as e:
        return f"<html><body><h1>Error</h1><p>Could not load {filename}: {e}</p></body></html>"


def _get_qrh_pages():
    """Return list of (title, html_content, file_path) tuples for QRH handbook.
    
    Auto-discovers and loads all HTML files from the Docs/qrh directory.
    Files are sorted alphabetically by filename (use number prefix for ordering).
    Title is derived from filename by:
    - Stripping leading number prefix (e.g., '01_' or '1_')
    - Removing 'qrh_' prefix if present
    - Replacing underscores with spaces
    - Title-casing the result
    """
    pages = []
    if not _QRH_DOCS_DIR.exists():
        return [("Error", "<html><body><h1>Error</h1><p>QRH docs directory not found</p></body></html>", None)]
    
    html_files = sorted(_QRH_DOCS_DIR.glob("*.html"))
    if not html_files:
        return [("Error", "<html><body><h1>Error</h1><p>No HTML files found in QRH docs directory</p></body></html>", None)]
    
    for file_path in html_files:
        # Derive title from filename
        name = file_path.stem
        # Strip leading number prefix (e.g., '01_', '1_', '001_')
        name = re.sub(r"^\d+_", "", name)
        if name.startswith("qrh_"):
            name = name[4:]
        title = name.replace("_", " ").title()
        
        try:
            html_content = file_path.read_text(encoding="utf-8")
        except Exception:
            html_content = f"<html><body><h1>Error</h1><p>Could not load {file_path.name}</p></body></html>"
        pages.append((title, html_content, file_path))
    return pages