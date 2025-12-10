# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
XML export operations for PSP/BIOS firmware structures.

This module provides:
    - XML directory descriptor generation (NewPspKit format)
    - PSPID selection dialog for multi-platform exports
    - Firmware entry export with metadata
"""

from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement, tostring

from .qt import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)
from .common import extract_entry_bytes, get_ps1_flags

from ...agesa.directory import (
    Directory,
    iter_entries,
    parse_dir_header,
    DirHeaderReal,
)
from ...agesa import constants as _constants
from ...agesa.entrytypes import lookup_entry_definition, IMAGE_ENTRY, POINT_ENTRY, VALUE_ENTRY
from ...agesa.constants import DirKind, is_combo_dir

if TYPE_CHECKING:
    from .models import LoadedImage
    from .controller import MainWindow


class PspidSelectionDialog(QDialog):
    """Dialog for selecting PSPIDs to export."""

    def __init__(self, available_pspids: Dict[int, List[str]], parent=None):
        """
        Initialize the dialog.
        
        Args:
            available_pspids: Dict mapping PSPID (int) to list of platform names
            parent: Parent widget
        """
        super().__init__(parent)
        self.setWindowTitle("Select Platforms to Export")
        self.setMinimumWidth(400)
        self.setMinimumHeight(300)

        self.selected_pspids: Set[int] = set()
        self.checkboxes: Dict[int, QCheckBox] = {}

        layout = QVBoxLayout(self)

        # Instructions
        layout.addWidget(QGroupBox("Select platforms to export:"))

        # Scrollable area for checkboxes
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)

        # Sort by platform name for display
        sorted_pspids = sorted(
            available_pspids.items(),
            key=lambda x: x[1][0] if x[1] else f"0x{x[0]:08X}"
        )

        for pspid, names in sorted_pspids:
            name_str = ", ".join(names) if names else "Unknown"
            label = f"{name_str} (0x{pspid:08X})"
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)  # Default to checked
            checkbox.stateChanged.connect(lambda state, p=pspid: self._on_checkbox_changed(p, state))
            self.checkboxes[pspid] = checkbox
            self.selected_pspids.add(pspid)
            scroll_layout.addWidget(checkbox)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

        # Select All / Deselect All buttons
        btn_layout = QVBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self._select_all)
        deselect_all_btn = QPushButton("Deselect All")
        deselect_all_btn.clicked.connect(self._deselect_all)
        btn_layout.addWidget(select_all_btn)
        btn_layout.addWidget(deselect_all_btn)
        layout.addLayout(btn_layout)

        # Dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _on_checkbox_changed(self, pspid: int, state: int) -> None:
        """Handle checkbox state change."""
        if state:
            self.selected_pspids.add(pspid)
        else:
            self.selected_pspids.discard(pspid)

    def _select_all(self) -> None:
        """Select all checkboxes."""
        for pspid, checkbox in self.checkboxes.items():
            checkbox.setChecked(True)

    def _deselect_all(self) -> None:
        """Deselect all checkboxes."""
        for pspid, checkbox in self.checkboxes.items():
            checkbox.setChecked(False)

    def get_selected_pspids(self) -> Set[int]:
        """Return the set of selected PSPIDs."""
        return self.selected_pspids.copy()


class XmlExportMixin:
    """
    Mixin class providing XML export functionality for PSP/BIOS firmware.
    
    Requires the host class to have:
    - loaded_images list
    - _append_console() method
    - _status_message() method
    - _derive_payload_export_path() method (from FileOperationsMixin)
    - _resolve_export_collision() method (from FileOperationsMixin)
    """

    def _collect_available_pspids(self: "MainWindow", images: List["LoadedImage"]) -> Dict[int, List[str]]:
        """Collect all available PSPIDs from loaded images.
        
        Sources:
        - Combo directory entries (2PSP, 2BHD): pspid field
        - ISH entries (type 0x48, 0x4A in $PSP): pspid from ISH structure
        """
        from ...agesa.utils import platform_names_for_pspid
        from ...agesa.ish import try_parse_ish_at

        pspid_map: Dict[int, List[str]] = {}

        for image in images:
            if not image.directories:
                continue

            # Collect PSPIDs from combo directory entries
            for directory in image.directories:
                if is_combo_dir(directory.kind):
                    for entry in iter_entries(image.data, directory):
                        pspid = entry.get("pspid")
                        if pspid is not None and pspid != 0:
                            if pspid not in pspid_map:
                                names = platform_names_for_pspid(pspid)
                                pspid_map[pspid] = names if names else []

                # Collect PSPIDs from ISH entries (type 0x48, 0x4A) in $PSP directories
                elif directory.kind == DirKind.PSP_L1:
                    for entry in iter_entries(image.data, directory):
                        type_id = entry.get("type_id")
                        if type_id is None:
                            continue
                        base_type = type_id & 0xFF
                        if base_type not in (0x48, 0x4A):
                            continue
                        
                        # Parse ISH at resolved offset to get PSPID
                        resolved_off = entry.get("resolved_off")
                        if resolved_off is None:
                            continue
                        
                        ish_record = try_parse_ish_at(bytes(image.data), int(resolved_off))
                        if ish_record is None:
                            continue
                        
                        pspid = getattr(ish_record, "pspid", None)
                        if pspid is not None and pspid != 0:
                            if pspid not in pspid_map:
                                names = platform_names_for_pspid(pspid)
                                pspid_map[pspid] = names if names else []

        return pspid_map

    def _get_directory_pspids(self: "MainWindow", image: "LoadedImage") -> Dict[int, Set[int]]:
        """Get mapping of directory offset to associated PSPIDs.
        
        Sources:
        - Combo directory entries point to L1 directories with PSPID association
        - ISH entries (type 0x48, 0x4A) contain PSPID and point to L2 directories
        """
        from ...agesa.ish import try_parse_ish_at

        dir_pspids: Dict[int, Set[int]] = {}

        for directory in image.directories:
            # From combo directories: resolved_off is L1 directory, pspid is from entry
            if is_combo_dir(directory.kind):
                for entry in iter_entries(image.data, directory):
                    pspid = entry.get("pspid")
                    resolved_off = entry.get("resolved_off")
                    if pspid is not None and pspid != 0 and resolved_off is not None:
                        dir_pspids.setdefault(int(resolved_off), set()).add(pspid)

            # From ISH entries in $PSP: parse ISH to get PSPID and pointed L2 directory
            elif directory.kind == DirKind.PSP_L1:
                for entry in iter_entries(image.data, directory):
                    type_id = entry.get("type_id")
                    if type_id is None:
                        continue
                    base_type = type_id & 0xFF
                    if base_type not in (0x48, 0x4A):
                        continue
                    
                    resolved_off = entry.get("resolved_off")
                    if resolved_off is None:
                        continue
                    
                    ish_record = try_parse_ish_at(bytes(image.data), int(resolved_off))
                    if ish_record is None:
                        continue
                    
                    pspid = getattr(ish_record, "pspid", None)
                    target_off = getattr(ish_record, "location_pointer", None)
                    
                    if pspid is not None and pspid != 0 and target_off is not None:
                        # Map the pointed L2 directory to this PSPID
                        dir_pspids.setdefault(int(target_off), set()).add(pspid)
                        # Also map the ISH stub location itself
                        dir_pspids.setdefault(int(resolved_off), set()).add(pspid)

        # Propagate PSPIDs from L1 to L2 directories
        # $PSP -> $PL2 via type 0x40/0x48/0x4A
        # $BHD -> $BL2 via type 0x70
        for directory in image.directories:
            parent_pspids = dir_pspids.get(directory.offset)
            if not parent_pspids:
                continue

            for entry in iter_entries(image.data, directory):
                type_id = entry.get("type_id")
                if type_id is None:
                    continue
                base_type = type_id & 0xFF

                # Check for L2 pointer types
                is_l2_pointer = (
                    (directory.kind == DirKind.PSP_L1 and base_type in (0x40, 0x48, 0x4A)) or
                    (directory.kind == DirKind.BHD_L1 and base_type == 0x70)
                )
                if is_l2_pointer:
                    resolved_off = entry.get("resolved_off")
                    if resolved_off is not None:
                        dir_pspids.setdefault(int(resolved_off), set()).update(parent_pspids)

        return dir_pspids

    def _export_firmware_xml(self: "MainWindow") -> None:
        """Export all PSP/BIOS firmware entries and generate XML descriptor."""
        images = getattr(self, "loaded_images", [])
        if not images:
            QMessageBox.information(
                self,
                "No Images",
                "Load a firmware image before exporting.",
            )
            return

        # Collect available PSPIDs
        available_pspids = self._collect_available_pspids(images)

        # Show PSPID selection dialog if there are PSPIDs to select
        selected_pspids: Optional[Set[int]] = None
        if available_pspids:
            dialog = PspidSelectionDialog(available_pspids, self)
            if dialog.exec() != QDialog.Accepted:
                return
            selected_pspids = dialog.get_selected_pspids()
            if not selected_pspids:
                QMessageBox.information(
                    self,
                    "No Selection",
                    "No platforms selected for export.",
                )
                return
        else:
            # No combo directories found - ask user if they want to proceed
            reply = QMessageBox.question(
                self,
                "No Platform Info",
                "No combo directories found in this firmware.\n"
                "All directories will be exported.\n\n"
                "Do you want to continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if reply != QMessageBox.Yes:
                return

        # Select output directory
        dest_dir = QFileDialog.getExistingDirectory(
            self,
            "Select output folder for firmware export",
            str(Path.cwd()),
        )
        if not dest_dir:
            return

        export_root = Path(dest_dir)
        total_exported = 0
        total_failures = 0

        for img_idx, image in enumerate(images):
            if not image.directories:
                continue

            # Get directory -> PSPID mapping for filtering
            dir_pspids = self._get_directory_pspids(image) if selected_pspids else {}

            # Create subfolder for each image if multiple
            if len(images) > 1:
                img_folder = export_root / f"image_{img_idx}"
            else:
                img_folder = export_root

            try:
                img_folder.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                self._append_console(f"Failed to create folder {img_folder}: {exc}")
                continue

            exported, failures, xml_content = self._export_image_firmware_xml(
                image, img_idx, img_folder, selected_pspids, dir_pspids
            )
            total_exported += exported
            total_failures += failures

            if xml_content:
                xml_path = img_folder / "PspDirectory.xml"
                try:
                    xml_path.write_text(xml_content, encoding="utf-8")
                    self._append_console(f"Generated XML: {xml_path}")
                except Exception as exc:
                    self._append_console(f"Failed to write XML: {exc}")
                    total_failures += 1

        if total_exported == 0 and total_failures == 0:
            QMessageBox.information(
                self,
                "No Data",
                "No firmware entries were found to export.",
            )
            return

        message = f"Exported {total_exported} firmware file(s)"
        if total_failures > 0:
            message += f" ({total_failures} failures)"
        message += f" to {export_root}"
        self._status_message(message)

        if total_failures > 0:
            QMessageBox.warning(
                self,
                "Export completed with errors",
                f"Exported {total_exported} files with {total_failures} failures.\n"
                "Check the console for details.",
            )
        else:
            QMessageBox.information(
                self,
                "Export Complete",
                f"Successfully exported {total_exported} firmware files.\n"
                f"XML descriptor saved to {export_root}",
            )

    def _export_image_firmware_xml(
        self: "MainWindow",
        image: "LoadedImage",
        image_index: int,
        export_folder: Path,
        selected_pspids: Optional[Set[int]] = None,
        dir_pspids: Optional[Dict[int, Set[int]]] = None,
    ) -> Tuple[int, int, Optional[str]]:
        """
        Export firmware entries from a single image and generate XML.
        
        Args:
            image: The loaded image to export from
            image_index: Index of the image
            export_folder: Folder to export files to
            selected_pspids: Set of PSPIDs to include (None = all)
            dir_pspids: Mapping of directory offsets to their associated PSPIDs
        
        Returns:
            Tuple of (exported_count, failure_count, xml_content)
        """
        exported = 0
        failures = 0

        # Determine address mode from first real directory header
        address_mode = self._detect_address_mode(image)

        # Get directory level types (A/B) from ISH entries
        level_types = self._get_directory_level_types(image)

        # Build XML structure
        root = Element("DIRS")
        root.set("AddressMode", str(address_mode))

        # Group directories by level
        dirs_by_level: Dict[int, List[Tuple[int, Directory]]] = {}
        for dir_idx, directory in enumerate(image.directories):
            level = self._get_directory_level(directory)
            dirs_by_level.setdefault(level, []).append((dir_idx, directory))

        # Track combo directories separately
        combo_dirs: List[Tuple[int, Directory]] = []

        # Process directories
        for dir_idx, directory in enumerate(image.directories):
            if _constants.is_combo_dir(directory.kind):
                combo_dirs.append((dir_idx, directory))
                continue

            # Filter by PSPID if selection was made
            if selected_pspids and dir_pspids:
                dir_associated_pspids = dir_pspids.get(directory.offset, set())
                # Skip directories not associated with any selected PSPID
                # Allow directories with no PSPID association (common/shared directories)
                if dir_associated_pspids and not dir_associated_pspids.intersection(selected_pspids):
                    continue

            # Create directory element
            dir_element, dir_exported, dir_failures = self._build_directory_xml(
                image, image_index, directory, dir_idx, export_folder, level_types
            )
            if dir_element is not None:
                root.append(dir_element)
            exported += dir_exported
            failures += dir_failures

        # Add combo directories if present
        for dir_idx, directory in combo_dirs:
            combo_element = self._build_combo_directory_xml(
                image, directory, dir_idx
            )
            if combo_element is not None:
                # Insert combo at beginning
                root.insert(0, combo_element)

        # Add ISH_HEADER elements for ISH entries (type 0x48, 0x4A)
        # ISH headers are separate XML elements, not part of entries
        # Filter by selected PSPIDs if any
        ish_headers = self._collect_ish_headers(image)
        for ish_header in ish_headers:
            # Filter ISH by PSPID if selection was made
            if selected_pspids:
                ish_pspid = ish_header.get("PspId", 0)
                if ish_pspid not in selected_pspids:
                    continue
            
            ish_element = self._build_ish_header_xml(ish_header)
            if ish_element is not None:
                root.append(ish_element)

        # Format XML with proper indentation
        xml_str = tostring(root, encoding="unicode")
        try:
            dom = minidom.parseString(xml_str)
            pretty_xml = dom.toprettyxml(indent="  ", encoding=None)
            # Remove extra blank lines and fix declaration
            lines = pretty_xml.split("\n")
            # Replace declaration with simpler one
            if lines and lines[0].startswith("<?xml"):
                lines[0] = '<?xml version="1.0" ?>'
            # Remove empty lines
            lines = [line for line in lines if line.strip()]
            xml_content = "\n".join(lines)
        except Exception:
            xml_content = f'<?xml version="1.0" ?>\n{xml_str}'

        return exported, failures, xml_content

    def _detect_address_mode(self, image: "LoadedImage") -> int:
        """Detect address mode from directory headers."""
        for directory in image.directories:
            if not is_combo_dir(directory.kind):
                try:
                    header = parse_dir_header(image.data, directory.offset, directory.kind)
                    if isinstance(header, DirHeaderReal):
                        return header.AddressMode
                except Exception:
                    pass
        return 0  # Default to mode 0

    def _get_directory_level(self, directory: Directory) -> int:
        """Get directory level (1 or 2)."""
        if directory.kind in (DirKind.PSP_L1, DirKind.BHD_L1):
            return 1
        elif directory.kind in (DirKind.PSP_L2, DirKind.BHD_L2):
            return 2
        return 0  # Combo directories

    def _get_directory_level_types(self: "MainWindow", image: "LoadedImage") -> Dict[int, str]:
        """
        Get mapping of directory offset to level type (A or B).
        
        ISH entry types determine slot:
        - Type 0x48 (PspL2ADir) -> points to L2A directory (Slot A)
        - Type 0x4A (PspL2BDir) -> points to L2B directory (Slot B)
        
        Also propagates level type to associated BIOS directories via type 0x49.
        
        Returns:
            Dict mapping directory offset to "A" or "B"
        """
        from ...agesa.ish import try_parse_ish_at

        level_types: Dict[int, str] = {}

        # First pass: get PSP L2 directory level types from ISH entries
        for directory in image.directories:
            if directory.kind != DirKind.PSP_L1:
                continue

            for entry in iter_entries(image.data, directory):
                type_id = entry.get("type_id")
                if type_id is None:
                    continue
                base_type = type_id & 0xFF
                
                # Determine level type from ISH entry type
                if base_type == 0x48:
                    level_type = "A"
                elif base_type == 0x4A:
                    level_type = "B"
                else:
                    continue

                resolved_off = entry.get("resolved_off")
                if resolved_off is None:
                    continue

                # Parse ISH to get the pointed L2 directory
                ish_record = try_parse_ish_at(bytes(image.data), int(resolved_off))
                if ish_record is None:
                    continue

                target_off = getattr(ish_record, "location_pointer", None)
                if target_off is not None:
                    level_types[int(target_off)] = level_type

        # Second pass: propagate level type to BIOS directories via type 0x49 entries
        for directory in image.directories:
            if directory.kind != DirKind.PSP_L2:
                continue
            
            # Check if this PSP L2 has a known level type
            psp_level_type = level_types.get(directory.offset)
            if not psp_level_type:
                continue

            # Look for type 0x49 (BIOS L2 pointer) entries
            for entry in iter_entries(image.data, directory):
                type_id = entry.get("type_id")
                if type_id is None:
                    continue
                base_type = type_id & 0xFF
                if base_type != 0x49:
                    continue

                resolved_off = entry.get("resolved_off")
                if resolved_off is not None:
                    level_types[int(resolved_off)] = psp_level_type

        return level_types

    def _collect_ish_headers(self: "MainWindow", image: "LoadedImage") -> List[Dict]:
        """
        Collect ISH (Image Slot Header) entries from the image.
        
        ISH entries are found as type 0x48 and 0x4A in $PSP directories.
        They contain boot priority, PSPID, and point to L2 directories.
        
        Deduplicates by Base address since multiple $PSP L1 directories
        may point to the same ISH entries.
        
        Returns:
            List of ISH header dicts with parsed fields (deduplicated by Base)
        """
        from ...agesa.ish import try_parse_ish_at

        # Use dict keyed by Base to deduplicate
        ish_by_base: Dict[int, Dict] = {}

        for directory in image.directories:
            if directory.kind != DirKind.PSP_L1:
                continue

            for entry in iter_entries(image.data, directory):
                type_id = entry.get("type_id")
                if type_id is None:
                    continue
                base_type = type_id & 0xFF
                if base_type not in (0x48, 0x4A):
                    continue

                resolved_off = entry.get("resolved_off")
                if resolved_off is None:
                    continue

                base_addr = int(resolved_off)
                
                # Skip if already collected this ISH
                if base_addr in ish_by_base:
                    continue

                ish_record = try_parse_ish_at(bytes(image.data), base_addr)
                if ish_record is None:
                    continue

                ish_dict = {
                    "Base": base_addr,
                    "BootPriority": getattr(ish_record, "boot_priority", 0),
                    "UpdateRetries": getattr(ish_record, "update_retry_count", 0),
                    "GlitchRetries": getattr(ish_record, "glitch_retry_count", 0),
                    "Location": getattr(ish_record, "location_pointer", 0),
                    "PspId": getattr(ish_record, "pspid", 0),
                    "SlotMaxSize": getattr(ish_record, "slot_max_size", 0),
                    "Reserved_1": getattr(ish_record, "reserved_1c", 0),
                }
                ish_by_base[base_addr] = ish_dict

        # Return as sorted list by Base address
        return [ish_by_base[k] for k in sorted(ish_by_base.keys())]

    def _build_ish_header_xml(self: "MainWindow", ish_dict: Dict) -> Optional[Element]:
        """
        Build XML element for an ISH_HEADER.
        <ISH_HEADER Base="0x..." BootPriority="0x..." ... />
        """
        element = Element("ISH_HEADER")
        element.set("Base", f"0x{ish_dict['Base']:X}")
        element.set("BootPriority", f"0x{ish_dict['BootPriority']:X}")
        element.set("UpdateRetries", f"0x{ish_dict['UpdateRetries']:X}")
        element.set("GlitchRetries", f"0x{ish_dict['GlitchRetries']:X}")
        element.set("Location", f"0x{ish_dict['Location']:X}")
        element.set("PspId", f"0x{ish_dict['PspId']:X}")
        element.set("SlotMaxSize", f"0x{ish_dict['SlotMaxSize']:X}")
        element.set("Reserved_1", f"0x{ish_dict['Reserved_1']:X}")
        return element

    def _build_directory_xml(
        self: "MainWindow",
        image: "LoadedImage",
        image_index: int,
        directory: Directory,
        dir_idx: int,
        export_folder: Path,
        level_types: Optional[Dict[int, str]] = None,
    ) -> Tuple[Optional[Element], int, int]:
        """
        Build XML element for a PSP or BIOS directory.
        
        Args:
            level_types: Optional dict mapping directory offsets to "A" or "B"
        
        Returns:
            Tuple of (element, exported_count, failure_count)
        """
        exported = 0
        failures = 0

        # Determine directory type and level
        is_psp = directory.kind in (DirKind.PSP_L1, DirKind.PSP_L2)
        level = self._get_directory_level(directory)
        tag_name = "PSP_DIR" if is_psp else "BIOS_DIR"

        dir_element = Element(tag_name)
        dir_element.set("Base", f"0x{directory.offset:x}")

        # Get header info for Size, SpiBlockSize, and AddressMode
        try:
            header = parse_dir_header(image.data, directory.offset, directory.kind)
            if isinstance(header, DirHeaderReal):
                # Calculate size from header info
                max_size_kb = header.MaxSize
                if max_size_kb > 0:
                    dir_element.set("Size", f"0x{max_size_kb * 0x1000:x}")  # 4KB units
                spi_block = header.SpiBlockSize
                if spi_block > 0:
                    # Version 0: direct value * 4KB; Version 1: 4KB * (1 << value)
                    if header.Version == 1:
                        spi_size = 0x1000 << spi_block  # 4KB * (1 << spi_block)
                    else:
                        spi_size = spi_block * 0x1000  # direct value * 4KB
                    dir_element.set("SpiBlockSize", f"0x{spi_size:x}")
                # AddressMode for this directory
                if header.AddressMode > 0:
                    dir_element.set("AddressMode", f"0x{header.AddressMode:x}")
        except Exception:
            pass

        # Add LevelType for L2 directories if known (A or B slot)
        if level_types and directory.offset in level_types:
            dir_element.set("LevelType", level_types[directory.offset])

        # Add Level attribute
        dir_element.set("Level", f"0x{level:x}")

        # Create subfolder for this directory
        level_type_suffix = ""
        if level_types and directory.offset in level_types:
            level_type_suffix = f"_{level_types[directory.offset]}"
        dir_folder_name = f"{directory.kind.value.replace('$', '')}_{level}{level_type_suffix}"
        dir_folder = export_folder / dir_folder_name
        try:
            dir_folder.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            self._append_console(f"Failed to create directory folder: {exc}")
            return None, 0, 1

        # Process entries
        entries = list(iter_entries(image.data, directory))
        for entry_idx, entry in enumerate(entries):
            entry_element, success = self._build_entry_xml(
                image, directory, entry, entry_idx, dir_folder
            )
            if entry_element is not None:
                dir_element.append(entry_element)
            if success:
                exported += 1
            elif entry.get("entry_kind") == IMAGE_ENTRY:
                # Only count failures for image entries
                failures += 1

        return dir_element, exported, failures

    def _build_entry_xml(
        self: "MainWindow",
        image: "LoadedImage",
        directory: Directory,
        entry: dict,
        entry_idx: int,
        dir_folder: Path,
    ) -> Tuple[Optional[Element], bool]:
        """
        Build XML element for a single entry and export its data.
        
        Returns:
            Tuple of (element, export_success)
        """
        type_id = entry.get("type_id")
        if type_id is None:
            return None, False

        base_type = type_id & 0xFF
        entry_def = lookup_entry_definition(directory.kind, type_id)
        entry_kind = entry_def.entry_type

        # Determine entry tag based on kind
        if entry_kind == VALUE_ENTRY:
            return self._build_value_entry_xml(entry, base_type), True
        elif entry_kind == POINT_ENTRY:
            return self._build_point_entry_xml(entry, base_type, directory.kind), True
        else:
            # IMAGE_ENTRY - export file and create element
            return self._build_image_entry_xml(
                image, directory, entry, entry_idx, base_type, dir_folder
            )

    def _build_value_entry_xml(self, entry: dict, base_type: int) -> Optional[Element]:
        """Build XML element for a VALUE_ENTRY."""
        elem = Element("VALUE_ENTRY")
        elem.set("Type", f"0x{base_type:X}")
        
        inline_raw = entry.get("inline_raw")
        if inline_raw is not None:
            elem.set("Value", f"0x{int(inline_raw) & 0xFFFFFFFF:02X}")
        
        return elem

    def _build_point_entry_xml(
        self, entry: dict, base_type: int, dir_kind: str
    ) -> Optional[Element]:
        """Build XML element for a POINT_ENTRY."""
        elem = Element("POINT_ENTRY")
        elem.set("Type", f"0x{base_type:X}")

        # Address from resolved offset or raw pointer
        resolved_off = entry.get("resolved_off")
        ptr64 = entry.get("ptr64")
        if resolved_off is not None:
            elem.set("Address", f"0x{int(resolved_off):x}")
        elif ptr64 is not None:
            elem.set("Address", f"0x{int(ptr64):x}")

        # Size
        size = entry.get("size")
        if size is not None and int(size) > 0:
            elem.set("Size", f"0x{int(size):x}")

        # BIOS-specific: Destination from entry object
        ent = entry.get("entry")
        destination = getattr(ent, "destination", None) if ent else None
        if destination is not None and int(destination) > 0:
            elem.set("Destination", f"0x{int(destination):x}")

        # BIOS-specific: TypeAttrib for entries with flags
        if dir_kind in (DirKind.BHD_L1, DirKind.BHD_L2):
            type_id = entry.get("type_id", 0)
            compressed = bool((type_id >> 19) & 1)
            copy_flag = bool((type_id >> 17) & 1)
            read_only = bool((type_id >> 18) & 1)
            region_type = (type_id >> 8) & 0xFF
            reset_image = bool((type_id >> 16) & 1)

            if any([compressed, copy_flag, read_only, region_type, reset_image]):
                attrib = SubElement(elem, "TypeAttrib")
                if compressed:
                    attrib.set("Compressed", "1")
                if copy_flag:
                    attrib.set("Copy", f"0x{1 if copy_flag else 0:X}")
                if read_only:
                    attrib.set("ReadOnly", f"0x{1 if read_only else 0:X}")
                if region_type:
                    attrib.set("RegionType", f"0x{region_type:X}")
                if reset_image:
                    attrib.set("ResetImage", "1")

        return elem

    def _build_image_entry_xml(
        self: "MainWindow",
        image: "LoadedImage",
        directory: Directory,
        entry: dict,
        entry_idx: int,
        base_type: int,
        dir_folder: Path,
    ) -> Tuple[Optional[Element], bool]:
        """Build XML element for an IMAGE_ENTRY and export the file."""
        from ...agesa.utils import fmt_type

        type_id = entry.get("type_id", 0)

        # Get instance and subprogram from the raw entry object
        ent = entry.get("entry")
        instance = getattr(ent, "instance", None) if ent else None
        sub_program = getattr(ent, "sub_program", None) if ent else None

        # Extract data using shared function
        data = extract_entry_bytes(image.data, entry)
        if data is None:
            return None, False

        # Build payload metadata for file_operations helpers
        offset = entry.get("resolved_off")
        
        # Determine compressed/encrypted/signed flags using shared function
        compressed_flag = bool(entry.get("compressed", False))
        ps1_compressed, encrypted_flag, signed_flag = get_ps1_flags(image.data, offset)
        if ps1_compressed:
            compressed_flag = True

        payload_meta = {
            "directory_kind": directory.kind,
            "type_id": type_id,
            "type_label": fmt_type(type_id, directory.kind, mode=True),
            "compressed": compressed_flag,
            "encrypted": encrypted_flag,
            "signed": signed_flag,
            "offset": int(offset) if offset is not None else None,
            "size": len(data),
        }

        # Use file_operations helper to derive export path
        export_path = self._derive_payload_export_path(
            dir_folder,
            payload_meta,
            include_directory_folder=False,
            payload_bytes=data,
        )

        # Modify filename to include instance/subprogram if present
        stem = export_path.stem
        suffix = export_path.suffix
        if instance is not None and int(instance) > 0:
            stem = f"{stem}_inst{int(instance)}"
        if sub_program is not None and int(sub_program) > 0:
            stem = f"{stem}_sub{int(sub_program)}"
        file_path = export_path.parent / f"{stem}{suffix}"

        # Handle filename collision using file_operations helper
        file_path = self._resolve_export_collision(file_path, payload_meta)

        # Write file
        try:
            file_path.write_bytes(data)
        except Exception as exc:
            self._append_console(f"Failed to write {file_path}: {exc}")
            return None, False

        # Build XML element
        elem = Element("IMAGE_ENTRY")
        elem.set("Type", f"0x{base_type:X}")

        # Instance attribute - include if present (even if 0x00)
        if instance is not None:
            elem.set("Instance", f"0x{int(instance):02X}")

        # SubProgram attribute - include if present and non-zero
        if sub_program is not None and int(sub_program) > 0:
            elem.set("SubProgram", f"0x{int(sub_program):X}")

        # File path (absolute)
        elem.set("File", str(file_path.resolve()))

        # Size if declared differs from actual
        declared_size = entry.get("declared_size") or entry.get("size")
        if declared_size and int(declared_size) != len(data):
            elem.set("Size", f"0x{int(declared_size):x}")

        return elem, True

    def _build_combo_directory_xml(
        self,
        image: "LoadedImage",
        directory: Directory,
        dir_idx: int,
    ) -> Optional[Element]:
        """Build XML element for a combo directory (2PSP/2BHD)."""
        elem = Element("COMBO_DIR")
        elem.set("Base", f"0x{directory.offset:08x}")
        elem.set("LookUpMode", "0")  # Default lookup mode

        # Process combo entries
        entries = list(iter_entries(image.data, directory))
        for entry in entries:
            combo_entry = SubElement(elem, "COMBO_ENTRY")
            
            id_select = entry.get("id_select", 0)
            pspid = entry.get("pspid", 0)
            resolved_off = entry.get("resolved_off", 0)

            combo_entry.set("IdSelect", f"0x{int(id_select):02X}")
            combo_entry.set("Id", f"0x{int(pspid):08X}")
            combo_entry.set("Address", f"0x{int(resolved_off):08x}")

        return elem
