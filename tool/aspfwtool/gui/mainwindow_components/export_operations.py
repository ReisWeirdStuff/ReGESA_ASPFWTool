# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Export operation mixin for MainWindow.

This module provides:
    - GUID catalog export to CSV
    - PSP structure export
    - AMD PEI/DXE module export
    - Named blob file writing
"""

import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, TYPE_CHECKING
from uuid import UUID

from .qt import (
    QFileDialog,
    QMessageBox,
    QStandardItem,
)
from .common import (
    UEFI_SECTION_ALIGNMENT,
    _align_up,
    _sanitize_filename,
)
from ..utils.roles import DETAIL_ROLE

if TYPE_CHECKING:
    from .models import LoadedImage

# File types for module export
_PEI_FILE_TYPES = {0x04, 0x06, 0x08}
_DXE_FILE_TYPES = {0x05, 0x07, 0x09, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F}


class ExportOperationsMixin:
    """
    Mixin class providing export functionality.
    
    Requires the host class to have:
    - loaded_images list
    - maintenance_mode attribute
    - uefi_tab_controller
    - psp_tab_controller
    - _append_console() method
    - _status_message() method
    - _rebuild_from_loaded_images() method
    - _interpret_uefi_file_blob() method
    """

    def _export_guid_catalog(self) -> None:
        """Export GUID catalog via UEFI tab controller."""
        self.uefi_tab_controller.export_guid_catalog()

    def _export_psp_structure(self) -> None:
        """Export PSP structure via PSP tab controller."""
        self.psp_tab_controller.export_structure()

    def _export_amd_modules(self) -> None:
        """Export AMD PEI/DXE modules from loaded images."""
        if not self.maintenance_mode:
            return

        images = [img for img in self.loaded_images if img.uefi_roots]
        if not images:
            QMessageBox.information(
                self,
                "No UEFI data",
                "Load a firmware image with UEFI parsing enabled before exporting.",
            )
            return

        target_dir = QFileDialog.getExistingDirectory(
            self, "Select export directory", str(Path.cwd())
        )
        if not target_dir:
            return

        # Load tracking.json to get whitelist of GUIDs to export
        tracking_path = Path(__file__).parent.parent.parent / "updatable" / "tracking.json"
        guid_whitelist: set = set()
        if tracking_path.exists():
            try:
                with tracking_path.open("r", encoding="utf-8") as f:
                    tracking = json.load(f)
                    for guid in tracking.get("uefi_guids", []):
                        guid_whitelist.add(str(guid).upper())
            except Exception:
                pass

        export_root = Path(target_dir)
        exported = 0
        failures: List[str] = []
        for image in images:
            for name, blob in self._collect_amd_module_exports(image, guid_whitelist):
                try:
                    self._write_named_blob(export_root, name, blob)
                except Exception as exc:
                    failures.append(str(exc))
                    self._append_console(f"AMD module export failed for {name}: {exc}")
                else:
                    exported += 1

        if exported == 0:
            QMessageBox.information(
                self,
                "No AMD modules",
                "No AMD PEI/DXE modules were discovered in the loaded images.",
            )
            return

        message = f"Exported {exported} AMD module{'s' if exported != 1 else ''} -> {export_root}"
        if failures:
            message += f" (failed: {len(failures)})"
        self._status_message(message)
        if failures:
            QMessageBox.warning(
                self,
                "Export completed with errors",
                "Some modules could not be written. Check logs for details.",
            )

    def _collect_amd_module_exports(
        self, image: "LoadedImage", guid_whitelist: set = None
    ) -> Iterable[tuple[str, bytes]]:
        """Collect AMD module exports from an image."""
        if guid_whitelist is None:
            guid_whitelist = set()
        for root in image.uefi_roots:
            for firmware_file in self._iter_uefi_files(root.volumes):
                export_data = self._prepare_module_export(image, firmware_file, guid_whitelist)
                if export_data is not None:
                    yield export_data

    def _iter_uefi_files(self, volumes: Sequence) -> Iterable:
        """Iterate over all UEFI files in volumes."""
        for volume in volumes:
            for firmware_file in volume.files:
                yield firmware_file
                yield from self._iter_section_descendants(
                    firmware_file.sections
                )

    def _iter_section_descendants(self, sections: Sequence) -> Iterable:
        """Recursively iterate through section descendants."""
        for section in sections:
            if section.volumes:
                yield from self._iter_uefi_files(section.volumes)
            if section.sections:
                yield from self._iter_section_descendants(section.sections)

    def _prepare_module_export(
        self, image: "LoadedImage", firmware_file, guid_whitelist: set = None
    ) -> Optional[tuple[str, bytes]]:
        """Prepare a module for export."""
        from ...uefi import lookup_guid_name
        
        if guid_whitelist is None:
            guid_whitelist = set()
        
        info = firmware_file.info
        extension = self._module_extension(info.type)
        if not extension:
            return None
        
        # Filter by GUID whitelist from tracking.json
        guid_str = str(info.guid).upper() if info.guid else ""
        if guid_whitelist and guid_str not in guid_whitelist:
            return None
        
        name = lookup_guid_name(info.guid)
        if not name:
            # Use GUID as fallback if no decoded name
            name = guid_str or "unknown"
        
        blob = self._extract_module_blob(image, info)
        if not blob:
            return None
        filename = self._module_filename(name, extension)
        return filename, blob

    def _module_extension(self, file_type: Optional[int]) -> Optional[str]:
        """Get file extension for module type."""
        if file_type is None:
            return None
        value = int(file_type)
        if value in _PEI_FILE_TYPES:
            return ".pei"
        if value in _DXE_FILE_TYPES:
            return ".dxe"
        return None

    def _module_filename(self, name: str, extension: str) -> str:
        """Generate filename for module export."""
        sanitized = _sanitize_filename(name, "module") or "module"
        if not extension.startswith("."):
            extension = f".{extension}"
        return f"{sanitized}{extension.lower()}"

    def _extract_module_blob(self, image: "LoadedImage", info) -> Optional[bytes]:
        """Extract module blob from firmware file info."""
        offset = info.absolute_offset
        size = info.size
        raw_blob = getattr(info, "raw_data", None)
        blob: Optional[bytes] = None
        if offset is None or size is None or size <= 0:
            if raw_blob is None:
                return None
            blob = raw_blob
        else:
            try:
                start = int(offset)
                length = int(size)
            except Exception:
                return None
            if start < 0 or length <= 0:
                return None
            end = min(len(image.data), start + length)
            if end <= start:
                return None
            blob = bytes(image.data[start:end])
        payload, _ = self._interpret_uefi_file_blob(blob)
        pe_image = self._extract_pe_image_from_sections(payload)
        return pe_image or payload

    def _extract_pe_image_from_sections(self, payload: bytes) -> Optional[bytes]:
        """Extract PE image from UEFI sections."""
        from ...uefi import (
            EFI_SECTION_COMPRESSION,
            decompress_compression_section,
        )
        from ...uefi.ffs import EFI_SECTION_PE32, EFI_SECTION_TE
        
        cursor = 0
        total = len(payload)
        while cursor + 4 <= total:
            size = int.from_bytes(payload[cursor : cursor + 3], "little")
            section_type = payload[cursor + 3]
            header_len = 4
            if size == 0xFFFFFF:
                if cursor + 12 > total:
                    break
                size = int.from_bytes(payload[cursor + 4 : cursor + 12], "little")
                header_len = 12
            end = cursor + size
            if size < header_len or end > total:
                break
            body = payload[cursor + header_len : end]
            if section_type in (EFI_SECTION_PE32, EFI_SECTION_TE):
                return bytes(body)
            if section_type == EFI_SECTION_COMPRESSION:
                try:
                    decompressed, _ctype, _ulen, _hdr = decompress_compression_section(
                        payload[cursor:end]
                    )
                except Exception:
                    decompressed = None
                if decompressed:
                    nested = self._extract_pe_image_from_sections(decompressed)
                    if nested:
                        return nested
            cursor = _align_up(end, UEFI_SECTION_ALIGNMENT)
        return None

    def _write_named_blob(self, base_dir: Path, name: str, data: bytes) -> Path:
        """Write blob to file with collision handling."""
        base_dir.mkdir(parents=True, exist_ok=True)
        target = base_dir / name
        if target.exists():
            stem = target.stem
            suffix = target.suffix
            counter = 2
            while target.exists():
                target = base_dir / f"{stem}_{counter}{suffix}"
                counter += 1
        target.write_bytes(data)
        return target

    def _load_guid_csv(self) -> None:
        """Load GUID mappings from CSV file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load GUID CSV",
            str(Path.cwd()),
            "CSV Files (*.csv);;All Files (*)",
        )
        if not file_path:
            return
        try:
            added = self._import_guid_csv(Path(file_path))
        except Exception as exc:
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        if added == 0:
            QMessageBox.information(
                self,
                "GUID import",
                "No new GUID entries were added.",
            )
        else:
            QMessageBox.information(
                self,
                "GUID import",
                f"Added {added} GUID entr{'y' if added == 1 else 'ies'}.",
            )
            try:
                self._rebuild_from_loaded_images()
            except Exception as exc:
                self._status_message(f"Rebuilding views after GUID import failed: {exc}")

    def _import_guid_csv(self, csv_path: Path) -> int:
        """Import GUID mappings from CSV file."""
        from ...uefi import GUID_NAME_MAP
        
        # Path to GUID data JSON
        _GUID_DATA_PATH = (
            Path(__file__).resolve().parent.parent.parent / "updatable" / "guid_names.json"
        )
        
        entries: list[tuple[str, str]] = []

        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            for row_number, row in enumerate(reader, 1):
                if not row:
                    continue
                guid_text = row[0].strip().strip("{}")
                if not guid_text:
                    raise ValueError(f"Row {row_number}: missing GUID value")
                try:
                    guid_value = UUID(guid_text)
                except ValueError as exc:
                    raise ValueError(f"Row {row_number}: invalid GUID '{guid_text}'") from exc

                if len(row) < 2:
                    raise ValueError(f"Row {row_number}: missing GUID name")
                name = row[1].strip()
                if not name:
                    raise ValueError(f"Row {row_number}: empty GUID name")

                normalized_guid = str(guid_value).upper()
                entries.append((normalized_guid, name))

        if not entries:
            return 0

        existing_guids: set[str] = {str(key).upper() for key in GUID_NAME_MAP}
        pending: set[str] = set()

        appended: List[Tuple[str, str]] = []
        for guid_upper, name in entries:
            if guid_upper in existing_guids or guid_upper in pending:
                continue
            pending.add(guid_upper)
            appended.append((guid_upper, name))

        if not appended:
            return 0

        if self.maintenance_mode:
            # Get current release version
            release_version = self._get_release_version()
            # Default empty structure with metadata
            _EMPTY_GUID_DATA = {
                "metadata": {
                    "version": release_version,
                    "description": "UEFI GUID to Name Mapping"
                },
                "guids": {}
            }
            try:
                if _GUID_DATA_PATH.exists():
                    guid_data = json.loads(_GUID_DATA_PATH.read_text(encoding="utf-8"))
                    if not isinstance(guid_data, dict):
                        guid_data = dict(_EMPTY_GUID_DATA)
                else:
                    guid_data = dict(_EMPTY_GUID_DATA)
            except (json.JSONDecodeError, OSError):
                guid_data = dict(_EMPTY_GUID_DATA)
            # Update metadata version to current release version
            if "metadata" in guid_data:
                guid_data["metadata"]["version"] = release_version
            # Support both flat format and nested format with metadata
            guid_json = guid_data.get("guids", guid_data) if isinstance(guid_data, dict) else {}
            if not isinstance(guid_json, dict):
                guid_json = {}
            for guid_text, name in appended:
                guid_json[guid_text.lower()] = name
            # If using nested format, put guids back into the structure
            if "guids" in guid_data:
                guid_data["guids"] = dict(sorted(guid_json.items()))
                output_data = guid_data
            else:
                output_data = dict(sorted(guid_json.items()))
            try:
                _GUID_DATA_PATH.write_text(
                    json.dumps(output_data, indent=2) + "\n",
                    encoding="utf-8",
                )
            except Exception as exc:
                raise RuntimeError(f"Failed to update GUID data: {exc}") from exc

        for guid_text, name in appended:
            GUID_NAME_MAP[UUID(guid_text)] = name

        return len(appended)

    def _collect_guid_map(self, image: "LoadedImage") -> Dict[object, set[Tuple[str, str]]]:
        """Collect GUID mappings from an image."""
        store: Dict[object, set[Tuple[str, str]]] = {}
        for root in image.uefi_roots:
            for volume in root.volumes:
                self.uefi_tab_controller.collect_guid_from_volume(volume, store)
        return store

    def _collect_tree_lines(
        self, item: QStandardItem, depth: int, lines: List[str]
    ) -> None:
        """Collect tree item text recursively for export."""
        indent = "  " * depth
        text = item.text()
        
        # Add visual separator for top-level items (images, directories)
        if depth == 0:
            lines.append("=" * 80)
            lines.append(f"{text}")
            lines.append("=" * 80)
        elif depth == 1:
            lines.append("")
            lines.append(f"{indent}┌─ {text}")
            lines.append(f"{indent}│")
        else:
            # Entry level - use tree characters
            lines.append(f"{indent}├─ {text}")
        
        detail = item.data(DETAIL_ROLE)
        if detail:
            detail_lines = str(detail).splitlines()
            for entry in detail_lines:
                if depth <= 1:
                    lines.append(f"{indent}│  {entry}")
                else:
                    lines.append(f"{indent}│    {entry}")
        
        child_count = item.rowCount()
        for row in range(child_count):
            child = item.child(row, 0)
            if child is not None:
                self._collect_tree_lines(child, depth + 1, lines)
        
        # Close directory sections
        if depth == 1:
            lines.append(f"{indent}└─────")
