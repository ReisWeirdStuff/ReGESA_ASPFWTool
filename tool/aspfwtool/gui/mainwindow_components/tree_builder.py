# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Firmware tree view construction utilities.

This module provides:
    - FirmwareTreeBuilder: Constructs PSP and UEFI tree models
    - Entry parsing and metadata extraction
    - Version decoding and display formatting
    - Key collection and display
"""

from __future__ import annotations

import copy
import os
import zlib
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from .qt import QStandardItem
from ..utils.roles import (
    DETAIL_ROLE,
    SUMMARY_ROLE,
    PAYLOAD_ROLE,
    CHAIN_ROLE,
    METADATA_ROLE,
    KEY_TABLE_ROLE,
    ENTRY_LOC_ROLE,
    OFFSET_ROLE,
    HEX_ROLE,
    PENDING_ACTION_ROLE,
)
from .common import (
    _container_get,
    _format_bytes,
    _format_dual_size,
    _format_optional_hex,
    _format_size_short,
    _mask_u64,
    _to_signed_64,
    _type_choice_table,
)
from .models import (
    BiosEntryRef,
    BiosTypeFields,
    LoadedImage,
    PspTypeFields,
    UefiRoot,
)
from ...agesa import crypto as _crypto
from ...agesa import image as image_mod
from ..tabs.psp_tab import PSP_ACTION_COLUMN, PSP_LOCATION_COLUMN

from ...agesa.directory import (
    Directory,
    dir_header_len,
    entry_span,
    iter_entries,
)
from ...agesa import constants as _constants
from ...agesa.efs import get_cached_efs_infos
from ...agesa.entrytypes import (
    VALUE_ENTRY,
    entry_type_label,
    lookup_entry_definition,
)
from ...agesa.ish import try_parse_ish_at
from ...agesa.keys import (
    KeySource,
    clear_key_sources,
    collect_key_display_records,
    dump_keyring_summary,
    extract_kdb_entries,
    preload_kdb_keys_for_directory,
)
from ...agesa.prom import parse_prom_blocks
from ...uefi import (
    EnumeratedFirmwareFile,
    EnumeratedFirmwareSection,
    EnumeratedFirmwareVolume,
    FirmwareFileInfo,
    enumerate_volumes,
    lookup_guid_name,
    scan_firmware_volumes,
)
from ...agesa.utils import fmt_type, platform_names_for_pspid
from ...agesa.metadata import decode_entry_metadata, identify_smu_platform
from ...agesa.constants import is_real_psp_dir, is_real_bios_dir
from ...agesa import agesa as _agesa
from ...agesa import ps1 as _ps1
from ...agesa import softfuse as _softfuse
from ...utils.debug_logger import get_logger


# Injected implementation from the original mainwindow module.  The class is
# intentionally kept identical aside from import adjustments so that existing
# behavior is preserved while allowing the surrounding controller to shrink.

# FFS types that may contain AGESA modules:
# 0x05=DXE_CORE, 0x06=PEIM, 0x07=DRIVER, 0x0A=MM, 0x0C=COMBINED_MM_DXE, 0x0D=MM_CORE, 0x0E=MM_STANDALONE
_AGESA_MODULE_FILE_TYPES = {0x05, 0x06, 0x07, 0x0A, 0x0C, 0x0D, 0x0E}
_HEX_PREVIEW_LIMIT = 1_048_576

# Generic EFI GUID name prefixes that should show GUID instead of name
_GENERIC_GUID_PREFIXES = (
    "EfiFirmwareFileSystem",
    "EfiFirmwareVolume",
    "EfiCrc32GuidedSectionExtraction",
    "LzmaCustomDecompress",
    "Brotli",
    "Lzma86",
)


def _is_generic_guid_name(name: str | None) -> bool:
    """Check if a GUID name is a generic EFI standard name."""
    if not name:
        return False
    return any(name.startswith(prefix) for prefix in _GENERIC_GUID_PREFIXES)


class CachedBiosEntry(NamedTuple):
    """Cached decompressed BIOS entry data and parsed volumes."""
    blob: bytes
    volumes: List["EnumeratedFirmwareVolume"]
    compressed_bios_info: dict


class FirmwareTreeBuilder:
    # Builds Qt tree items from parsed firmware structures.

    def __init__(
        self,
        *,
        discovery_mode: str = "auto",
        efs_offset: Optional[int] = None,
        include_uefi: bool = True,
    ) -> None:
        self.discovery_mode = discovery_mode
        self.efs_offset = efs_offset
        self.include_uefi = include_uefi
        self._log_callback: Optional[Callable[[str], None]] = None
        self._progress_callback: Optional[Callable[[int, int, str], None]] = None
        self._psp_column_count: Optional[int] = None
        self._uefi_column_count: Optional[int] = None
        self._pad_columns: Optional[int] = None
        self._psp_entry_cache: Dict[int, List[dict]] = {}
        self._bios_entry_cache: Dict[int, List[BiosEntryRef]] = {}  # 0x62 entries per image
        self._decompressed_bios_cache: Dict[Tuple[int, int], CachedBiosEntry] = {}  # (image_index, source_offset) -> cached data
        self._dir_child_map: Dict[Tuple[int, Optional[int]], List[int]] = {}
        self._dir_parent_map: Dict[int, Tuple[int, Optional[int]]] = {}
        self._current_directories: Optional[Sequence[Directory]] = None
        self._keys_preloaded: set[Tuple[int, int]] = set()
        self._current_image: Optional[LoadedImage] = None
        cpu_count = os.cpu_count() or 0
        self._max_worker_count = max(2, min(32, cpu_count or 2))
        self._parallel_entry_threshold = 4

    def set_progress_callback(self, callback: Optional[Callable[[int, int, str], None]]) -> None:
        """Set a progress callback function.
        
        Args:
            callback: Function(current, total, message) called during tree building.
        """
        self._progress_callback = callback

    @property
    def progress_callback(self):
        """Get the current progress callback."""
        return self._progress_callback

    @progress_callback.setter
    def progress_callback(self, callback):
        """Set the progress callback."""
        self._progress_callback = callback
        self._yield_counter = 0

    def _report_progress(self, current: int, total: int, context: dict) -> None:
        """Report progress to the callback if set.
        
        Args:
            current: Current progress count
            total: Total items to process  
            context: Dict with 'stage' and optional extra info
        """
        if self._progress_callback:
            try:
                stage = context.get("stage", "building_directories")
                self._progress_callback(stage, current, total, context)
            except Exception:
                pass

    def _yield_to_ui(self) -> None:
        """Periodically yield to UI to prevent freezing.
        
        Calls the progress callback with a 'heartbeat' stage every N calls
        to allow processEvents() to run on the main thread.
        """
        self._yield_counter = getattr(self, "_yield_counter", 0) + 1
        # Yield every 10 items to balance responsiveness vs performance
        if self._yield_counter % 10 == 0 and self._progress_callback:
            try:
                self._progress_callback("heartbeat", 0, 0, {})
            except Exception:
                pass

    def load_images(
        self,
        inputs: Sequence[Path],
        progress_callback=None,
        log_callback=None,
        max_images: Optional[int] = None,
    ) -> List[LoadedImage]:
        self._log_callback = log_callback
        expanded = image_mod.collect_inputs(inputs, None)
        if not expanded:
            raise RuntimeError(
                "No firmware images were discovered in the selected paths."
            )
        if max_images is not None and len(expanded) > max_images:
            expanded = expanded[:max_images]
            if log_callback:
                try:
                    log_callback(
                        f"Limiting to the first {max_images} input(s); extra images were skipped."
                    )
                except Exception:
                    pass
        loaded: List[LoadedImage] = []
        total = len(expanded)
        for image_index, path in enumerate(expanded):
            try:
                _crypto.keyring_clear()
            except Exception:  # pragma: no cover - defensive
                pass
            clear_key_sources()
            if progress_callback:
                try:
                    progress_callback("reading", image_index, total, path)
                except Exception:
                    pass
            try:
                bytes_data, was_capsule = image_mod._read_image_bytes_with_capsule(
                    path
                )
                if progress_callback:
                    try:
                        progress_callback("parsing", image_index, total, path)
                    except Exception:
                        pass
                image = self.process_image_bytes(
                    path, bytes_data, image_index, was_capsule=was_capsule
                )
            except Exception as exc:
                raise RuntimeError(f"Failed to process {path}: {exc}") from exc
            loaded.append(image)
            if progress_callback:
                try:
                    progress_callback("finished", image_index + 1, total, path)
                except Exception:
                    pass
        return loaded

    def process_image_bytes(
        self,
        path: Path,
        data: bytes,
        image_index: int | None = None,
        *,
        was_capsule: bool = False,
        log_callback=None,
    ) -> LoadedImage:
        logger = get_logger()
        if log_callback is None:
            log_callback = self._log_callback
        buf = bytearray(data)
        logger.info(f"Processing image: {path.name} ({len(data):,} bytes)")
        dirs = image_mod.collect_dirs(
            buf,
            self.discovery_mode,
            efs_offset=self.efs_offset,
        )
        logger.info(f"Found {len(dirs)} PSP/BIOS directories")
        efs_infos = [copy.deepcopy(info) for info in get_cached_efs_infos(buf)]
        if efs_infos:
            logger.info(f"Found {len(efs_infos)} EFS info block(s)")
        prom_infos = parse_prom_blocks(buf)
        if prom_infos:
            logger.info(f"Found {len(prom_infos)} PROM block(s)")
        uefi_roots: List[UefiRoot] = []
        if self.include_uefi:
            uefi_roots = self._collect_uefi_roots(image_index or 0, buf)
            if uefi_roots:
                logger.info(f"Found {len(uefi_roots)} UEFI firmware volume(s)")
        logger.info(f"Image processing complete: {path.name}")
        return LoadedImage(
            path=path,
            data=buf,
            directories=dirs,
            efs_infos=efs_infos,
            prom_infos=prom_infos,
            uefi_roots=uefi_roots,
            was_capsule=was_capsule,
        )

    def build_psp_rows(
        self, images: Sequence[LoadedImage]
    ) -> List[List[QStandardItem]]:
        rows: List[List[QStandardItem]] = []
        self._psp_entry_cache = {}
        self._bios_entry_cache = {}
        self._decompressed_bios_cache = {}  # Clear decompressed BIOS cache per build
        self._keys_preloaded.clear()
        previous_pad = self._pad_columns
        self._pad_columns = self._psp_column_count
        for image_index, image in enumerate(images):
            self._psp_entry_cache[image_index] = []
            self._bios_entry_cache[image_index] = []
            rows.append(self._build_image_row(image_index, image))
            image.psp_entries = list(self._psp_entry_cache.get(image_index, []))
            image.bios_entry_refs = list(self._bios_entry_cache.get(image_index, []))
        self._pad_columns = previous_pad
        return rows

    def build_uefi_rows(
        self, images: Sequence[LoadedImage]
    ) -> List[List[QStandardItem]]:
        rows: List[List[QStandardItem]] = []
        previous_pad = self._pad_columns
        self._pad_columns = self._uefi_column_count
        for image_index, image in enumerate(images):
            if not image.uefi_roots:
                continue
            previous_image = self._current_image
            self._current_image = image
            try:
                rows.append(self._build_uefi_image_row(image_index, image))
            finally:
                self._current_image = previous_image
        self._pad_columns = previous_pad
        return rows

    # Helpers for item construction

    def _make_row(
        self,
        label: str,
        detail: str,
        *,
        summary: Optional[str] = None,
        extra_columns: Optional[Sequence[Optional[str]]] = None,
        payload: Optional[dict] = None,
        pad_to: Optional[int] = None,
    ) -> List[QStandardItem]:
        primary = QStandardItem(label)
        primary.setEditable(False)
        primary.setData(detail, DETAIL_ROLE)
        if summary:
            primary.setData(summary, SUMMARY_ROLE)
        if payload is not None:
            primary.setData(payload, PAYLOAD_ROLE)
        items = [primary]
        for text in extra_columns or []:
            item = QStandardItem(text or "")
            item.setEditable(False)
            items.append(item)
        target = pad_to or self._pad_columns
        if target is not None and len(items) < target:
            for _ in range(target - len(items)):
                filler = QStandardItem("")
                filler.setEditable(False)
                items.append(filler)
        return items

    def set_column_counts(
        self, psp_columns: Optional[int] = None, uefi_columns: Optional[int] = None
    ) -> None:
        self._psp_column_count = psp_columns
        self._uefi_column_count = uefi_columns

    def _format_pending_location(
        self, action: Optional[dict], current_offset: Optional[int]
    ) -> Optional[str]:
        if not isinstance(action, dict):
            return None
        kind = action.get("action")
        if kind == "replace":
            new_off = action.get("new_payload_offset")
            if new_off is None:
                return None
            old_off = action.get("original_payload_offset")
            if old_off is None:
                old_off = current_offset
            if old_off is None:
                return f"{_format_optional_hex(new_off)} (pending)"
            try:
                if int(old_off) == int(new_off):
                    return None
            except Exception:
                pass
            return f"{_format_optional_hex(old_off)} \u2192 {_format_optional_hex(new_off)}"
        if kind == "insert":
            new_off = action.get("payload_offset")
            if new_off is None:
                return None
            return f"{_format_optional_hex(new_off)} (pending)"
        return None

    def _describe_entry(
        self,
        image_index: int,
        directory_index: int,
        directory: Directory,
        info: dict,
        data: bytes,
    ) -> dict:
        logger = get_logger()
        entry_index = info.get("index")
        raw_type = info.get("type_id")
        type_label = fmt_type(raw_type, directory.kind, mode=False)
        name_only = fmt_type(raw_type, directory.kind, mode=True)
        
        # Debug log entry parsing
        type_hex = f"0x{raw_type & 0xFF:02X}" if isinstance(raw_type, int) else "?"
        logger.debug(f"  Entry {entry_index}: {type_hex} {name_only}")
        
        definition = (
            lookup_entry_definition(directory.kind, int(raw_type))
            if isinstance(raw_type, int)
            else None
        )
        entry_category = entry_type_label(info.get("entry_type"))
        label = (
            f"{entry_index:02d}: {type_label}"
            if entry_index is not None
            else type_label
        )
        inline_offset = info.get("inline_offset")
        resolved_off = info.get("resolved_off")
        size = int(info.get("size") or 0)
        declared = int(info.get("declared_size") or 0)
        ptr64 = info.get("ptr64")
        inline_raw = info.get("inline_raw")
        pointer_value = ptr64 if inline_raw is None else None
        
        # For mode 1 addresses (ARM physical), resolved_off may be incorrect.
        # Extract the correct flash offset from ptr64 low 46 bits.
        corrected_resolved_off = resolved_off
        if ptr64 is not None and inline_raw is None:
            mode = (ptr64 >> 62) & 0x3
            if mode == 1:
                # Mode 1: direct flash offset in low 46 bits
                correct_offset = ptr64 & 0x3FFFFFFFFFFF
                if 0 < correct_offset < len(data):
                    corrected_resolved_off = correct_offset
        
        resolved_for_display = (
            inline_offset if inline_offset is not None else corrected_resolved_off
        )

        # Warn if size is invalid
        if size >= 0xFFFFFFFF:
            fallback_size = declared if 0 < declared < 0xFFFFFFFF else 0
            logger.warning(
                f"Could not resolve entry size for directory {directory_index} ({directory.kind.value}) entry {label} Invalid size 0x{size:X}, using fallback size 0x{fallback_size:X}"
            )
            size = fallback_size
        
        # Warn if entry offset could not be resolved
        if resolved_off is None and inline_offset is None and ptr64 is not None:
            logger.warning(
                f"Could not resolve entry address for directory {directory_index} ({directory.kind.value}) entry {label} Invalid address pointer=0x{ptr64:X}"
            )

        entry_hash_offset = inline_offset if inline_offset is not None else corrected_resolved_off
        entry_hash_length = declared if declared > 0 else size
        agesa_module_matches: List[dict] = []

        metadata_fields: OrderedDict[str, str] = OrderedDict()
        soft_fuse_info: Optional[dict] = None
        ish_target_offset: Optional[int] = None
        ish_stub_bytes: Optional[bytes] = None
        ish_pspid: Optional[int] = None
        ish_platforms: List[str] = []
        entry_pspid: Optional[int] = None
        entry_platforms: List[str] = []
        entry = info.get("entry")
        smu_platform_info: Optional[dict] = None

        def _bool_text(value: object) -> str:
            return "yes" if bool(value) else "no"

        metadata_fields.setdefault("Directory", directory.kind)
        metadata_fields.setdefault("Directory index", str(directory_index))
        metadata_fields.setdefault(
            "Entry index", str(entry_index) if entry_index is not None else "-"
        )
        metadata_fields.setdefault("Entry category", entry_category or "-")
        metadata_fields.setdefault("Entry type", type_label)

        if (
            definition
            and definition.entry_type == VALUE_ENTRY
            and isinstance(raw_type, int)
            and (raw_type & 0xFF) == 0x0B
            and isinstance(inline_raw, int)
        ):
            chain = _softfuse.parse_soft_fuse_chain(int(inline_raw))
            entry_offset = info.get("entry_offset")
            data_offset = inline_offset
            if not isinstance(data_offset, int) and isinstance(entry_offset, int):
                data_offset = int(entry_offset) + 8
            resolved_for_display = data_offset
            pointer_value = None
            raw_value = _mask_u64(int(inline_raw))
            soft_fuse_info = {
                "label": label,
                "raw": _to_signed_64(raw_value),
                "raw_u64": raw_value,
                "chain": chain,
                "image_index": image_index,
                "directory_index": directory_index,
                "entry_index": entry_index,
                "entry_offset": info.get("entry_offset"),
            }

        pointer_low = (raw_type & 0xFF) if isinstance(raw_type, int) else None
        if not _constants.is_combo_dir(directory.kind) and pointer_low in (0x48, 0x4A):
            candidate_offset = resolved_off
            if info.get("ish_target_offset") is not None:
                try:
                    ish_target_offset = int(info.get("ish_target_offset"))
                except Exception:
                    ish_target_offset = None
            if candidate_offset is not None:
                try:
                    stub_start = int(candidate_offset)
                except Exception:
                    stub_start = None
                else:
                    stub_end = stub_start + 32
                    if 0 <= stub_start < stub_end <= len(data):
                        ish_stub_bytes = bytes(data[stub_start:stub_end])
                    record = (
                        try_parse_ish_at(data, stub_start)
                        if stub_start is not None
                        else None
                    )
                    if record is not None:
                        loc = getattr(record, "location_pointer", None)
                        try:
                            loc_int = int(loc)
                        except Exception:
                            loc_int = None
                        if loc_int is not None and 0 <= loc_int < len(data):
                            ish_target_offset = loc_int
                            pointer_value = pointer_value or loc_int
                        pspid_val = getattr(record, "pspid", None)
                        try:
                            ish_pspid = int(pspid_val)
                        except Exception:
                            ish_pspid = None
                        if ish_pspid is not None:
                            ish_platforms = platform_names_for_pspid(ish_pspid) or []
        if ish_pspid is None and info.get("ish_pspid") is not None:
            try:
                ish_pspid = int(info.get("ish_pspid"))
            except Exception:
                ish_pspid = None
        if not ish_platforms and info.get("ish_platforms"):
            raw_platforms = info.get("ish_platforms")
            if isinstance(raw_platforms, (list, tuple)):
                ish_platforms = [str(name) for name in raw_platforms]

        if (
            isinstance(raw_type, int)
            and (raw_type & 0xFF) == 0x08
            and resolved_off is not None
            and size > 0
        ):
            try:
                entry_start = int(resolved_off)
            except Exception:
                entry_start = None
            if entry_start is not None:
                entry_end = min(len(data), entry_start + int(size))
                if 0 <= entry_start < entry_end <= len(data):
                    smu_platform_info = identify_smu_platform(
                        data[entry_start:entry_end]
                    )
        if ish_target_offset is None and info.get("ish_target_offset") is not None:
            try:
                ish_target_offset = int(info.get("ish_target_offset"))
            except Exception:
                ish_target_offset = None
        if ish_stub_bytes is None and info.get("ish_stub_offset") is not None:
            try:
                stub_start = int(info.get("ish_stub_offset"))
            except Exception:
                stub_start = None
            else:
                stub_end = stub_start + 32
                if 0 <= stub_start < stub_end <= len(data):
                    ish_stub_bytes = bytes(data[stub_start:stub_end])

        detail_lines = [
            f"Directory: {directory.kind.value}",
            f"Directory index: {directory_index}",
            f"Entry index: {entry_index if entry_index is not None else '-'}",
        ]

        def _record_bitfield(label: str, value: Optional[str]) -> None:
            if not label or value is None:
                return
            text = str(value)
            metadata_fields.setdefault(label, text)
            detail_lines.append(f"{label}: {text}")

        if _constants.is_combo_dir(directory.kind):
            type_label = "Directory pointer"
            name_only = "Directory pointer"
            label = (
                f"{entry_index:02d}: {type_label}"
                if entry_index is not None
                else type_label
            )
            entry_category = "Pointer"
            detail_lines.append("Type: Directory pointer")
            detail_lines.append("Entry category: Pointer")
            detail_lines.append(f"Pointer: {_format_optional_hex(ptr64)}")
            detail_lines.append(
                f"Resolved offset: {_format_optional_hex(resolved_off)}"
            )
            detail_lines.append(f"Resolution mode: {info.get('mode', '-')}")
            pspid_value = _container_get(entry, "pspid")
            if pspid_value is None:
                pspid_value = info.get("pspid")
            label_prefix = (
                f"{entry_index:02d}: " if entry_index is not None else ""
            )
            if isinstance(pspid_value, int):
                platforms = platform_names_for_pspid(pspid_value) or []
                if platforms:
                    name_only = (
                        f"{', '.join(platforms)} (0x{pspid_value:08X})"
                    )
                    label = (
                        f"{label_prefix}{', '.join(platforms)} "
                        f"(0x{pspid_value:08X})"
                    )
                else:
                    name_only = f"PSPID 0x{pspid_value:08X}"
                    label = f"{label_prefix}PSPID 0x{pspid_value:08X}"
        else:
            detail_lines.extend(
                [
                    f"Declared size: {_format_bytes(declared)}",
                    f"Resolved size: {_format_bytes(size)}",
                    f"Pointer: {_format_optional_hex(pointer_value)}",
                    f"Resolved offset: {_format_optional_hex(resolved_for_display)}",
                    f"Resolution mode: {info.get('mode', '-')}",
                ]
            )
        if inline_raw is not None:
            detail_lines.append(
                f"Inline data captured at {_format_optional_hex(resolved_for_display)}"
            )
        if ish_pspid is not None:
            detail_lines.append(f"PSPID: 0x{ish_pspid:08X}")
            if ish_platforms:
                detail_lines.append(f"Platform names: {', '.join(ish_platforms)}")
            entry_pspid = ish_pspid
            entry_platforms = list(ish_platforms)
        if ish_target_offset is not None:
            detail_lines.append(
                f"Pointed directory: {_format_optional_hex(ish_target_offset)}"
            )
        if pointer_low in (0x48, 0x4A) and resolved_off is not None:
            metadata_fields["ISH offset"] = _format_optional_hex(resolved_off)
        if ish_target_offset is not None:
            metadata_fields.setdefault(
                "Pointed address", f"0x{int(ish_target_offset):X}"
            )
        if ish_pspid is not None:
            metadata_fields.setdefault("PSPID", f"0x{ish_pspid:08X}")
            if ish_platforms:
                metadata_fields.setdefault("Platform", ", ".join(ish_platforms))

        if _constants.is_combo_dir(directory.kind):
            pspid = _container_get(entry, "pspid")
            if pspid is None:
                pspid = info.get("pspid")
            if isinstance(pspid, int):
                detail_lines.append(f"PSPID: 0x{pspid:08X}")
                names = platform_names_for_pspid(pspid)
                if names:
                    detail_lines.append(f"Platform names: {', '.join(names)}")
                entry_pspid = int(pspid)
                if names:
                    entry_platforms = list(names)
        else:
            pass  # Type value already shown in metadata_fields
            # Show destination address for BHD/BL2 entries
            # EntryBHD has a single 64-bit destination field
            dest_full = _container_get(entry, "destination")
            if isinstance(dest_full, int):
                detail_lines.append(f"Destination: 0x{dest_full:016X}")
                # For BIOS firmware entries (0x62), calculate x86 reset vector address
                # On AMD Secured platforms, the PSP loads BIOS to 'destination' and
                # the x86 reset vector is at (destination + size - 0x10)
                if isinstance(raw_type, int) and (raw_type & 0xFF) == 0x62 and size:
                    reset_vector_addr = dest_full + size - 0x10
                    detail_lines.append(f"x86 Reset Vector: 0x{reset_vector_addr:X}")

        type_value_text = "-"
        if isinstance(raw_type, int):
            type_value_text = f"0x{int(raw_type) & 0xFFFFFFFF:08X}"
        if isinstance(raw_type, int):
            metadata_fields.setdefault("Type value", type_value_text)
            if is_real_psp_dir(directory.kind):
                psp_fields = PspTypeFields.from_value(raw_type)
                sub_text = f"0x{psp_fields.subprogram:02X} ({psp_fields.subprogram})"
                _record_bitfield("SubProgram", sub_text)
                _record_bitfield("SPI ROM ID", str(psp_fields.rom_id))
                _record_bitfield("Writable", _bool_text(psp_fields.writable))
                _record_bitfield("Instance", str(psp_fields.instance))
            elif is_real_bios_dir(directory.kind):
                bios_fields = BiosTypeFields.from_value(raw_type)
                _record_bitfield("Region type", f"0x{bios_fields.region_type:02X}")
                _record_bitfield("Reset image", _bool_text(bios_fields.reset_image))
                _record_bitfield("Copy image", _bool_text(bios_fields.copy_image))
                _record_bitfield("Read-only", _bool_text(bios_fields.read_only))
                _record_bitfield(
                    "Compressed flag", _bool_text(bios_fields.compressed)
                )
                _record_bitfield("Instance", str(bios_fields.instance))
                _record_bitfield(
                    "SubProgram", f"0x{bios_fields.subprogram:X}"
                )
                _record_bitfield("ROM ID", str(bios_fields.rom_id))
                _record_bitfield("Writable", _bool_text(bios_fields.writable))

        if not entry_platforms and metadata_fields.get("Platform"):
            entry_platforms = [
                part.strip()
                for part in str(metadata_fields["Platform"]).split(",")
                if part.strip()
            ]

        tooltip = ""
        if isinstance(raw_type, int):
            table = _type_choice_table(directory.kind)
            type_meta = table.get(raw_type & 0xFF)
            if type_meta and len(type_meta) > 3:
                tooltip = type_meta[3]
        if not tooltip and definition:
            tooltip = definition.description if definition else ""

        metadata_tokens: List[str] = []

        if smu_platform_info:
            platform_label = smu_platform_info.get("name") or "SMU"
            description = smu_platform_info.get("description")
            if description:
                platform_label = f"{platform_label} ({description})"
            metadata_fields.setdefault("SMU Platform", platform_label)

        entry_digest = self._hash_image_range(
            data, entry_hash_offset, entry_hash_length
        )
        if entry_digest:
            metadata_fields.setdefault("Payload SHA256", entry_digest)

        # Get parent directory index for key scoping
        # L2 directories can use keys from their L1 parent (but not combo parents)
        parent_info = self._dir_parent_map.get(directory_index)
        parent_directory_index: Optional[int] = None
        if parent_info is not None:
            parent_idx = parent_info[0]
            # Only use parent if it's not a combo directory
            if self._current_directories and parent_idx < len(self._current_directories):
                parent_dir = self._current_directories[parent_idx]
                if not _constants.is_combo_dir(parent_dir.kind):
                    parent_directory_index = parent_idx

        tokens, version_fields = self._extract_version_metadata(
            data,
            directory,
            raw_type,
            resolved_off,
            size,
            declared,
            directory_index,
            entry_index,
            parent_directory_index,
        )
        metadata_tokens.extend(tokens)
        for key, value in version_fields.items():
            if key not in metadata_fields:
                metadata_fields[key] = value

        # Add SMU platform name after version metadata
        if smu_platform_info:
            smu_name = smu_platform_info.get("name")
            if smu_name:
                metadata_tokens.append(smu_name)

        if entry_digest:
            self._annotate_agesa_entry(
                metadata_fields, metadata_tokens, entry_digest, name_only
            )

        if (
            is_real_bios_dir(directory.kind)
            and isinstance(raw_type, int)
            and (raw_type & 0xFF) == 0x62
        ):
            # Check reset_image flag and add to metadata
            bios_fields = BiosTypeFields.from_value(raw_type)
            if bios_fields.reset_image:
                metadata_tokens.append("Reset Image")
            
            declared_for_modules = entry_hash_length or declared or size
            agesa_module_matches = self._collect_agesa_modules_from_bios(
                image_index, data, resolved_off, declared_for_modules,
                directory_index, info
            )
            if agesa_module_matches:
                metadata_fields.setdefault(
                    "AGESA Modules",
                    "; ".join(
                        self._format_agesa_module(match)
                        for match in agesa_module_matches
                    ),
                )
                metadata_tokens.append(
                    f"AGESA modules={len(agesa_module_matches)}"
                )

        payload: Optional[dict] = None
        payload_offset = (
            resolved_for_display if resolved_for_display is not None else resolved_off
        )
        payload_size = size
        if ish_stub_bytes and resolved_off is not None:
            payload_offset = resolved_off
            payload_size = len(ish_stub_bytes)
        ps1_header = None
        if (
            payload_offset is not None
            and payload_size >= _ps1.PS1_HEADER_LEN
            and 0 <= int(payload_offset) <= len(data) - _ps1.PS1_HEADER_LEN
            and data[int(payload_offset) + 0x10 : int(payload_offset) + 0x14] == b"$PS1"
        ):
            ps1_header = _ps1.parse_ps1_header(data, int(payload_offset))

        compression_mode_value = info.get("compression_mode")
        compression_mode: Optional[str] = None
        compressed_flag = bool(info.get("compressed") or compression_mode_value)
        encrypted_flag = False
        signed_flag = False
        if compression_mode_value:
            compression_mode = str(compression_mode_value)
            compressed_flag = True
        if ps1_header is not None:
            if ps1_header.is_compressed:
                compressed_flag = True
                compression_mode = "ps1"
            else:
                if compression_mode == "ps1":
                    compression_mode = None
                if compression_mode_value is None and not info.get("compressed"):
                    compressed_flag = False
            # Check encrypted and signed status from PS1 header
            if ps1_header.is_encrypted:
                encrypted_flag = True
            if ps1_header.signature_length > 0:
                signed_flag = True

        def _is_compressed_token(value: object) -> bool:
            return isinstance(value, str) and value.lower().startswith("compressed")

        if compressed_flag:
            metadata_fields.setdefault("Compression", "Compressed")
            if not any(_is_compressed_token(token) for token in metadata_tokens):
                metadata_tokens.append("Compressed")
        else:
            metadata_fields.pop("Compression", None)
            metadata_tokens = [
                token
                for token in metadata_tokens
                if not _is_compressed_token(token)
            ]

        filtered_tokens: List[str] = []
        for token in metadata_tokens:
            tok = token.strip()
            if not tok:
                continue
            if tok not in filtered_tokens:
                filtered_tokens.append(tok)

        metadata_parts: List[str] = []
        if filtered_tokens:
            metadata_parts.append(", ".join(filtered_tokens))
        if ish_pspid is not None:
            if ish_platforms:
                metadata_parts.append(
                    f"PSPID 0x{ish_pspid:08X} ({', '.join(ish_platforms)})"
                )
            else:
                metadata_parts.append(f"PSPID 0x{ish_pspid:08X}")
        if ish_target_offset is not None:
            metadata_parts.append(f"Ptr 0x{int(ish_target_offset):X}")
        metadata = " | ".join(part for part in metadata_parts if part)

        key_entries: List[dict] = []
        if (
            isinstance(raw_type, int)
            and (raw_type & 0xFF) == 0x50
            and resolved_off is not None
        ):
            try:
                entries = extract_kdb_entries(
                    data,
                    int(resolved_off),
                    size or declared or None,
                )
            except Exception:
                entries = []
            for entry in entries:
                key_entries.append(
                    {
                        "key_id": entry.key_id,
                        "exponent": entry.exponent,
                        "modulus": entry.modulus,
                        "bits": entry.bits,
                    }
                )

        # For bounds checking, use declared_size if size is unreasonably large
        # (e.g., for compressed BIOS entries where size is decompressed size)
        bounds_check_size = payload_size
        if declared > 0 and declared < payload_size:
            bounds_check_size = declared
        
        # Always build a payload dict if we have an offset
        # This allows extraction to work even when size info is incomplete
        # Use declared_size as fallback if size is 0
        effective_size = payload_size if payload_size > 0 else declared
        if payload_offset is not None and effective_size > 0:
            # Determine actual extractable size - prefer declared_size for compressed entries
            actual_payload_size = bounds_check_size if bounds_check_size < payload_size and bounds_check_size > 0 else effective_size
            
            # Check bounds with the smaller size
            check_size = min(actual_payload_size, declared) if declared > 0 else actual_payload_size
            in_bounds = (
                0 <= int(payload_offset) < len(data)
                and int(payload_offset) + check_size <= len(data)
            )
            
            # If bounds check fails, try checking if offset is at least valid
            if not in_bounds:
                # Maybe declared_size is wrong - check if we can extract at least something
                available = len(data) - int(payload_offset) if int(payload_offset) < len(data) else 0
                if available > 0:
                    actual_payload_size = min(actual_payload_size, available)
                    in_bounds = True
            
            # Build payload if we have valid offset (extraction may still work)
            if in_bounds or 0 <= int(payload_offset) < len(data):
                # Use the size we can actually extract
                if not in_bounds:
                    available = len(data) - int(payload_offset)
                    actual_payload_size = min(actual_payload_size, available) if available > 0 else 0
                
                payload = {
                    "image_index": image_index,
                    "directory_index": directory_index,
                    "offset": int(payload_offset),
                    "size": int(actual_payload_size) if actual_payload_size > 0 else int(declared) if declared > 0 else int(payload_size),
                    "label": label,
                    "directory": directory.kind,
                    "entry_index": entry_index,
                    "compressed": compressed_flag,
                    "compression_mode": compression_mode,
                    "encrypted": encrypted_flag,
                    "signed": signed_flag,
                    "declared_size": int(declared) if declared else 0,
                    "decompressed_size": int(payload_size) if compressed_flag else 0,
                }
                if ish_stub_bytes and pointer_low in (0x48, 0x4A):
                    payload["ish_stub"] = True
                if isinstance(raw_type, int):
                    payload["type_id"] = int(raw_type) & 0xFF
                payload["type_label"] = name_only
                payload["directory_kind"] = directory.kind
                if entry_pspid is not None:
                    payload["pspid"] = int(entry_pspid)
                if entry_platforms:
                    payload["platform_names"] = list(dict.fromkeys(entry_platforms))

        # Compression info is already in metadata_fields

        size_display = _format_dual_size(size)

        display_offset = (
            resolved_for_display if inline_raw is not None else resolved_off
        )
        location_display = _format_optional_hex(display_offset)

        return {
            "label": label,
            "name_only": name_only,
            "detail_lines": detail_lines,
            "size_display": size_display,
            "metadata": metadata,
            "payload": payload,
            "resolved_off": display_offset,
            "location_value": display_offset,
            "location_display": location_display,
            "size": size,
            "tooltip": tooltip,
            "soft_fuse_chain": soft_fuse_info,
            "metadata_fields": metadata_fields,
            "key_entries": key_entries,
            "entry_locator": {
                "image_index": image_index,
                "directory_index": directory_index,
                "entry_index": entry_index,
            },
            "ish_target_offset": ish_target_offset,
            "ish_stub_bytes": ish_stub_bytes,
        }

    def _snapshot_entry_metadata(
        self, directory: Directory, info: dict
    ) -> Dict[str, int]:
        snapshot: Dict[str, int] = {}

        def _store(key: str, value) -> None:
            try:
                if value is None:
                    return
                snapshot[key] = int(value)
            except Exception:
                return

        _store("index", info.get("index"))
        _store("entry_offset", info.get("entry_offset"))
        _store("type_value", info.get("type_id"))
        _store("declared_size", info.get("declared_size"))
        _store("pointer_value", info.get("ptr64"))
        if _constants.is_combo_dir(directory.kind):
            _store("combo_pspid", info.get("pspid"))
            _store("combo_pointer", info.get("ptr64"))
        return snapshot

    def _hash_image_range(
        self, data: bytes, offset: Optional[int], length: Optional[int]
    ) -> Optional[str]:
        if offset is None or length is None:
            return None
        return _agesa.hash_buffer_slice(data, offset, length)

    def _annotate_agesa_entry(
        self,
        metadata_fields: OrderedDict[str, str],
        metadata_tokens: List[str],
        digest: str,
        entry_label: str,
    ) -> None:
        record = _agesa.lookup_entry(digest)
        if not record:
            return
        version = _agesa.extract_version(record)
        if version:
            metadata_fields.setdefault("AGESA Version", version)
            #metadata_tokens.append(f"AGESA={version}")
            metadata_tokens.append(f" {version}")
        entry_name = (
            record.get("name")
            or record.get("type_name")
            or entry_label
            or "PSP entry"
        )
        metadata_fields.setdefault("AGESA Entry", str(entry_name))
        notes = record.get("notes")
        if notes:
            metadata_fields.setdefault("AGESA Notes", str(notes))

    def _iter_section_files_for_modules(
        self, sections: Sequence[EnumeratedFirmwareSection]
    ) -> Iterable[EnumeratedFirmwareFile]:
        for section in sections:
            for nested_volume in section.volumes:
                yield from self._iter_enumerated_files([nested_volume])
            yield from self._iter_section_files_for_modules(section.sections)

    def _iter_enumerated_files(
        self, volumes: Sequence[EnumeratedFirmwareVolume]
    ) -> Iterable[EnumeratedFirmwareFile]:
        for volume in volumes:
            for firmware_file in volume.files:
                yield firmware_file
                yield from self._iter_section_files_for_modules(
                    firmware_file.sections
                )

    def _hash_blob_slice(
        self, blob: bytes, offset: Optional[int], size: Optional[int]
    ) -> Optional[str]:
        if offset is None or size is None:
            return None
        return _agesa.hash_buffer_slice(blob, offset, size)

    def _collect_agesa_modules_from_bios(
        self,
        image_index: int,
        data: bytes,
        offset: Optional[int],
        declared_size: int,
        directory_index: int,
        info: dict,
    ) -> List[dict]:
        """Collect AGESA module info from a BIOS entry using cached decompression."""
        if offset is None or declared_size <= 0:
            return []
        
        # Use cached BIOS entry to avoid redundant decompression
        cached = self._get_cached_bios_entry(
            image_index, data, int(offset), declared_size, info, directory_index
        )
        if cached is None:
            return []
        
        blob = cached.blob
        enumerated = cached.volumes
        
        matches: List[dict] = []
        seen: set[str] = set()
        for firmware_file in self._iter_enumerated_files(enumerated):
            file_info = firmware_file.info
            if file_info.type not in _AGESA_MODULE_FILE_TYPES:
                continue
            name = lookup_guid_name(file_info.guid)
            if not name or not name.lower().startswith("amd"):
                continue
            digest = self._hash_blob_slice(blob, file_info.absolute_offset, file_info.size)
            if digest is None or digest in seen:
                continue
            record = _agesa.lookup_module(digest)
            if not record:
                continue
            seen.add(digest)
            matches.append(
                {
                    "name": name,
                    "version": _agesa.extract_version(record),
                    "digest": digest,
                    "guid": str(file_info.guid),
                }
            )
        return matches

    def _format_agesa_module(self, match: dict) -> str:
        name = match.get("name") or match.get("guid") or "module"
        version = match.get("version")
        if version:
            return f"{name} ({version})"
        return str(name)

    def _lookup_agesa_module_match(
        self, info: FirmwareFileInfo
    ) -> Optional[dict]:
        if info.type not in _AGESA_MODULE_FILE_TYPES:
            return None
        name = lookup_guid_name(info.guid)
        image = self._current_image
        if image is None:
            return None
        offset = info.absolute_offset
        size = info.size
        raw_data = getattr(info, "raw_data", None)
        
        # Hash from image buffer if offset available, otherwise from raw_data
        digest = None
        if offset is not None and size is not None and size > 0:
            digest = _agesa.hash_buffer_slice(image.data, offset, size)
        elif raw_data is not None and len(raw_data) > 0:
            digest = _agesa.hash_bytes(raw_data)
        
        if digest is None:
            return None
        record = _agesa.lookup_module(digest)
        if not record:
            return None
        return {
            "name": name,
            "version": _agesa.extract_version(record),
            "digest": digest,
        }

    def _extract_version_metadata(
        self,
        data: bytes,
        directory: Directory,
        raw_type,
        resolved_off: Optional[int],
        size: int,
        declared: int,
        directory_index: int,
        entry_index: Optional[int],
        parent_directory_index: Optional[int] = None,
    ) -> Tuple[List[str], OrderedDict[str, str]]:
        if (
            resolved_off is None
            or size <= 0
            or not isinstance(raw_type, int)
            or _constants.is_combo_dir(directory.kind)
        ):
            return [], OrderedDict()

        try:
            source = KeySource(directory_index, entry_index, int(resolved_off), parent_directory_index)
        except Exception:
            source = None

        try:
            meta = decode_entry_metadata(
                data,
                directory.kind,
                int(raw_type),
                int(resolved_off),
                size,
                source=source,
                metadata_size=declared,
            )
        except Exception:
            return [], OrderedDict()

        if not meta:
            return [], OrderedDict()

        tokens: List[str] = []
        fields: OrderedDict[str, str] = OrderedDict()
        version_val: Optional[str] = None
        signature_val: Optional[str] = None
        hash_type: Optional[str] = None
        hash_status: Optional[str] = None
        compressed = False

        for token in str(meta).split(","):
            tok = token.strip()
            if not tok:
                continue
            tokens.append(tok)
            lower = tok.lower()
            if tok.startswith("Ver="):
                version_val = tok.split("=", 1)[1]
            elif lower.startswith(("verified", "unverified", "verified?")):
                signature_val = tok
            elif lower.startswith("sha"):
                if lower == "sha_na":
                    hash_type = "N/A"
                    hash_status = "N/A"
                else:
                    parts = tok.split("_", 1)
                    hash_type = parts[0].upper()
                    hash_status = parts[1].upper() if len(parts) > 1 else "OK"
            if lower.startswith("compressed"):
                compressed = True

        if version_val is not None:
            fields["Version"] = version_val
        if signature_val is not None:
            fields["Signature"] = signature_val
        if hash_type is not None:
            fields["Hash Type"] = hash_type
        if hash_status is not None:
            fields["Hash Status"] = hash_status
        if compressed:
            fields["Compression"] = "Compressed"

        return tokens, fields

    def _collect_uefi_roots(
        self,
        image_index: int,
        data: bytes,
    ) -> List[UefiRoot]:
        if not self.include_uefi:
            return []
        try:
            volumes = scan_firmware_volumes(
                data, 0, len(data), log_callback=self._log_callback
            )
        except Exception:
            return []
        if not volumes:
            return []
        enumerated, _, _ = enumerate_volumes(volumes)
        
        # Filter out volumes that are inside compressed/encrypted PSP entries
        # These are false positives from scanning binary data
        filtered = self._filter_false_positive_volumes(image_index, enumerated)
        
        detail_lines = [
            "Scanned entire image",
            f"Size: {_format_bytes(len(data))}",
            f"Firmware volumes discovered: {len(filtered)}",
        ]
        if len(enumerated) != len(filtered):
            detail_lines.append(f"Filtered out {len(enumerated) - len(filtered)} false positives inside compressed entries")
        root = UefiRoot(
            image_index=image_index,
            directory_index=-1,
            directory_kind="image",
            entry_index=None,
            entry_label="firmware image",
            offset=0,
            size=len(data),
            detail="\n".join(detail_lines),
            volumes=filtered,
        )
        return [root]
    
    def _filter_false_positive_volumes(
        self,
        image_index: int,
        volumes: List[EnumeratedFirmwareVolume],
    ) -> List[EnumeratedFirmwareVolume]:
        """Filter out UEFI volumes that are inside compressed/encrypted PSP entries."""
        entries = self._psp_entry_cache.get(image_index, [])
        if not entries:
            return volumes
        
        def is_inside_compressed_entry(vol: EnumeratedFirmwareVolume) -> bool:
            offset = vol.info.absolute_offset
            size = vol.info.size
            if offset is None or size <= 0:
                return False
            end = int(offset) + int(size)
            for record in entries:
                if not record.get("compressed"):
                    continue
                entry_off = record.get("offset")
                entry_size = record.get("size") or 0
                if entry_off is None or entry_size <= 0:
                    continue
                entry_end = int(entry_off) + int(entry_size)
                # If volume is fully inside compressed entry, it's a false positive
                if int(entry_off) <= int(offset) and end <= entry_end:
                    return True
            return False
        
        return [v for v in volumes if not is_inside_compressed_entry(v)]

    def _find_bios_entry_refs_for_offset(
        self,
        image_index: int,
        offset: Optional[int],
        size: int,
    ) -> List[BiosEntryRef]:
        """Find all 0x62 BIOS entries that overlap with the given offset range.
        
        Returns list of BiosEntryRef for all entries whose region overlaps this offset.
        Uses overlap detection - volumes may start slightly before the 0x62 source offset
        due to headers, so we check for any significant overlap.
        """
        if offset is None or size <= 0:
            return []
        refs = self._bios_entry_cache.get(image_index, [])
        if not refs:
            return []
        vol_start = int(offset)
        vol_end = vol_start + int(size)
        matching: List[BiosEntryRef] = []
        for ref in refs:
            ref_start = ref.source_offset
            ref_end = ref_start + ref.size
            # Check for overlap: volume overlaps with BIOS entry region
            # Allow some tolerance - volumes may start slightly before 0x62 source offset
            overlap_start = max(vol_start, ref_start)
            overlap_end = min(vol_end, ref_end)
            overlap_size = overlap_end - overlap_start
            # Consider it a match if there's significant overlap (at least 50% of volume or ref)
            if overlap_size > 0:
                vol_overlap_ratio = overlap_size / size if size > 0 else 0
                ref_overlap_ratio = overlap_size / ref.size if ref.size > 0 else 0
                if vol_overlap_ratio >= 0.5 or ref_overlap_ratio >= 0.5:
                    matching.append(ref)
        return matching

    def _build_image_row(
        self, image_index: int, image: LoadedImage
    ) -> List[QStandardItem]:
        path = image.path
        detail_lines = [
            f"Input: {path}",
            f"Discovery mode: {self.discovery_mode.upper()}",
            f"EFS offset: {f'0x{int(self.efs_offset):X}' if self.efs_offset is not None else 'auto'}",
            f"Include UEFI parsing: {'yes' if self.include_uefi else 'no'}",
            f"Decoded image size: {_format_bytes(len(image.data))}",
            f"Discovered directories: {len(image.directories)}",
        ]
        try:
            disk_size = path.stat().st_size
            detail_lines.append(f"On-disk size: {_format_bytes(disk_size)}")
        except OSError:
            pass
        row = self._make_row(
            f"{path.name} ({len(image.directories)} directories)",
            "\n".join(detail_lines),
            summary=f"{path.name}: {len(image.directories)} directories",
            extra_columns=[
                "",
                _format_size_short(len(image.data)),
                "",
                str(path),
            ],
            payload={"image_index": image_index},
        )
        primary = row[0]
        directories = image.directories
        self._current_directories = directories
        offset_to_index = {d.offset: idx for idx, d in enumerate(directories)}
        self._dir_child_map = {}
        self._dir_parent_map = {}
        self._keys_preloaded = set()
        previous_image = self._current_image
        self._current_image = image
        try:
            _crypto.keyring_clear()
        except Exception:
            pass
        clear_key_sources()
        for parent_index, directory in enumerate(directories):
            self._yield_to_ui()  # Prevent UI freeze during directory scanning
            for entry in iter_entries(image.data, directory):
                child_off = entry.get("resolved_off")
                if child_off is None:
                    continue
                try:
                    target_off = int(child_off)
                except Exception:
                    continue
                pointer_targets = [target_off]
                raw_type = entry.get("type_id")
                pointer_low = (raw_type & 0xFF) if isinstance(raw_type, int) else None
                if not _constants.is_combo_dir(directory.kind) and pointer_low in (0x48, 0x4A):
                    record = try_parse_ish_at(image.data, target_off)
                    if record is not None:
                        loc = getattr(record, "location_pointer", None)
                        try:
                            loc_int = int(loc)
                        except Exception:
                            loc_int = None
                        if loc_int is not None:
                            pointer_targets.insert(0, loc_int)
                            entry["ish_target_offset"] = loc_int
                        pspid_val = getattr(record, "pspid", None)
                        try:
                            entry["ish_pspid"] = int(pspid_val)
                        except Exception:
                            entry["ish_pspid"] = None
                        entry["ish_platforms"] = (
                            platform_names_for_pspid(entry.get("ish_pspid") or 0)
                            if entry.get("ish_pspid") is not None
                            else []
                        )
                    entry["ish_stub_offset"] = target_off
                child_index = None
                for candidate_off in pointer_targets:
                    child_index = offset_to_index.get(candidate_off)
                    if child_index is not None:
                        break
                if child_index is None:
                    for candidate_index, candidate in enumerate(directories):
                        header = dir_header_len(candidate.kind)
                        span = max(int(header), 0x10)
                        for candidate_off in pointer_targets:
                            if (
                                candidate.offset
                                <= candidate_off
                                < candidate.offset + span
                            ):
                                child_index = candidate_index
                                break
                        if child_index is not None:
                            break
                if child_index is None:
                    continue
                key = (parent_index, entry.get("index"))
                children = self._dir_child_map.setdefault(key, [])
                if child_index not in children:
                    children.append(child_index)
                self._dir_parent_map.setdefault(
                    child_index, (parent_index, entry.get("index"))
                )
        
        # Count total entries for accurate progress reporting
        total_entries = sum(d.count for d in directories)
        self._progress_total_entries = total_entries
        self._progress_processed_entries = 0
        self._progress_image_name = path.name
        
        # Preload keys from ALL directories BEFORE processing entries.
        # This ensures keys are available for signature verification regardless
        # of directory processing order.
        _logger = get_logger()
        _logger.debug(f"[tree_builder] Preloading keys from {len(directories)} directories")
        for index, directory in enumerate(directories):
            key = (image_index, index)
            if key not in self._keys_preloaded:
                try:
                    entries = list(iter_entries(image.data, directory))
                    preload_kdb_keys_for_directory(
                        image.data,
                        entries,
                        directory_index=index,
                        directory_kind=directory.kind,
                    )
                except Exception:
                    pass
                self._keys_preloaded.add(key)
        _logger.debug("[tree_builder] Key preload complete")
        
        visited_dirs: set[int] = set()
        for index, directory in enumerate(directories):
            if index in self._dir_parent_map:
                continue
            if index in visited_dirs:
                continue
            visited_dirs.add(index)
            primary.appendRow(
                self._build_directory_row(
                    image_index, index, directory, image.data, visited_dirs
                )
            )
        for index, directory in enumerate(directories):
            if index in visited_dirs:
                continue
            visited_dirs.add(index)
            primary.appendRow(
                self._build_directory_row(
                    image_index, index, directory, image.data, visited_dirs
                )
            )
        image.keyring_entries = collect_key_display_records()
        dump_keyring_summary()  # Log keyring summary for debug
        self._current_directories = None
        self._dir_child_map = {}
        self._dir_parent_map = {}
        self._current_image = previous_image
        return row

    def _build_directory_row(
        self,
        image_index: int,
        index: int,
        directory: Directory,
        data: bytes,
        visited: set[int],
    ) -> List[QStandardItem]:
        logger = get_logger()
        logger.info(
            f"Parsing directory {index}: {directory.kind.value} @ "
            f"0x{directory.offset:08X} ({directory.count} entries)"
        )
        label = (
            f"{index:02d}: {directory.kind.value} @ {_format_optional_hex(directory.offset)}"
        )
        detail_lines = [
            f"Directory index: {index}",
            f"Kind: {directory.kind.value}",
            f"Magic: {directory.magic}",
            f"Offset: {_format_optional_hex(directory.offset)}",
            f"Entries: {directory.count}",
        ]
        header_len = int(dir_header_len(directory.kind))
        entry_len = int(entry_span(directory.kind))
        table_len = header_len + entry_len * int(directory.count)
        blob: Optional[bytes] = None
        if directory.offset is not None:
            start = int(directory.offset)
            end = start + max(table_len, 0)
            if 0 <= start < end <= len(data):
                blob = bytes(data[start:end])
        blob = self._clip_hex_blob(blob)
        row = self._make_row(
            label,
            "\n".join(detail_lines),
            summary=f"{directory.kind.value} ({directory.count} entries)",
            extra_columns=[
                _format_optional_hex(directory.offset),
                str(directory.count),
                "",
                f"offset {_format_optional_hex(directory.offset)}",
            ],
            payload={
                "image_index": image_index,
                "directory_index": index,
                "directory_kind": directory.kind,
                "offset": directory.offset,
                "size": table_len,
                "label": label,
                "is_directory": True,
            },
        )
        primary = row[0]
        primary.setData(
            {
                "image_index": image_index,
                "directory_index": index,
                "entry_index": None,
            },
            ENTRY_LOC_ROLE,
        )
        if blob:
            primary.setData(blob, HEX_ROLE)
        entries = list(iter_entries(data, directory))
        key = (image_index, index)
        if key not in self._keys_preloaded:
            try:
                preload_kdb_keys_for_directory(
                    data,
                    entries,
                    directory_index=index,
                    directory_kind=directory.kind,
                )
            except Exception:
                pass
            self._keys_preloaded.add(key)
        contexts = self._describe_entries_for_directory(
            image_index, index, directory, entries, data
        )
        entry_rows: List[Tuple[Optional[int], List[QStandardItem]]] = []
        for entry, context in zip(entries, contexts):
            # Report entry-based progress
            self._progress_processed_entries = getattr(self, "_progress_processed_entries", 0) + 1
            total = getattr(self, "_progress_total_entries", 0)
            processed = self._progress_processed_entries
            image_name = getattr(self, "_progress_image_name", "")
            self._report_progress(
                processed, total,
                {"stage": "building_entries", "image": image_name, "dir_index": index, "entry_index": entry.get("index")}
            )
            entry_rows.append(
                (
                    entry.get("index") if isinstance(entry.get("index"), int) else None,
                    self._build_entry_row(
                        image_index,
                        index,
                        directory,
                        entry,
                        data,
                        visited,
                        context=context,
                    ),
                )
            )

        pending_actions = {}
        if self._current_image is not None:
            pending_actions = {
                key: value
                for key, value in getattr(
                    self._current_image, "pending_entry_actions", {}
                ).items()
                if key[0] == index
            }

        removal_actions = [
            action
            for (dir_idx, _entry_idx), action in pending_actions.items()
            if action.get("action") == "remove"
            and not action.get("is_0x62_edit")  # keep 0x62 edits attached to entry row
        ]
        removal_actions.sort(key=lambda action: action.get("entry_index", -1))
        pending_removals = list(removal_actions)

        def _append_ready_removals(before_index: Optional[int]) -> None:
            nonlocal pending_removals
            if not pending_removals:
                return
            if before_index is None:
                return
            ready: List[dict] = []
            if isinstance(before_index, int):
                threshold = int(before_index)
                remaining: List[dict] = []
                for action in pending_removals:
                    entry_idx = action.get("entry_index")
                    if isinstance(entry_idx, int) and entry_idx <= threshold:
                        ready.append(action)
                    else:
                        remaining.append(action)
                pending_removals = remaining
            else:
                ready = pending_removals
                pending_removals = []
            for action in ready:
                placeholder = self._build_removed_entry_row(
                    image_index, index, directory, action
                )
                if placeholder:
                    primary.appendRow(placeholder)

        for entry_index, row_items in entry_rows:
            _append_ready_removals(entry_index)
            primary.appendRow(row_items)

        _append_ready_removals(None)

        for action in pending_removals:
            placeholder = self._build_removed_entry_row(
                image_index, index, directory, action
            )
            if placeholder:
                primary.appendRow(placeholder)
        return row

    def _describe_entries_for_directory(
        self,
        image_index: int,
        directory_index: int,
        directory: Directory,
        entries: Sequence[dict],
        data: bytes,
    ) -> List[dict]:
        entry_list = list(entries)
        if not entry_list:
            return []
        if (
            self._max_worker_count <= 1
            or len(entry_list) < self._parallel_entry_threshold
        ):
            results = []
            for entry in entry_list:
                self._yield_to_ui()  # Prevent UI freeze
                results.append(
                    self._describe_entry(
                        image_index, directory_index, directory, entry, data
                    )
                )
            return results

        worker_count = min(self._max_worker_count, len(entry_list))

        def _worker(entry: dict) -> dict:
            return self._describe_entry(
                image_index, directory_index, directory, entry, data
            )

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            return list(executor.map(_worker, entry_list))

    def _build_entry_row(
        self,
        image_index: int,
        directory_index: int,
        directory: Directory,
        info: dict,
        data: bytes,
        visited: set[int],
        context: Optional[dict] = None,
    ) -> List[QStandardItem]:
        if context is None:
            context = self._describe_entry(
                image_index, directory_index, directory, info, data
            )
        detail = "\n".join(context["detail_lines"])
        summary = (
            f"{directory.kind.value} entry {info.get('index') if info.get('index') is not None else '?'}: "
            f"{context['name_only']}"
        )
        row = self._make_row(
            context["label"],
            detail,
            summary=summary,
            extra_columns=[
                context.get("location_display"),
                context.get("size_display"),
                "",
                context.get("metadata"),
            ],
            payload=context["payload"],
        )
        tooltip = context.get("tooltip")
        if tooltip:
            row[0].setToolTip(str(tooltip))
        payload_bytes: Optional[bytes] = None
        payload_info = context.get("payload")
        if isinstance(payload_info, dict):
            off = payload_info.get("offset")
            sz = payload_info.get("size")
            if off is not None and sz:
                try:
                    start = int(off)
                    length = int(sz)
                except Exception:
                    start = length = 0
                if 0 <= start < start + length <= len(data):
                    payload_bytes = bytes(data[start : start + length])
        if payload_bytes is None and context.get("ish_stub_bytes"):
            blob = context.get("ish_stub_bytes")
            if isinstance(blob, (bytes, bytearray)):
                payload_bytes = bytes(blob)
        if payload_bytes:
            clipped = self._clip_hex_blob(payload_bytes)
            if clipped:
                row[0].setData(clipped, HEX_ROLE)
        chain = context.get("soft_fuse_chain")
        if chain:
            row[0].setData(chain, CHAIN_ROLE)
        metadata_fields = context.get("metadata_fields")
        if metadata_fields:
            row[0].setData(metadata_fields, METADATA_ROLE)
        key_entries = context.get("key_entries")
        if key_entries:
            row[0].setData(key_entries, KEY_TABLE_ROLE)
        locator = context.get("entry_locator")
        if locator:
            row[0].setData(locator, ENTRY_LOC_ROLE)
        resolved_off = context.get("resolved_off")
        if resolved_off is not None:
            try:
                row[0].setData(int(resolved_off), OFFSET_ROLE)
            except Exception:
                pass
        # Extract compressed flag from payload if available
        payload_info = context.get("payload")
        is_compressed = payload_info.get("compressed", False) if isinstance(payload_info, dict) else False
        record = {
            "label": context["label"],
            "offset": context.get("resolved_off"),
            "size": context.get("size"),
            "directory_index": directory_index,
            "directory_kind": directory.kind,
            "entry_index": info.get("index"),
            "entry_snapshot": self._snapshot_entry_metadata(directory, info),
            "compressed": is_compressed,
        }
        if self._psp_entry_cache is not None:
            self._psp_entry_cache.setdefault(image_index, []).append(record)
        key = (directory_index, info.get("index"))
        for child_index in self._dir_child_map.get(key, []):
            if child_index in visited or self._current_directories is None:
                continue
            visited.add(child_index)
            child_directory = self._current_directories[child_index]
            row[0].appendRow(
                self._build_directory_row(
                    image_index, child_index, child_directory, data, visited
                )
            )
        extra_target = context.get("ish_target_offset")
        if extra_target is not None and self._current_directories is not None:
            try:
                extra_offset = int(extra_target)
            except Exception:
                extra_offset = None
            if extra_offset is not None:
                for idx, child_directory in enumerate(self._current_directories):
                    if int(child_directory.offset or -1) != extra_offset:
                        continue
                    if idx in visited:
                        break
                    visited.add(idx)
                    row[0].appendRow(
                        self._build_directory_row(
                            image_index, idx, child_directory, data, visited
                        )
                    )
                    break
        for volume, decompressed, compressed_bios_info in self._enumerate_entry_volumes(image_index, info, data, directory_index):
            row[0].appendRow(
                self._build_psp_volume_row(image_index, volume, decompressed, compressed_bios_info=compressed_bios_info)
            )
            # Track 0x62 BIOS entry region for cross-referencing with UEFI tab
            if compressed_bios_info and self._bios_entry_cache is not None:
                # Add to bios_entry_cache only once per unique entry (use source_offset as dedup key)
                existing_refs = self._bios_entry_cache.get(image_index, [])
                source_offset = compressed_bios_info.get("source_offset", 0)
                already_added = any(ref.source_offset == source_offset for ref in existing_refs)
                if not already_added:
                    bios_ref = BiosEntryRef(
                        directory_index=compressed_bios_info.get("directory_index", -1),
                        entry_index=compressed_bios_info.get("entry_index", -1),
                        source_offset=source_offset,
                        size=compressed_bios_info.get("decompressed_size", 0),
                        destination=compressed_bios_info.get("destination"),
                        compressed=compressed_bios_info.get("compressed_size", 0) > 0,
                    )
                    self._bios_entry_cache.setdefault(image_index, []).append(bios_ref)
        
        # Also track 0x62 entries even if no UEFI volumes were found inside
        # This helps flag UEFI volumes in the UEFI tab that fall within 0x62 regions
        raw_type = info.get("type_id")
        if isinstance(raw_type, int) and (raw_type & 0xFF) == 0x62 and self._bios_entry_cache is not None:
            resolved_off = context.get("resolved_off")
            entry_size = context.get("size") or info.get("size") or 0
            if resolved_off is not None and entry_size > 0:
                try:
                    source_off = int(resolved_off)
                except Exception:
                    source_off = 0
                if source_off > 0:
                    existing_refs = self._bios_entry_cache.get(image_index, [])
                    already_added = any(ref.source_offset == source_off for ref in existing_refs)
                    if not already_added:
                        entry_obj = info.get("entry")
                        dest = getattr(entry_obj, "destination", None) if entry_obj else None
                        is_compressed = bool(info.get("compressed"))
                        bios_ref = BiosEntryRef(
                            directory_index=directory_index,
                            entry_index=info.get("index") or -1,
                            source_offset=source_off,
                            size=int(entry_size),
                            destination=dest,
                            compressed=is_compressed,
                        )
                        self._bios_entry_cache.setdefault(image_index, []).append(bios_ref)
        
        entry_idx = info.get("index")
        raw_type = info.get("type_id")
        is_bios_entry = isinstance(raw_type, int) and (raw_type & 0xFF) == 0x62
        if (
            self._current_image is not None
            and isinstance(entry_idx, int)
            and hasattr(self._current_image, "pending_entry_actions")
        ):
            # Debug: log pending actions check for 0x62 entries
            if is_bios_entry:
                logger = get_logger()
                pending_keys = list(self._current_image.pending_entry_actions.keys())
                logger.debug(f"[tree_builder] 0x62 entry: dir={directory_index}, entry={entry_idx}, pending_keys={pending_keys}")
            
            action = self._current_image.pending_entry_actions.get(
                (directory_index, entry_idx)
            )
            if action:
                logger = get_logger()
                logger.debug(f"[tree_builder] Found pending action for ({directory_index}, {entry_idx}): is_0x62_edit={action.get('is_0x62_edit')}")
            # For regular PSP entries, skip "remove" actions (they get placeholder rows)
            # For 0x62 edits, always show the action on the entry row itself
            if isinstance(action, dict):
                is_0x62_edit = action.get("is_0x62_edit", False)
                if is_0x62_edit or action.get("action") != "remove":
                    row[0].setData(action, PENDING_ACTION_ROLE)
                    action_item = row[PSP_ACTION_COLUMN]
                    if action_item is not None:
                        action_item.setText(action.get("action_text") or "modify")
                        logger = get_logger()
                        logger.debug(f"[tree_builder] Set action text: {action.get('action_text')}")
                    location_item = (
                        row[PSP_LOCATION_COLUMN]
                        if len(row) > PSP_LOCATION_COLUMN
                        else None
                    )
                    preview = self._format_pending_location(
                        action, context.get("location_value")
                    )
                    if location_item is not None and preview:
                        location_item.setText(preview)
        return row

    def _build_removed_entry_row(
        self,
        image_index: int,
        directory_index: int,
        directory: Directory,
        action: dict,
    ) -> Optional[List[QStandardItem]]:
        if not isinstance(action, dict):
            return None
        context = action.get("context") or {}
        label = context.get("label") or (
            f"{action.get('entry_index', '-')}: <removed entry>"
        )
        detail_text = context.get("detail") or "Queued removal"
        summary = context.get("summary") or "Queued removal"
        size_display = context.get("size_display") or "-"
        metadata = context.get("metadata") or "Queued removal"
        location_display = context.get("location_display")
        if not location_display:
            fallback_offset = (
                action.get("payload_offset")
                if action.get("payload_offset") is not None
                else action.get("entry_offset")
            )
            location_display = _format_optional_hex(fallback_offset)

        row = self._make_row(
            label,
            detail_text,
            summary=summary,
            extra_columns=[location_display, size_display, "", metadata],
            payload={},
        )
        primary = row[0]
        locator = {
            "image_index": image_index,
            "directory_index": directory_index,
            "entry_index": action.get("entry_index"),
        }
        primary.setData(locator, ENTRY_LOC_ROLE)
        pending_info = dict(action)
        pending_info.setdefault("placeholder", True)
        primary.setData(pending_info, PENDING_ACTION_ROLE)
        action_item = row[PSP_ACTION_COLUMN]
        if action_item is not None:
            action_item.setText(action.get("action_text") or "Remove")
        return row

    def _enumerate_entry_volumes(
        self, image_index: int, info: dict, data: bytes, directory_index: int = -1
    ) -> List[Tuple[EnumeratedFirmwareVolume, bool, Optional[dict]]]:
        """Enumerate UEFI volumes within a PSP entry using cached decompression.
        
        Returns list of (volume, decompressed, compressed_bios_info) tuples.
        compressed_bios_info is a dict with entry metadata for compressed BIOS entries.
        """
        if not self.include_uefi:
            return []
        if info.get("inline_raw") is not None:
            return []
        offset = info.get("resolved_off")
        if offset is None:
            return []
        try:
            base_offset = int(offset)
        except Exception:
            return []
        size = int(info.get("size") or 0)
        declared = int(info.get("declared_size") or 0)
        results: List[Tuple[EnumeratedFirmwareVolume, bool, Optional[dict]]] = []
        
        # Check for BIOS entries (type 0x62) - use cache for these
        raw_type = info.get("type_id")
        is_bios_entry = isinstance(raw_type, int) and (raw_type & 0xFF) == 0x62
        
        if is_bios_entry:
            # Use cached decompression for 0x62 entries
            cached = self._get_cached_bios_entry(
                image_index, data, base_offset, declared or size, info, directory_index
            )
            if cached and cached.volumes:
                is_compressed = cached.compressed_bios_info.get("compressed_size", 0) > 0
                for volume in cached.volumes:
                    results.append((volume, is_compressed, cached.compressed_bios_info))
            return results
        
        # For non-BIOS entries, scan directly (no cache needed - rare case)
        for volume in self._scan_volumes_with_base(data, base_offset, size):
            results.append((volume, False, None))
        if results:
            return results
        if declared and declared != size:
            for volume in self._scan_volumes_with_base(data, base_offset, declared):
                results.append((volume, False, None))
        return results
    
    def _find_zlib_offset(self, data: bytes, offset: int, size: int) -> int:
        """Find the offset where zlib stream starts within a compressed BIOS blob."""
        if offset < 0 or offset + size > len(data):
            return 0x100  # Default
        blob = data[offset:offset + min(size, 0x200)]
        for start in (0x100, 0x20, 0):
            if start >= len(blob):
                continue
            # Check for zlib header (0x78 9C, 0x78 DA, etc.)
            if blob[start] == 0x78 and len(blob) > start + 1:
                if blob[start + 1] in (0x01, 0x5E, 0x9C, 0xDA):
                    return start
        return 0x100  # Default

    def _scan_volumes_with_base(
        self, buf: bytes, offset: int, size: int
    ) -> List[EnumeratedFirmwareVolume]:
        if offset < 0 or size <= 0:
            return []
        try:
            volumes = scan_firmware_volumes(
                buf, offset, size, log_callback=self._log_callback
            )
        except Exception:
            return []
        if not volumes:
            return []
        enumerated, _, _ = enumerate_volumes(volumes)
        return enumerated

    def _scan_volumes_from_blob(
        self, blob: bytes, base_offset: int
    ) -> List[EnumeratedFirmwareVolume]:
        if not blob:
            return []
        try:
            volumes = scan_firmware_volumes(
                blob, 0, len(blob), log_callback=self._log_callback
            )
        except Exception:
            return []
        if not volumes:
            return []
        enumerated, _, _ = enumerate_volumes(volumes)
        self._adjust_enumerated_offsets(enumerated, base_offset)
        return enumerated

    def _get_cached_bios_entry(
        self,
        image_index: int,
        data: bytes,
        base_offset: int,
        declared_size: int,
        info: dict,
        directory_index: int = -1,
    ) -> Optional[CachedBiosEntry]:
        """Get or create cached decompressed BIOS entry data.
        
        This caches the decompressed blob and parsed volumes to avoid
        redundant decompression and parsing for the same 0x62 entry.
        
        Args:
            image_index: Index of the current image
            data: Raw image data
            base_offset: Source offset of the BIOS entry in flash
            declared_size: Declared size of the entry (compressed size for zlib)
            info: Entry info dict with type_id, ptr64, entry_offset, index, etc.
            directory_index: Directory index for compressed_bios_info
            
        Returns:
            CachedBiosEntry with blob, volumes, and compressed_bios_info, or None
        """
        logger = get_logger()
        cache_key = (image_index, base_offset)
        
        # Return cached entry if available
        if cache_key in self._decompressed_bios_cache:
            logger.debug(f"BIOS entry cache HIT: image={image_index}, offset=0x{base_offset:X}")
            return self._decompressed_bios_cache[cache_key]
        
        # Check if this is a valid 0x62 entry
        raw_type = info.get("type_id")
        is_bios_entry = isinstance(raw_type, int) and (raw_type & 0xFF) == 0x62
        if not is_bios_entry:
            return None
        
        logger.debug(f"BIOS entry cache MISS: image={image_index}, offset=0x{base_offset:X}, entry={info.get('index')}")
        
        # Get entry metadata
        size = int(info.get("size") or 0)
        declared = int(info.get("declared_size") or declared_size)
        ptr64 = info.get("ptr64") or 0
        entry_offset = info.get("entry_offset")
        entry_obj = info.get("entry")
        destination = getattr(entry_obj, "destination", None) if entry_obj else None
        
        # Determine if compressed
        is_compressed = bool(info.get("compressed"))
        
        blob: Optional[bytes] = None
        volumes: List[EnumeratedFirmwareVolume] = []
        
        if is_compressed:
            # For compressed BIOS entries, may need to adjust offset for mode 1
            actual_offset = base_offset
            mode = (ptr64 >> 62) & 0x3
            if mode == 1:
                # Mode 1: direct flash offset in low 46 bits
                correct_offset = ptr64 & 0x3FFFFFFFFFFF
                if 0 < correct_offset < len(data):
                    actual_offset = correct_offset
            
            # Read enough data for decompression
            compressed_read_size = declared if declared > 0 else size
            if size > 0 and declared > 0:
                compressed_read_size = max(declared, 0x200)
            
            blob = self._maybe_decompress_bios_entry(data, actual_offset, compressed_read_size)
            if blob:
                # Scan volumes in decompressed blob
                try:
                    raw_volumes = scan_firmware_volumes(
                        blob, 0, len(blob), log_callback=self._log_callback
                    )
                    if raw_volumes:
                        volumes, _, _ = enumerate_volumes(raw_volumes)
                        self._adjust_enumerated_offsets(volumes, actual_offset)
                except Exception:
                    pass
                
                # Build compressed_bios_info
                actual_compressed_size = declared if declared > 0 else size
                if size > 0 and declared > 0:
                    actual_compressed_size = min(declared, size)
                
                compressed_bios_info = {
                    "directory_index": directory_index,
                    "entry_index": info.get("index"),
                    "entry_offset": entry_offset,
                    "source_offset": actual_offset,
                    "ptr64": ptr64,
                    "destination": destination,
                    "compressed_size": actual_compressed_size,
                    "decompressed_size": len(blob),
                    "zlib_offset": self._find_zlib_offset(data, actual_offset, actual_compressed_size),
                    "decompressed_blob": blob,
                }
                
                cached = CachedBiosEntry(blob, volumes, compressed_bios_info)
                self._decompressed_bios_cache[cache_key] = cached
                return cached
        else:
            # Uncompressed 0x62 entry
            actual_size = size if size > 0 else declared
            if actual_size > 0 and base_offset + actual_size <= len(data):
                blob = bytes(data[base_offset:base_offset + actual_size])
                try:
                    raw_volumes = scan_firmware_volumes(
                        data, base_offset, actual_size, log_callback=self._log_callback
                    )
                    if raw_volumes:
                        volumes, _, _ = enumerate_volumes(raw_volumes)
                except Exception:
                    pass
                
                bios_info = {
                    "directory_index": directory_index,
                    "entry_index": info.get("index"),
                    "entry_offset": entry_offset,
                    "source_offset": base_offset,
                    "ptr64": ptr64,
                    "destination": destination,
                    "compressed_size": 0,
                    "decompressed_size": actual_size,
                    "zlib_offset": 0,
                    "decompressed_blob": None,
                }
                
                cached = CachedBiosEntry(blob, volumes, bios_info)
                self._decompressed_bios_cache[cache_key] = cached
                return cached
        
        return None

    def _maybe_decompress_bios_entry(
        self, buf: bytes, offset: int, declared_size: int
    ) -> Optional[bytes]:
        if offset < 0 or offset >= len(buf):
            return None
        if declared_size <= 0:
            declared_size = len(buf) - offset
        limit = min(len(buf), offset + max(declared_size, 0))
        candidate = bytes(buf[offset:limit])
        for start in (0, 0x20, 0x100):
            if start >= len(candidate):
                continue
            chunk = candidate[start:]
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                try:
                    return zlib.decompress(chunk, wbits)
                except zlib.error:
                    continue
        return None

    def _adjust_enumerated_offsets(
        self, volumes: Sequence[EnumeratedFirmwareVolume], base_offset: int
    ) -> None:
        for volume in volumes:
            info = volume.info
            if info.absolute_offset is not None:
                info.absolute_offset = int(info.absolute_offset) + base_offset
            else:
                info.absolute_offset = base_offset + int(info.relative_offset)
            for firmware_file in volume.files:
                file_info = firmware_file.info
                if file_info.absolute_offset is not None:
                    file_info.absolute_offset = (
                        int(file_info.absolute_offset) + base_offset
                    )
                else:
                    file_info.absolute_offset = base_offset + int(
                        file_info.relative_offset
                    )
                self._adjust_section_offsets(firmware_file.sections, base_offset)

    def _adjust_section_offsets(
        self, sections: Sequence[EnumeratedFirmwareSection], base_offset: int
    ) -> None:
        for section in sections:
            info = section.info
            if info.absolute_offset is not None:
                info.absolute_offset = int(info.absolute_offset) + base_offset
            else:
                info.absolute_offset = base_offset + int(info.relative_offset)
            self._adjust_enumerated_offsets(section.volumes, base_offset)
            self._adjust_section_offsets(section.sections, base_offset)

    def _build_psp_volume_row(
        self,
        image_index: int,
        volume: EnumeratedFirmwareVolume,
        decompressed: bool,
        root_index: Optional[int] = None,
        compressed_bios_info: Optional[dict] = None,
    ) -> List[QStandardItem]:
        info = volume.info
        # Prefer FV name GUID over filesystem GUID for display
        fv_name_guid = getattr(info, "fv_name", None)
        if fv_name_guid:
            fv_name_friendly = lookup_guid_name(fv_name_guid)
            if fv_name_friendly and not _is_generic_guid_name(fv_name_friendly):
                name = fv_name_friendly
            else:
                name = str(fv_name_guid).upper()
        else:
            guid_name = lookup_guid_name(info.filesystem_guid)
            # For generic EFI names, prefer showing the GUID
            if guid_name and not _is_generic_guid_name(guid_name):
                name = guid_name
            elif info.filesystem_guid is not None:
                name = str(info.filesystem_guid).upper()
            else:
                name = f"FV #{volume.index if volume.index is not None else '?'}"
        guid_name = lookup_guid_name(info.filesystem_guid)
        guid_text = str(info.filesystem_guid).upper() if info.filesystem_guid else "-"
        if guid_name:
            guid_text = f"{guid_text} ({guid_name})"
        detail_lines = [
            f"Firmware volume index: {volume.index if volume.index is not None else '-'}",
            f"Absolute offset: {_format_optional_hex(info.absolute_offset)}",
            f"Relative offset: 0x{info.relative_offset:X}",
            f"Size: 0x{info.size:X}",
            f"Header length: 0x{info.header_length:X}",
            f"Revision: {info.revision}",
            f"Attributes: 0x{info.attributes:08X}",
            f"Filesystem GUID: {guid_text}",
            f"Used size: 0x{info.used_size:X}",
            f"Free size: 0x{info.free_size:X}",
        ]
        if fv_name_guid:
            fv_name_text = str(fv_name_guid).upper()
            friendly = lookup_guid_name(fv_name_guid)
            if friendly:
                fv_name_text = f"{fv_name_text} ({friendly})"
            detail_lines.append(f"FV name GUID: {fv_name_text}")
        # Add compressed BIOS info to detail if present
        if compressed_bios_info:
            detail_lines.append("")
            detail_lines.append("Compressed BIOS entry info:")
            detail_lines.append(f"  Source offset: 0x{compressed_bios_info.get('source_offset') or 0:X}")
            detail_lines.append(f"  Destination: 0x{compressed_bios_info.get('destination') or 0:X}")
            detail_lines.append(f"  Compressed size: 0x{compressed_bios_info.get('compressed_size') or 0:X}")
            detail_lines.append(f"  Decompressed size: 0x{compressed_bios_info.get('decompressed_size') or 0:X}")
            reset_vec = (compressed_bios_info.get('destination') or 0) + (compressed_bios_info.get('decompressed_size') or 0) - 0x10
            detail_lines.append(f"  Reset vector: 0x{reset_vec:X}")
        payload = None
        hex_blob_for_extraction: Optional[bytes] = None
        if info.absolute_offset is not None and info.size > 0:
            # For items inside decompressed BIOS, extract data from the decompressed blob
            if compressed_bios_info:
                decompressed_blob = compressed_bios_info.get("decompressed_blob")
                source_offset = compressed_bios_info.get("source_offset", 0)
                if decompressed_blob:
                    # Calculate relative offset within decompressed blob
                    rel_offset = int(info.absolute_offset) - source_offset
                    if 0 <= rel_offset < len(decompressed_blob):
                        end = min(rel_offset + int(info.size), len(decompressed_blob))
                        hex_blob_for_extraction = bytes(decompressed_blob[rel_offset:end])
            # For items in compressed BIOS, set offset=None to force using hex_blob
            # since the adjusted offset points to ROM, not the decompressed blob
            display_offset = None if compressed_bios_info else int(info.absolute_offset)
            payload = {
                "image_index": image_index,
                "offset": display_offset,
                "size": int(info.size),
                "label": f"FV_{volume.index if volume.index is not None else 'unknown'}",
                "guid": info.filesystem_guid,
                "name": name,
                "uefi_kind": "volume",
                "volume_index": volume.index,
            }
            if hex_blob_for_extraction:
                payload["hex_blob"] = hex_blob_for_extraction
            if root_index is not None:
                payload["root_index"] = root_index
            # Include compressed BIOS info in payload for edit operations (without the blob to save memory)
            if compressed_bios_info:
                cbi_copy = {k: v for k, v in compressed_bios_info.items() if k != "decompressed_blob"}
                payload["compressed_bios_info"] = cbi_copy
        metadata_parts = ["FV"]
        if decompressed:
            metadata_parts.append("decompressed")
        if compressed_bios_info:
            metadata_parts.append("BIOS 0x62")
        metadata = " | ".join(part for part in metadata_parts if part)
        row = self._make_row(
            name,
            "\n".join(detail_lines),
            summary=f"Firmware volume {volume.index if volume.index is not None else '?'}",
            extra_columns=[
                _format_optional_hex(info.absolute_offset),
                _format_dual_size(info.size),
                "",
                metadata,
            ],
            payload=payload,
        )
        primary = row[0]
        # Build any placeholders for removed files (0x62 edit context).
        removed_placeholders: List[Tuple[Optional[int], List[QStandardItem]]] = []
        if compressed_bios_info and self._current_image is not None:
            dir_idx = compressed_bios_info.get("directory_index")
            entry_idx = compressed_bios_info.get("entry_index")
            pending_action = getattr(self._current_image, "pending_entry_actions", {}).get(
                (dir_idx, entry_idx)
            )
            if isinstance(pending_action, dict) and pending_action.get("is_0x62_edit"):
                ctx_list = pending_action.get("removed_file_context")
                if isinstance(ctx_list, dict):
                    ctx_list = [ctx_list]
                if isinstance(ctx_list, list):
                    for ctx in ctx_list:
                        if not isinstance(ctx, dict):
                            continue
                        # Match placeholder to this volume
                        ctx_vol_idx = ctx.get("volume_index")
                        ctx_vol_guid = (ctx.get("volume_guid") or "").lower()
                        matches_volume = False
                        if ctx_vol_idx is not None and volume.index is not None:
                            try:
                                matches_volume = int(volume.index) == int(ctx_vol_idx)
                            except Exception:
                                matches_volume = False
                        if not matches_volume and ctx_vol_guid and info.filesystem_guid:
                            matches_volume = str(info.filesystem_guid).lower() == ctx_vol_guid
                        if matches_volume:
                            placeholder_row = self._build_removed_ffs_row(pending_action, ctx)
                            if placeholder_row:
                                removed_placeholders.append(
                                    (ctx.get("file_index") if isinstance(ctx.get("file_index"), int) else None, placeholder_row)
                                )
        removed_placeholders.sort(key=lambda tup: tup[0] if tup[0] is not None else 0x7FFFFFFF)

        placeholder_iter = iter(removed_placeholders)
        next_placeholder = next(placeholder_iter, None)

        for firmware_file in volume.files:
            # Insert placeholders in the correct order relative to file indices
            while next_placeholder is not None:
                idx_value, placeholder_row = next_placeholder
                if idx_value is None:
                    primary.appendRow(placeholder_row)
                    next_placeholder = next(placeholder_iter, None)
                    continue
                try:
                    file_idx_val = int(firmware_file.index) if firmware_file.index is not None else None
                except Exception:
                    file_idx_val = None
                if file_idx_val is not None and idx_value is not None and idx_value <= file_idx_val:
                    primary.appendRow(placeholder_row)
                    next_placeholder = next(placeholder_iter, None)
                    continue
                break

            primary.appendRow(
                self._build_psp_file_row(
                    image_index, firmware_file, decompressed, root_index,
                    compressed_bios_info=compressed_bios_info
                )
            )

        # Append any remaining placeholders
        while next_placeholder is not None:
            _, placeholder_row = next_placeholder
            primary.appendRow(placeholder_row)
            next_placeholder = next(placeholder_iter, None)
        return row

    def _build_removed_ffs_row(
        self,
        action: dict,
        context: dict,
    ) -> Optional[List[QStandardItem]]:
        """Build a placeholder row for a removed FFS file inside a 0x62 entry."""
        if not isinstance(context, dict):
            return None
        label = context.get("name") or context.get("guid") or "<removed file>"
        guid_text = context.get("guid")
        type_name = context.get("type_name") or "FFS"
        size_val = context.get("size")
        detail_lines = [f"{label}", "Queued removal of FFS file"]
        if guid_text:
            detail_lines.append(f"GUID: {guid_text}")
        if type_name:
            detail_lines.append(f"Type: {type_name}")
        if size_val is not None:
            try:
                detail_lines.append(f"Size: 0x{int(size_val):X}")
            except Exception:
                pass
        rel_off = context.get("relative_offset")
        abs_off = context.get("absolute_offset")
        location_display = _format_optional_hex(abs_off if abs_off is not None else rel_off)
        size_display = _format_optional_hex(size_val)

        row = self._make_row(
            label,
            "\n".join(detail_lines),
            summary="Queued removal",
            extra_columns=[location_display, size_display, "", "FFS | queued removal"],
            payload={},
        )
        primary = row[0]
        pending_info = dict(action)
        pending_info.setdefault("placeholder", True)
        primary.setData(pending_info, PENDING_ACTION_ROLE)
        action_item = row[PSP_ACTION_COLUMN]
        if action_item is not None:
            action_item.setText(action.get("action_text") or "Remove")
        return row

    def _build_psp_file_row(
        self,
        image_index: int,
        firmware_file: EnumeratedFirmwareFile,
        decompressed: bool,
        root_index: Optional[int] = None,
        compressed_bios_info: Optional[dict] = None,
    ) -> List[QStandardItem]:
        info = firmware_file.info
        guid_name = lookup_guid_name(info.guid)
        # Use display_name if available (e.g., "Startup AP data padding file")
        display_name = getattr(info, "display_name", None)
        name = display_name or guid_name or str(info.guid)
        guid_text = str(info.guid)
        if guid_name:
            guid_text = f"{guid_text} ({guid_name})"
        elif display_name:
            guid_text = f"{guid_text} ({display_name})"
        type_name = info.type_name or "FFS"
        detail_lines = [
            f"File index: {firmware_file.index if firmware_file.index is not None else '-'}",
            f"Absolute offset: {_format_optional_hex(info.absolute_offset)}",
            f"Relative offset: 0x{info.relative_offset:X}",
            f"Size: 0x{info.size:X}",
            f"Header length: 0x{info.header_length:X}",
            f"Type: {type_name} (0x{info.type:02X})",
            f"State: 0x{info.state:02X}",
            f"Attributes: 0x{info.attributes:02X}",
            f"GUID: {guid_text}",
        ]
        payload = None
        hex_blob_for_extraction: Optional[bytes] = None
        if info.absolute_offset is not None and info.size > 0:
            # For items inside decompressed BIOS, extract data from the decompressed blob
            if compressed_bios_info:
                decompressed_blob = compressed_bios_info.get("decompressed_blob")
                source_offset = compressed_bios_info.get("source_offset", 0)
                if decompressed_blob:
                    # Calculate relative offset within decompressed blob
                    rel_offset = int(info.absolute_offset) - source_offset
                    if 0 <= rel_offset < len(decompressed_blob):
                        end = min(rel_offset + int(info.size), len(decompressed_blob))
                        hex_blob_for_extraction = bytes(decompressed_blob[rel_offset:end])
            # For items in compressed BIOS, set offset=None to force using hex_blob
            # since the adjusted offset points to ROM, not the decompressed blob
            display_offset = None if compressed_bios_info else int(info.absolute_offset)
            payload = {
                "image_index": image_index,
                "offset": display_offset,
                "size": int(info.size),
                "label": f"FFS_{firmware_file.index if firmware_file.index is not None else 'unknown'}",
                "guid": info.guid,
                "name": name,
                "uefi_kind": "file",
                "file_index": firmware_file.index,
            }
            if hex_blob_for_extraction:
                payload["hex_blob"] = hex_blob_for_extraction
            if root_index is not None:
                payload["root_index"] = root_index
            # Include compressed BIOS info for edit operations (without the blob to save memory)
            if compressed_bios_info:
                cbi_copy = {k: v for k, v in compressed_bios_info.items() if k != "decompressed_blob"}
                payload["compressed_bios_info"] = cbi_copy
        metadata_parts = [f"FFS {type_name}" if type_name else "FFS"]
        if decompressed:
            metadata_parts.append("decompressed")
        if compressed_bios_info:
            metadata_parts.append("BIOS 0x62")
        if guid_name:
            metadata_parts.append(f"GUID {guid_name}")
        metadata = " | ".join(part for part in metadata_parts if part)
        row = self._make_row(
            name,
            "\n".join(detail_lines),
            summary=f"Firmware file {type_name}",
            extra_columns=[
                _format_optional_hex(info.absolute_offset),
                _format_dual_size(info.size),
                "",
                metadata,
            ],
            payload=payload,
            )
        primary = row[0]
        # Propagate pending 0x62 actions down to the file row (insert/replace).
        if compressed_bios_info and self._current_image is not None:
            dir_idx = compressed_bios_info.get("directory_index")
            entry_idx = compressed_bios_info.get("entry_index")
            pending_action = getattr(self._current_image, "pending_entry_actions", {}).get(
                (dir_idx, entry_idx)
            )
            if isinstance(pending_action, dict) and pending_action.get("is_0x62_edit"):
                # For removals we show only the placeholder row, not the remaining files.
                if pending_action.get("action") != "remove":
                    target_guid = (pending_action.get("file_guid") or "").lower()
                    target_index = pending_action.get("target_file_index")
                    matches_guid = (
                        bool(info.guid)
                        and target_guid
                        and str(info.guid).lower() == target_guid
                    )
                    matches_index = (
                        target_index is not None
                        and firmware_file.index is not None
                        and int(firmware_file.index) == int(target_index)
                    )
                    if matches_guid or matches_index:
                        primary.setData(pending_action, PENDING_ACTION_ROLE)
                        action_item = row[PSP_ACTION_COLUMN]
                        if action_item is not None:
                            action_item.setText(
                                pending_action.get("action_text")
                                or pending_action.get("action", "modify").capitalize()
                            )
        for section in firmware_file.sections:
            primary.appendRow(
                self._build_psp_section_row(
                    image_index, section, decompressed, root_index,
                    compressed_bios_info=compressed_bios_info
                )
            )
        return row

    def _build_psp_section_row(
        self,
        image_index: int,
        section: EnumeratedFirmwareSection,
        decompressed: bool,
        root_index: Optional[int] = None,
        compressed_bios_info: Optional[dict] = None,
    ) -> List[QStandardItem]:
        info = section.info
        type_name = info.type_name or "Section"
        detail_lines = [
            f"Section type: {type_name} (0x{info.type:02X})",
            f"Absolute offset: {_format_optional_hex(info.absolute_offset)}",
            f"Relative offset: 0x{info.relative_offset:X}",
            f"Size: 0x{info.size:X}",
        ]
        metadata_parts: List[str] = [type_name]
        if decompressed:
            metadata_parts.append("decompressed")
        if info.guid is not None:
            guid_name = lookup_guid_name(info.guid)
            guid_text = str(info.guid)
            if guid_name:
                guid_text = f"{guid_text} ({guid_name})"
                metadata_parts.append(f"GUID {guid_name}")
            detail_lines.append(f"GUID: {guid_text}")
        if info.compression_name:
            detail_lines.append(f"Compression: {info.compression_name}")
            metadata_parts.append(info.compression_name)
        if info.uncompressed_length is not None:
            detail_lines.append(f"Uncompressed size: 0x{info.uncompressed_length:X}")
        if info.virtual:
            detail_lines.append("Virtual section: yes")
        if info.notes:
            detail_lines.append("Notes:")
            for note in info.notes:
                detail_lines.append(f"  - {note}")
        payload = None
        hex_blob_for_extraction: Optional[bytes] = None
        if info.absolute_offset is not None and info.size > 0:
            # For items inside decompressed BIOS, extract data from the decompressed blob
            if compressed_bios_info:
                decompressed_blob = compressed_bios_info.get("decompressed_blob")
                source_offset = compressed_bios_info.get("source_offset", 0)
                if decompressed_blob:
                    # Calculate relative offset within decompressed blob
                    rel_offset = int(info.absolute_offset) - source_offset
                    if 0 <= rel_offset < len(decompressed_blob):
                        end = min(rel_offset + int(info.size), len(decompressed_blob))
                        hex_blob_for_extraction = bytes(decompressed_blob[rel_offset:end])
            # For items in compressed BIOS, set offset=None to force using hex_blob
            # since the adjusted offset points to ROM, not the decompressed blob
            display_offset = None if compressed_bios_info else int(info.absolute_offset)
            payload = {
                "image_index": image_index,
                "offset": display_offset,
                "size": int(info.size),
                "label": f"SEC_{info.type_name}",
                "guid": info.guid,
                "name": info.type_name,
                "uefi_kind": "section",
            }
            if hex_blob_for_extraction:
                payload["hex_blob"] = hex_blob_for_extraction
            if root_index is not None:
                payload["root_index"] = root_index
            # Include compressed BIOS info for edit operations (without the blob to save memory)
            if compressed_bios_info:
                cbi_copy = {k: v for k, v in compressed_bios_info.items() if k != "decompressed_blob"}
                payload["compressed_bios_info"] = cbi_copy
        metadata = " | ".join(part for part in metadata_parts if part)
        row = self._make_row(
            type_name,
            "\n".join(detail_lines),
            summary=f"Section {type_name}",
            extra_columns=[
                _format_optional_hex(info.absolute_offset),
                _format_dual_size(info.size),
                "",
                metadata,
            ],
            payload=payload,
        )
        primary = row[0]
        for nested_volume in section.volumes:
            primary.appendRow(
                self._build_psp_volume_row(
                    image_index, nested_volume, decompressed, root_index,
                    compressed_bios_info=compressed_bios_info
                )
            )
        for nested_section in section.sections:
            primary.appendRow(
                self._build_psp_section_row(
                    image_index, nested_section, decompressed, root_index,
                    compressed_bios_info=compressed_bios_info
                )
            )
        return row

    def _build_uefi_image_row(
        self, image_index: int, image: LoadedImage
    ) -> List[QStandardItem]:
        path = image.path
        detail_lines = [
            f"Input: {path}",
            f"UEFI roots discovered: {len(image.uefi_roots)}",
        ]
        row = self._make_row(
            f"{path.name}",
            "\n".join(detail_lines),
            summary=f"{path.name}: {len(image.uefi_roots)} UEFI regions",
            extra_columns=[
                "Image",
                _format_dual_size(len(image.data)),
                str(path),
                "",
            ],
            payload={"image_index": image_index},
        )
        primary = row[0]
        for root_index, root in enumerate(image.uefi_roots):
            primary.appendRow(self._build_uefi_root_row(root_index, root))
        return row

    def _build_uefi_root_row(self, root_index: int, root: UefiRoot) -> List[QStandardItem]:
        label = f"Image region ({len(root.volumes)} FV)"
        remarks = f"Offset {_format_optional_hex(root.offset)}"
        row = self._make_row(
            label,
            root.detail,
            summary=f"UEFI scan covering {len(root.volumes)} volumes",
            extra_columns=[
                "Region",
                _format_dual_size(root.size),
                remarks,
                "",
            ],
            payload={
                "image_index": root.image_index,
                "offset": root.offset,
                "size": root.size,
                "label": root.entry_label,
                "uefi_kind": "root",
                "root_index": root_index,
            },
        )
        primary = row[0]
        for volume in root.volumes:
            primary.appendRow(
                self._build_volume_row(root.image_index, root_index, volume)
            )
        return row

    def _build_volume_row(
        self,
        image_index: int,
        root_index: int,
        volume: EnumeratedFirmwareVolume,
        *,
        volume_chain: Optional[Sequence[EnumeratedFirmwareVolume]] = None,
        file_chain: Optional[Sequence[EnumeratedFirmwareFile]] = None,
        section_chain: Optional[Sequence[EnumeratedFirmwareSection]] = None,
        section_path: Optional[Sequence[int]] = None,
    ) -> List[QStandardItem]:
        volume_chain = list(volume_chain or []) + [volume]
        file_chain = list(file_chain or [])
        section_chain = list(section_chain or [])
        section_path_list = list(section_path or [])
        info = volume.info
        # Prefer FV name GUID over filesystem GUID for display
        fv_name_guid = getattr(info, "fv_name", None)
        if fv_name_guid:
            fv_name_friendly = lookup_guid_name(fv_name_guid)
            if fv_name_friendly and not _is_generic_guid_name(fv_name_friendly):
                name = fv_name_friendly
            else:
                name = str(fv_name_guid).upper()
        else:
            guid_name = lookup_guid_name(info.filesystem_guid)
            # For generic EFI names, prefer showing the GUID
            if guid_name and not _is_generic_guid_name(guid_name):
                name = guid_name
            elif info.filesystem_guid is not None:
                name = str(info.filesystem_guid).upper()
            else:
                name = f"FV #{volume.index if volume.index is not None else '?'}"
        guid_name = lookup_guid_name(info.filesystem_guid)
        guid_text = str(info.filesystem_guid).upper() if info.filesystem_guid else "-"
        if guid_name:
            guid_text = f"{guid_text} ({guid_name})"
        detail_lines = [
            f"Firmware volume index: {volume.index if volume.index is not None else '-'}",
            f"Absolute offset: {_format_optional_hex(info.absolute_offset)}",
            f"Relative offset: 0x{info.relative_offset:X}",
            f"Size: 0x{info.size:X}",
            f"Header length: 0x{info.header_length:X}",
            f"Revision: {info.revision}",
            f"Attributes: 0x{info.attributes:08X}",
            f"Filesystem GUID: {guid_text}",
            f"Used size: 0x{info.used_size:X}",
            f"Free size: 0x{info.free_size:X}",
        ]
        if fv_name_guid:
            fv_name_text = str(fv_name_guid).upper()
            friendly = lookup_guid_name(fv_name_guid)
            if friendly:
                fv_name_text = f"{fv_name_text} ({friendly})"
            detail_lines.append(f"FV name GUID: {fv_name_text}")
        try:
            abs_offset = (
                int(info.absolute_offset)
                if info.absolute_offset is not None
                else None
            )
        except Exception:
            abs_offset = None
        try:
            size_value = int(info.size)
        except Exception:
            size_value = 0
        
        # Check if this volume is within any 0x62 BIOS entry regions
        bios_refs = self._find_bios_entry_refs_for_offset(image_index, abs_offset, size_value)
        info_column_text = ""
        if bios_refs:
            # Show 0x62 flag in info column with all directory/entry pairs
            ref_labels = [f"D{ref.directory_index}E{ref.entry_index}" for ref in bios_refs]
            info_column_text = f"0x62 {', '.join(ref_labels)}"
            detail_lines.append("")
            detail_lines.append(f"Referenced by {len(bios_refs)} PSP 0x62 BIOS entry(s):")
            for ref in bios_refs:
                detail_lines.append(f"  Directory #{ref.directory_index}, Entry #{ref.entry_index}")
                detail_lines.append(f"    Source offset: 0x{ref.source_offset:X}")
                detail_lines.append(f"    Region size: 0x{ref.size:X}")
                if ref.destination is not None:
                    detail_lines.append(f"    Destination (memory): 0x{ref.destination:X}")
                detail_lines.append(f"    Compressed: {'Yes' if ref.compressed else 'No'}")
        
        payload = {
            "image_index": image_index,
            "offset": abs_offset,
            "size": size_value,
            "label": f"FV_{volume.index if volume.index is not None else 'unknown'}",
            # Prefer FV name GUID (unique volume identifier) over filesystem GUID for copy
            "guid": fv_name_guid if fv_name_guid else info.filesystem_guid,
            # Also store filesystem GUID separately for search functionality
            "filesystem_guid": info.filesystem_guid,
            "name": name,
            "uefi_kind": "volume",
            "volume_index": volume.index,
            "root_index": root_index,
            "uefi_volume_chain": volume_chain,
            "uefi_file_chain": file_chain,
            "uefi_section_chain": section_chain,
            "uefi_section_path": section_path_list,
            "virtual": info.absolute_offset is None,
            "bios_entry_refs": bios_refs,  # Track all PSP 0x62 references
        }
        hex_blob = None
        if info.absolute_offset is None and getattr(info, "raw_data", None):
            hex_blob = self._clip_hex_blob(info.raw_data)  # type: ignore[arg-type]
            if hex_blob:
                payload["hex_blob"] = hex_blob
        row = self._make_row(
            name,  # Keep name clean, no [0x62] prefix
            "\n".join(detail_lines),
            summary=f"Firmware volume {volume.index if volume.index is not None else '?'}",
            extra_columns=[
                "FV",
                _format_dual_size(info.size),
                "",  # Action column (set dynamically)
                info_column_text,  # Info column - show 0x62 flag here
                "",  # Diff column (set dynamically)
            ],
            payload=payload,
        )
        primary = row[0]
        if hex_blob:
            primary.setData(hex_blob, HEX_ROLE)
        for firmware_file in volume.files:
            primary.appendRow(
                self._build_firmware_file_row(
                    image_index,
                    root_index,
                    volume,
                    firmware_file,
                    volume_chain=volume_chain,
                    file_chain=file_chain,
                    section_chain=section_chain,
                    section_path=section_path_list,
                )
            )
        return row

    def _build_firmware_file_row(
        self,
        image_index: int,
        root_index: int,
        volume: EnumeratedFirmwareVolume,
        firmware_file: EnumeratedFirmwareFile,
        *,
        volume_chain: Optional[Sequence[EnumeratedFirmwareVolume]] = None,
        file_chain: Optional[Sequence[EnumeratedFirmwareFile]] = None,
        section_chain: Optional[Sequence[EnumeratedFirmwareSection]] = None,
        section_path: Optional[Sequence[int]] = None,
    ) -> List[QStandardItem]:
        volume_chain = list(volume_chain or [])
        file_chain = list(file_chain or []) + [firmware_file]
        section_chain = list(section_chain or [])
        section_path_list = list(section_path or [])
        info = firmware_file.info
        guid_name = lookup_guid_name(info.guid)
        # Use display_name if available (e.g., "Startup AP data padding file")
        display_name = getattr(info, "display_name", None)
        name = display_name or guid_name or str(info.guid)
        guid_text = str(info.guid)
        if guid_name:
            guid_text = f"{guid_text} ({guid_name})"
        elif display_name:
            guid_text = f"{guid_text} ({display_name})"
        detail_lines = [
            f"File index: {firmware_file.index if firmware_file.index is not None else '-'}",
            f"Absolute offset: {_format_optional_hex(info.absolute_offset)}",
            f"Relative offset: 0x{info.relative_offset:X}",
            f"Size: 0x{info.size:X}",
            f"Header length: 0x{info.header_length:X}",
            f"Type: {info.type_name} (0x{info.type:02X})",
            f"State: 0x{info.state:02X}",
            f"Attributes: 0x{info.attributes:02X}",
            f"GUID: {guid_text}",
        ]
        module_metadata: List[str] = []
        agesa_module_match = self._lookup_agesa_module_match(info)
        if agesa_module_match:
            version = agesa_module_match.get("version")
            if version:
                detail_lines.append(f"AGESA version: {version}")
                module_metadata.append(f"AGESA {version}")
            digest = agesa_module_match.get("digest")
            if digest:
                detail_lines.append(f"Module SHA256: {digest}")
        try:
            abs_offset = (
                int(info.absolute_offset)
                if info.absolute_offset is not None
                else None
            )
        except Exception:
            abs_offset = None
        try:
            size_value = int(info.size)
        except Exception:
            size_value = 0
        
        # Check if this file is within any 0x62 BIOS entry regions
        bios_refs = self._find_bios_entry_refs_for_offset(image_index, abs_offset, size_value)
        if bios_refs:
            detail_lines.append("")
            detail_lines.append(f"Inside {len(bios_refs)} PSP 0x62 BIOS entry(s):")
            for ref in bios_refs:
                detail_lines.append(f"  Directory #{ref.directory_index}, Entry #{ref.entry_index}")
        
        payload = {
            "image_index": image_index,
            "offset": abs_offset,
            "size": size_value,
            "label": f"FFS_{firmware_file.index if firmware_file.index is not None else 'unknown'}",
            "guid": info.guid,
            "name": name,
            "uefi_kind": "file",
            "volume_index": volume.index,
            "file_index": firmware_file.index,
            "root_index": root_index,
            "uefi_volume_chain": volume_chain,
            "uefi_file_chain": file_chain,
            "uefi_section_chain": section_chain,
            "uefi_section_path": section_path_list,
            "virtual": info.absolute_offset is None,
            "bios_entry_refs": bios_refs,  # Track all PSP 0x62 references
        }
        hex_blob = None
        if info.absolute_offset is None and getattr(info, "raw_data", None):
            hex_blob = self._clip_hex_blob(info.raw_data)  # type: ignore[arg-type]
            if hex_blob:
                payload["hex_blob"] = hex_blob
        metadata_text = ", ".join(module_metadata)
        type_text = f"FFS {info.type_name}" if info.type_name else "FFS"
        # Build info text - combine AGESA metadata with 0x62 flag
        info_parts = []
        if metadata_text:
            info_parts.append(metadata_text)
        if bios_refs:
            # Show all directory/entry pairs
            ref_labels = [f"D{ref.directory_index}E{ref.entry_index}" for ref in bios_refs]
            info_parts.append(f"0x62 {', '.join(ref_labels)}")
        info_text = ", ".join(info_parts)
        row = self._make_row(
            name,  # Keep name clean
            "\n".join(detail_lines),
            summary=f"Firmware file {info.type_name}",
            extra_columns=[
                type_text,
                _format_dual_size(info.size),
                "",  # Action column (set dynamically)
                info_text,  # Info column - show 0x62 flag here
                "",  # Diff column (set dynamically)
            ],
            payload=payload,
        )
        primary = row[0]
        if hex_blob:
            primary.setData(hex_blob, HEX_ROLE)

        # Check for pending UEFI actions and mark row accordingly
        # Key includes parent volume offset and file_index to handle duplicate GUIDs
        if (
            self._current_image is not None
            and hasattr(self._current_image, "pending_uefi_actions")
            and volume_chain
        ):
            # Use the root (non-virtual) volume's offset for the key
            root_vol = volume_chain[0] if volume_chain else None
            vol_offset = int(root_vol.info.absolute_offset or 0) if root_vol and root_vol.info.absolute_offset is not None else 0
            guid_str = str(info.guid).upper() if info.guid else ""
            file_idx = firmware_file.index
            file_idx_str = str(file_idx) if file_idx is not None else "?"
            action_key = f"{image_index}:{vol_offset:X}:{guid_str}:{file_idx_str}"
            pending_action = self._current_image.pending_uefi_actions.get(action_key)
            if isinstance(pending_action, dict):
                primary.setData(pending_action, PENDING_ACTION_ROLE)
                action_item = row[3] if len(row) > 3 else None
                if action_item is not None:
                    action_item.setText(pending_action.get("action_text") or "modify")

        for section_index, section in enumerate(firmware_file.sections):
            primary.appendRow(
                self._build_section_row(
                    image_index,
                    root_index,
                    volume,
                    firmware_file,
                    section,
                    section_index,
                    volume_chain=volume_chain,
                    file_chain=file_chain,
                    section_chain=section_chain,
                    section_path=section_path_list,
                )
            )
        return row

    def _build_section_row(
        self,
        image_index: int,
        root_index: int,
        volume: EnumeratedFirmwareVolume,
        firmware_file: EnumeratedFirmwareFile,
        section: EnumeratedFirmwareSection,
        section_index: int,
        depth: int = 0,
        *,
        volume_chain: Optional[Sequence[EnumeratedFirmwareVolume]] = None,
        file_chain: Optional[Sequence[EnumeratedFirmwareFile]] = None,
        section_chain: Optional[Sequence[EnumeratedFirmwareSection]] = None,
        section_path: Optional[Sequence[int]] = None,
    ) -> List[QStandardItem]:
        volume_chain = list(volume_chain or [])
        file_chain = list(file_chain or [])
        section_chain = list(section_chain or []) + [section]
        section_path_list = list(section_path or []) + [section_index]
        info = section.info
        detail_lines = [
            f"Section type: {info.type_name} (0x{info.type:02X})",
            f"Absolute offset: {_format_optional_hex(info.absolute_offset)}",
            f"Relative offset: 0x{info.relative_offset:X}",
            f"Size: 0x{info.size:X}",
        ]
        metadata_parts = []
        if info.guid is not None:
            guid_name = lookup_guid_name(info.guid)
            guid_text = str(info.guid)
            if guid_name:
                guid_text = f"{guid_text} ({guid_name})"
            detail_lines.append(f"GUID: {guid_text}")
            metadata_parts.append(f"GUID {guid_text}")
        if info.compression_name:
            detail_lines.append(f"Compression: {info.compression_name}")
            metadata_parts.append(info.compression_name)
        if info.uncompressed_length is not None:
            detail_lines.append(f"Uncompressed size: 0x{info.uncompressed_length:X}")
        if info.virtual:
            detail_lines.append("Virtual section: yes")
        if info.notes:
            detail_lines.append("Notes:")
            for note in info.notes:
                detail_lines.append(f"  - {note}")
        try:
            abs_offset = (
                int(info.absolute_offset)
                if info.absolute_offset is not None
                else None
            )
        except Exception:
            abs_offset = None
        try:
            size_value = int(info.size)
        except Exception:
            size_value = 0
        
        # Check if this section is within any 0x62 BIOS entry regions
        bios_refs = self._find_bios_entry_refs_for_offset(image_index, abs_offset, size_value)
        if bios_refs:
            detail_lines.append("")
            detail_lines.append(f"Inside {len(bios_refs)} PSP 0x62 BIOS entry(s):")
            for ref in bios_refs:
                detail_lines.append(f"  Directory #{ref.directory_index}, Entry #{ref.entry_index}")
        
        payload = {
            "image_index": image_index,
            "offset": abs_offset,
            "size": size_value,
            "label": f"SEC_{info.type_name}",
            "guid": info.guid,
            "name": info.type_name,
            "uefi_kind": "section",
            "volume_index": volume.index,
            "file_index": firmware_file.index,
            "section_index": section_index,
            "section_depth": depth,
            "section_type": info.type,
            "compression_type": info.compression_type,
            "uncompressed_length": info.uncompressed_length,
            "virtual": info.virtual,
            "root_index": root_index,
            "uefi_volume_chain": volume_chain,
            "uefi_file_chain": file_chain,
            "uefi_section_chain": section_chain,
            "uefi_section_path": section_path_list,
            "bios_entry_refs": bios_refs,  # Track all PSP 0x62 references
        }
        hex_blob = None
        if info.absolute_offset is None and getattr(info, "processed_payload", None):
            hex_blob = self._clip_hex_blob(info.processed_payload)  # type: ignore[arg-type]
            if hex_blob:
                payload["hex_blob"] = hex_blob
        # Build remarks - combine metadata with 0x62 flag
        remarks_parts = list(metadata_parts)
        if bios_refs:
            # Show all directory/entry pairs
            ref_labels = [f"D{ref.directory_index}E{ref.entry_index}" for ref in bios_refs]
            remarks_parts.append(f"0x62 {', '.join(ref_labels)}")
        remarks = " | ".join(remarks_parts) if remarks_parts else ""
        row = self._make_row(
            info.type_name,  # Keep name clean
            "\n".join(detail_lines),
            summary=f"Section {info.type_name}",
            extra_columns=[
                "Section",
                _format_dual_size(info.size),
                "",  # Action column (set dynamically)
                remarks,  # Info column (metadata + 0x62 flag)
                "",  # Diff column (set dynamically)
            ],
            payload=payload,
        )
        primary = row[0]
        if hex_blob:
            primary.setData(hex_blob, HEX_ROLE)
        for nested_volume in section.volumes:
            primary.appendRow(
                self._build_volume_row(
                    image_index,
                    root_index,
                    nested_volume,
                    volume_chain=volume_chain,
                    file_chain=file_chain,
                    section_chain=section_chain,
                    section_path=section_path_list,
                )
            )
        for nested_idx, nested_section in enumerate(section.sections):
            primary.appendRow(
                self._build_section_row(
                    image_index,
                    root_index,
                    volume,
                    firmware_file,
                    nested_section,
                    nested_idx,
                    depth=depth + 1,
                    volume_chain=volume_chain,
                    file_chain=file_chain,
                    section_chain=section_chain,
                    section_path=section_path_list,
                )
            )
        return row


    def _clip_hex_blob(self, blob: Optional[bytes]) -> Optional[bytes]:
        if not blob:
            return None
        data = bytes(blob)
        if len(data) <= _HEX_PREVIEW_LIMIT:
            return data
        return data[:_HEX_PREVIEW_LIMIT]
