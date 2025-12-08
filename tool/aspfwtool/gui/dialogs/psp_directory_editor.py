# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
PSP directory entry viewer and editor dialogs.

This module provides:
    - DirectoryEditDialog for viewing/editing directory entries
    - Entry field configuration and validation
    - Checksum display and verification
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QAbstractItemView,
    QSizePolicy,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QMenu,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...agesa.constants import DirKind, is_combo_dir, is_real_bios_dir
from ...agesa import constants as _constants
from ...agesa.directory import (
    Directory,
    dir_header_len,
    entry_span,
    parse_dir_header,
)
from ...utils import get_logger

_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1


@dataclass(frozen=True)
class _FieldSpec:
    key: str
    label: str
    bits: int
    mode: str  # "hex", "uint", or "pointer"


@dataclass
class _EntryRow:
    index: int
    entry_info: Optional[dict]
    entry_offset: Optional[int]
    original: Dict[str, Optional[int]]


class _ReorderableTable(QTableWidget):
    """QTableWidget variant that moves rows in-place during drag/drop."""

    def dropEvent(self, event):  # type: ignore[override]
        super().dropEvent(event)
        if self.dragDropMode() != QAbstractItemView.InternalMove:
            return
        parent = self.parent()
        while parent is not None and not hasattr(parent, "_apply_removal_style"):
            parent = parent.parent() if hasattr(parent, "parent") else None
        if parent is not None and hasattr(parent, "_apply_removal_style"):
            for row_idx in range(self.rowCount()):
                index_item = self.item(row_idx, 0)
                state = False
                if index_item is not None:
                    state = bool(index_item.data(_REMOVAL_FLAG_ROLE))
                parent._apply_removal_style(row_idx, state)


_ROW_INDEX_ROLE = Qt.UserRole + 10
_SPEC_KEY_ROLE = Qt.UserRole + 11
_ORIGINAL_ROLE = Qt.UserRole + 12
_REMOVAL_FLAG_ROLE = Qt.UserRole + 13

class DirectoryEditDialog(QDialog):
    """Dialog used to edit PSP directory entries."""

    def __init__(
        self,
        parent: QWidget,
        directory: Directory,
        entries: List[dict],
        data: bytes,
    ) -> None:
        super().__init__(parent)
        self.directory = directory
        self._image_data = data
        self._field_specs = self._field_specs_for_kind(directory.kind)
        self._header_original = self._extract_header_metadata()
        self._rows = self._build_rows(entries)
        self._entry_info_map: Dict[int, Optional[dict]] = {
            row.index: row.entry_info for row in self._rows
        }
        self._cached_operations: Optional[
            Tuple[List[dict], List[int], Optional[List[int]], Optional[dict]]
        ] = None

        #self.setMinimumSize(900, 560)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        self.tabs = QTabWidget(self)
        self.tabs.setDocumentMode(True)
        self.tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.tabs)

        entries_tab = QWidget(self.tabs)
        entries_layout = QVBoxLayout(entries_tab)
        entries_layout.setContentsMargins(6, 6, 6, 6)
        entries_layout.setSpacing(8)
        self.table = _ReorderableTable(entries_tab)
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        entries_layout.addWidget(self.table)
        self._empty_label = QLabel("No entries found for this directory.", entries_tab)
        self._empty_label.setAlignment(Qt.AlignCenter)
        self._empty_label.setWordWrap(True)
        self._empty_label.hide()
        entries_layout.addWidget(self._empty_label)
        hint_label = QLabel(
            "Drag rows to reorder. Right-click a row to mark or unmark it for removal.",
            entries_tab,
        )
        hint_label.setWordWrap(True)
        entries_layout.addWidget(hint_label)
        self.tabs.addTab(entries_tab, "Entries")

        header_tab = QWidget(self.tabs)
        header_layout = QVBoxLayout(header_tab)
        header_layout.setContentsMargins(6, 6, 6, 6)
        header_layout.setSpacing(8)
        header_form_container = QWidget(header_tab)
        header_form_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        header_layout.addWidget(header_form_container)
        header_layout.addStretch(1)
        self._header_form = QFormLayout(header_form_container)
        self._header_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._header_form.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        self._header_form.setHorizontalSpacing(12)
        self._header_form.setVerticalSpacing(6)
        self.tabs.addTab(header_tab, "Header")

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, parent=self)
        layout.addWidget(self.button_box)

        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setDragEnabled(True)
        self.table.setAcceptDrops(True)
        self.table.setDragDropOverwriteMode(False)
        self.table.setDragDropMode(QAbstractItemView.InternalMove)
        self.table.setDefaultDropAction(Qt.MoveAction)
        self.table.setDropIndicatorShown(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_context_menu)

        self.setWindowTitle(f"Edit {directory.kind.value} directory")
        if self.tabs is not None:
            self.tabs.setCurrentIndex(0)

        self._index_column = 0
        self._first_field_column = 1
        self._column_specs: Dict[int, _FieldSpec] = {}
        self._cookie_edit: Optional[QLineEdit] = None
        self._max_size_spin: Optional[QSpinBox] = None
        self._spi_block_spin: Optional[QSpinBox] = None
        self._base_bits_spin: Optional[QSpinBox] = None
        self._info_value_label: Optional[QLabel] = None
        self._address_mode_label: Optional[QLabel] = None
        self._size_override_label: Optional[QLabel] = None
        self._count_spin: Optional[QSpinBox] = None
        self._checksum_label: Optional[QLabel] = None
        self._base_addr_label: Optional[QLabel] = None

        self._setup_table()
        get_logger().debug(
            f"Directory editor prepared {len(self._rows)} entries for {directory.kind.value}"
        )
        if self.table is not None:
            self.table.resizeColumnsToContents()
            has_rows = bool(self._rows)
            self.table.setVisible(has_rows)
            if self._empty_label is not None:
                self._empty_label.setVisible(not has_rows)
            self.table.viewport().update()
            self.table.repaint()
        if self._empty_label is not None and not self._rows:
            self._empty_label.setText("No entries found for this directory.")
        self._setup_header_tab()

        self.button_box.accepted.connect(self._on_accept)
        self.button_box.rejected.connect(self.reject)

    # ------------------------------------------------------------------
    # UI construction helpers
    # ------------------------------------------------------------------
    def _setup_table(self) -> None:
        if self.table is None:
            return
        headers = ["Index"] + [spec.label for spec in self._field_specs]
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.clearContents()
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setDragEnabled(True)
        self.table.setAcceptDrops(True)
        self.table.setDragDropOverwriteMode(False)
        self.table.setDragDropMode(QAbstractItemView.InternalMove)
        self.table.setDefaultDropAction(Qt.MoveAction)
        self.table.setDropIndicatorShown(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setRowCount(len(self._rows))

        self.table.blockSignals(True)
        for row_idx, row in enumerate(self._rows):
            index_item = QTableWidgetItem(str(row.index))
            index_flags = Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsDragEnabled
            index_item.setFlags(index_flags)
            index_item.setData(_ROW_INDEX_ROLE, row.index)
            index_item.setData(_REMOVAL_FLAG_ROLE, False)
            self.table.setItem(row_idx, self._index_column, index_item)

            for offset, spec in enumerate(self._field_specs, start=self._first_field_column):
                text = self._format_field(spec, row.original.get(spec.key))
                item = QTableWidgetItem(text)
                item.setData(_ROW_INDEX_ROLE, row.index)
                item.setData(_SPEC_KEY_ROLE, spec.key)
                item.setData(
                    _ORIGINAL_ROLE,
                    self._encode_qvariant_value(row.original.get(spec.key)),
                )
                flags = Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsDragEnabled
                if spec.mode != "readonly":
                    flags |= Qt.ItemIsEditable
                item.setFlags(flags)
                if spec.mode in {"hex", "pointer"}:
                    item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                else:
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.table.setItem(row_idx, offset, item)
                self._column_specs[offset] = spec
            self._apply_removal_style(row_idx, False)
        self.table.blockSignals(False)
        self.table.itemChanged.connect(self._on_item_changed)
        row_preview = []
        if self._rows:
            for col in range(self.table.columnCount()):
                item = self.table.item(0, col)
                if item is not None:
                    row_preview.append(item.text())
        get_logger().debug(
            f"Directory editor table setup: rows={len(self._rows)}, columns={self.table.columnCount()}, first_row={row_preview}"
        )

    def _set_row_removal_state(self, row: int, state: bool) -> None:
        if self.table is None or not (0 <= row < self.table.rowCount()):
            return
        index_item = self.table.item(row, self._index_column)
        if index_item is None:
            return
        index_item.setData(_REMOVAL_FLAG_ROLE, bool(state))
        self._apply_removal_style(row, state)

    def _apply_removal_style(self, row: int, state: bool) -> None:
        if self.table is None:
            return
        column_count = self.table.columnCount()
        for col in range(column_count):
            item = self.table.item(row, col)
            if item is None:
                continue
            font = item.font()
            font.setStrikeOut(state)
            item.setFont(font)
            if state:
                item.setBackground(QBrush(QColor(255, 220, 220)))
            else:
                item.setBackground(QBrush())

    def _on_table_context_menu(self, pos) -> None:
        if self.table is None or self.table.rowCount() == 0:
            return
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        self.table.selectRow(row)
        index_item = self.table.item(row, self._index_column)
        is_marked = False
        if index_item is not None:
            is_marked = bool(index_item.data(_REMOVAL_FLAG_ROLE))
        menu = QMenu(self.table)
        toggle_action = menu.addAction(
            "Unmark removal" if is_marked else "Mark for removal"
        )
        chosen = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if chosen == toggle_action:
            self._set_row_removal_state(row, not is_marked)

    def _setup_header_tab(self) -> None:
        if self._header_form is None:
            return

        if not self._header_original:
            message = QLabel(
                "Directory header metadata could not be read; header edits are unavailable.",
                self,
            )
            message.setWordWrap(True)
            self._header_form.addRow(message)
            return

        # === Cookie (4 bytes) - View only ===
        cookie_label = QLabel(self)
        cookie_bytes = self._header_original.get("cookie")
        if isinstance(cookie_bytes, (bytes, bytearray)) and len(cookie_bytes) == 4:
            try:
                cookie_text = cookie_bytes.decode("ascii")
            except Exception:
                cookie_text = cookie_bytes.hex().upper()
            cookie_label.setText(f"{cookie_text} ({cookie_bytes.hex().upper()})")
        self._header_form.addRow("Cookie (4B):", cookie_label)
        
        # === Checksum (4 bytes) - View only ===
        # Read checksum from offset 4 in the header
        offset = getattr(self.directory, "offset", None)
        checksum_value = 0
        if offset is not None:
            try:
                off_int = int(offset)
                checksum_value = int.from_bytes(self._image_data[off_int + 4:off_int + 8], "little")
            except Exception:
                pass
        checksum_label = QLabel(f"0x{checksum_value:08X}", self)
        self._header_form.addRow("Checksum (4B):", checksum_label)
        self._checksum_label = checksum_label
        
        # === Total Entries (4 bytes) - Editable ===
        count_spin = QSpinBox(self)
        count_spin.setRange(0, 0x7FFFFFFF)  # Use INT32_MAX (Qt limit)
        count_spin.setValue(int(self._header_original.get("count", 0)))
        self._header_form.addRow("Total Entries (4B):", count_spin)
        self._count_spin = count_spin

        if _constants.is_combo_dir(self.directory.kind):
            # Combo directories have a different header format (no Additional Info field)
            note = QLabel(
                "Combo directories (2PSP/2BHD) have a 20-byte reserved field instead of Additional Info.",
                self,
            )
            note.setWordWrap(True)
            self._header_form.addRow(note)
            return

        # === Additional Info (4 bytes) - Contains sub-fields ===
        raw_info = int(self._header_original.get("info", 0))
        info_label = QLabel(f"0x{raw_info:08X}", self)
        self._header_form.addRow("Additional Info (4B):", info_label)
        self._info_value_label = info_label
        
        # Add separator
        separator = QLabel("── Additional Info Fields ──", self)
        separator.setStyleSheet("color: gray; font-style: italic;")
        self._header_form.addRow("", separator)

        # === Reserved bit 0 (1 bit) - View only ===
        reserved_bit0 = raw_info & 0x1
        reserved_bit0_label = QLabel(f"{reserved_bit0}", self)
        self._header_form.addRow("Reserved [0]:", reserved_bit0_label)

        # === Max Size (10 bits) [10:1] - Editable ===
        max_size_spin = QSpinBox(self)
        max_size_spin.setRange(0, 0x3FF)
        max_size_spin.setValue(int(self._header_original.get("max_size", 0)))
        max_size_spin.setToolTip("Maximum directory size in 4KB units (bits 10:1)")
        max_size_spin.valueChanged.connect(self._update_info_preview)
        self._header_form.addRow("Max Size [10:1] (10b):", max_size_spin)
        self._max_size_spin = max_size_spin

        # === SPI Block Size (4 bits) [14:11] - Editable ===
        spi_block_spin = QSpinBox(self)
        spi_block_spin.setRange(0, 0x0F)
        spi_block_spin.setValue(int(self._header_original.get("spi_block", 0)))
        spi_block_spin.setToolTip("SPI flash block size (bits 14:11)")
        spi_block_spin.valueChanged.connect(self._update_info_preview)
        self._header_form.addRow("SPI Block Size [14:11] (4b):", spi_block_spin)
        self._spi_block_spin = spi_block_spin

        # === Base Address (15 bits) [29:15] - Editable ===
        base_bits_spin = QSpinBox(self)
        base_bits_spin.setRange(0, 0x7FFF)
        base_bits_spin.setValue(int(self._header_original.get("base_bits", 0)))
        base_bits_spin.setToolTip("Base address bits (bits 29:15), shifted << 12 for actual address")
        base_bits_spin.valueChanged.connect(self._update_info_preview)
        self._header_form.addRow("Base Address [29:15] (15b):", base_bits_spin)
        self._base_bits_spin = base_bits_spin
        
        # Show computed base address
        base_addr = int(self._header_original.get("base_bits", 0)) << 12
        base_addr_label = QLabel(f"0x{base_addr:08X}", self)
        base_addr_label.setToolTip("Computed base address = Base Address Bits << 12")
        self._header_form.addRow("  (Computed Address):", base_addr_label)
        self._base_addr_label = base_addr_label

        # === Address Mode (2 bits) [31:30] - View only ===
        address_mode_value = int(self._header_original.get("address_mode", 0)) & 0x3
        mode_names = {0: "X86 physical", 1: "BIOS offset", 2: "Directory relative", 3: "Partition relative"}
        mode_text = f"{address_mode_value} - {mode_names.get(address_mode_value, 'Unknown')}"
        address_mode_label = QLabel(mode_text, self)
        address_mode_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._header_form.addRow("Address Mode [31:30] (2b):", address_mode_label)
        self._address_mode_label = address_mode_label

        self._update_info_preview()

    # ------------------------------------------------------------------
    # Data preparation helpers
    # ------------------------------------------------------------------
    def _field_specs_for_kind(self, kind: DirKind) -> List[_FieldSpec]:
        if is_combo_dir(kind):
            return [
                _FieldSpec("type_value", "Type", 32, "hex"),
                _FieldSpec("combo_pspid", "Match (PSPID)", 32, "hex"),
                _FieldSpec("combo_pointer", "Pointer", 64, "pointer"),
            ]
        if is_real_bios_dir(kind):
            # BHD/BL2 entry: 24 bytes
            # type_id (4B): Type[7:0], RegionType[15:8], flags[31:16]
            # size (4B)
            # source (8B): address[61:0], mode[63:62]
            # destination (8B)
            return [
                _FieldSpec("entry_type", "Type", 8, "hex"),
                _FieldSpec("region_type", "Region", 8, "hex"),
                _FieldSpec("reset_image", "Reset", 1, "hex"),
                _FieldSpec("copy_image", "Copy", 1, "hex"),
                _FieldSpec("read_only", "RO", 1, "hex"),
                _FieldSpec("compressed", "Comp", 1, "hex"),
                _FieldSpec("instance", "Inst", 4, "hex"),
                _FieldSpec("subprogram", "SubProg", 3, "hex"),
                _FieldSpec("rom_id", "RomID", 2, "hex"),
                _FieldSpec("writable", "Wrt", 1, "hex"),
                _FieldSpec("reserved", "Rsv", 2, "hex"),
                _FieldSpec("declared_size", "Size", 32, "uint"),
                _FieldSpec("source_address", "Source Addr", 62, "hex"),
                _FieldSpec("address_mode", "Mode", 2, "hex"),
                _FieldSpec("destination", "Destination", 64, "hex"),
            ]
        # PSP/PL2 entry: 16 bytes
        # type_id (4B): Type[7:0], SubProgram[15:8], RomId[17:16], Writable[18], Instance[22:19], Reserved[31:23]
        # size (4B)
        # location (8B): address[61:0], mode[63:62]
        return [
            _FieldSpec("entry_type", "Type(0:7)", 8, "hex"),
            _FieldSpec("subprogram", "SubProg(8:15)", 8, "hex"),
            _FieldSpec("rom_id", "RomId(16:17)", 2, "hex"),
            _FieldSpec("writable", "Wrt(18)", 1, "hex"),
            _FieldSpec("instance", "Inst(19:22)", 4, "hex"),
            _FieldSpec("reserved", "Rsv(23:31)", 9, "hex"),
            _FieldSpec("declared_size", "Size", 32, "uint"),
            _FieldSpec("address", "Address(62b)", 62, "hex"),
            _FieldSpec("address_mode", "Mode(2b)", 2, "hex"),
        ]

    def _build_rows(self, entries: List[dict]) -> List[_EntryRow]:
        normalized: List[_EntryRow] = []
        header_len = dir_header_len(self.directory.kind)
        span = entry_span(self.directory.kind)
        total = int(getattr(self.directory, "count", 0) or 0)
        if total <= 0:
            header_count = int(self._header_original.get("count", 0) or 0)
            if header_count > 0:
                total = header_count
        base_offset: Optional[int]
        try:
            base_offset = int(getattr(self.directory, "offset", None))
        except Exception:
            base_offset = None

        entry_map: Dict[int, dict] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            try:
                idx = int(entry.get("index"))
            except Exception:
                continue
            entry_map[idx] = entry

        if entry_map:
            highest_index = max(entry_map)
            if highest_index >= total:
                total = highest_index + 1
        elif entries and total <= 0:
            total = len(entries)

        if total <= 0 and isinstance(base_offset, int):
            max_entries = max(
                0,
                (len(self._image_data) - (base_offset + header_len)) // max(span, 1),
            )
            total = min(max_entries, 0x100)

        for idx in range(total):
            info = entry_map.get(idx)
            entry_offset: Optional[int] = None
            if isinstance(base_offset, int):
                candidate = base_offset + header_len + idx * span
                if 0 <= candidate <= len(self._image_data) - span:
                    entry_offset = candidate
                    if not info:
                        chunk = self._image_data[entry_offset : entry_offset + span]
                        if all(b == 0xFF for b in chunk):
                            if entry_map:
                                # Keep index placeholder when explicit entry info exists elsewhere
                                pass
                            else:
                                break
            if entry_offset is None and info:
                try:
                    candidate = int(info.get("entry_offset"))
                except Exception:
                    candidate = None
                if (
                    isinstance(candidate, int)
                    and 0 <= candidate <= len(self._image_data) - span
                ):
                    entry_offset = candidate
            original_values = self._read_entry_defaults(entry_offset, info)
            if idx == 0:
                get_logger().debug(
                    f"Entry {idx}: offset={entry_offset}, values={original_values}"
                )
            normalized.append(_EntryRow(idx, info, entry_offset, original_values))

        return normalized

    def _read_entry_defaults(
        self, entry_offset: Optional[int], entry_info: Optional[dict]
    ) -> Dict[str, Optional[int]]:
        values: Dict[str, Optional[int]] = {spec.key: None for spec in self._field_specs}
        if entry_offset is None:
            return values
        span = entry_span(self.directory.kind)
        if entry_offset < 0 or entry_offset + span > len(self._image_data):
            return values
        blob = self._image_data[entry_offset : entry_offset + span]

        def _load32(start: int) -> int:
            return int.from_bytes(blob[start : start + 4], "little", signed=False)

        def _load64(start: int) -> int:
            return int.from_bytes(blob[start : start + 8], "little", signed=False)

        if _constants.is_combo_dir(self.directory.kind):
            values["type_value"] = _load32(0)
            values["combo_pspid"] = _load32(4)
            values["combo_pointer"] = _load64(8)
        elif is_real_bios_dir(self.directory.kind):
            # BHD/BL2 entry: 24 bytes
            # Parse type_id (4 bytes) into individual bit fields
            type_id = _load32(0)
            values["entry_type"] = type_id & 0xFF                    # bits 7:0
            values["region_type"] = (type_id >> 8) & 0xFF            # bits 15:8
            values["reset_image"] = (type_id >> 16) & 0x1            # bit 16
            values["copy_image"] = (type_id >> 17) & 0x1             # bit 17
            values["read_only"] = (type_id >> 18) & 0x1              # bit 18
            values["compressed"] = (type_id >> 19) & 0x1             # bit 19
            values["instance"] = (type_id >> 20) & 0xF               # bits 23:20
            values["subprogram"] = (type_id >> 24) & 0x7             # bits 26:24
            values["rom_id"] = (type_id >> 27) & 0x3                 # bits 28:27
            values["writable"] = (type_id >> 29) & 0x1               # bit 29
            values["reserved"] = (type_id >> 30) & 0x3               # bits 31:30
            
            # Size (4 bytes)
            values["declared_size"] = _load32(4)
            
            # Source (8 bytes): address in bits 61:0, mode in bits 63:62
            source = _load64(8)
            values["source_address"] = source & ((1 << 62) - 1)      # bits 61:0
            values["address_mode"] = (source >> 62) & 0x3            # bits 63:62
            
            # Destination (8 bytes)
            values["destination"] = _load64(16)
        else:
            # PSP/PL2 entry: 16 bytes
            # Parse type_id (4 bytes) into individual bit fields
            type_id = _load32(0)
            values["entry_type"] = type_id & 0xFF                    # bits 7:0
            values["subprogram"] = (type_id >> 8) & 0xFF             # bits 15:8
            values["rom_id"] = (type_id >> 16) & 0x3                 # bits 17:16
            values["writable"] = (type_id >> 18) & 0x1               # bit 18
            values["instance"] = (type_id >> 19) & 0xF               # bits 22:19
            values["reserved"] = (type_id >> 23) & 0x1FF             # bits 31:23
            
            # Size (4 bytes)
            values["declared_size"] = _load32(4)
            
            # Location (8 bytes): address in bits 61:0, mode in bits 63:62
            location = _load64(8)
            values["address"] = location & ((1 << 62) - 1)           # bits 61:0
            values["address_mode"] = (location >> 62) & 0x3          # bits 63:62

        if entry_info:
            for key in values:
                raw = entry_info.get(key)
                if raw is None:
                    continue
                try:
                    values[key] = int(raw)
                except Exception:
                    continue

        return values

    def _extract_header_metadata(self) -> Dict[str, int]:
        offset = getattr(self.directory, "offset", None)
        try:
            off_int = int(offset)
        except Exception:
            return {}
        header_len = dir_header_len(self.directory.kind)
        if off_int < 0 or off_int + header_len > len(self._image_data):
            return {}
        header_bytes = bytes(self._image_data[off_int : off_int + header_len])
        info: Dict[str, int] = {"cookie": header_bytes[:4], "count": 0}
        try:
            header = parse_dir_header(self._image_data, off_int, self.directory.kind)
        except Exception:
            header = None
        if header is None:
            return info
        info["count"] = int(getattr(header, "Count", 0) or 0)
        if _constants.is_combo_dir(self.directory.kind):
            return info
        raw_info = int(getattr(header, "Info", 0) or 0) & 0xFFFFFFFF
        info.update(
            {
                "info": raw_info,
                "max_size": int(getattr(header, "MaxSize", 0) or 0) & 0x3FF,
                "spi_block": int(getattr(header, "SpiBlockSize", 0) or 0) & 0x0F,
                "base_bits": int(getattr(header, "BaseAddressBits", 0) or 0) & 0x7FFF,
                "address_mode": int(getattr(header, "AddressMode", 0) or 0) & 0x03,
                "reserved_bit0": raw_info & 0x1,
            }
        )
        return info

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------
    def _format_field(self, spec: _FieldSpec, value: Optional[int]) -> str:
        if spec.mode == "pointer":
            return self._format_pointer(value)
        if value is None:
            return ""
        if spec.mode == "hex":
            digits = f"{int(value) & ((1 << spec.bits) - 1):X}"
            return f"0x{digits}" if digits else "0x0"
        if spec.mode == "uint":
            return f"0x{int(value):X}"
        return str(int(value))

    @staticmethod
    def _format_pointer(value: Optional[int]) -> str:
        if value is None:
            return "0x"
        intval = int(value)
        if intval == 0:
            return "0x0"
        return f"0x{intval:X}"

    @staticmethod
    def _normalize_pointer_text(text: str) -> str:
        stripped = text.strip()
        if not stripped:
            return "0x"
        if not stripped.lower().startswith("0x"):
            stripped = f"0x{stripped}"
        prefix, tail = stripped[:2], stripped[2:]
        raw_tail = tail
        tail = tail.upper()
        trimmed = tail.lstrip("0")
        if not trimmed:
            return prefix + ("0" if raw_tail else "")
        return prefix + trimmed

    # ------------------------------------------------------------------
    # Header helpers
    # ------------------------------------------------------------------
    def _update_info_preview(self) -> None:
        if not all([self._info_value_label, self._max_size_spin, self._spi_block_spin, self._base_bits_spin]):
            return
        max_size = int(self._max_size_spin.value()) & 0x3FF
        spi_block = int(self._spi_block_spin.value()) & 0x0F
        base_bits = int(self._base_bits_spin.value()) & 0x7FFF
        address_mode = int(self._header_original.get("address_mode", 0)) & 0x03
        reserved = int(self._header_original.get("reserved_bit0", 0)) & 0x01
        info_value = (
            reserved
            | (max_size << 1)
            | (spi_block << 11)
            | (base_bits << 15)
            | (address_mode << 30)
        )
        self._info_value_label.setText(f"0x{info_value:08X}")
        
        # Update computed base address label
        if hasattr(self, "_base_addr_label") and self._base_addr_label is not None:
            base_addr = base_bits << 12
            self._base_addr_label.setText(f"0x{base_addr:08X}")

    def _collect_header_update(self) -> Optional[dict]:
        if not self._header_original:
            return None
        update: Dict[str, object] = {}
        
        # Cookie is now read-only, so we don't collect it
        
        # Collect count if changed
        if hasattr(self, "_count_spin") and self._count_spin is not None:
            new_count = int(self._count_spin.value())
            old_count = int(self._header_original.get("count", 0))
            if new_count != old_count:
                update["count"] = new_count
        
        if _constants.is_combo_dir(self.directory.kind):
            return update or None
        if not all([self._info_value_label, self._max_size_spin, self._spi_block_spin, self._base_bits_spin]):
            return update or None
        info_original = self._header_original.get("info")
        if info_original is None:
            return update or None
        max_size = int(self._max_size_spin.value()) & 0x3FF
        spi_block = int(self._spi_block_spin.value()) & 0x0F
        base_bits = int(self._base_bits_spin.value()) & 0x7FFF
        address_mode = int(self._header_original.get("address_mode", 0)) & 0x03
        reserved = int(self._header_original.get("reserved_bit0", 0)) & 0x01
        info_value = (
            reserved
            | (max_size << 1)
            | (spi_block << 11)
            | (base_bits << 15)
            | (address_mode << 30)
        ) & 0xFFFFFFFF
        if info_value != (int(info_original) & 0xFFFFFFFF):
            update.update(
                {
                    "info": info_value,
                    "max_size": max_size,
                    "spi_block": spi_block,
                    "base_bits": base_bits,
                }
            )
        return update or None

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------
    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        spec = self._column_specs.get(item.column())
        if spec is None:
            return
        text = item.text()
        normalized = text
        if spec.mode == "pointer":
            normalized = self._normalize_pointer_text(text)
        elif spec.mode == "hex" and text.strip().lower().startswith("0x"):
            prefix, tail = text.strip()[:2], text.strip()[2:]
            normalized = prefix + tail.upper()
        if normalized != text:
            if self.table is not None:
                self.table.blockSignals(True)
                item.setText(normalized)
                self.table.blockSignals(False)

    def _on_accept(self) -> None:
        try:
            operations = self.build_operations()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid value", str(exc))
            return
        self._cached_operations = operations
        self.accept()

    # ------------------------------------------------------------------
    # Operation building
    # ------------------------------------------------------------------
    def _parse_item_value(
        self, spec: _FieldSpec, item: QTableWidgetItem
    ) -> Tuple[int, bool, Optional[str]]:
        original = item.data(_ORIGINAL_ROLE)
        original_int = self._decode_original_int(original)
        text = item.text().strip()
        if spec.mode == "pointer":
            normalized = self._normalize_pointer_text(text)
            if normalized == "0x":
                if original_int is None:
                    return 0, False, "0x"
                return int(original_int), False, "0x"
            try:
                value = int(normalized, 0)
            except ValueError as exc:
                raise ValueError(f"{spec.label}: enter a hexadecimal address.") from exc
            value &= (1 << spec.bits) - 1
            changed = original_int is None or int(value) != int(original_int)
            return value, changed, normalized
        if not text:
            if original_int is None:
                return 0, False, None
            return int(original_int), False, None
        try:
            value = int(text, 0)
        except ValueError as exc:
            raise ValueError(f"{spec.label}: enter a valid integer value.") from exc
        if spec.mode == "hex":
            value &= (1 << spec.bits) - 1
        changed = original_int is None or int(value) != int(original_int)
        return value, changed, None

    def build_operations(
        self,
    ) -> Tuple[List[dict], List[int], Optional[List[int]], Optional[dict]]:
        edits: List[dict] = []
        removals: List[int] = []
        header_update = self._collect_header_update()

        if self.table is None:
            return edits, removals, None, header_update

        current_order: List[int] = []
        row_count = self.table.rowCount()
        for row_idx in range(row_count):
            index_item = self.table.item(row_idx, self._index_column)
            if index_item is None:
                continue
            entry_idx = index_item.data(_ROW_INDEX_ROLE)
            if entry_idx is None:
                continue
            entry_idx = int(entry_idx)
            current_order.append(entry_idx)

            removal_state = bool(index_item.data(_REMOVAL_FLAG_ROLE))
            if removal_state:
                removals.append(entry_idx)
                continue

            config: Dict[str, object] = {}
            pointer_text_override: Optional[str] = None
            combo_pointer_text: Optional[str] = None

            for col_idx, spec in self._column_specs.items():
                if col_idx < self._first_field_column:
                    continue
                item = self.table.item(row_idx, col_idx)
                if item is None or not (item.flags() & Qt.ItemIsEditable):
                    continue
                value, changed, text_value = self._parse_item_value(spec, item)
                if not changed:
                    continue
                config[spec.key] = value
                if spec.key == "pointer_value" and text_value is not None:
                    pointer_text_override = text_value
                elif spec.key == "combo_pointer" and text_value is not None:
                    combo_pointer_text = text_value
            if pointer_text_override is not None:
                config["pointer_text"] = pointer_text_override
            if combo_pointer_text is not None:
                config["combo_pointer_text"] = combo_pointer_text
            if config:
                get_logger().debug(f"Entry {entry_idx} has changes: {config}")
                edits.append(
                    {
                        "entry_index": entry_idx,
                        "config": config,
                        "entry_info": self._entry_info_map.get(entry_idx),
                    }
                )

        reorder: Optional[List[int]] = None
        expected = list(range(len(self._rows)))
        if current_order and current_order != expected:
            if sorted(current_order) != expected:
                raise ValueError(
                    "Entries are missing or duplicated; unable to determine new order."
                )
            reorder = current_order

        return edits, removals, reorder, header_update

    def result_operations(
        self,
    ) -> Tuple[List[dict], List[int], Optional[List[int]], Optional[dict]]:
        if self._cached_operations is not None:
            return self._cached_operations
        return self.build_operations()
    @staticmethod
    def _encode_qvariant_value(value):
        if isinstance(value, int) and not (_INT64_MIN <= value <= _INT64_MAX):
            return str(value)
        return value

    @staticmethod
    def _decode_original_int(value) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, int):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError:
                try:
                    return int(value)
                except ValueError:
                    return None
        try:
            return int(value)
        except Exception:
            return None
