# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Detail pane widgets for displaying firmware entry information.

This module provides:
    - DetailPane widget for entry details and structured tables
    - NoScrollComboBox that ignores wheel scrolling
    - Hex viewer integration
    - Soft fuse chain display
"""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import datetime
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QFontDatabase, QFontMetrics, QGuiApplication, QTextCursor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractScrollArea,
    QComboBox,
    QFileDialog,
    QHeaderView,
    QMenu,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .hex_viewer import _configure_hex_editor, _hex_dump, _update_hex_editor_selection
from ..mainwindow_components.common import _mask_u64, _to_signed_64
from ...agesa import crypto as _crypto


class NoScrollComboBox(QComboBox):
    """Combo box that ignores wheel scrolling to avoid accidental changes."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.setFocusPolicy(Qt.ClickFocus)
        self._install_line_edit_filter()

    def wheelEvent(self, event) -> None:  # type: ignore[override]
        if not self.view().isVisible():
            event.ignore()
            return
        super().wheelEvent(event)

    def setEditable(self, editable: bool) -> None:  # type: ignore[override]
        super().setEditable(editable)
        self._install_line_edit_filter()

    def eventFilter(self, obj, event):  # type: ignore[override]
        if (
            obj is self.lineEdit()
            and event.type() == QEvent.Wheel
            and not self.view().isVisible()
        ):
            event.ignore()
            return True
        return super().eventFilter(obj, event)

    def _install_line_edit_filter(self) -> None:
        editor = self.lineEdit()
        if editor is None:
            return
        editor.setFocusPolicy(Qt.ClickFocus)
        try:
            editor.removeEventFilter(self)
        except Exception:
            pass
        editor.installEventFilter(self)


class DetailPane(QWidget):
    """Composite widget used to show entry details and structured tables."""

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        *,
        on_soft_fuse_change=None,
        status_callback=None,
    ) -> None:
        super().__init__(parent)
        self.on_soft_fuse_change = on_soft_fuse_change
        self.status_callback = status_callback

        # Build UI in Python
        wrapper_layout = QVBoxLayout(self)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(6)

        self.splitter = QSplitter(Qt.Vertical, self)
        self.splitter.setObjectName("detail_splitter")
        self.splitter.setChildrenCollapsible(True)
        wrapper_layout.addWidget(self.splitter)

        # info_container with all tables
        self.info_container = QWidget(self.splitter)
        self.info_container.setObjectName("info_container")
        info_layout = QVBoxLayout(self.info_container)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(6)

        self.text = QPlainTextEdit(self.info_container)
        self.text.setObjectName("detail_text")
        self.text.setReadOnly(True)
        info_layout.addWidget(self.text)

        self.metadata_table = QTableWidget(self.info_container)
        self.metadata_table.setObjectName("metadata_table")
        self.metadata_table.setColumnCount(2)
        self.metadata_table.setRowCount(0)
        self.metadata_table.horizontalHeader().setVisible(True)
        self.metadata_table.verticalHeader().setVisible(False)
        info_layout.addWidget(self.metadata_table)

        self.soft_fuse_table = QTableWidget(self.info_container)
        self.soft_fuse_table.setObjectName("soft_fuse_table")
        self.soft_fuse_table.setColumnCount(3)
        self.soft_fuse_table.setRowCount(0)
        self.soft_fuse_table.horizontalHeader().setVisible(True)
        self.soft_fuse_table.verticalHeader().setVisible(False)
        info_layout.addWidget(self.soft_fuse_table)

        self.key_table = QTableWidget(self.info_container)
        self.key_table.setObjectName("key_table")
        self.key_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.key_table.setColumnCount(3)
        self.key_table.setRowCount(0)
        self.key_table.horizontalHeader().setVisible(True)
        self.key_table.verticalHeader().setVisible(False)
        info_layout.addWidget(self.key_table)

        # hex_view as second splitter child
        self.hex_view = QPlainTextEdit(self.splitter)
        self.hex_view.setObjectName("hex_view")
        self.hex_view.setReadOnly(True)
        self.hex_view.setVisible(False)

        self.metadata_table.setColumnCount(2)
        self.metadata_table.setHorizontalHeaderLabels(["Field", "Value"])
        self.metadata_table.verticalHeader().setVisible(False)
        self.metadata_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.metadata_table.horizontalHeader().setStretchLastSection(True)
        self.metadata_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.metadata_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.metadata_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.metadata_table.customContextMenuRequested.connect(
            self._on_metadata_context_menu
        )
        self.metadata_table.hide()

        self.soft_fuse_table.setColumnCount(3)
        self.soft_fuse_table.setHorizontalHeaderLabels(["Bit", "Value", "Action"])
        self.soft_fuse_table.verticalHeader().setVisible(False)
        self.soft_fuse_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.soft_fuse_table.hide()

        self._hex_blob: Optional[bytes] = None
        self._hex_dump_cache: Dict[bool, str] = {True: "", False: ""}
        self._hex_placeholder_message: Optional[str] = None
        self._hex_line_width = 16
        self._hex_line_width_cache: Dict[bool, int] = {True: 0, False: 0}

        self.key_table.setColumnCount(3)
        self.key_table.setHorizontalHeaderLabels(["Key ID", "Bits", "Exponent"])
        self.key_table.verticalHeader().setVisible(False)
        self.key_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.key_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.key_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.key_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.key_table.customContextMenuRequested.connect(
            self._on_key_table_context_menu
        )
        self.key_table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustIgnored)
        self.key_table.hide()

        self.hex_view.setReadOnly(True)
        self.hex_view.hide()
        self.hex_view.installEventFilter(self)
        self.hex_view.cursorPositionChanged.connect(
            self._update_hex_selection_mirror
        )
        self.hex_view.selectionChanged.connect(self._update_hex_selection_mirror)

        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)

        self._soft_fuse_info: Optional[dict] = None
        self._soft_fuse_row_map: Dict[int, int] = {}
        self._soft_fuse_action_map: Dict[int, QTableWidgetItem] = {}
        self._key_entries: List[dict] = []
        self._metadata_rows: List[Tuple[str, str]] = []
        self._fixed_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        if self._fixed_font.pointSizeF() <= 0:
            self._fixed_font.setPointSize(10)
        self.hex_view.setFont(self._fixed_font)
        self._update_splitter_sizes()

    def detach_hex_view(self) -> QPlainTextEdit:
        if hasattr(self, "splitter") and self.hex_view.parent() is self.splitter:
            try:
                self.splitter.removeWidget(self.hex_view)
            except Exception:
                pass
        self.hex_view.hide()
        self.hex_view.setParent(None)
        return self.hex_view

    def set_soft_fuse_handler(self, callback) -> None:
        self.on_soft_fuse_change = callback

    def set_status_callback(self, callback) -> None:
        self.status_callback = callback

    def clear(self) -> None:
        self.text.clear()
        self.metadata_table.setRowCount(0)
        self.metadata_table.hide()
        self.soft_fuse_table.setRowCount(0)
        self.soft_fuse_table.hide()
        self.key_table.setRowCount(0)
        self.key_table.hide()
        self.hex_view.clear()
        self.hex_view.hide()
        _configure_hex_editor(
            self.hex_view,
            blob=None,
            width=self._hex_line_width,
            include_ascii=False,
        )
        self._update_hex_selection_mirror()
        self._soft_fuse_info = None
        self._soft_fuse_row_map.clear()
        self._soft_fuse_action_map.clear()
        self._key_entries = []
        self._metadata_rows = []
        self._hex_blob = None
        self._hex_dump_cache = {True: "", False: ""}
        self._hex_placeholder_message = None
        self._hex_line_width_cache = {True: 0, False: 0}
        self._update_splitter_sizes()

    def update(
        self,
        detail_text: str,
        metadata: Optional[Dict[str, str]] = None,
        soft_fuse: Optional[dict] = None,
        key_entries: Optional[List[dict]] = None,
        hex_blob: Optional[bytes] = None,
    ) -> None:
        combined_metadata = self._merge_metadata(detail_text, metadata)
        metadata_visible = self._show_metadata(combined_metadata)
        self.text.setPlainText(detail_text or "")
        self.text.setVisible(not metadata_visible)
        self._show_soft_fuse(soft_fuse)
        self._show_key_table(key_entries)
        self._show_hex_blob(hex_blob)
        self._update_splitter_sizes()

    def _show_metadata(self, metadata: Optional[OrderedDict[str, str]]) -> bool:
        self.metadata_table.setRowCount(0)
        self._metadata_rows = []
        if not metadata:
            self.metadata_table.hide()
            return False
        for row, (field, value) in enumerate(metadata.items()):
            self.metadata_table.insertRow(row)
            field_item = QTableWidgetItem(str(field))
            field_item.setFlags(Qt.ItemIsEnabled)
            value_item = QTableWidgetItem(str(value))
            value_item.setFlags(Qt.ItemIsEnabled)
            value_item.setToolTip(str(value))
            self.metadata_table.setItem(row, 0, field_item)
            self.metadata_table.setItem(row, 1, value_item)
            self._metadata_rows.append((str(field), str(value)))
        header = self.metadata_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        self._adjust_table_height(self.metadata_table)
        self.metadata_table.show()
        self._update_splitter_sizes()
        return True

    def _merge_metadata(
        self, detail_text: Optional[str], metadata: Optional[Dict[str, str]]
    ) -> OrderedDict[str, str]:
        merged: OrderedDict[str, str] = OrderedDict()
        if isinstance(metadata, dict):
            for field, value in metadata.items():
                merged[str(field)] = self._stringify_metadata_value(value)
        parsed = self._parse_detail_text(detail_text)
        for field, value in parsed.items():
            merged.setdefault(field, value)
        return merged

    def _stringify_metadata_value(self, value) -> str:
        if value is None:
            return "-"
        if isinstance(value, (list, tuple)):
            return ", ".join(self._stringify_metadata_value(v) for v in value)
        if isinstance(value, Enum):
            return str(value.value)
        return str(value)

    def _parse_detail_text(self, detail_text: Optional[str]) -> OrderedDict[str, str]:
        parsed: OrderedDict[str, str] = OrderedDict()
        if not detail_text:
            return parsed

        current_key: Optional[str] = None
        buffer: List[str] = []

        def _flush() -> None:
            nonlocal current_key, buffer
            if current_key is None:
                buffer.clear()
                return
            text = "\n".join(token for token in buffer if token).strip()
            if not text:
                text = "-"
            if current_key in parsed:
                existing = parsed[current_key]
                if text and text not in existing.splitlines():
                    parsed[current_key] = f"{existing}\n{text}" if existing else text
            else:
                parsed[current_key] = text
            current_key = None
            buffer = []

        for line in detail_text.splitlines():
            raw = line.rstrip()
            stripped = raw.strip()
            if not stripped:
                _flush()
                continue
            colon_pos = raw.find(":")
            if (
                colon_pos > 0
                and not raw.lstrip().startswith("- ")
            ):
                _flush()
                key = raw[:colon_pos].strip()
                value = raw[colon_pos + 1 :].strip()
                current_key = key or f"Field {len(parsed) + 1}"
                buffer = [value]
                continue
            if current_key is not None:
                buffer.append(stripped)
            else:
                field_name = f"Field {len(parsed) + 1}"
                parsed[field_name] = stripped
        _flush()
        return parsed

    def _show_soft_fuse(self, data: Optional[dict]) -> None:
        self.soft_fuse_table.setRowCount(0)
        self._soft_fuse_info = None
        self._soft_fuse_row_map.clear()
        self._soft_fuse_action_map.clear()
        if not data:
            self.soft_fuse_table.hide()
            return
        chain = data.get("chain")
        if chain is None or not getattr(chain, "fields", None):
            self.soft_fuse_table.hide()
            return
        raw_source = data.get("raw_u64", data.get("raw", getattr(chain, "raw_value", 0)))
        raw_value = _mask_u64(raw_source)
        fields = list(getattr(chain, "fields", []))
        self._soft_fuse_info = dict(data)
        self._soft_fuse_info["raw_u64"] = raw_value
        self._soft_fuse_info["raw"] = _to_signed_64(raw_value)
        self._soft_fuse_info["fields"] = fields

        reserved_bits = list(getattr(chain, "reserved_bits", []))
        self._soft_fuse_info["reserved_bits"] = reserved_bits

        self.soft_fuse_table.setRowCount(len(fields) + len(reserved_bits) + 1)
        raw_label = QTableWidgetItem("Raw Value")
        raw_label.setFlags(Qt.ItemIsEnabled)
        raw_value_item = QTableWidgetItem(f"0x{raw_value:016X}")
        raw_value_item.setFlags(Qt.ItemIsEnabled)
        self.soft_fuse_table.setItem(0, 0, raw_label)
        self.soft_fuse_table.setItem(0, 1, raw_value_item)
        self.soft_fuse_table.setItem(0, 2, QTableWidgetItem(""))
        for idx, field in enumerate(fields, start=1):
            bit_item = QTableWidgetItem(str(field.bit))
            bit_item.setFlags(Qt.ItemIsEnabled)
            self.soft_fuse_table.setItem(idx, 0, bit_item)
            combo = NoScrollComboBox(self.soft_fuse_table)
            combo.setEditable(True)
            combo.addItem(f"0x00 - {field.zero_label}", 0)
            combo.addItem(f"0x01 - {field.one_label}", 1)
            current_value = 1 if raw_value & (1 << field.bit) else 0
            current_index = combo.findData(current_value)
            combo.setCurrentIndex(
                current_index if current_index >= 0 else current_value
            )
            combo.currentIndexChanged.connect(
                partial(self._on_soft_fuse_combo_changed, field.bit)
            )
            self.soft_fuse_table.setCellWidget(idx, 1, combo)
            self._soft_fuse_row_map[field.bit] = idx
            action_item = QTableWidgetItem("-")
            action_item.setFlags(Qt.ItemIsEnabled)
            action_item.setToolTip("No changes queued")
            self.soft_fuse_table.setItem(idx, 2, action_item)
            self._soft_fuse_action_map[field.bit] = action_item
        if reserved_bits:
            for offset, bit in enumerate(reserved_bits, start=len(fields) + 1):
                bit_item = QTableWidgetItem(str(bit))
                bit_item.setFlags(Qt.ItemIsEnabled)
                self.soft_fuse_table.setItem(offset, 0, bit_item)
                value = 1 if raw_value & (1 << bit) else 0
                value_item = QTableWidgetItem(str(value))
                value_item.setFlags(Qt.ItemIsEnabled)
                self.soft_fuse_table.setItem(offset, 1, value_item)
                self.soft_fuse_table.setItem(offset, 2, QTableWidgetItem(""))
        header = self.soft_fuse_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        self._adjust_table_height(self.soft_fuse_table)
        self.soft_fuse_table.show()
        self._update_splitter_sizes()

    def _show_key_table(self, key_entries: Optional[List[dict]]) -> None:
        self.key_table.setRowCount(0)
        self._key_entries = []
        if not key_entries:
            self.key_table.hide()
            return
        self._key_entries = list(key_entries)
        for row, entry in enumerate(self._key_entries):
            self.key_table.insertRow(row)
            key_id = entry.get("key_id", b"")
            bits = entry.get("bits")
            exponent = entry.get("exponent")
            key_item = QTableWidgetItem(key_id.hex().upper())
            key_item.setFlags(Qt.ItemIsEnabled)
            bits_item = QTableWidgetItem(str(bits) if bits is not None else "-")
            bits_item.setFlags(Qt.ItemIsEnabled)
            exp_item = QTableWidgetItem(
                f"0x{int(exponent):X}" if exponent is not None else "-"
            )
            exp_item.setFlags(Qt.ItemIsEnabled)
            self.key_table.setItem(row, 0, key_item)
            self.key_table.setItem(row, 1, bits_item)
            self.key_table.setItem(row, 2, exp_item)
        header = self.key_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        self._adjust_table_height(self.key_table, max_height=280)
        self.key_table.show()
        self._update_splitter_sizes()

    def _show_hex_blob(self, blob: Optional[bytes]) -> None:
        self._hex_placeholder_message = None
        if not blob:
            self._hex_blob = None
            self._hex_dump_cache = {True: "", False: ""}
            self.hex_view.clear()
            self.hex_view.hide()
            _configure_hex_editor(
                self.hex_view,
                blob=None,
                width=self._hex_line_width,
                include_ascii=False,
            )
            self._update_hex_selection_mirror()
            self._update_splitter_sizes()
            return
        if len(blob) > 1_048_576:
            message = "HEX view disabled for payloads larger than 1 MiB."
            self._hex_blob = None
            self._hex_dump_cache = {True: "", False: ""}
            self._hex_placeholder_message = message
            self.hex_view.setPlainText(message)
            _configure_hex_editor(
                self.hex_view,
                blob=None,
                width=self._hex_line_width,
                include_ascii=False,
            )
            self._update_hex_selection_mirror()
            self.hex_view.show()
            self._update_splitter_sizes()
            return
        self._hex_blob = bytes(blob)
        self._hex_dump_cache = {
            True: _hex_dump(self._hex_blob, width=self._hex_line_width, include_ascii=True),
            False: _hex_dump(
                self._hex_blob, width=self._hex_line_width, include_ascii=False
            ),
        }
        self._hex_line_width_cache = {True: 0, False: 0}
        self._apply_hex_dump()
        self.hex_view.show()
        self._update_hex_selection_mirror()
        self._update_splitter_sizes()

    def _apply_hex_dump(self) -> None:
        if self._hex_placeholder_message is not None:
            _configure_hex_editor(
                self.hex_view,
                blob=None,
                width=self._hex_line_width,
                include_ascii=False,
            )
            return
        if self._hex_blob is None:
            _configure_hex_editor(
                self.hex_view,
                blob=None,
                width=self._hex_line_width,
                include_ascii=False,
            )
            return
        include_ascii = self._should_show_ascii()
        text = self._hex_dump_cache.get(include_ascii, "")
        if self.hex_view.toPlainText() != text:
            self.hex_view.setPlainText(text)
        _configure_hex_editor(
            self.hex_view,
            blob=self._hex_blob,
            width=self._hex_line_width,
            include_ascii=include_ascii,
        )
        self._update_hex_selection_mirror()

    def _update_hex_selection_mirror(self) -> None:
        editor = getattr(self, "hex_view", None)
        if editor is None:
            return
        if not editor.isVisible():
            editor.setExtraSelections([])
            return
        _update_hex_editor_selection(editor)

    def _should_show_ascii(self) -> bool:
        viewport = self.hex_view.viewport()
        available = viewport.width()
        if available <= 0:
            return True
        ascii_width = self._estimate_line_width(True)
        metrics = QFontMetrics(self.hex_view.font())
        padding = metrics.horizontalAdvance("  ")
        if ascii_width and ascii_width + padding <= available:
            return True
        base_width = self._estimate_line_width(False)
        if base_width + padding <= available:
            return False
        return False

    def _estimate_line_width(self, include_ascii: bool) -> int:
        cached = self._hex_line_width_cache.get(include_ascii)
        if cached:
            return cached
        sample = bytes(range(self._hex_line_width))
        dump = _hex_dump(sample, width=self._hex_line_width, include_ascii=include_ascii)
        sample_line = ""
        for line in dump.splitlines():
            stripped = line.strip()
            if not stripped or line.startswith("Offset"):
                continue
            if set(stripped) <= {"-"}:
                continue
            sample_line = line
            break
        metrics = QFontMetrics(self.hex_view.font())
        width = metrics.horizontalAdvance(sample_line) if sample_line else 0
        self._hex_line_width_cache[include_ascii] = width
        return width

    def _update_splitter_sizes(self) -> None:
        splitter = getattr(self, "splitter", None)
        if splitter is None:
            return
        if self.hex_view.parent() is not splitter:
            return
        if not splitter.isVisible():
            return
        if not self.hex_view.isVisible():
            total = splitter.height() or self.height() or 0
            if total > 0:
                splitter.setSizes([total, 0])
            return
        total = splitter.height() or self.height() or 0
        if total <= 0:
            return
        info_height = max(int(total * 0.55), 160)
        hex_height = max(total - info_height, 120)
        splitter.setSizes([info_height, hex_height])

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._update_splitter_sizes()

    def eventFilter(self, obj, event):  # type: ignore[override]
        if obj is self.hex_view and event is not None:
            etype = event.type()
            if etype == QEvent.Resize or etype == QEvent.FontChange:
                self._hex_line_width_cache = {True: 0, False: 0}
                self._apply_hex_dump()
        return super().eventFilter(obj, event)

    def _normalize_soft_fuse_value(self, value, text: Optional[str]) -> int:
        if isinstance(value, bool):
            return 1 if value else 0
        if isinstance(value, int):
            return int(value) & 1
        candidates: List[str] = []
        if isinstance(value, str):
            candidates.append(value)
        if isinstance(text, str):
            candidates.append(text)
        for candidate in candidates:
            match = re.match(r"\s*(0x[0-9A-Fa-f]+|\d+)", candidate)
            if match:
                token = match.group(1)
                try:
                    return int(token, 0) & 1
                except Exception:
                    continue
        return 0

    def _on_soft_fuse_combo_changed(self, bit: int, index: int) -> None:
        if self._soft_fuse_info is None:
            return
        combo = self.sender()
        # Use currentData() instead of itemData(index) for editable combos
        # When user types in the combo, index may not correspond to actual selection
        try:
            value = combo.currentData()  # type: ignore[attr-defined]
        except Exception:
            value = None
        text = ""
        try:
            text = combo.currentText()  # type: ignore[call-arg]
        except Exception:
            text = ""
        value = self._normalize_soft_fuse_value(value, text)
        current_raw = _mask_u64(
            self._soft_fuse_info.get("raw_u64", self._soft_fuse_info.get("raw", 0))
        )
        old_value = 1 if current_raw & (1 << bit) else 0
        raw = current_raw
        if value:
            raw |= 1 << bit
        else:
            raw &= ~(1 << bit)
        raw = _mask_u64(raw)
        self._soft_fuse_info["previous_raw"] = current_raw
        self._soft_fuse_info["raw_u64"] = raw
        self._soft_fuse_info["raw"] = _to_signed_64(raw)
        raw_item = self.soft_fuse_table.item(0, 1)
        if raw_item is not None:
            raw_item.setText(f"0x{raw:016X}")
        action_item = self._soft_fuse_action_map.get(bit)
        if isinstance(action_item, QTableWidgetItem):
            action_item.setText("modify")
        self._update_pointer_line(raw)
        fields = self._soft_fuse_info.get("fields", [])
        field = next((f for f in fields if f.bit == bit), None)
        label_text = self._soft_fuse_label(field) if field is not None else f"Bit {bit}"
        new_value = int(value) & 1
        if isinstance(action_item, QTableWidgetItem):
            action_item.setToolTip(f"{label_text}: {old_value} -> {new_value}")
        if self.on_soft_fuse_change:
            try:
                self.on_soft_fuse_change(
                    self._soft_fuse_info,
                    raw,
                    bit,
                    old_value,
                    new_value,
                    label_text,
                )
            except Exception as exc:
                self._emit_status(str(exc))
        else:
            self._emit_status(
                f"Soft Fuse change queued ({label_text}: {old_value} -> {new_value})"
            )

    def _soft_fuse_label(self, field) -> str:
        if field is None:
            return ""
        zero = getattr(field, "zero_label", "") or ""
        one = getattr(field, "one_label", "") or ""
        prefix_chars: List[str] = []
        for a, b in zip(zero, one):
            if a.lower() != b.lower():
                break
            prefix_chars.append(a)
        base = "".join(prefix_chars).strip(" -:;,")
        if not base:
            for candidate in (zero, one):
                text = candidate or ""
                lowered = text.lower()
                for suffix in (
                    " disabled",
                    " enabled",
                    " not passed",
                    " requested",
                ):
                    if lowered.endswith(suffix):
                        text = text[: -len(suffix)].strip()
                        break
                if text:
                    base = text
                    break
        if not base:
            base = zero or one or f"Bit {getattr(field, 'bit', '?')}"
        return base

    def _update_pointer_line(self, raw: int) -> None:
        text = self.text.toPlainText()
        if not text:
            return
        lines = text.splitlines()
        updated = False
        for idx, line in enumerate(lines):
            if line.startswith("Pointer:"):
                lines[idx] = f"Pointer: 0x{raw:016X}"
                updated = True
                break
        if updated:
            self.text.blockSignals(True)
            self.text.setPlainText("\n".join(lines))
            self.text.blockSignals(False)

    def _on_metadata_context_menu(self, pos) -> None:
        if not self._metadata_rows:
            return
        table = self.metadata_table
        indexes = table.selectedIndexes()
        rows = sorted({index.row() for index in indexes if index.isValid()})
        if not rows:
            clicked = table.indexAt(pos)
            if not clicked.isValid():
                return
            rows = [clicked.row()]
            table.selectRow(clicked.row())
        menu = QMenu(table)
        copy_field = menu.addAction("Copy field name")
        copy_value = menu.addAction("Copy field value")
        copy_pair = menu.addAction("Copy field + value")
        menu.addSeparator()
        copy_all = menu.addAction("Copy all rows")
        chosen = menu.exec_(table.mapToGlobal(pos))
        if chosen is None:
            return
        if chosen == copy_all:
            text = self._format_metadata_rows(range(len(self._metadata_rows)))
        elif chosen == copy_field:
            text = "\n".join(self._metadata_rows[row][0] for row in rows)
        elif chosen == copy_value:
            text = "\n".join(self._metadata_rows[row][1] for row in rows)
        else:
            text = self._format_metadata_rows(rows)
        if not text:
            return
        QGuiApplication.clipboard().setText(text)
        if chosen == copy_all:
            self._emit_status("All metadata copied to clipboard")
        elif chosen == copy_field:
            self._emit_status("Field name copied to clipboard")
        elif chosen == copy_value:
            self._emit_status("Field value copied to clipboard")
        else:
            self._emit_status("Field and value copied to clipboard")

    def _format_metadata_rows(self, rows: Iterable[int]) -> str:
        parts: List[str] = []
        for row in rows:
            if not (0 <= row < len(self._metadata_rows)):
                continue
            field, value = self._metadata_rows[row]
            if value and value != "-":
                parts.append(f"{field}: {value}")
            else:
                parts.append(field)
        return "\n".join(parts)

    def _on_key_table_context_menu(self, pos) -> None:
        if not self._key_entries:
            return
        row = self.key_table.indexAt(pos).row()
        if not (0 <= row < len(self._key_entries)):
            row = self.key_table.currentRow()
        if not (0 <= row < len(self._key_entries)):
            return
        entry = self._key_entries[row]
        menu = QMenu(self.key_table)
        copy_raw = menu.addAction("Copy Key (Raw HEX)")
        copy_pem = menu.addAction("Copy Key (PEM)")
        copy_id = menu.addAction("Copy ID (Hex)")
        export_pem = menu.addAction("Export (PEM)")
        chosen = menu.exec_(self.key_table.mapToGlobal(pos))
        if chosen is None:
            return
        pub = _crypto.PublicKey(
            int.from_bytes(entry["modulus"], "big"), int(entry["exponent"])
        )
        if chosen == copy_raw:
            der_hex = _crypto.public_key_to_der(pub).hex().upper()
            QGuiApplication.clipboard().setText(der_hex)
            self._emit_status("Key DER copied to clipboard")
        elif chosen == copy_pem:
            pem = _crypto.public_key_to_pem(pub).decode("ascii")
            QGuiApplication.clipboard().setText(pem)
            self._emit_status("Key PEM copied to clipboard")
        elif chosen == copy_id:
            QGuiApplication.clipboard().setText(entry["key_id"].hex().upper())
            self._emit_status("Key ID copied to clipboard")
        elif chosen == export_pem:
            default_name = f"{entry['key_id'].hex().upper()}_pub.pem"
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export public key",
                str(Path.cwd() / default_name),
                "PEM files (*.pem);;All files (*)",
            )
            if file_path:
                Path(file_path).write_bytes(_crypto.public_key_to_pem(pub))
                self._emit_status(f"Exported PEM to {file_path}")

    def _adjust_table_height(
        self, table: QTableWidget, max_height: Optional[int] = None
    ) -> None:
        table.resizeRowsToContents()
        height = table.horizontalHeader().height()
        for row in range(table.rowCount()):
            height += table.rowHeight(row)
        height += table.frameWidth() * 2 + 6
        if max_height is not None:
            final_height = min(height, int(max_height))
            table.setMaximumHeight(int(max_height))
        else:
            final_height = height
            table.setMaximumHeight(16777215)
        table.setMinimumHeight(final_height)

    def _append_console(self, message: str) -> None:
        if not message:
            return
        console = getattr(self, "console", None)
        if console is None:
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        console.appendPlainText(f"[{timestamp}] {message}")
        cursor = console.textCursor()
        cursor.movePosition(QTextCursor.End)
        console.setTextCursor(cursor)
        console.ensureCursorVisible()

    def _emit_status(self, message: str) -> None:
        if not message:
            return
        if self.status_callback:
            self.status_callback(message)
