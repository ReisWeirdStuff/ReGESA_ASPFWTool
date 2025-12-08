# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Microcode metadata display dialog.

This module provides:
    - MicrocodeDetailsDialog: Modal dialog for displaying parsed microcode
      patch metadata including date, revision, and processor information.
"""

from __future__ import annotations

from dataclasses import fields

from .qt import (
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    Qt,
)
from ...agesa.microcode import MicrocodeHeader


_FIELD_LABELS = {
    "date": "Date",
    "update_revision": "Update revision",
    "loader_id": "Loader ID",
    "data_size": "Data size",
    "initialization_flag": "Initialization flag",
    "data_checksum": "Data checksum",
    "northbridge_vendor_id": "Northbridge vendor ID",
    "northbridge_device_id": "Northbridge device ID",
    "southbridge_vendor_id": "Southbridge vendor ID",
    "southbridge_device_id": "Southbridge device ID",
    "processor_signature": "Processor signature",
    "cpuid": "CPUID",
    "northbridge_revision_id": "Northbridge revision ID",
    "southbridge_revision_id": "Southbridge revision ID",
    "bios_api_revision": "BIOS API revision",
    "load_control": "Load control",
    "reserved_1e": "Reserved 0x1E",
    "reserved_1f": "Reserved 0x1F",
}


_HEX_ONLY_FIELDS = {"data_checksum"}
_DATE_CODE_FIELDS = {"year", "month", "day"}
_DECIMAL_FIELDS = {"data_size"}


def _hex_digits(value: int, width: int) -> str:
    return f"{int(value) & ((1 << (width * 4)) - 1):0{width}X}"


class MicrocodeDetailsDialog(QDialog):
    """Modal dialog presenting decoded microcode patch metadata."""

    def __init__(
        self,
        parent: QWidget,
        *,
        header: MicrocodeHeader,
        payload_size: int,
        label: str,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Microcode Details - {label}")
        self.setAttribute(Qt.WA_DeleteOnClose, True)

        # Build UI in Python
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        summary_label = QLabel(self)
        summary_label.setObjectName("summary_label")
        layout.addWidget(summary_label)

        field_table = QTableWidget(self)
        field_table.setObjectName("field_table")
        field_table.setColumnCount(2)
        layout.addWidget(field_table)

        button_box = QDialogButtonBox(QDialogButtonBox.Close, self)
        button_box.setObjectName("button_box")
        layout.addWidget(button_box)

        button_box.rejected.connect(self.reject)
        close_button = button_box.button(QDialogButtonBox.Close)
        if close_button is not None:
            close_button.setAutoDefault(True)
            close_button.setDefault(True)

        summary_label.setText(self._build_summary(header, payload_size))
        self._populate_table(field_table, header)

    def _build_summary(self, header: MicrocodeHeader, payload_size: int) -> str:
        year, month, day = header.date_tuple
        year_txt = _hex_digits(year, 4)
        month_txt = _hex_digits(month, 2)
        day_txt = _hex_digits(day, 2)
        date_text = f"{day_txt}/{month_txt}/{year_txt}"
        revision_text = f"0x{header.update_revision:08X}"
        loader_text = f"0x{header.loader_id:04X}"
        body_size = max(payload_size - 0x20, 0)
        if header.data_size:
            declared = f"Declared data: 0x{header.data_size:02X} ({header.data_size})"
        else:
            declared = "Declared data: n/a"
        return (
            f"Date: {date_text} | Revision: {revision_text} | Loader ID: {loader_text}\n"
            f"Payload size: {payload_size} bytes (body {body_size} bytes) | {declared}"
        )

    def _populate_table(self, table: QTableWidget, header: MicrocodeHeader) -> None:
        table.setRowCount(0)
        table.setColumnCount(2)
        table.verticalHeader().setVisible(False)
        header_view = table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.Stretch)

        cpuid_text = getattr(header, "cpuid", None)
        row_index = 0
        if isinstance(cpuid_text, str) and cpuid_text:
            table.insertRow(row_index)
            label_item = QTableWidgetItem(_FIELD_LABELS.get("cpuid", "CPUID"))
            value_item = QTableWidgetItem(cpuid_text)
            value_item.setToolTip(cpuid_text)
            table.setItem(row_index, 0, label_item)
            table.setItem(row_index, 1, value_item)
            row_index += 1

        date_text = self._format_value("date", header.date_tuple)
        table.insertRow(row_index)
        label_item = QTableWidgetItem(_FIELD_LABELS.get("date", "Date"))
        value_item = QTableWidgetItem(date_text)
        value_item.setToolTip(date_text)
        table.setItem(row_index, 0, label_item)
        table.setItem(row_index, 1, value_item)
        row_index += 1

        for field in fields(header):
            if field.name in {"year", "month", "day"}:
                continue
            name = field.name
            label = _FIELD_LABELS.get(name, name)
            value = getattr(header, name)
            display = self._format_value(name, value)
            table.insertRow(row_index)
            label_item = QTableWidgetItem(label)
            value_item = QTableWidgetItem(display)
            value_item.setToolTip(display)
            table.setItem(row_index, 0, label_item)
            table.setItem(row_index, 1, value_item)
            row_index += 1

        table.resizeRowsToContents()

    def _format_value(self, name: str, value) -> str:
        if isinstance(value, str):
            return value
        if name == "date" and isinstance(value, tuple):
            year, month, day = value
            year_txt = _hex_digits(year, 4)
            month_txt = _hex_digits(month, 2)
            day_txt = _hex_digits(day, 2)
            return f"{day_txt}/{month_txt}/{year_txt}"
        if name in _DATE_CODE_FIELDS:
            decoded = int(value) & 0xFFFF
            return f"0x{decoded:04X} ({decoded})"
        if name in _DECIMAL_FIELDS:
            return str(int(value))
        if name in _HEX_ONLY_FIELDS:
            return f"0x{int(value):08X}"
        return f"0x{int(value):04X} ({int(value)})"
