# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
EFS (Embedded Firmware Structure) tab widget helpers.

This module provides:
    - EFS field display and editing widgets
    - SPI configuration tables
    - eSPI configuration handling
    - UBU action table display
"""

from __future__ import annotations

from functools import partial
from typing import Callable, Dict, Optional, Sequence, Tuple, TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QAbstractItemView,
    QComboBox,
    QGroupBox,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..widgets.detail_pane import NoScrollComboBox

from ...agesa.efs import (
    EfsInfo,
    EfsPointerStatus,
    EspiInfo,
    UbuInfo,
    ESPI_ALERT_MODE_TABLE,
    ESPI_DATA_BUS_TABLE,
    ESPI_CLOCK_PIN_TABLE,
    ESPI_DEVICE_CAP_TABLE,
    ESPI_IO_MODE_TABLE,
    ESPI_FREQ_TABLE,
    SPI_FASTSPEED_TABLE,
    SPI_MICRON_TABLE,
    SPI_QPR_DUMMY_TABLE,
    SPI_READMODE_TABLE,
    UBU_ACTION_AFTER_TABLE,
    UBU_ACTION_LED_TABLE,
    UBU_ACTION_BEEP_TABLE,
)

if TYPE_CHECKING:  # pragma: no cover - typing helpers only
    from ..mainwindow_components.controller import MainWindow

EFS_POINTER_FIELDS: Dict[str, str] = {
    "IMC FW": "IMC_FW_Address_Legacy",
    "GbE FW": "GBE_FW_Address_Legacy",
    "xHCI FW": "xHCI_FW_Address_Legacy",
    "Prom FW": "Prom_FW",
    "LP Prom FW": "LP_Prom_FW",
    "PSP Combo": "PSP_Directory_Table_Combo",
    "PSP Legacy": "PSP_Directory_Table_Legacy",
    "PSP L1 Backup": "PSP_L1_Backup",
    "BIOS Combo": "BIOS_Directory_Combo",
    "BIOS F17h M30h": "BIOS_Directory_F17h_M30h",
    "BIOS F17h M10h": "BIOS_Directory_F17h_M10h",
    "BIOS F17h M00h": "BIOS_Directory_F17h_M00h",
}

EFS_FIELD_OFFSETS: Dict[str, int] = {
    "IMC_FW_Address_Legacy": 0x04,
    "GBE_FW_Address_Legacy": 0x08,
    "xHCI_FW_Address_Legacy": 0x0C,
    "PSP_Directory_Table_Legacy": 0x10,
    "PSP_Directory_Table_Combo": 0x14,
    "BIOS_Directory_F17h_M00h": 0x18,
    "BIOS_Directory_F17h_M10h": 0x1C,
    "BIOS_Directory_F17h_M30h": 0x20,
    "EFS_Generation": 0x24,
    "BIOS_Directory_Combo": 0x28,
    "PSP_L1_Backup": 0x2C,
    "Prom_FW": 0x30,
    "LP_Prom_FW": 0x34,
}

SPI_FIELD_TABLES: Dict[str, Dict[int, str]] = {
    "SPI_ReadMode_F15h_M60h": SPI_READMODE_TABLE,
    "SPI_FastSpeed_F15h_M60h": SPI_FASTSPEED_TABLE,
    "SPI_ReadMode_F17h_M00h": SPI_READMODE_TABLE,
    "SPI_FastSpeed_F17h_M00h": SPI_FASTSPEED_TABLE,
    "QPR_Dummy_Cycle_F17h_M00h": SPI_QPR_DUMMY_TABLE,
    "SPI_ReadMode_F17h_M30h": SPI_READMODE_TABLE,
    "SPI_FastSpeed_F17h_M30h": SPI_FASTSPEED_TABLE,
    "SPI_Micron_Detect_F17h_M30h": SPI_MICRON_TABLE,
}

EFS_SPI_FIELD_OFFSETS: Dict[str, int] = {
    "SPI_ReadMode_F15h_M60h": 0x40,
    "SPI_FastSpeed_F15h_M60h": 0x41,
    "SPI_ReadMode_F17h_M00h": 0x43,
    "SPI_FastSpeed_F17h_M00h": 0x44,
    "QPR_Dummy_Cycle_F17h_M00h": 0x45,
    "SPI_ReadMode_F17h_M30h": 0x47,
    "SPI_FastSpeed_F17h_M30h": 0x48,
    "SPI_Micron_Detect_F17h_M30h": 0x49,
}

# eSPI field offsets relative to EFS base (at 0x50-0x53)
ESPI_FIELD_OFFSETS: Dict[str, int] = {
    "eSPI0": 0x50,
    "eSPI1": 0x51,
    "eSPI0_Config": 0x52,
    "eSPI1_Config": 0x53,
}

# eSPI0/eSPI1 channel bit field definitions (within single byte)
ESPI_CHANNEL_FIELDS = [
    ("Valid", 0, 1, {0: "No", 1: "Yes"}),
    ("Port 80", 1, 1, {0: "Disabled", 1: "Enabled"}),
    ("Alert Mode", 2, 1, ESPI_ALERT_MODE_TABLE),
    ("Data Bus", 3, 1, ESPI_DATA_BUS_TABLE),
    ("Clock", 4, 1, ESPI_CLOCK_PIN_TABLE),
    ("Device Cap", 5, 1, ESPI_DEVICE_CAP_TABLE),
    ("IO Mode", 6, 2, ESPI_IO_MODE_TABLE),
]

# eSPI Config bit field definitions (within single byte)
ESPI_CONFIG_FIELDS = [
    ("Enhancement", 0, 1, {0: "Disabled", 1: "Enabled"}),
    ("Frequency", 1, 3, ESPI_FREQ_TABLE),
]

# UBU field offsets relative to UBU table base
UBU_FIELD_OFFSETS: Dict[str, int] = {
    "UBU_ActionAfter": 0x0B,  # bits 0-1 of Action byte
    "UBU_LED": 0x0B,          # bit 2 of Action byte
    "UBU_Beep": 0x0B,         # bit 3 of Action byte
}

UBU_FIELD_TABLES: Dict[str, Dict[int, str]] = {
    "UBU_ActionAfter": UBU_ACTION_AFTER_TABLE,
    "UBU_LED": UBU_ACTION_LED_TABLE,
    "UBU_Beep": UBU_ACTION_BEEP_TABLE,
}

POINTER_STATUS_HEADERS: Sequence[str] = [
    "Raw",
    "Normalized",
    "Cookie",
    "Expects dir",
    "In range",
    "Valid",
]

POINTER_STATUS_COLUMN_WIDTHS: Dict[str, int] = {
    "Raw": 140,
    "Normalized": 120,
    "Cookie": 160,
    "Expects dir": 100,
    "In range": 100,
    "Valid": 90,
}

POINTER_COLUMN_WIDTHS: Dict[int, int] = {
    0: 170,  # Pointer label
    1: 140,  # Value editor
}

POINTER_QUEUE_COLUMN_WIDTH = 130
POINTER_ACTION_COLUMN_WIDTH = 110


def _format_bitfield(
    value: int, *, width: Optional[int] = None, group: int = 4
) -> str:
    raw = int(value)
    if width is not None and width > 0:
        mask = (1 << width) - 1
        raw &= mask
        pad_width = width
    else:
        pad_width = max(raw.bit_length(), 1)
    bits = f"{raw:0{pad_width}b}"
    if group > 0:
        return " ".join(bits[i : i + group] for i in range(0, len(bits), group))
    return bits


def _format_pointer_status(status: Optional[EfsPointerStatus]) -> str:
    if status is None:
        return "Pointer status unavailable"
    normalized = "-" if status.normalized is None else f"0x{int(status.normalized):X}"
    cookie = status.cookie.value if status.cookie else "-"
    expects = "yes" if status.expects_directory else "no"
    valid = "yes" if status.valid else "no"
    in_range = "yes" if status.in_range else "no"
    return (
        f"raw=0x{status.raw_value & 0xFFFFFFFF:08X} normalized={normalized} "
        f"expects_dir={expects} in_range={in_range} cookie={cookie} valid={valid}"
    )


class EfsTabController:
    """Encapsulates the dynamic EFS tab widgets and interactions."""

    def __init__(
        self,
        window: "MainWindow",
        efs_scroll: QScrollArea,
        efs_layout: QVBoxLayout,
        *,
        container_get: Callable[[object, str], object | None],
        format_optional_hex: Callable[[Optional[int]], str],
    ) -> None:
        self.window = window
        self.efs_scroll = efs_scroll
        self.efs_layout = efs_layout
        self._container_get = container_get
        self._format_optional_hex = format_optional_hex
        self.field_widgets: Dict[Tuple[int, int], Dict[str, Dict[str, object]]] = {}

        self.efs_layout.setContentsMargins(12, 12, 12, 12)
        self.efs_layout.setSpacing(12)

    # ------------------------------------------------------------------
    # Public API

    def refresh(self) -> None:
        self._clear_layout(self.efs_layout)
        self.clear_field_widgets()
        window = self.window

        if not window.loaded_images:
            empty = QLabel("No firmware loaded.")
            empty.setAlignment(Qt.AlignCenter)
            self.efs_layout.addWidget(empty)
            self.efs_layout.addStretch()
            return

        image_count = len(window.loaded_images)
        active = getattr(window, "_active_image_index", None)
        if active is not None and 0 <= active < image_count:
            indices = [active]
        else:
            indices = list(range(image_count))
        display_count = len(indices)
        for image_index in indices:
            image = window.loaded_images[image_index]
            if display_count == 1:
                title = "Embedded Firmware Structure"
            else:
                title = f"Image #{image_index + 1}"
            group = QGroupBox(title)
            group_layout = QVBoxLayout(group)

            if image.efs_infos:
                for efs_info in image.efs_infos:
                    group_layout.addWidget(
                        self._build_efs_section(image_index, efs_info)
                    )
            else:
                no_efs = QLabel("No Embedded Firmware Structure located.")
                no_efs.setWordWrap(True)
                group_layout.addWidget(no_efs)

            self.efs_layout.addWidget(group)

        self.efs_layout.addStretch()

    def clear_field_widgets(self) -> None:
        self.field_widgets.clear()

    def get_field_widgets(
        self, image_index: int, efs_offset: int
    ) -> Optional[Dict[str, Dict[str, object]]]:
        return self.field_widgets.get((image_index, efs_offset))

    def write_efs_value(
        self,
        image_index: int,
        efs_offset: int,
        field_name: str,
        value: int,
        width: int,
        previous: Optional[int],
        *,
        kind: str,
    ) -> bool:
        return self._write_efs_value(
            image_index,
            efs_offset,
            field_name,
            value,
            width,
            previous,
            kind=kind,
        )

    def update_pointer_display(
        self,
        image_index: int,
        efs_offset: int,
        field_name: str,
        previous: Optional[int],
        value: int,
    ) -> None:
        bundle = self.field_widgets.get((image_index, efs_offset), {})
        editor = bundle.get("pointers", {}).get(field_name)
        if isinstance(editor, QLineEdit):
            editor.blockSignals(True)
            editor.setText(f"0x{int(value) & 0xFFFFFFFF:08X}")
            editor.setProperty("last_value", int(value) & 0xFFFFFFFF)
            editor.blockSignals(False)
        message = self._format_efs_change_message(field_name, previous, value, 4)
        detail_cells = bundle.get("pointer_status_details", {}).get(field_name)
        if isinstance(detail_cells, dict):
            self._apply_pointer_status_cells(detail_cells, None)
            for cell in detail_cells.values():
                if isinstance(cell, QTableWidgetItem):
                    cell.setToolTip(message)
        status_item = bundle.get("statuses", {}).get(field_name)
        if isinstance(status_item, QTableWidgetItem):
            status_item.setText("Queued (save)")
            status_item.setToolTip(message)
        action_item = bundle.get("pointer_actions", {}).get(field_name)
        if isinstance(action_item, QTableWidgetItem):
            action_item.setText("modify")
            action_item.setToolTip(message)
        self.window._status_message(message)

    # ------------------------------------------------------------------
    # Internal helpers

    def _clear_layout(self, layout: QVBoxLayout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            child_layout = item.layout()
            if child_layout is not None:
                self._clear_layout(child_layout)  # type: ignore[arg-type]

    def _build_efs_section(self, image_index: int, info: EfsInfo) -> QWidget:
        box = QGroupBox(f"EFS @ 0x{info.offset:08X}")
        layout = QVBoxLayout(box)

        header_rows = [
            ("Segment base", self._format_optional_hex(info.segment_base)),
            ("Pointer count", str(info.score)),
            ("Generation", _format_bitfield(info.generation_raw, width=16)),
        ]
        if info.second_generation is not None:
            header_rows.append(
                ("Second generation", "yes" if info.second_generation else "no")
            )
        if info.multigen_mask is not None:
            header_rows.append(("Multi-generation mask", f"0x{info.multigen_mask:04X}"))
        layout.addWidget(self._create_kv_table(header_rows))

        pointer_table = QTableWidget(
            len(EFS_POINTER_FIELDS), 4 + len(POINTER_STATUS_HEADERS)
        )
        pointer_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        pointer_table.setSizeAdjustPolicy(
            QAbstractScrollArea.AdjustToContentsOnFirstShow
        )
        pointer_table.setHorizontalHeaderLabels(
            [
                "Pointer",
                "Value",
                *POINTER_STATUS_HEADERS,
                "Status",
                "Action",
            ]
        )
        pointer_table.verticalHeader().setVisible(False)
        pointer_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        pointer_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        pointer_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents
        )
        for idx in range(len(POINTER_STATUS_HEADERS)):
            pointer_table.horizontalHeader().setSectionResizeMode(
                2 + idx, QHeaderView.ResizeToContents
            )
        status_column_index = 2 + len(POINTER_STATUS_HEADERS)
        pointer_table.horizontalHeader().setSectionResizeMode(
            status_column_index, QHeaderView.ResizeToContents
        )
        pointer_table.horizontalHeader().setSectionResizeMode(
            status_column_index + 1, QHeaderView.Stretch
        )
        pointer_widgets: Dict[str, QLineEdit] = {}
        status_widgets: Dict[str, QTableWidgetItem] = {}
        action_widgets: Dict[str, QTableWidgetItem] = {}
        status_detail_widgets: Dict[str, Dict[str, QTableWidgetItem]] = {}
        for row, (label, field_name) in enumerate(EFS_POINTER_FIELDS.items()):
            pointer_table.setItem(row, 0, QTableWidgetItem(label))
            raw_value = int(getattr(info.header, field_name, 0)) & 0xFFFFFFFF
            editor = QLineEdit(f"0x{raw_value:08X}")
            editor.setMaximumWidth(160)
            editor.setProperty("last_value", raw_value)
            editor.editingFinished.connect(
                partial(
                    self._on_efs_pointer_changed,
                    image_index,
                    info,
                    field_name,
                    editor,
                )
            )
            pointer_widgets[field_name] = editor
            pointer_table.setCellWidget(row, 1, editor)
            status = info.pointer_status.get(label)
            detail_cells: Dict[str, QTableWidgetItem] = {}
            for offset, column_name in enumerate(POINTER_STATUS_HEADERS):
                column_index = 2 + offset
                detail_item = QTableWidgetItem("-")
                detail_item.setFlags(Qt.ItemIsEnabled)
                if column_name in {"Raw", "Normalized"}:
                    detail_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                elif column_name in {"Expects dir", "In range", "Valid"}:
                    detail_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                else:
                    detail_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                pointer_table.setItem(row, column_index, detail_item)
                detail_cells[column_name] = detail_item
            self._apply_pointer_status_cells(detail_cells, status)
            status_detail_widgets[field_name] = detail_cells
            queue_column = 2 + len(POINTER_STATUS_HEADERS)
            status_item = QTableWidgetItem("-")
            status_item.setFlags(Qt.ItemIsEnabled)
            status_item.setToolTip("No changes queued")
            pointer_table.setItem(row, queue_column, status_item)
            status_widgets[field_name] = status_item
            action_column = queue_column + 1
            action_item = QTableWidgetItem("-")
            action_item.setFlags(Qt.ItemIsEnabled)
            action_item.setToolTip("No changes queued")
            pointer_table.setItem(row, action_column, action_item)
            action_widgets[field_name] = action_item
        pointer_display = self._finalize_summary_table(pointer_table)
        self._configure_pointer_table_columns(pointer_table)
        layout.addWidget(pointer_display)

        spi_fields = list(info.spi_config.items())
        spi_widgets: Dict[str, QComboBox] = {}
        spi_actions: Dict[str, QTableWidgetItem] = {}
        if spi_fields:
            spi_table = QTableWidget(len(spi_fields), 3)
            spi_table.setHorizontalHeaderLabels([
                "SPI field",
                "Value",
                "Action",
            ])
            spi_table.verticalHeader().setVisible(False)
            spi_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            spi_table.horizontalHeader().setSectionResizeMode(
                0, QHeaderView.ResizeToContents
            )
            spi_table.horizontalHeader().setSectionResizeMode(
                1, QHeaderView.ResizeToContents
            )
            spi_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)

            for row, (field, (value, description)) in enumerate(spi_fields):
                label_item = QTableWidgetItem(self._format_spi_field_label(field))
                label_item.setToolTip(field)
                spi_table.setItem(row, 0, label_item)
                combo = NoScrollComboBox()
                combo.setEditable(True)
                table = SPI_FIELD_TABLES.get(field, {})
                for code, desc in sorted(table.items()):
                    combo.addItem(f"0x{code:02X} - {desc}", code)
                value_int = int(value) & 0xFF
                combo.setProperty("spi_fallback_desc", description or "")
                self._set_spi_combo_value(combo, value_int, table)
                combo.setProperty("last_value", value_int)
                self._update_spi_combo_tooltip(combo, table, description)
                handler = partial(
                    self._on_efs_spi_changed,
                    image_index,
                    info,
                    field,
                    combo,
                    table,
                )
                combo.currentIndexChanged.connect(handler)
                if combo.isEditable() and combo.lineEdit() is not None:
                    combo.lineEdit().editingFinished.connect(handler)
                spi_table.setCellWidget(row, 1, combo)
                spi_widgets[field] = combo
                action_item = QTableWidgetItem("-")
                action_item.setFlags(Qt.ItemIsEnabled)
                action_item.setToolTip("No changes queued")
                spi_table.setItem(row, 2, action_item)
                spi_actions[field] = action_item

            layout.addWidget(self._finalize_summary_table(spi_table))

        # eSPI Configuration Section
        espi_widgets: Dict[str, QComboBox] = {}
        espi_actions: Dict[str, QTableWidgetItem] = {}
        if info.espi_info is not None:
            espi_widget, espi_widgets, espi_actions = self._build_espi_section(
                image_index, info, info.espi_info
            )
            layout.addWidget(espi_widget)
        else:
            espi_box = QGroupBox("eSPI Configuration")
            espi_layout = QVBoxLayout(espi_box)
            espi_label = QLabel("No eSPI configuration found in this EFS.")
            espi_label.setWordWrap(True)
            espi_layout.addWidget(espi_label)
            layout.addWidget(espi_box)

        # UBU Table Section
        ubu_widgets: Dict[str, QComboBox] = {}
        ubu_actions: Dict[str, QTableWidgetItem] = {}
        if info.ubu_info is not None:
            ubu_widget, ubu_widgets, ubu_actions = self._build_ubu_section(
                image_index, info, info.ubu_info
            )
            layout.addWidget(ubu_widget)
        else:
            ubu_box = QGroupBox("UBU Table")
            ubu_layout = QVBoxLayout(ubu_box)
            ubu_label = QLabel("No UBU table found in this EFS.")
            ubu_label.setWordWrap(True)
            ubu_layout.addWidget(ubu_label)
            layout.addWidget(ubu_box)

        self.field_widgets[(image_index, info.offset)] = {
            "pointers": pointer_widgets,
            "spi": spi_widgets,
            "statuses": status_widgets,
            "pointer_actions": action_widgets,
            "spi_actions": spi_actions,
            "pointer_status_details": status_detail_widgets,
            "espi": espi_widgets,
            "espi_actions": espi_actions,
            "ubu": ubu_widgets,
            "ubu_actions": ubu_actions,
        }

        return box

    def _build_espi_section(
        self,
        image_index: int,
        efs_info: EfsInfo,
        espi: EspiInfo,
    ) -> Tuple[QWidget, Dict[str, QComboBox], Dict[str, QTableWidgetItem]]:
        """Build the editable eSPI configuration section."""
        box = QGroupBox(f"eSPI Configuration @ 0x{espi.offset:08X}")
        layout = QVBoxLayout(box)

        espi_widgets: Dict[str, QComboBox] = {}
        espi_actions: Dict[str, QTableWidgetItem] = {}

        # Info rows (non-editable)
        info_rows = [
            ("Offset", f"0x{espi.offset:08X}"),
            ("Raw bytes", espi.raw_bytes.hex().upper()),
        ]
        layout.addWidget(self._create_kv_table(info_rows))

        # Build editable table for eSPI channels
        # Each channel (eSPI0, eSPI1) has fields, each config (eSPI0_Config, eSPI1_Config) has fields
        espi_fields = []
        for idx, (channel, config, byte_offset) in enumerate([
            (espi.espi0, espi.espi0_config, 0x50),
            (espi.espi1, espi.espi1_config, 0x51),
        ]):
            channel_name = f"eSPI{idx}"
            config_name = f"eSPI{idx}_Config"
            if channel is not None:
                espi_fields.append((f"{channel_name}_Valid", channel.valid, byte_offset, 0, 1, {0: "No", 1: "Yes"}))
                espi_fields.append((f"{channel_name}_Port80", channel.enable_80_port, byte_offset, 1, 1, {0: "Disabled", 1: "Enabled"}))
                espi_fields.append((f"{channel_name}_AlertMode", channel.alert_mode, byte_offset, 2, 1, ESPI_ALERT_MODE_TABLE))
                espi_fields.append((f"{channel_name}_DataBus", channel.data_bus, byte_offset, 3, 1, ESPI_DATA_BUS_TABLE))
                espi_fields.append((f"{channel_name}_Clock", channel.clock_pin, byte_offset, 4, 1, ESPI_CLOCK_PIN_TABLE))
                espi_fields.append((f"{channel_name}_DeviceCap", channel.device_capability, byte_offset, 5, 1, ESPI_DEVICE_CAP_TABLE))
                espi_fields.append((f"{channel_name}_IOMode", channel.io_mode, byte_offset, 6, 2, ESPI_IO_MODE_TABLE))
            if config is not None:
                config_offset = byte_offset + 2  # 0x52 for eSPI0_Config, 0x53 for eSPI1_Config
                espi_fields.append((f"{config_name}_Enhancement", config.enhancement, config_offset, 0, 1, {0: "Disabled", 1: "Enabled"}))
                espi_fields.append((f"{config_name}_Frequency", config.frequency, config_offset, 1, 3, ESPI_FREQ_TABLE))

        if espi_fields:
            espi_table = QTableWidget(len(espi_fields), 3)
            espi_table.setHorizontalHeaderLabels(["Field", "Value", "Action"])
            espi_table.verticalHeader().setVisible(False)
            espi_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            espi_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            espi_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            espi_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)

            for row, (field_name, current_value, byte_off, bit_off, bit_width, table) in enumerate(espi_fields):
                # Label
                label_item = QTableWidgetItem(field_name.replace("_", " "))
                label_item.setToolTip(f"Byte offset: 0x{byte_off:02X}, Bit: {bit_off}, Width: {bit_width}")
                espi_table.setItem(row, 0, label_item)

                # Combo box
                combo = NoScrollComboBox()
                combo.setEditable(True)
                for code, desc in sorted(table.items()):
                    combo.addItem(f"0x{code:02X} - {desc}", code)
                value_int = int(current_value) if isinstance(current_value, bool) else current_value
                idx_to_select = combo.findData(value_int)
                if idx_to_select >= 0:
                    combo.setCurrentIndex(idx_to_select)
                else:
                    combo.setEditText(f"0x{value_int:02X}")
                combo.setProperty("last_value", value_int)
                combo.setProperty("byte_offset", byte_off)
                combo.setProperty("bit_offset", bit_off)
                combo.setProperty("bit_width", bit_width)

                handler = partial(
                    self._on_espi_changed,
                    image_index,
                    efs_info,
                    field_name,
                    combo,
                    table,
                    byte_off,
                    bit_off,
                    bit_width,
                )
                combo.currentIndexChanged.connect(handler)
                espi_table.setCellWidget(row, 1, combo)
                espi_widgets[field_name] = combo

                # Action column
                action_item = QTableWidgetItem("-")
                action_item.setFlags(Qt.ItemIsEnabled)
                action_item.setToolTip("No changes queued")
                espi_table.setItem(row, 2, action_item)
                espi_actions[field_name] = action_item

            layout.addWidget(self._finalize_summary_table(espi_table))

        return box, espi_widgets, espi_actions

    def _build_ubu_section(
        self,
        image_index: int,
        efs_info: EfsInfo,
        ubu: UbuInfo,
    ) -> Tuple[QWidget, Dict[str, QComboBox], Dict[str, QTableWidgetItem]]:
        """Build the editable UBU table section."""
        box = QGroupBox(f"UBU Table @ 0x{ubu.table_offset:08X}")
        layout = QVBoxLayout(box)

        ubu_widgets: Dict[str, QComboBox] = {}
        ubu_actions: Dict[str, QTableWidgetItem] = {}

        # Info rows (non-editable)
        info_rows = [
            ("Pointer offset", f"0x{ubu.pointer_offset:08X}"),
            ("Table offset", f"0x{ubu.table_offset:08X}"),
            ("Signature", f"0x{ubu.signature:08X} ($UBU)"),
            ("Checksum", f"0x{ubu.checksum:08X}"),
            ("Table size", f"0x{ubu.table_size:X} ({ubu.table_size} bytes)"),
            ("Version", f"{ubu.version}"),
        ]
        if ubu.filename:
            info_rows.append(("Filename", ubu.filename))
        if ubu.capsule_header_addr != 0xFFFFFFFF:
            info_rows.append(("Capsule header addr", f"0x{ubu.capsule_header_addr:08X}"))
        if ubu.capsule_header_size != 0xFFFFFFFF:
            info_rows.append(("Capsule header size", f"0x{ubu.capsule_header_size:X}"))
        layout.addWidget(self._create_kv_table(info_rows))

        # Editable action fields - all in byte at offset 0x0B from UBU table
        action_byte_offset = ubu.table_offset + 0x0B
        ubu_fields = [
            ("UBU_ActionAfter", ubu.action_after_ubu, action_byte_offset, 0, 2, UBU_ACTION_AFTER_TABLE),
            ("UBU_LED", ubu.action_led, action_byte_offset, 2, 1, UBU_ACTION_LED_TABLE),
            ("UBU_Beep", ubu.action_beep, action_byte_offset, 3, 1, UBU_ACTION_BEEP_TABLE),
        ]

        ubu_table = QTableWidget(len(ubu_fields), 3)
        ubu_table.setHorizontalHeaderLabels(["Field", "Value", "Action"])
        ubu_table.verticalHeader().setVisible(False)
        ubu_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        ubu_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        ubu_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        ubu_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)

        for row, (field_name, current_value, byte_off, bit_off, bit_width, table) in enumerate(ubu_fields):
            # Label
            label_text = field_name.replace("UBU_", "").replace("ActionAfter", "After UBU Action")
            label_item = QTableWidgetItem(label_text)
            label_item.setToolTip(f"Byte offset: 0x{byte_off:08X}, Bit: {bit_off}, Width: {bit_width}")
            ubu_table.setItem(row, 0, label_item)

            # Combo box
            combo = NoScrollComboBox()
            combo.setEditable(True)
            for code, desc in sorted(table.items()):
                combo.addItem(f"0x{code:02X} - {desc}", code)
            value_int = int(current_value)
            idx_to_select = combo.findData(value_int)
            if idx_to_select >= 0:
                combo.setCurrentIndex(idx_to_select)
            else:
                combo.setEditText(f"0x{value_int:02X}")
            combo.setProperty("last_value", value_int)
            combo.setProperty("byte_offset", byte_off)
            combo.setProperty("bit_offset", bit_off)
            combo.setProperty("bit_width", bit_width)

            handler = partial(
                self._on_ubu_changed,
                image_index,
                efs_info,
                ubu,
                field_name,
                combo,
                table,
                byte_off,
                bit_off,
                bit_width,
            )
            combo.currentIndexChanged.connect(handler)
            ubu_table.setCellWidget(row, 1, combo)
            ubu_widgets[field_name] = combo

            # Action column
            action_item = QTableWidgetItem("-")
            action_item.setFlags(Qt.ItemIsEnabled)
            action_item.setToolTip("No changes queued")
            ubu_table.setItem(row, 2, action_item)
            ubu_actions[field_name] = action_item

        layout.addWidget(self._finalize_summary_table(ubu_table))

        # Protected regions table (non-editable)
        if ubu.protected_regions:
            regions_table = QTableWidget(len(ubu.protected_regions), 3)
            regions_table.setHorizontalHeaderLabels(["Region", "Offset", "Length"])
            regions_table.verticalHeader().setVisible(False)
            regions_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            regions_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

            for row, region in enumerate(ubu.protected_regions):
                regions_table.setItem(row, 0, QTableWidgetItem(f"Block {row}"))
                regions_table.setItem(row, 1, QTableWidgetItem(f"0x{region.offset:08X}"))
                regions_table.setItem(row, 2, QTableWidgetItem(f"0x{region.length:X}"))

            layout.addWidget(QLabel("Protected Regions:"))
            layout.addWidget(self._finalize_summary_table(regions_table))

        # Additional info
        extra_rows = []
        if ubu.signature_protection is not None:
            extra_rows.append(("Signature protection", ubu.signature_protection.hex().upper()))
        if ubu.bios_version_protection is not None:
            extra_rows.append(("BIOS version protection", f"0x{ubu.bios_version_protection:04X}"))

        if extra_rows:
            layout.addWidget(self._create_kv_table(extra_rows))

        return box, ubu_widgets, ubu_actions

    def _pointer_status_values(
        self, status: Optional[EfsPointerStatus]
    ) -> Dict[str, str]:
        values = {name: "-" for name in POINTER_STATUS_HEADERS}
        if status is None:
            return values
        values["Raw"] = f"0x{status.raw_value & 0xFFFFFFFF:08X}"
        values["Normalized"] = (
            "-" if status.normalized is None else f"0x{int(status.normalized):X}"
        )
        values["Cookie"] = status.cookie.value if status.cookie else "-"
        values["Expects dir"] = "yes" if status.expects_directory else "no"
        values["In range"] = "yes" if status.in_range else "no"
        values["Valid"] = "yes" if status.valid else "no"
        return values

    def _apply_pointer_status_cells(
        self,
        cells: Dict[str, QTableWidgetItem],
        status: Optional[EfsPointerStatus],
    ) -> None:
        if not cells:
            return
        values = self._pointer_status_values(status)
        tooltip = _format_pointer_status(status)
        for name, item in cells.items():
            if not isinstance(item, QTableWidgetItem):
                continue
            item.setText(values.get(name, "-"))
            item.setToolTip(tooltip)

    def _configure_pointer_table_columns(self, table: QTableWidget) -> None:
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setMinimumSectionSize(80)
        for index, width in POINTER_COLUMN_WIDTHS.items():
            header.setSectionResizeMode(index, QHeaderView.Stretch)
            header.resizeSection(index, width)
        for offset, name in enumerate(POINTER_STATUS_HEADERS):
            column = 2 + offset
            header.setSectionResizeMode(column, QHeaderView.Stretch)
            width = POINTER_STATUS_COLUMN_WIDTHS.get(name)
            if isinstance(width, int) and width > 0:
                header.resizeSection(column, width)
        queue_column = 2 + len(POINTER_STATUS_HEADERS)
        header.setSectionResizeMode(queue_column, QHeaderView.Stretch)
        header.resizeSection(queue_column, POINTER_QUEUE_COLUMN_WIDTH)
        action_column = queue_column + 1
        header.setSectionResizeMode(action_column, QHeaderView.Stretch)
        header.resizeSection(action_column, POINTER_ACTION_COLUMN_WIDTH)

    def _create_kv_table(self, rows: Sequence[tuple[str, str]]) -> QTableWidget:
        table = QTableWidget(len(rows), 2)
        table.setHorizontalHeaderLabels(["Field", "Value"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        for row, (label, value) in enumerate(rows):
            table.setItem(row, 0, QTableWidgetItem(label))
            table.setItem(row, 1, QTableWidgetItem(value))
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        return self._finalize_summary_table(table)

    def _finalize_summary_table(self, table: QTableWidget) -> QTableWidget:
        table.resizeColumnsToContents()
        table.resizeRowsToContents()
        height = table.horizontalHeader().height()
        for row in range(table.rowCount()):
            height += table.rowHeight(row)
        height += table.frameWidth() * 2 + 6
        table.setMinimumHeight(height)
        return table

    def _update_spi_combo_tooltip(
        self,
        combo: QComboBox,
        table: Dict[int, str],
        fallback: Optional[str] = None,
    ) -> None:
        if fallback is None:
            stored = combo.property("spi_fallback_desc")
            if isinstance(stored, str):
                fallback = stored
        value = self._parse_spi_value(combo)
        if value is None:
            desc = combo.currentText().strip() or (fallback or "")
        else:
            desc = table.get(value, fallback or f"0x{value:02X}")
        combo.setToolTip(desc)
        line_edit = combo.lineEdit()
        if line_edit is not None:
            line_edit.setToolTip(desc)

    def _extract_spi_description(self, text: str) -> Optional[str]:
        clean = text.strip()
        if not clean:
            return None
        if " - " in clean:
            candidate = clean.split(" - ", 1)[1].strip()
            if candidate:
                return candidate
        parts = clean.split(None, 1)
        if len(parts) > 1:
            candidate = parts[1].strip()
            if candidate:
                return candidate
        return None

    def _set_spi_combo_value(
        self,
        combo: QComboBox,
        value: Optional[int],
        table: Optional[Dict[int, str]] = None,
    ) -> None:
        if value is None:
            return
        target = int(value) & 0xFF
        lookup = table or {}
        fallback_raw = combo.property("spi_fallback_desc")
        fallback = fallback_raw if isinstance(fallback_raw, str) else ""
        label_prefix = f"0x{target:02X}"
        descriptor = lookup.get(target) or fallback
        display_text = f"{label_prefix} - {descriptor}" if descriptor else label_prefix
        combo.blockSignals(True)
        idx = combo.findData(target)
        if idx >= 0:
            combo.setItemText(idx, display_text)
            combo.setCurrentIndex(idx)
        else:
            raw_custom = combo.property("custom_values") or []
            custom_values = {int(v) for v in raw_custom}
            if target not in custom_values:
                combo.addItem(display_text, target)
                custom_values.add(target)
                combo.setProperty("custom_values", list(custom_values))
            idx = combo.findData(target)
            if idx >= 0:
                combo.setItemText(idx, display_text)
                combo.setCurrentIndex(idx)
            else:
                combo.setCurrentText(display_text)
        if combo.isEditable() and combo.lineEdit() is not None:
            combo.lineEdit().setText(combo.currentText())
        combo.blockSignals(False)
        self._update_spi_combo_tooltip(combo, lookup, descriptor or None)

    def _format_efs_values(
        self, width: int, previous: Optional[int], new_value: int
    ) -> tuple[str, str]:
        length = max(int(width), 1)
        digits = length * 2
        mask = (1 << (length * 8)) - 1
        new_text = f"0x{int(new_value) & mask:0{digits}X}"
        if previous is None:
            old_text = "--"
        else:
            old_text = f"0x{int(previous) & mask:0{digits}X}"
        return old_text, new_text

    def _format_efs_change_message(
        self,
        field_name: str,
        previous: Optional[int],
        new_value: int,
        width: int,
    ) -> str:
        old_text, new_text = self._format_efs_values(width, previous, new_value)
        return f"EFS: {field_name} change queued ({old_text} -> {new_text})"

    def _format_spi_field_label(self, field_name: str) -> str:
        parts: list[str] = []
        for token in field_name.split("_"):
            if not token:
                continue
            start = 0
            for idx in range(1, len(token)):
                current = token[idx]
                prev = token[idx - 1]
                next_char = token[idx + 1] if idx + 1 < len(token) else ""
                if current.isupper() and (
                    prev.islower() or (next_char and next_char.islower())
                ):
                    parts.append(token[start:idx])
                    start = idx
            parts.append(token[start:])
        return " ".join(filter(None, parts))

    def _on_efs_pointer_changed(
        self,
        image_index: int,
        info: EfsInfo,
        field_name: str,
        editor: QLineEdit,
    ) -> None:
        last_raw = editor.property("last_value")
        try:
            last_value = int(last_raw)
        except Exception:
            last_value = None
        text = editor.text().strip()
        if not text:
            if last_value is not None:
                editor.blockSignals(True)
                editor.setText(f"0x{last_value:08X}")
                editor.blockSignals(False)
            return
        try:
            value = int(text, 0) & 0xFFFFFFFF
        except ValueError:
            self.window._status_message(f"{field_name}: invalid value '{text}'")
            if last_value is not None:
                editor.blockSignals(True)
                editor.setText(f"0x{last_value:08X}")
                editor.blockSignals(False)
            return
        if last_value is not None and value == last_value:
            editor.blockSignals(True)
            editor.setText(f"0x{value:08X}")
            editor.blockSignals(False)
            return
        if not self._write_efs_value(
            image_index,
            info.offset,
            field_name,
            value,
            4,
            last_value,
            kind="pointer",
        ):
            if last_value is not None:
                editor.blockSignals(True)
                editor.setText(f"0x{last_value:08X}")
                editor.blockSignals(False)
            return
        editor.setProperty("last_value", value)
        editor.blockSignals(True)
        editor.setText(f"0x{value:08X}")
        editor.blockSignals(False)
        try:
            setattr(info.header, field_name, value)
        except Exception:
            pass
        label = next(
            (key for key, name in EFS_POINTER_FIELDS.items() if name == field_name),
            None,
        )
        if label and isinstance(info.pointer_status, dict):
            try:
                info.pointer_status[label] = None
            except Exception:
                pass
        message = self._format_efs_change_message(field_name, last_value, value, 4)
        bundle = self.field_widgets.get((image_index, info.offset), {})
        detail_cells = bundle.get("pointer_status_details", {}).get(field_name)
        if isinstance(detail_cells, dict):
            self._apply_pointer_status_cells(detail_cells, None)
            for cell in detail_cells.values():
                if isinstance(cell, QTableWidgetItem):
                    cell.setToolTip(message)
        status_item = bundle.get("statuses", {}).get(field_name)
        if isinstance(status_item, QTableWidgetItem):
            status_item.setText("Queued (save)")
            status_item.setToolTip(message)
            action_item = bundle.get("pointer_actions", {}).get(field_name)
            if isinstance(action_item, QTableWidgetItem):
                action_item.setText("modify")
                action_item.setToolTip(message)
            self.window._status_message(message)
        else:
            self.window._status_message(message)

    def _parse_spi_value(self, combo: QComboBox) -> Optional[int]:
        data = combo.currentData()
        if data is not None:
            try:
                return int(data) & 0xFF
            except Exception:
                return None
        text = combo.currentText().strip()
        if not text:
            return None
        token = text.split()[0]
        try:
            return int(token, 0) & 0xFF
        except Exception:
            return None

    def _on_efs_spi_changed(
        self,
        image_index: int,
        info: EfsInfo,
        field_name: str,
        combo: QComboBox,
        table: Dict[int, str],
        *_: object,
    ) -> None:
        raw_text = combo.currentText().strip()
        typed_desc = self._extract_spi_description(raw_text)
        last_raw = combo.property("last_value")
        try:
            last_value = int(last_raw)
        except Exception:
            last_value = None
        value = self._parse_spi_value(combo)
        if value is None:
            self.window._status_message(
                f"{field_name}: invalid value '{combo.currentText().strip()}'"
            )
            if last_value is not None:
                self._set_spi_combo_value(combo, last_value, table)
            return
        if last_value is not None and value == last_value:
            self._set_spi_combo_value(combo, value, table)
            return
        if not self._write_efs_value(
            image_index,
            info.offset,
            field_name,
            value,
            1,
            last_value,
            kind="spi",
        ):
            if last_value is not None:
                self._set_spi_combo_value(combo, last_value, table)
            return
        combo.setProperty("last_value", value)
        descriptor = table.get(value)
        if descriptor is None:
            descriptor = typed_desc
        combo.setProperty("spi_fallback_desc", descriptor or "")
        self._set_spi_combo_value(combo, value, table)
        try:
            info.spi_config[field_name] = (value, descriptor or f"0x{value:02X}")
        except Exception:
            pass
        message = self._format_efs_change_message(field_name, last_value, value, 1)
        bundle = self.field_widgets.get((image_index, info.offset), {})
        action_item = bundle.get("spi_actions", {}).get(field_name)
        if isinstance(action_item, QTableWidgetItem):
            action_item.setText("modify")
            action_item.setToolTip(message)
        self.window._status_message(message)

    def _on_espi_changed(
        self,
        image_index: int,
        info: EfsInfo,
        field_name: str,
        combo: QComboBox,
        table: Dict[int, str],
        byte_offset: int,
        bit_offset: int,
        bit_width: int,
        *_: object,
    ) -> None:
        """Handle eSPI field value change."""
        last_raw = combo.property("last_value")
        try:
            last_value = int(last_raw)
        except Exception:
            last_value = None

        data = combo.currentData()
        if data is None:
            if last_value is not None:
                idx = combo.findData(last_value)
                if idx >= 0:
                    combo.setCurrentIndex(idx)
            return
        value = int(data)

        if last_value is not None and value == last_value:
            return

        # Write the bitfield value
        if not self._write_espi_bitfield(
            image_index, byte_offset, bit_offset, bit_width, value, last_value
        ):
            if last_value is not None:
                idx = combo.findData(last_value)
                if idx >= 0:
                    combo.setCurrentIndex(idx)
            return

        combo.setProperty("last_value", value)
        desc = table.get(value, str(value))
        message = f"eSPI {field_name}: {last_value} -> {value} ({desc})"

        bundle = self.field_widgets.get((image_index, info.offset), {})
        action_item = bundle.get("espi_actions", {}).get(field_name)
        if isinstance(action_item, QTableWidgetItem):
            action_item.setText("modify")
            action_item.setToolTip(message)
        self.window._status_message(message)

    def _on_ubu_changed(
        self,
        image_index: int,
        efs_info: EfsInfo,
        ubu: UbuInfo,
        field_name: str,
        combo: QComboBox,
        table: Dict[int, str],
        byte_offset: int,
        bit_offset: int,
        bit_width: int,
        *_: object,
    ) -> None:
        """Handle UBU field value change."""
        last_raw = combo.property("last_value")
        try:
            last_value = int(last_raw)
        except Exception:
            last_value = None

        data = combo.currentData()
        if data is None:
            if last_value is not None:
                idx = combo.findData(last_value)
                if idx >= 0:
                    combo.setCurrentIndex(idx)
            return
        value = int(data)

        if last_value is not None and value == last_value:
            return

        # Write the bitfield value
        if not self._write_ubu_bitfield(
            image_index, ubu, byte_offset, bit_offset, bit_width, value, last_value
        ):
            if last_value is not None:
                idx = combo.findData(last_value)
                if idx >= 0:
                    combo.setCurrentIndex(idx)
            return

        combo.setProperty("last_value", value)
        desc = table.get(value, str(value))
        message = f"UBU {field_name}: {last_value} -> {value} ({desc})"

        bundle = self.field_widgets.get((image_index, efs_info.offset), {})
        action_item = bundle.get("ubu_actions", {}).get(field_name)
        if isinstance(action_item, QTableWidgetItem):
            action_item.setText("modify")
            action_item.setToolTip(message)
        self.window._status_message(message)

    def _write_espi_bitfield(
        self,
        image_index: int,
        byte_offset: int,
        bit_offset: int,
        bit_width: int,
        value: int,
        previous: Optional[int],
    ) -> bool:
        """Write a bitfield value to an eSPI configuration byte."""
        window = self.window
        if not (0 <= image_index < len(window.loaded_images)):
            window._status_message("Unable to resolve firmware image for update")
            return False
        image = window.loaded_images[image_index]

        if byte_offset < 0 or byte_offset >= len(image.data):
            QMessageBox.warning(
                window,
                "Invalid update",
                "eSPI field offset is outside of the firmware image.",
            )
            return False

        # Read current byte, modify bitfield, write back
        old_byte = image.data[byte_offset]
        mask = ((1 << bit_width) - 1) << bit_offset
        new_byte = (old_byte & ~mask) | ((value << bit_offset) & mask)

        try:
            image.data[byte_offset] = new_byte
        except Exception as exc:
            image.data[byte_offset] = old_byte
            QMessageBox.critical(window, "Failed to update eSPI", str(exc))
            return False

        image.needs_reparse = True
        window._mark_image_dirty(image_index)
        entry_desc = f"eSPI @0x{byte_offset:08X} bit[{bit_offset}:{bit_offset + bit_width - 1}]: {previous} -> {value}"
        image.change_log.append(entry_desc)
        return True

    def _write_ubu_bitfield(
        self,
        image_index: int,
        ubu: UbuInfo,
        byte_offset: int,
        bit_offset: int,
        bit_width: int,
        value: int,
        previous: Optional[int],
    ) -> bool:
        """Write a bitfield value to a UBU table byte and update checksum."""
        window = self.window
        if not (0 <= image_index < len(window.loaded_images)):
            window._status_message("Unable to resolve firmware image for update")
            return False
        image = window.loaded_images[image_index]

        if byte_offset < 0 or byte_offset >= len(image.data):
            QMessageBox.warning(
                window,
                "Invalid update",
                "UBU field offset is outside of the firmware image.",
            )
            return False

        # Read current byte, modify bitfield, write back
        old_byte = image.data[byte_offset]
        mask = ((1 << bit_width) - 1) << bit_offset
        new_byte = (old_byte & ~mask) | ((value << bit_offset) & mask)

        try:
            image.data[byte_offset] = new_byte
            # Update UBU checksum after modification
            self._update_ubu_checksum(image, ubu)
        except Exception as exc:
            image.data[byte_offset] = old_byte
            QMessageBox.critical(window, "Failed to update UBU", str(exc))
            return False

        image.needs_reparse = True
        window._mark_image_dirty(image_index)
        entry_desc = f"UBU @0x{byte_offset:08X} bit[{bit_offset}:{bit_offset + bit_width - 1}]: {previous} -> {value}"
        image.change_log.append(entry_desc)
        return True

    def _update_ubu_checksum(self, image, ubu: UbuInfo) -> None:
        """Recalculate and update the UBU table checksum (Fletcher32)."""
        from ..agesa.efs import _fletcher32

        table_start = ubu.table_offset
        table_size = ubu.table_size

        # Clear checksum field before calculation (at offset 0x04, 4 bytes)
        checksum_offset = table_start + 0x04
        image.data[checksum_offset:checksum_offset + 4] = b'\x00\x00\x00\x00'

        # Calculate new checksum over the table
        table_data = bytes(image.data[table_start:table_start + table_size])
        new_checksum = _fletcher32(table_data)

        # Write new checksum
        image.data[checksum_offset:checksum_offset + 4] = new_checksum.to_bytes(4, 'little')

    def _write_efs_value(
        self,
        image_index: int,
        efs_offset: int,
        field_name: str,
        value: int,
        width: int,
        previous: Optional[int],
        *,
        kind: str,
    ) -> bool:
        window = self.window
        if not (0 <= image_index < len(window.loaded_images)):
            window._status_message("Unable to resolve firmware image for update")
            return False
        image = window.loaded_images[image_index]
        base = int(efs_offset)
        offsets = EFS_FIELD_OFFSETS if kind == "pointer" else EFS_SPI_FIELD_OFFSETS
        rel_off = offsets.get(field_name)
        if rel_off is None:
            window._status_message(f"{field_name} is not editable")
            return False
        start = base + rel_off
        end = start + max(int(width), 1)
        if start < 0 or end > len(image.data):
            QMessageBox.warning(
                window,
                "Invalid update",
                "EFS field offset is outside of the firmware image.",
            )
            return False
        backup = bytes(image.data[start:end])
        try:
            image.data[start:end] = int(value).to_bytes(max(width, 1), "little")
        except Exception as exc:
            image.data[start:end] = backup
            QMessageBox.critical(window, "Failed to update EFS", str(exc))
            return False
        image.needs_reparse = True
        window._mark_image_dirty(image_index)
        try:
            old_text, new_text = self._format_efs_values(width, previous, value)
            entry_desc = f"EFS {field_name} @0x{start:08X}: {old_text} -> {new_text}"
        except Exception:
            entry_desc = f"EFS {field_name} updated"
        image.change_log.append(entry_desc)
        return True
