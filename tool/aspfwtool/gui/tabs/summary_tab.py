# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Summary tab widget helpers for firmware overview display.

This module provides:
    - Firmware summary information display
    - Keyring summary table
    - PSPID platform table
    - Promontory firmware information
"""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple, TYPE_CHECKING

from PySide6.QtCore import Qt, QPoint
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QFormLayout,
    QGroupBox,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QFileDialog,
    QMenu,
)

from ...agesa.directory import iter_entries
from ...agesa import constants as _constants
from .efs_tab import EFS_POINTER_FIELDS
from ...agesa import ps1 as _ps1
from ...agesa import crypto as _crypto
from ...agesa.prom import PromInfo, parse_prom_blocks
from ...agesa.utils import platform_names_for_pspid

if TYPE_CHECKING:  # pragma: no cover - typing helpers only
    from PySide6.QtWidgets import QScrollArea
    from ..mainwindow_components.controller import MainWindow
    from ..mainwindow_components.models import LoadedImage


class SummaryTabController:
    """Encapsulates the dynamic summary tab widgets and interactions."""

    def __init__(
        self,
        window: "MainWindow",
        summary_scroll: "QScrollArea",
        summary_layout: QVBoxLayout,
        *,
        container_get: Callable[[object, str], object | None],
        format_bytes: Callable[[int], str],
        format_optional_hex: Callable[[Optional[int]], str],
    ) -> None:
        self.window = window
        self.summary_scroll = summary_scroll
        self.summary_layout = summary_layout
        self._container_get = container_get
        self._format_bytes = format_bytes
        self._format_optional_hex = format_optional_hex

        self.summary_layout.setContentsMargins(12, 12, 12, 12)
        self.summary_layout.setSpacing(12)

    def refresh_summary(self) -> None:
        self._clear_layout(self.summary_layout)
        window = self.window

        if not window.loaded_images:
            empty = QLabel("No firmware loaded.")
            empty.setAlignment(Qt.AlignCenter)
            self.summary_layout.addWidget(empty)
            self.summary_layout.addStretch()
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
                title = "Firmware summary"
            else:
                title = f"Image #{image_index + 1}"
            group = QGroupBox(title)
            group_layout = QVBoxLayout(group)
            uefi_count = sum(len(root.volumes) for root in image.uefi_roots)
            info_rows = [
                ("Size", self._format_bytes(len(image.data))),
                ("Directories", str(len(image.directories))),
                ("UEFI volumes", str(uefi_count)),
            ]
            group_layout.addWidget(self._create_kv_table(info_rows))
            group_layout.addWidget(self._build_keyring_section(image_index, image))

            pspid_table = self._build_pspid_table(image)
            if pspid_table is not None:
                group_layout.addWidget(pspid_table)

            group_layout.addWidget(
                self._build_prom_section(image_index, image.prom_infos)
            )
            self.summary_layout.addWidget(group)

        self.summary_layout.addStretch()

    def _clear_layout(self, layout: QVBoxLayout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            child_layout = item.layout()
            if child_layout is not None:
                self._clear_layout(child_layout)  # type: ignore[arg-type]

    def _build_keyring_section(self, image_index: int, image: "LoadedImage") -> QWidget:
        box = QGroupBox("Loaded keys")
        layout = QVBoxLayout(box)
        records = list(getattr(image, "keyring_entries", []) or [])
        if not records:
            empty = QLabel("No public keys discovered in this image.")
            empty.setWordWrap(True)
            layout.addWidget(empty)
            return box

        table = QTableWidget(len(records), 4)
        table.setHorizontalHeaderLabels(
            ["Key ID", "Bits", "Directory entries", "Offsets"]
        )
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QAbstractItemView.NoSelection)
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)

        for row, record in enumerate(records):
            key_text = record.key_id.hex().upper()
            table.setItem(row, 0, QTableWidgetItem(key_text))

            bits_item = QTableWidgetItem(str(record.bits or ""))
            bits_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            table.setItem(row, 1, bits_item)

            entries_item = QTableWidgetItem(record.entry_locations or "-")
            table.setItem(row, 2, entries_item)

            offsets_item = QTableWidgetItem(record.address_locations or "-")
            table.setItem(row, 3, offsets_item)
            table.setRowHeight(row, max(table.rowHeight(row), 28))

        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(
            partial(self._show_keyring_context_menu, table, tuple(records))
        )
        table.resizeRowsToContents()
        layout.addWidget(table)
        return box

    def _show_keyring_context_menu(
        self,
        table: QTableWidget,
        records: Sequence[object],
        position: QPoint,
    ) -> None:
        index = table.indexAt(position)
        if not index.isValid():
            return
        row = index.row()
        if not (0 <= row < len(records)):
            return
        record = records[row]
        menu = QMenu(table)
        menu.addAction("Copy key ID", partial(self._copy_key_id, record))
        menu.addAction("Copy key PEM", partial(self._copy_key_pem, record))
        menu.addAction("Export key PEM", partial(self._export_key_pem, record))
        global_pos = table.viewport().mapToGlobal(position)
        menu.exec(global_pos)

    def _copy_key_id(self, record) -> None:
        key_hex = record.key_id.hex().upper()
        QGuiApplication.clipboard().setText(key_hex)
        self.window._status_message(f"Copied key ID {key_hex}")

    def _copy_key_pem(self, record) -> None:
        try:
            pem_bytes = _crypto.public_key_to_pem(record.public_key)
        except Exception as exc:
            self.window._status_message(f"Unable to encode key PEM: {exc}")
            return
        try:
            text = pem_bytes.decode("ascii")
        except Exception:
            text = pem_bytes.decode("utf-8", errors="ignore")
        QGuiApplication.clipboard().setText(text)
        short = record.key_id[:2].hex().upper()
        self.window._status_message(f"Copied PEM for key {short}")

    def _export_key_pem(self, record) -> None:
        default_name = f"{record.key_id.hex().upper()}_pub.pem"
        file_path, _ = QFileDialog.getSaveFileName(
            self.window,
            "Export public key",
            str(Path.cwd() / default_name),
            "PEM files (*.pem);;All files (*)",
        )
        if not file_path:
            return
        try:
            pem_bytes = _crypto.public_key_to_pem(record.public_key)
            Path(file_path).write_bytes(pem_bytes)
        except Exception as exc:
            QMessageBox.warning(
                self.window,
                "Export failed",
                f"Unable to export key: {exc}",
            )
            return
        self.window._status_message(f"Exported PEM to {file_path}")

    def _build_prom_section(
        self, image_index: int, infos: Sequence[PromInfo]
    ) -> QWidget:
        box = QGroupBox("Prom Firmware")
        layout = QVBoxLayout(box)
        if not infos:
            label = QLabel("No Prom firmware detected.")
            label.setWordWrap(True)
            layout.addWidget(label)
            return box

        for idx, prom in enumerate(infos):
            section = QGroupBox(f"FW #{idx} ({prom.type_name})")
            section_layout = QVBoxLayout(section)
            form = QFormLayout()
            form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

            def add_row(title: str, text: str) -> None:
                value_label = QLabel(text)
                value_label.setWordWrap(True)
                value_label.setTextInteractionFlags(
                    Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard
                )
                value_label.setTextFormat(Qt.PlainText)
                form.addRow(title, value_label)

            add_row("Offset:", self._format_optional_hex(prom.offset))
            add_row("Header version:", f"0x{prom.header_version:04X}")
            if prom.label:
                add_row("Label:", prom.label)
            if prom.firmware_version:
                add_row("Firmware version:", prom.firmware_version)
            if prom.firmware_date:
                add_row("Firmware date:", prom.firmware_date)
            if prom.checksum_ok:
                checksum_text = f"OK (0x{prom.computed_checksum:08X})"
            else:
                checksum_text = (
                    f"NG (0x{prom.computed_checksum:08X}), "
                    f"Expected (0x{prom.expected_checksum:08X})"
                )
            add_row("Checksum:", checksum_text)
            add_row("Block size:", self._format_bytes(prom.block_size))
            add_row("Payload offset:", self._format_optional_hex(prom.payload_offset))
            add_row("Payload size:", self._format_bytes(prom.payload_size))

            ps1_info = self._resolve_prom_ps1(image_index, prom)
            add_row("PSP Entry:", "yes" if ps1_info is not None else "no")

            section_layout.addLayout(form)

            buttons = QHBoxLayout()
            buttons.addStretch()

            extract_button = QPushButton("Extract")
            extract_button.clicked.connect(
                partial(self._extract_prom_block, image_index, idx, prom.label)
            )
            buttons.addWidget(extract_button)

            replace_button = QPushButton("Replace")
            replace_button.clicked.connect(
                partial(self._replace_prom_block, image_index, idx)
            )
            buttons.addWidget(replace_button)

            remove_button = QPushButton("Remove")
            remove_button.clicked.connect(
                partial(self._remove_prom_block, image_index, idx)
            )
            buttons.addWidget(remove_button)

            if ps1_info is not None:
                tooltip = "Secure processor managed firmware: use the PSP tab to modify or remove this block."
                replace_button.setToolTip(tooltip)
                remove_button.setToolTip(tooltip)

            section_layout.addLayout(buttons)
            layout.addWidget(section)

        return box

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

    def _resolve_prom_ps1(
        self, image_index: int, prom: PromInfo
    ) -> Optional[Tuple[int, int, _ps1.PS1Header]]:
        window = self.window
        if not (0 <= image_index < len(window.loaded_images)):
            return None
        image = window.loaded_images[image_index]
        start = int(prom.offset) - 0x100
        if start < 0:
            return None
        data = image.data
        if start + _ps1.PS1_HEADER_LEN > len(data):
            return None
        header = _ps1.parse_ps1_header(data, start)
        if header is None:
            return None

        body_size = int(header.size_signed)
        if body_size <= 0:
            body_size = int(prom.block_size)
        body_size = max(body_size, 0)
        signature_len = header.signature_length
        total_length = _ps1.PS1_HEADER_LEN + body_size + signature_len
        if total_length <= _ps1.PS1_HEADER_LEN:
            return None

        end = min(start + total_length, len(data))
        if end <= start:
            return None
        return start, end - start, header

    def _get_prom_info(self, image_index: int, block_index: int) -> Optional[PromInfo]:
        window = self.window
        if not (0 <= image_index < len(window.loaded_images)):
            QMessageBox.warning(
                window, "Invalid selection", "Image index is out of range."
            )
            return None
        image = window.loaded_images[image_index]
        if not (0 <= block_index < len(image.prom_infos)):
            QMessageBox.warning(
                window, "Invalid selection", "Prom firmware index is out of range."
            )
            return None
        return image.prom_infos[block_index]

    def _extract_prom_block(
        self, image_index: int, block_index: int, prom_type: Optional[str]
    ) -> None:
        prom = self._get_prom_info(image_index, block_index)
        if prom is None:
            return
        window = self.window
        image = window.loaded_images[image_index]
        data = image.data
        start = int(prom.offset)
        block_size = int(prom.block_size)
        if start < 0 or block_size <= 0 or start + block_size > len(data):
            QMessageBox.warning(
                window,
                "Extraction failed",
                "Prom firmware extends outside of the firmware image.",
            )
            return

        if prom_type:
            mapping = {
                "3328A_FW": "TypeId0x93_Prom21Fw",
                "3308A_FW": "LP_Prom19FW",
                "3306B_FW": "LP_PromFW",
                "3306A_FW": "PromFW",
            }
            name = mapping.get(prom_type, "UnknownPromFW")
        else:
            name = "UnknownPromFW"

        ps1_info = self._resolve_prom_ps1(image_index, prom)
        if ps1_info is not None:
            ps1_start, ps1_length, _ = ps1_info
            blob = bytes(data[ps1_start : ps1_start + ps1_length])
            extension = "sbin"
        else:
            blob = bytes(data[start : start + block_size])
            extension = "bin"

        export_name = f"{name}.{extension}"
        file_path, _ = QFileDialog.getSaveFileName(
            window,
            "Extract Prom firmware",
            str(Path.cwd() / export_name),
            "All files (*)",
        )
        if not file_path:
            return
        try:
            Path(file_path).write_bytes(blob)
        except Exception as exc:
            QMessageBox.critical(window, "Extraction failed", str(exc))
            return
        window._status_message(
            f"Extracted Prom firmware #{block_index} ({len(blob)} bytes) -> {file_path}"
        )

    def _replace_prom_block(self, image_index: int, block_index: int) -> None:
        prom = self._get_prom_info(image_index, block_index)
        if prom is None:
            return
        window = self.window
        if self._resolve_prom_ps1(image_index, prom) is not None:
            QMessageBox.information(
                window,
                "Replace Prom firmware",
                "This block is managed by the security processor.\nPlease use the PSP tab to modify it.",
            )
            return
        file_path, _ = QFileDialog.getOpenFileName(
            window,
            "Select replacement data",
            str(Path.cwd()),
            "All files (*)",
        )
        if not file_path:
            return
        try:
            new_blob = Path(file_path).read_bytes()
        except Exception as exc:
            QMessageBox.critical(window, "Replacement failed", str(exc))
            return

        image = window.loaded_images[image_index]
        start = int(prom.offset)
        block_size = int(prom.block_size)
        if start < 0 or block_size <= 0 or start + block_size > len(image.data):
            QMessageBox.warning(
                window,
                "Replacement failed",
                "Prom firmware extends outside of the firmware image.",
            )
            return
        if len(new_blob) > block_size:
            QMessageBox.warning(
                window,
                "Replacement failed",
                "Replacement data is larger than the Prom firmware.",
            )
            return
        if len(new_blob) < block_size:
            tail_start = start + len(new_blob)
            tail = image.data[tail_start : start + block_size]
            if any(byte != 0xFF for byte in tail):
                QMessageBox.warning(
                    window,
                    "Replacement failed",
                    "Replacement would overwrite non-0xFF data beyond the new file size.",
                )
                return

        end = start + block_size
        backup = bytes(image.data[start:end])
        try:
            image.data[start : start + len(new_blob)] = new_blob
            if len(new_blob) < block_size:
                image.data[start + len(new_blob) : end] = b"\xff" * (
                    block_size - len(new_blob)
                )
        except Exception as exc:
            image.data[start:end] = backup
            QMessageBox.critical(window, "Replacement failed", str(exc))
            return

        change_desc = (
            f"Prom block #{block_index:02d} replaced with {Path(file_path).name} "
            f"({len(new_blob)} bytes)"
        )
        image.change_log.append(change_desc)
        image.needs_reparse = True
        window._mark_image_dirty(image_index)
        window._record_modified_range(image_index, start, block_size)
        image.prom_infos = parse_prom_blocks(image.data)
        window._status_message(change_desc)
        window._rebuild_from_loaded_images()

    def _remove_prom_block(self, image_index: int, block_index: int) -> None:
        prom = self._get_prom_info(image_index, block_index)
        if prom is None:
            return
        window = self.window
        if self._resolve_prom_ps1(image_index, prom) is not None:
            QMessageBox.information(
                window,
                "Remove Prom firmware",
                "This block is managed by the security processor.\nPlease use the PSP tab to remove it.",
            )
            return
        confirm = QMessageBox.question(
            window,
            "Remove Prom firmware",
            "Fill this Prom firmware with 0xFF and clear Prom FW pointers?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        image = window.loaded_images[image_index]
        start = int(prom.offset)
        block_size = int(prom.block_size)
        if start < 0 or block_size <= 0 or start + block_size > len(image.data):
            QMessageBox.warning(
                window,
                "Removal failed",
                "Prom firmware extends outside of the firmware image.",
            )
            return

        end = start + block_size
        image.data[start:end] = b"\xff" * block_size
        change_desc = f"Prom block #{block_index:02d} removed (filled with 0xFF)"
        image.change_log.append(change_desc)
        image.needs_reparse = True
        window._mark_image_dirty(image_index)
        window._record_modified_range(image_index, start, block_size)
        self._zero_prom_efs_fields(image_index)
        image.prom_infos = parse_prom_blocks(image.data)
        window._status_message(change_desc)
        window._rebuild_from_loaded_images()

    def _zero_prom_efs_fields(self, image_index: int) -> None:
        window = self.window
        controller = getattr(window, "efs_tab_controller", None)
        if controller is None:
            return
        if not (0 <= image_index < len(window.loaded_images)):
            return
        image = window.loaded_images[image_index]
        for info in image.efs_infos:
            for field_name in ("Prom_FW", "LP_Prom_FW"):
                previous = getattr(info.header, field_name, None)
                try:
                    previous_int = int(previous)
                except Exception:
                    previous_int = None
                if previous_int == 0:
                    continue
                if not controller.write_efs_value(
                    image_index,
                    info.offset,
                    field_name,
                    0,
                    4,
                    previous_int,
                    kind="pointer",
                ):
                    continue
                try:
                    setattr(info.header, field_name, 0)
                except Exception:
                    pass
                label = next(
                    (
                        key
                        for key, attr in EFS_POINTER_FIELDS.items()
                        if attr == field_name
                    ),
                    None,
                )
                if label and isinstance(info.pointer_status, dict):
                    try:
                        info.pointer_status[label] = None
                    except Exception:
                        pass
                controller.update_pointer_display(
                    image_index, info.offset, field_name, previous_int, 0
                )

    def _build_pspid_table(self, image: "LoadedImage") -> Optional[QWidget]:
        rows = []
        for dir_index, directory in enumerate(image.directories):
            if not _constants.is_combo_dir(directory.kind):
                continue
            for entry in iter_entries(image.data, directory):
                pspid = self._container_get(entry.get("entry"), "pspid")
                if not isinstance(pspid, int):
                    continue
                names = platform_names_for_pspid(pspid)
                label = (
                    f"{directory.kind.value} {dir_index:02d}:{entry.get('index'):02d}"
                    if entry.get("index") is not None
                    else f"{directory.kind.value} {dir_index:02d}"
                )
                rows.append(
                    (label, f"0x{pspid:08X}", ", ".join(names) if names else "-")
                )
        if not rows:
            return None
        table = QTableWidget(len(rows), 3)
        table.setHorizontalHeaderLabels(["Entry", "PSPID", "Platform names"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        for row, (entry_label, pspid_text, names_text) in enumerate(rows):
            table.setItem(row, 0, QTableWidgetItem(entry_label))
            table.setItem(row, 1, QTableWidgetItem(pspid_text))
            table.setItem(row, 2, QTableWidgetItem(names_text))
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        box = QGroupBox("PSP ID directory map")
        layout = QVBoxLayout(box)
        layout.addWidget(self._finalize_summary_table(table))
        return box
