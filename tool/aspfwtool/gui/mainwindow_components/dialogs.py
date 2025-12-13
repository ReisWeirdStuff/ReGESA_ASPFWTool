# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""Dialog classes for entry editing and configuration.

This module provides:
    - EntryEditDialog: Configure PSP/BIOS entry metadata during replace/insert
    - Type selection and validation
    - ISH (Image Slot Header) builder integration
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Dict, Optional

from .qt import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
    Qt,
)
from .common import _format_dual_size, _iter_type_choices
from .models import BiosTypeFields, PspTypeFields
from ...agesa.constants import DirKind
from ...agesa import constants as _constants
from ...agesa.entrytypes import POINT_ENTRY, lookup_entry_definition
from ...agesa.ish import ISH_LEN, build_ish_stub, ish_defaults
from ..widgets.detail_pane import NoScrollComboBox


class EntryEditDialog(QDialog):
    """Dialog used to configure PSP/BHD entry metadata during replace/insert."""

    # Class-level variable to remember the last file selection directory
    _last_browse_directory: Optional[Path] = None

    def __init__(
        self,
        parent: QWidget,
        *,
        directory_kind: DirKind,
        title: str,
        initial_type: Optional[int],
        initial_size: int,
        address_mode: Optional[int],
        address_value: Optional[int],
        initial_pointer: Optional[int],
        require_data: bool,
        allow_size_override: bool = False,
        allow_file_selection: bool = True,
        allow_address_mode_edit: bool = False,
        ish_presets: Optional[Dict[int, Dict[str, int]]] = None,
        enable_ish_builder: Optional[bool] = None,
        lock_entry_type: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.directory_kind = directory_kind
        self.require_data = require_data
        self._base_require_data = bool(require_data)
        self._allow_file_selection = bool(allow_file_selection)
        if enable_ish_builder is None:
            enable_ish_builder = allow_file_selection
        self._allow_ish_builder = bool(enable_ish_builder and directory_kind == DirKind.PSP_L1)
        self._pointer_entry = False
        self._lock_entry_type = bool(lock_entry_type)
        self._allow_address_mode_edit = bool(
            allow_address_mode_edit and not _constants.is_combo_dir(directory_kind)
        )
        self._ish_presets: Dict[int, Dict[str, int]] = {
            (int(key) & 0xFF): dict(value)
            for key, value in (ish_presets or {}).items()
        }
        self._ish_cached_values: Dict[int, Dict[str, int]] = {}
        self._ish_active_type: Optional[int] = None
        self._ish_stub_data: bytes = b""
        self._ish_payload_active = False
        self._data_blob: bytes = b""
        self._file_path: Optional[Path] = None
        self._initial_size = max(int(initial_size or 0), 0)
        self._allow_size_override = bool(allow_size_override)
        self._size_override_value: Optional[int] = None
        self._pointer_value_locked = False
        self.combo_pspid_edit: Optional[QLineEdit] = None
        self.combo_pointer_edit: Optional[QLineEdit] = None
        self.pointer_value_edit: Optional[QLineEdit] = None
        self.pointer_value_label: Optional[QLabel] = None
        self.ish_group: Optional[QGroupBox] = None
        self._ish_hex_fields: Dict[str, QLineEdit] = {}
        self.ish_glitch_retry_spin: Optional[QSpinBox] = None
        self._ish_info_label: Optional[QLabel] = None
        self._config_provider: Callable[[], dict]
        self._cached_config: Optional[dict] = None
        self._cached_pointer_config: Optional[dict] = None
        self._initial_pointer = (
            int(initial_pointer) & 0xFFFFFFFFFFFFFFFF
            if initial_pointer is not None
            else None
        )
        self._address_mode_value: Optional[int] = (
            int(address_mode) & 0x3 if isinstance(address_mode, int) else None
        )
        if self._address_mode_value is None and self._allow_address_mode_edit:
            self._address_mode_value = 0
        self._initial_address_value: Optional[int] = (
            int(address_value) & ((1 << 62) - 1)
            if address_value is not None
            else None
        )

        # Build UI in Python
        wrapper = QVBoxLayout(self)
        wrapper.setContentsMargins(12, 12, 12, 12)
        wrapper.setSpacing(10)

        form_container = QWidget(self)
        form_container.setObjectName("form_container")
        form = QFormLayout(form_container)
        form.setObjectName("form_layout")
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        # Path field with browse button
        self.path_label_widget = QLabel("Payload source:", form_container)
        self.path_label_widget.setObjectName("path_label")
        self.path_field_widget = QWidget(form_container)
        self.path_field_widget.setObjectName("path_field_widget")
        path_layout = QHBoxLayout(self.path_field_widget)
        path_layout.setContentsMargins(0, 0, 0, 0)
        path_layout.setSpacing(6)

        self.path_edit = QLineEdit(self.path_field_widget)
        self.path_edit.setObjectName("path_edit")
        self.path_edit.setReadOnly(True)
        path_layout.addWidget(self.path_edit)

        self.browse_button = QPushButton("Browse...", self.path_field_widget)
        self.browse_button.setObjectName("browse_button")
        path_layout.addWidget(self.browse_button)

        form.addRow(self.path_label_widget, self.path_field_widget)

        wrapper.addWidget(form_container)

        self.button_box = QDialogButtonBox(
            QDialogButtonBox.Cancel | QDialogButtonBox.Ok, self
        )
        self.button_box.setObjectName("button_box")
        wrapper.addWidget(self.button_box)

        self.declared_size_display = QLabel("", self)
        self.declared_size_display.setObjectName("declared_size_display")
        self.declared_size_display.setWordWrap(True)
        self.declared_size_display.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.browse_button.clicked.connect(self._select_file)
        self.declared_size_display.setText("")

        if not self._allow_file_selection:
            self._set_file_inputs_visible(False)

        self.type_combo = NoScrollComboBox(self)
        current_type = int(initial_type or 0) & 0xFF
        found_type = False
        for type_id, label in _iter_type_choices(directory_kind):
            text = f"0x{type_id:02X} - {label}"
            self.type_combo.addItem(text, type_id)
            if type_id == current_type:
                found_type = True
        if not found_type:
            self.type_combo.addItem(f"0x{current_type:02X}", current_type)
            self.type_combo.setCurrentIndex(self.type_combo.count() - 1)
        else:
            index = self.type_combo.findData(current_type)
            if index >= 0:
                self.type_combo.setCurrentIndex(index)
        self.type_combo.setEditable(True)
        self.type_combo.setInsertPolicy(QComboBox.NoInsert)
        self.type_combo.setMaxVisibleItems(16)
        form.addRow("Entry type:", self.type_combo)
        self._type_combo_label = form.labelForField(self.type_combo)
        if self._lock_entry_type:
            self.type_combo.setEditable(False)
            self.type_combo.setEnabled(False)

        self.size_display = QLineEdit(self)
        self.size_display.setReadOnly(True)
        self.size_display.setFocusPolicy(Qt.NoFocus)
        self.size_display.setText(_format_dual_size(self._initial_size))
        form.addRow("Entry size:", self.size_display)
        self._size_display_label = form.labelForField(self.size_display)
        form.addRow("Declared size:", self.declared_size_display)
        self._declared_size_label = form.labelForField(self.declared_size_display)

        if _constants.is_combo_dir(directory_kind):
            self.require_data = False
            self._set_file_inputs_visible(False)
            # Hide size fields for combo directories
            self.size_display.setVisible(False)
            if self._size_display_label:
                self._size_display_label.setVisible(False)
            self.declared_size_display.setVisible(False)
            if self._declared_size_label:
                self._declared_size_label.setVisible(False)
            # Rename type to Mode for combo directories
            if self._type_combo_label:
                self._type_combo_label.setText("Mode:")
            initial_match = self._initial_size
            self.combo_pspid_edit = QLineEdit(self)
            self.combo_pspid_edit.setPlaceholderText(
                "Hex match value (PSPID/chip ID)"
            )
            initial_match_value: Optional[int]
            try:
                initial_match_value = int(initial_match) & 0xFFFFFFFF
            except Exception:
                initial_match_value = None
            self._configure_hex_input(self.combo_pspid_edit, 8, initial_match_value)
            form.addRow("PSPID:", self.combo_pspid_edit)
            self.combo_pointer_edit = QLineEdit(self)
            self.combo_pointer_edit.setPlaceholderText(
                "Hex directory address (64-bit)"
            )
            pointer_initial = self._initial_pointer
            self._configure_hex_input(
                self.combo_pointer_edit,
                16,
                pointer_initial if pointer_initial is not None else None,
            )
            form.addRow("Address:", self.combo_pointer_edit)
            self._config_provider = self._collect_combo_config
        elif _constants.is_real_psp_dir(directory_kind):
            fields = PspTypeFields.from_value(initial_type or 0)
            self.subprogram_spin = self._make_spinbox(0, 0xFF, fields.subprogram)
            self.rom_id_combo = NoScrollComboBox(self)
            for value in range(4):
                self.rom_id_combo.addItem(f"{value}", value)
            self.rom_id_combo.setCurrentIndex(int(fields.rom_id))
            self.writable_combo = NoScrollComboBox(self)
            self.writable_combo.addItem("Read-only (0)", 0)
            self.writable_combo.addItem("Writable (1)", 1)
            self.writable_combo.setCurrentIndex(int(fields.writable))
            self.instance_spin = self._make_spinbox(0, 0xF, fields.instance)
            self.reserved_spin = self._make_spinbox(0, 0x1FF, fields.reserved)
            self.reserved_spin.setDisplayIntegerBase(16)
            form.addRow("SubProgram (8:15):", self.subprogram_spin)
            form.addRow("SPI ROM ID (16:17):", self.rom_id_combo)
            form.addRow("Writable (18):", self.writable_combo)
            form.addRow("Instance (19:22):", self.instance_spin)
            form.addRow("Reserved (23:31):", self.reserved_spin)
            self._config_provider = lambda: {
                "type_value": int(self._collect_psp_fields())
            }
        else:
            fields = BiosTypeFields.from_value(initial_type or 0)
            self.region_spin = self._make_spinbox(0, 0xFF, fields.region_type)
            self.reset_check = QCheckBox("Reset image (bit 16)", self)
            self.reset_check.setChecked(bool(fields.reset_image))
            self.copy_check = QCheckBox("Copy image (bit 17)", self)
            self.copy_check.setChecked(bool(fields.copy_image))
            self.readonly_check = QCheckBox("Read only (bit 18)", self)
            self.readonly_check.setChecked(bool(fields.read_only))
            self.compressed_check = QCheckBox("Compressed (bit 19)", self)
            self.compressed_check.setChecked(bool(fields.compressed))
            self.instance_spin = self._make_spinbox(0, 0xF, fields.instance)
            self.subprogram_spin = self._make_spinbox(0, 0x7, fields.subprogram)
            self.rom_id_combo = NoScrollComboBox(self)
            for value in range(4):
                self.rom_id_combo.addItem(f"{value}", value)
            self.rom_id_combo.setCurrentIndex(int(fields.rom_id))
            self.writable_combo = NoScrollComboBox(self)
            self.writable_combo.addItem("Not writable (0)", 0)
            self.writable_combo.addItem("Writable (1)", 1)
            self.writable_combo.setCurrentIndex(int(fields.writable))
            self.reserved_spin = self._make_spinbox(0, 0x3, fields.reserved)
            self.reserved_spin.setDisplayIntegerBase(16)
            form.addRow("Region type (8:15):", self.region_spin)
            form.addRow("Flags:", self.reset_check)
            form.addRow("", self.copy_check)
            form.addRow("", self.readonly_check)
            form.addRow("", self.compressed_check)
            form.addRow("Instance (20:23):", self.instance_spin)
            form.addRow("SubProgram (24:26):", self.subprogram_spin)
            form.addRow("ROM ID (27:28):", self.rom_id_combo)
            form.addRow("Writable (29):", self.writable_combo)
            form.addRow("Reserved (30:31):", self.reserved_spin)
            self._config_provider = lambda: {
                "type_value": int(self._collect_bios_fields())
            }

        self.address_mode_combo: Optional[QComboBox]
        self.address_mode_label_widget: Optional[QLabel]
        self.address_mode_combo_label: Optional[QLabel]
        self.address_mode_label_label: Optional[QLabel]
        self.address_label: Optional[QLabel]
        self.entry_address_label_label: Optional[QLabel]
        if _constants.is_combo_dir(directory_kind):
            self.address_mode_combo = None
            self.address_mode_label_widget = None
            self.address_mode_combo_label = None
            self.address_mode_label_label = None
            self.pointer_value_edit = None
            self.pointer_value_label = None
            pointer_text = "-"
            if self._initial_pointer is not None:
                pointer_text = f"0x{self._initial_pointer:016X}"
            self.address_label = QLabel(pointer_text, self)
            form.addRow("Current pointer:", self.address_label)
            try:
                self.entry_address_label_label = form.labelForField(self.address_label)
            except Exception:
                self.entry_address_label_label = None
        else:
            mode_labels = {
                0: "0 - X86 physical",
                1: "1 - BIOS offset",
                2: "2 - Directory relative",
                3: "3 - Partition relative",
            }
            mode_value = int(self._address_mode_value or 0) & 0x3
            mode_text = mode_labels.get(mode_value, f"{mode_value}")
            self.address_mode_label_widget = QLabel(mode_text, self)
            form.addRow("Addressing mode (62:63):", self.address_mode_label_widget)
            try:
                self.address_mode_label_label = form.labelForField(
                    self.address_mode_label_widget
                )
            except Exception:
                self.address_mode_label_label = None

            self.address_mode_combo = NoScrollComboBox(self)
            for value, label in mode_labels.items():
                self.address_mode_combo.addItem(label, value)
            index = self.address_mode_combo.findData(mode_value)
            if index < 0:
                index = 0
            self.address_mode_combo.setCurrentIndex(index)
            self.address_mode_combo.currentIndexChanged.connect(
                self._on_address_mode_changed
            )
            self.address_mode_combo.setVisible(self._allow_address_mode_edit)
            self.address_mode_combo.setEnabled(self._allow_address_mode_edit)
            form.addRow("Addressing mode (62:63):", self.address_mode_combo)
            try:
                self.address_mode_combo_label = form.labelForField(self.address_mode_combo)
            except Exception:
                self.address_mode_combo_label = None
            combo_visible = self._allow_address_mode_edit
            if self.address_mode_combo_label is not None:
                self.address_mode_combo_label.setVisible(combo_visible)
            if self.address_mode_label_widget is not None:
                self.address_mode_label_widget.setVisible(not combo_visible)

            addr_text = "-"
            if address_value is not None:
                try:
                    addr_text = f"0x{int(address_value):X}"
                except Exception:
                    addr_text = str(address_value)
            self.address_label = QLabel(addr_text, self)
            form.addRow("Entry address (0:61):", self.address_label)
            try:
                self.entry_address_label_label = form.labelForField(self.address_label)
            except Exception:
                self.entry_address_label_label = None

            self.pointer_value_edit = QLineEdit(self)
            self.pointer_value_edit.setPlaceholderText("0x pointer value")
            self._configure_hex_input(
                self.pointer_value_edit,
                16,
                self._initial_address_value,
            )
            form.addRow("Pointer value (0:61):", self.pointer_value_edit)
            try:
                self.pointer_value_label = form.labelForField(self.pointer_value_edit)
            except Exception:
                self.pointer_value_label = None
        if self.pointer_value_label is not None:
            self.pointer_value_label.setVisible(False)
        if self.pointer_value_edit is not None:
            self.pointer_value_edit.setVisible(False)

        if self._allow_ish_builder:
            self._init_ish_widgets(form)

        self._size_override_label: Optional[QLabel] = None
        if self._allow_size_override:
            self.size_override_edit = QLineEdit(self)
            self.size_override_edit.setPlaceholderText("Auto")
            self.size_override_edit.setToolTip(
                "Override the declared entry size (decimal or hex). Leave blank to use the payload size."
            )
            form.addRow("Declared size override:", self.size_override_edit)
            try:
                self._size_override_label = form.labelForField(self.size_override_edit)
            except Exception:
                self._size_override_label = None
            self.size_override_edit.textChanged.connect(self._update_size_widgets)
        else:
            self.size_override_edit = None

        self.button_box.accepted.connect(self._on_accept)
        self.button_box.rejected.connect(self.reject)

        self.type_combo.currentIndexChanged.connect(self._on_type_changed)
        self.type_combo.editTextChanged.connect(self._on_type_changed)

        self._update_size_widgets()
        self._on_type_changed()
        self._update_size_override_visibility()
        self._update_accept_state()

    def _make_spinbox(self, minimum: int, maximum: int, value: int) -> QSpinBox:
        spin = QSpinBox(self)
        spin.setRange(int(minimum), int(maximum))
        spin.setValue(int(value))
        spin.setDisplayIntegerBase(16)
        spin.setPrefix("0x")
        return spin

    def _select_file(self) -> None:
        # Use last browse directory if available, otherwise current working directory
        initial_dir = (
            str(EntryEditDialog._last_browse_directory)
            if EntryEditDialog._last_browse_directory is not None
            else str(Path.cwd())
        )
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select entry payload", initial_dir
        )
        if not file_path:
            return
        try:
            data = Path(file_path).read_bytes()
        except Exception as exc:
            QMessageBox.critical(self, "Failed to read file", str(exc))
            return
        self._data_blob = bytes(data)
        self._file_path = Path(file_path)
        # Remember the directory for next time
        EntryEditDialog._last_browse_directory = Path(file_path).parent
        if self.path_edit is not None:
            self.path_edit.setText(str(file_path))
        self._update_size_widgets()
        self._update_accept_state()

    def _configure_hex_input(
        self, widget: QLineEdit, digits: int, initial_value: Optional[int]
    ) -> None:
        """Force a QLineEdit to keep a ``0x`` prefix with hexadecimal digits."""

        max_len = max(int(digits), 1)
        widget.setProperty("_hex_digits", max_len)

        def _normalize() -> None:
            text = widget.text() or ""
            if text.lower().startswith("0x"):
                raw = text[2:]
            else:
                raw = text
            filtered = re.sub(r"[^0-9a-fA-F]", "", raw.upper())[:max_len]
            normalized = "0x" + filtered
            if not filtered:
                normalized = "0x"
            if widget.text() != normalized:
                cursor = max(widget.cursorPosition(), 2)
                widget.blockSignals(True)
                widget.setText(normalized)
                widget.blockSignals(False)
                widget.setCursorPosition(min(max(cursor, 2), len(normalized)))
            else:
                if widget.cursorPosition() < 2:
                    widget.setCursorPosition(2)

        def _ensure_cursor(_old: int, _new: int) -> None:
            if widget.cursorPosition() < 2:
                widget.setCursorPosition(2)

        widget.setMaxLength(2 + max_len)
        display_value: str
        if initial_value is None:
            display_value = "0x"
        else:
            digits_text = f"{int(initial_value) & ((1 << (4 * max_len)) - 1):X}".lstrip("0")
            display_value = f"0x{digits_text or '0'}"
        widget.setText(display_value)
        widget.cursorPositionChanged.connect(_ensure_cursor)
        widget.textEdited.connect(lambda _text: _normalize())
        widget.editingFinished.connect(_normalize)
        _normalize()

    def _init_ish_widgets(self, form: QFormLayout) -> None:
        if self.ish_group is not None:
            return
        group = QGroupBox("ISH stub configuration", self)
        layout = QFormLayout(group)
        layout.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        def _add_hex_field(name: str, label: str) -> None:
            edit = QLineEdit(self)
            self._configure_hex_input(edit, 8, 0)
            layout.addRow(label, edit)
            self._ish_hex_fields[name] = edit
            edit.textEdited.connect(lambda _text=None: self._on_ish_field_changed())
            edit.editingFinished.connect(lambda _text=None: self._on_ish_field_changed())

        _add_hex_field("boot_priority", "Boot priority:")
        _add_hex_field("update_retry_count", "Update retry count:")
        _add_hex_field("location_pointer", "Target directory offset:")
        _add_hex_field("pspid", "PSP ID:")
        _add_hex_field("slot_max_size", "Slot max size:")
        _add_hex_field("reserved_1c", "Reserved @0x1C:")

        self.ish_glitch_retry_spin = self._make_spinbox(0, 0xFF, 0)
        self.ish_glitch_retry_spin.valueChanged.connect(
            lambda _value: self._on_ish_field_changed()
        )
        layout.addRow("Glitch retry count:", self.ish_glitch_retry_spin)

        self._ish_info_label = QLabel(
            f"Generates {ISH_LEN}-byte ISH record.", self
        )
        self._ish_info_label.setWordWrap(True)
        layout.addRow(self._ish_info_label)

        self.ish_group = group
        form.addRow(group)
        group.setVisible(False)

    def _ish_builder_visible(self) -> bool:
        return bool(self.ish_group is not None and self.ish_group.isVisible())

    def _clear_ish_payload(self) -> None:
        self._ish_stub_data = b""
        if self._ish_payload_active:
            self._data_blob = b""
        self._ish_payload_active = False

    def _set_hex_line_value(self, widget: Optional[QLineEdit], value: int) -> None:
        if widget is None:
            return
        digits = widget.property("_hex_digits")
        try:
            digits_int = int(digits)
        except Exception:
            digits_int = 8
        mask = (1 << (4 * max(digits_int, 1))) - 1
        text = f"0x{int(value) & mask:X}"
        widget.blockSignals(True)
        widget.setText(text)
        widget.blockSignals(False)

    def _apply_ish_values(self, values: Dict[str, int]) -> None:
        if not self._ish_hex_fields:
            return
        for name, widget in self._ish_hex_fields.items():
            self._set_hex_line_value(widget, values.get(name, 0))
        if self.ish_glitch_retry_spin is not None:
            self.ish_glitch_retry_spin.blockSignals(True)
            self.ish_glitch_retry_spin.setValue(
                int(values.get("glitch_retry_count", 0)) & 0xFF
            )
            self.ish_glitch_retry_spin.blockSignals(False)

    def _collect_ish_field_values(self, *, strict: bool) -> Optional[Dict[str, int]]:
        if not self._ish_builder_visible():
            return None

        def _read(name: str, label: str, required: bool = False) -> Optional[int]:
            widget = self._ish_hex_fields.get(name)
            if widget is None:
                return 0
            text = (widget.text() or "").strip()
            if text.lower() in {"", "0x", "0x_"}:
                if required:
                    if strict:
                        raise ValueError(f"Enter {label}.")
                    return None
                return 0
            try:
                value = int(text, 16)
            except ValueError:
                if strict:
                    raise ValueError(f"Enter a hexadecimal value for {label}.")
                return None
            digits = widget.property("_hex_digits")
            try:
                bits = max(int(digits), 1) * 4
            except Exception:
                bits = 32
            max_value = (1 << bits) - 1
            if value < 0 or value > max_value:
                if strict:
                    raise ValueError(f"{label} must fit within {bits} bits.")
                return None
            return value

        boot = _read("boot_priority", "the boot priority")
        if boot is None:
            return None
        update = _read("update_retry_count", "the update retry count")
        if update is None:
            return None
        location = _read(
            "location_pointer", "the target directory offset", required=True
        )
        if location is None:
            return None
        pspid = _read("pspid", "the PSP ID", required=True)
        if pspid is None:
            return None
        slot_size = _read("slot_max_size", "the slot max size")
        if slot_size is None:
            return None
        reserved_1c = _read("reserved_1c", "the reserved value at 0x1C")
        if reserved_1c is None:
            return None
        glitch = (
            int(self.ish_glitch_retry_spin.value()) & 0xFF
            if self.ish_glitch_retry_spin is not None
            else 0
        )
        return {
            "boot_priority": boot,
            "update_retry_count": update,
            "glitch_retry_count": glitch,
            "location_pointer": location,
            "pspid": pspid,
            "slot_max_size": slot_size,
            "reserved_0d": 0,
            "reserved_1c": reserved_1c,
        }

    def _refresh_ish_stub(self, *, silent: bool) -> None:
        if not self._allow_ish_builder:
            return
        if not self._ish_builder_visible():
            self._clear_ish_payload()
            return
        try:
            values = self._collect_ish_field_values(strict=not silent)
        except ValueError as exc:
            self._clear_ish_payload()
            if silent:
                return
            raise exc
        if values is None:
            self._clear_ish_payload()
            if silent:
                return
            raise ValueError("Enter valid ISH stub values before continuing.")
        stub = build_ish_stub(values)
        self._ish_stub_data = stub
        self._ish_payload_active = True
        self._data_blob = stub
        current_type = self._current_type_value() & 0xFF
        self._ish_cached_values[current_type] = dict(values)
        self._update_size_widgets()
        self._update_accept_state()

    def _on_ish_field_changed(self) -> None:
        if not self._ish_builder_visible():
            return
        self._refresh_ish_stub(silent=True)

    def _update_ish_visibility(self) -> None:
        if not self._allow_ish_builder or self.ish_group is None:
            return
        current_type = self._current_type_value() & 0xFF
        if self._ish_active_type in (0x48, 0x4A):
            cached = self._collect_ish_field_values(strict=False)
            if cached:
                self._ish_cached_values[self._ish_active_type] = dict(cached)
        active = (
            self.directory_kind == DirKind.PSP_L1
            and current_type in (0x48, 0x4A)
            and self._pointer_entry
        )
        self._ish_active_type = current_type if active else None
        self.ish_group.setVisible(active)
        if active:
            values = self._ish_cached_values.get(current_type)
            if not values:
                values = self._ish_presets.get(current_type)
            if not values:
                values = ish_defaults(current_type)
            self._apply_ish_values(dict(values))
            self._refresh_ish_stub(silent=True)
        else:
            self._clear_ish_payload()
            self._update_size_widgets()
            self._update_accept_state()
    def _collect_psp_fields(self) -> int:
        fields = PspTypeFields(
            entry_type=self._current_type_value(),
            subprogram=int(self.subprogram_spin.value()),
            rom_id=int(self.rom_id_combo.currentData() or 0),
            writable=int(self.writable_combo.currentData() or 0),
            instance=int(self.instance_spin.value()),
            reserved=int(self.reserved_spin.value()),
        )
        return fields.to_value()

    def _collect_bios_fields(self) -> int:
        fields = BiosTypeFields(
            entry_type=self._current_type_value(),
            region_type=int(self.region_spin.value()),
            reset_image=1 if self.reset_check.isChecked() else 0,
            copy_image=1 if self.copy_check.isChecked() else 0,
            read_only=1 if self.readonly_check.isChecked() else 0,
            compressed=1 if self.compressed_check.isChecked() else 0,
            instance=int(self.instance_spin.value()),
            subprogram=int(self.subprogram_spin.value()),
            rom_id=int(self.rom_id_combo.currentData() or 0),
            writable=int(self.writable_combo.currentData() or 0),
            reserved=int(self.reserved_spin.value()),
        )
        return fields.to_value()

    def _collect_combo_config(self) -> dict:
        id_select = int(self._current_type_value()) & 0xFFFFFFFF
        match_text = self.combo_pspid_edit.text().strip() if self.combo_pspid_edit else ""
        if not match_text:
            raise ValueError("Enter a match value for the combo entry (PSPID or chip ID).")
        if match_text.lower() in {"0x", "0x_"}:
            raise ValueError("Enter a hexadecimal match value for the combo entry.")
        try:
            match_value = int(match_text, 16)
        except ValueError as exc:
            raise ValueError(
                "Enter a valid hexadecimal match value using the 0x prefix."
            ) from exc
        if not (0 <= match_value <= 0xFFFFFFFF):
            raise ValueError("Match value must fit within 32 bits.")
        pointer_text = (
            self.combo_pointer_edit.text().strip() if self.combo_pointer_edit else ""
        )
        if not pointer_text:
            raise ValueError("Enter a directory address for the combo entry.")
        if pointer_text.lower() in {"0x", "0x_"}:
            raise ValueError("Enter a hexadecimal directory address for the combo entry.")
        try:
            pointer_value = int(pointer_text, 16)
        except ValueError as exc:
            raise ValueError(
                "Enter a valid hexadecimal directory address using the 0x prefix."
            ) from exc
        if not (0 <= pointer_value <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("Directory address must fit within 64 bits.")
        return {
            "type_value": id_select,
            "combo_pspid": match_value & 0xFFFFFFFF,
            "combo_pointer": pointer_value & 0xFFFFFFFFFFFFFFFF,
            "combo_pointer_text": pointer_text,
        }

    def _current_type_value(self) -> int:
        data = self.type_combo.currentData()
        if isinstance(data, int):
            return int(data) & 0xFF
        text = (self.type_combo.currentText() or "").strip()
        if not text:
            return 0
        first_token = text.split()[0]
        for candidate in (text, first_token):
            try:
                return int(candidate, 0) & 0xFF
            except Exception:
                pass
        match = re.search(r"0[xX][0-9a-fA-F]+", text)
        if match:
            try:
                return int(match.group(0), 16) & 0xFF
            except Exception:
                return 0
        try:
            return int(text, 16) & 0xFF
        except Exception:
            return 0

    def _update_accept_state(self) -> None:
        ok_button = self.button_box.button(QDialogButtonBox.Ok)
        if ok_button is None:
            return
        if self.require_data:
            ok_button.setEnabled(bool(self._data_blob))
        else:
            ok_button.setEnabled(True)
        if (
            ok_button is not None
            and not self.require_data
            and self._ish_builder_visible()
        ):
            ok_button.setEnabled(bool(self._ish_stub_data))

    def _set_file_inputs_visible(self, visible: bool) -> None:
        if not self._allow_file_selection:
            visible = False
        if self.path_edit is not None:
            self.path_edit.setVisible(visible)
        if self.browse_button is not None:
            self.browse_button.setVisible(visible)
        if self.path_label_widget is not None:
            self.path_label_widget.setVisible(visible)
        if self.path_field_widget is not None:
            self.path_field_widget.setVisible(visible)

    def _current_payload_size(self) -> int:
        return len(self._data_blob) if self._data_blob else self._initial_size

    def _update_size_widgets(self) -> None:
        size_text = _format_dual_size(self._current_payload_size())
        if hasattr(self, "size_display") and self.size_display is not None:
            self.size_display.setText(size_text)
        if _constants.is_combo_dir(self.directory_kind):
            return
        helper_text = self._declared_size_helper_text(size_text)
        self.declared_size_display.setText(helper_text)

    def _is_declared_size_locked(self) -> bool:
        return (self._current_type_value() & 0xFF) in (0x48, 0x49, 0x4A)

    def _update_size_override_visibility(self) -> None:
        if self.size_override_edit is None:
            return
        locked = self._is_declared_size_locked()
        visible = self._allow_size_override and not locked
        self.size_override_edit.setVisible(visible)
        if self._size_override_label is not None:
            self._size_override_label.setVisible(visible)
        if locked:
            self._size_override_value = 0
            self.size_override_edit.setText("0x0")
        elif not self.size_override_edit.text().strip():
            self.size_override_edit.setPlaceholderText("Auto")
        self._update_size_widgets()

    def _update_pointer_mode(self, pointer_entry: bool) -> None:
        if _constants.is_combo_dir(self.directory_kind):
            self._pointer_entry = True
            self.require_data = False
            self._update_size_widgets()
            self._update_accept_state()
            self._update_size_override_visibility()
            return
        manage_file_inputs = self._allow_file_selection
        if pointer_entry:
            self._pointer_entry = True
            self.require_data = False
            if manage_file_inputs:
                self._set_file_inputs_visible(False)
            if self._address_mode_value is None:
                self._address_mode_value = 0
        else:
            self._pointer_entry = False
            self.require_data = self._base_require_data
            if manage_file_inputs:
                self._set_file_inputs_visible(True)
        show_pointer_inputs = bool(pointer_entry and not _constants.is_combo_dir(self.directory_kind))
        pointer_locked = bool(show_pointer_inputs and self._should_lock_pointer_value())
        self._pointer_value_locked = pointer_locked
        combo_should_show = bool(self._allow_address_mode_edit and not pointer_entry)
        if self.address_mode_combo is not None:
            self.address_mode_combo.setVisible(combo_should_show)
            self.address_mode_combo.setEnabled(combo_should_show)
            if combo_should_show:
                self._sync_address_mode_combo()
        if self.address_mode_combo_label is not None:
            self.address_mode_combo_label.setVisible(combo_should_show)
        if self.address_mode_label_widget is not None:
            self.address_mode_label_widget.setVisible(not pointer_entry and not combo_should_show)
        if self.address_mode_label_label is not None:
            self.address_mode_label_label.setVisible(
                not pointer_entry and not combo_should_show
            )
        if self.address_label is not None:
            self.address_label.setVisible(not pointer_entry)
        if self.entry_address_label_label is not None:
            self.entry_address_label_label.setVisible(not pointer_entry)
        if self.pointer_value_edit is not None:
            placeholder = "0x pointer value"
            if pointer_locked:
                placeholder = "Auto (ISH stub)"
            self.pointer_value_edit.setPlaceholderText(placeholder)
            self.pointer_value_edit.setVisible(show_pointer_inputs)
            self.pointer_value_edit.setEnabled(show_pointer_inputs and not pointer_locked)
            self.pointer_value_edit.setReadOnly(pointer_locked)
            if show_pointer_inputs:
                text = self.pointer_value_edit.text().strip().lower()
                if text in {"", "0x", "0x_"}:
                    initial = self._initial_address_value
                    if initial is None and self._initial_pointer is not None:
                        initial = int(self._initial_pointer) & ((1 << 62) - 1)
                    if initial is not None:
                        self.pointer_value_edit.setText(f"0x{initial:X}")
        if self.pointer_value_label is not None:
            self.pointer_value_label.setVisible(show_pointer_inputs)
            self.pointer_value_label.setEnabled(not pointer_locked)
        self._update_size_widgets()
        self._update_accept_state()
        self._update_size_override_visibility()

    def _declared_size_helper_text(self, payload_text: str) -> str:
        if self._is_declared_size_locked():
            return "Declared size fixed to 0x0"
        if self._pointer_entry and not self.require_data:
            if self._ish_payload_active and self._data_blob:
                return f"ISH stub payload: {payload_text}"
            return "Pointer entry (no payload)"
        override_desc = self._format_size_override_helper()
        if override_desc:
            return override_desc
        return f"Declared size matches payload ({payload_text})"

    def _format_size_override_helper(self) -> str:
        if (
            not self._allow_size_override
            or self.size_override_edit is None
            or not self.size_override_edit.isVisible()
        ):
            return ""
        raw = self.size_override_edit.text().strip()
        if not raw:
            return ""
        try:
            value = int(raw, 0)
        except Exception:
            return f"Declared size override: {raw}"
        if value < 0:
            return f"Declared size override: {raw}"
        return f"Declared size override: {_format_dual_size(value)}"

    def _should_lock_pointer_value(self) -> bool:
        if self.directory_kind != DirKind.PSP_L1:
            return False
        if not self._pointer_entry:
            return False
        return (self._current_type_value() & 0xFF) in (0x48, 0x4A)

    def _on_type_changed(self, *_args) -> None:
        if _constants.is_combo_dir(self.directory_kind):
            self._pointer_entry = True
            self.require_data = False
            self._update_size_widgets()
            self._update_accept_state()
            self._update_size_override_visibility()
            return
        definition = lookup_entry_definition(
            self.directory_kind, self._current_type_value()
        )
        pointer_entry = bool(definition and definition.entry_type == POINT_ENTRY)
        self._update_pointer_mode(pointer_entry)
        self._update_size_override_visibility()
        self._update_ish_visibility()

    def _on_accept(self) -> None:
        if self.require_data and not self._data_blob:
            QMessageBox.warning(
                self, "Missing data", "Select a payload file before saving."
            )
            return
        if self._allow_size_override and self.size_override_edit is not None:
            if not self.size_override_edit.isVisible() or self._is_declared_size_locked():
                self._size_override_value = 0
            else:
                text = self.size_override_edit.text().strip()
                if text:
                    try:
                        value = int(text, 0)
                    except ValueError:
                        QMessageBox.warning(
                            self,
                            "Invalid size",
                            "Enter a valid decimal or hexadecimal size override.",
                        )
                        return
                    if value < 0:
                        QMessageBox.warning(
                            self,
                            "Invalid size",
                            "Size override must be non-negative.",
                        )
                        return
                    self._size_override_value = value
                else:
                    self._size_override_value = None
        else:
            self._size_override_value = None
        self._cached_config = None
        self._cached_pointer_config = None
        try:
            pointer_config = self._collect_pointer_config()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid value", str(exc))
            return
        if self._allow_ish_builder:
            try:
                self._refresh_ish_stub(silent=False)
            except ValueError as exc:
                QMessageBox.warning(self, "Invalid ISH value", str(exc))
                return
        try:
            self._cached_config = dict(self._config_provider())
            self._cached_pointer_config = dict(pointer_config)
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid value", str(exc))
            return
        self.accept()

    def result_config(self) -> dict:
        base = dict(self._cached_config or self._config_provider())
        base.setdefault("type_value", int(self._current_type_value()))
        if self.address_mode_combo is not None:
            mode_value: Optional[int] = int(self.address_mode_combo.currentData() or 0)
        else:
            mode_value = self._address_mode_value
        pointer_config = dict(
            self._cached_pointer_config or self._collect_pointer_config()
        )
        base.update(
            {
                "address_mode": mode_value,
                "data": bytes(self._data_blob),
                "file_path": str(self._file_path) if self._file_path else None,
                "size": len(self._data_blob) if self._data_blob else self._initial_size,
                "size_override": self._size_override_value,
            }
        )
        base.update(pointer_config)
        if self._ish_builder_visible():
            try:
                ish_fields = self._collect_ish_field_values(strict=False)
            except ValueError:
                ish_fields = None
            if ish_fields:
                base["ish_stub_fields"] = dict(ish_fields)
        return base

    def _collect_pointer_config(self) -> dict:
        if _constants.is_combo_dir(self.directory_kind):
            return {}
        if not self._pointer_entry:
            return {}
        pointer_value: Optional[int] = None
        pointer_text = ""
        if not self._pointer_value_locked:
            if self.pointer_value_edit is None:
                raise ValueError("Pointer entry is missing pointer input.")
            pointer_text_input = self.pointer_value_edit.text().strip()
            if pointer_text_input.lower() in {"", "0x", "0x_"}:
                raise ValueError("Enter a hexadecimal pointer value for the entry.")
            try:
                pointer_value = int(pointer_text_input, 16)
            except ValueError as exc:
                raise ValueError(
                    "Enter a valid hexadecimal pointer value using the 0x prefix."
                ) from exc
            if pointer_value < 0 or pointer_value >= (1 << 62):
                raise ValueError(
                    "Pointer value must fit within 62 bits (0-0x3FFF_FFFF_FFFF_FFFF)."
                )
            pointer_text = f"0x{pointer_value:X}"
        else:
            pointer_value = self._initial_address_value
            if pointer_value is None and self._initial_pointer is not None:
                pointer_value = int(self._initial_pointer) & ((1 << 62) - 1)
            if pointer_value is not None:
                pointer_text = f"0x{pointer_value:X}"
        mode_value = self._address_mode_value or 0
        if self.address_mode_combo is not None and self.address_mode_combo.isVisible():
            data = self.address_mode_combo.currentData()
            if isinstance(data, int):
                mode_value = data & 0x3
        config = {
            "pointer_value": None
            if pointer_value is None
            else pointer_value & ((1 << 62) - 1),
            "pointer_text": pointer_text,
            "address_mode": mode_value & 0x3,
        }
        if self._is_declared_size_locked():
            config["declared_size"] = 0
        return config

    def _sync_address_mode_combo(self) -> None:
        if self.address_mode_combo is None:
            return
        target = int(self._address_mode_value or 0) & 0x3
        index = self.address_mode_combo.findData(target)
        if index < 0:
            index = 0
        self.address_mode_combo.blockSignals(True)
        self.address_mode_combo.setCurrentIndex(index)
        self.address_mode_combo.blockSignals(False)
        self._address_mode_value = int(self.address_mode_combo.currentData() or 0) & 0x3

    def _on_address_mode_changed(self, _index: int) -> None:
        if self.address_mode_combo is None:
            return
        data = self.address_mode_combo.currentData()
        if isinstance(data, int):
            self._address_mode_value = data & 0x3
