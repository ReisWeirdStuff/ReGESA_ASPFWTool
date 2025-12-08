# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Hex dialog mixin for MainWindow.

This module provides:
    - Hex view dialogs for binary data display
    - APCB token display dialog
    - Microcode details dialog
    - Hex selection handling
"""

from typing import List, TYPE_CHECKING

from .qt import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QEvent,
    QFontDatabase,
    QFontMetrics,
    QGuiApplication,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QObject,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QTextOption,
    QVBoxLayout,
    Qt,
)
from .microcode_dialog import MicrocodeDetailsDialog
from ..widgets.hex_viewer import (
    _clamp_hex_editor_cursor,
    _configure_hex_editor,
    _auto_hex_width,
    _hex_dump,
    _hex_editor_selection_range,
    _normalize_hex_blob,
    _update_hex_editor_selection,
)
from ...agesa import constants as _constants

if TYPE_CHECKING:
    pass  # Forward type references go here if needed


class HexDialogsMixin:
    """
    Mixin class providing hex view dialog functionality.
    
    Requires the host class to have:
    - _display_scale attribute
    - _hex_dialogs list
    - _resolve_payload_bytes() method
    - _format_payload_location() method
    - height() method (from QMainWindow)
    """

    _hex_dialogs: List[QDialog]
    _display_scale: float

    def _show_hex_dialog(self, blob: bytes, title: str) -> None:
        """Display a hex dump dialog for the given binary data."""
        if blob is None or len(blob) == 0:
            QMessageBox.information(
                self, "Empty data", "No bytes available to display."
            )
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)

        # Build UI in Python
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        editor = QPlainTextEdit(dialog)
        editor.setObjectName("hex_editor")
        editor.setReadOnly(True)
        editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(editor)

        font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        scale = getattr(self, "_display_scale", 1.0)
        base_size = font.pointSizeF()
        if base_size <= 0:
            base_size = float(font.pointSize() or 9)
        font.setPointSizeF(base_size * float(scale))
        editor.setFont(font)
        editor.setWordWrapMode(QTextOption.NoWrap)
        editor.setContextMenuPolicy(Qt.CustomContextMenu)
        editor.customContextMenuRequested.connect(
            lambda pos, ed=editor: self._show_hex_context_menu(ed, pos)
        )
        editor.cursorPositionChanged.connect(
            lambda ed=editor: _update_hex_editor_selection(ed)
        )
        editor.selectionChanged.connect(
            lambda ed=editor: _update_hex_editor_selection(ed)
        )
        auto_width = _auto_hex_width(len(blob))
        metrics = QFontMetrics(font)
        char_width = max(metrics.horizontalAdvance("M"), 1)

        def _build_dump(show_ascii: bool) -> tuple[str, int]:
            text = _hex_dump(blob, width=auto_width, include_ascii=show_ascii)
            lines = text.splitlines() or [""]
            max_chars = max(len(line) for line in lines)
            width_px = char_width * (max_chars + 2) + editor.frameWidth() * 2 + 32
            return text, width_px

        dump_with_ascii, width_ascii_raw = _build_dump(True)
        dump_hex_only, width_hex_raw = _build_dump(False)

        screen = QApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            max_allowed_width = max(int(avail.width() * 0.9), 640)
        else:
            max_allowed_width = 1600

        ascii_possible = width_ascii_raw <= max_allowed_width
        include_ascii = ascii_possible
        required_width = width_ascii_raw if include_ascii else min(width_hex_raw, max_allowed_width)
        dump_text = dump_with_ascii if include_ascii else dump_hex_only

        editor.setPlainText(dump_text)
        _configure_hex_editor(
            editor, blob=blob, width=auto_width, include_ascii=include_ascii
        )

        width_hex_clamped = min(width_hex_raw, max_allowed_width)
        width_ascii_clamped = min(width_ascii_raw, max_allowed_width)

        dialog.setMinimumWidth(int(width_hex_clamped))
        dialog.setMaximumWidth(int(width_ascii_clamped))

        width = max(int(required_width), dialog.minimumWidth())
        width = min(width, dialog.maximumWidth())

        # Calculate content height based on line count
        line_count = dump_text.count('\n') + 1
        line_height = metrics.lineSpacing()
        content_height = line_count * line_height + editor.frameWidth() * 2 + 40

        # Max height = main window height
        main_window_height = self.height() or 800
        max_height = main_window_height

        # Fit content height, clamped to max
        height = min(content_height, max_height)
        height = max(height, 200)  # minimum usable height

        dialog.resize(int(width), int(height))

        dumps = {True: (dump_with_ascii, width_ascii_raw), False: (dump_hex_only, width_hex_raw)}
        state = {"include_ascii": include_ascii}

        ascii_threshold = max(
            dialog.minimumWidth(),
            min(dialog.maximumWidth(), width_ascii_raw) - char_width,
        )

        def _apply_dump(show_ascii: bool) -> None:
            if state["include_ascii"] == show_ascii:
                return
            text, _width_needed = dumps[show_ascii]
            state["include_ascii"] = show_ascii
            editor.blockSignals(True)
            editor.setPlainText(text)
            editor.blockSignals(False)
            _configure_hex_editor(
                editor, blob=blob, width=auto_width, include_ascii=show_ascii
            )
            target_max = width_ascii_clamped if ascii_possible else width_hex_clamped
            dialog.setMaximumWidth(int(target_max))
            dialog.setMinimumWidth(int(width_hex_clamped))
            if show_ascii and ascii_possible:
                target_width = min(
                    max(int(width_ascii_raw), dialog.minimumWidth()), dialog.maximumWidth()
                )
                if dialog.width() < target_width:
                    dialog.resize(target_width, dialog.height())
            _update_hex_editor_selection(editor)

        if ascii_possible:
            class _HexDialogFilter(QObject):
                def eventFilter(self, obj, event):
                    if obj is dialog and event.type() == QEvent.Resize:
                        current_width = dialog.width()
                        want_ascii = current_width >= ascii_threshold
                        _apply_dump(bool(want_ascii))
                    return QObject.eventFilter(self, obj, event)

            resize_filter = _HexDialogFilter(dialog)
            dialog.installEventFilter(resize_filter)
            dialog._hex_resize_filter = resize_filter  # type: ignore[attr-defined]

        dialog.finished.connect(lambda _result, d=dialog: self._on_hex_dialog_closed(d))
        dialog.destroyed.connect(
            lambda _obj=None, d=dialog: self._on_hex_dialog_closed(d)
        )
        _update_hex_editor_selection(editor)
        dialog.show()
        self._hex_dialogs.append(dialog)

    def _on_hex_dialog_closed(self, dialog: QDialog) -> None:
        """Clean up when a hex dialog is closed."""
        try:
            self._hex_dialogs.remove(dialog)
        except ValueError:
            pass

    def _show_apcb_tokens(self, payload: dict) -> None:
        """Display APCB tokens dialog for the given payload."""
        # Import here to avoid circular imports
        from ...apcb import ApcbParseError, parse_apcb_tokens
        
        blob = self._resolve_payload_bytes(payload)
        if blob is None:
            QMessageBox.warning(
                self, "No data", "Unable to resolve payload bytes for this item."
            )
            return
        try:
            result = parse_apcb_tokens(blob)
        except ApcbParseError as exc:
            QMessageBox.warning(self, "APCB parsing failed", str(exc))
            return
        tokens = result.tokens
        if not tokens:
            QMessageBox.information(
                self,
                "APCB Tokens",
                "No APCB tokens were discovered in this payload.",
            )
            return

        dialog = QDialog(self)
        label = payload.get("label", "APCB")
        dialog.setWindowTitle(f"APCB Tokens - {label}")
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        summary_label = QLabel(
            f"Version: {result.version} | Tokens: {len(tokens)}", dialog
        )
        layout.addWidget(summary_label)

        search_layout = QHBoxLayout()
        search_label = QLabel("Search:", dialog)
        search_edit = QLineEdit(dialog)
        search_edit.setPlaceholderText("Enter token name or UID…")
        search_edit.setClearButtonEnabled(True)
        search_layout.addWidget(search_label)
        search_layout.addWidget(search_edit)
        layout.addLayout(search_layout)

        table = QTableWidget(dialog)
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(
            ["Name", "Token ID", "Value", "Usage / Definition"]
        )
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setWordWrap(True)
        table.setRowCount(len(tokens))

        for row, record in enumerate(tokens):
            token_text = f"0x{record.token_uid:04X}"
            id_item = QTableWidgetItem(token_text)
            id_item.setTextAlignment(Qt.AlignCenter)
            name_text = record.name or token_text
            name_item = QTableWidgetItem(name_text)
            usage = (record.usage or "").strip()
            details = (record.details or "").strip()
            if usage and details and usage != details:
                description = f"{usage}\n{details}"
            else:
                description = usage or details
            if not description:
                description = "-"
            desc_item = QTableWidgetItem(description)
            desc_item.setToolTip(description.replace("\n", "<br>"))
            value_item = QTableWidgetItem(record.value_hex)
            value_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            table.setItem(row, 0, name_item)
            table.setItem(row, 1, id_item)
            table.setItem(row, 2, value_item)
            table.setItem(row, 3, desc_item)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)
        table.resizeRowsToContents()
        layout.addWidget(table)

        def _filter_rows(text: str) -> None:
            query = text.strip().lower()
            for row in range(table.rowCount()):
                if not query:
                    table.setRowHidden(row, False)
                    continue
                name_item = table.item(row, 0)
                id_item = table.item(row, 1)
                name_text = name_item.text().lower() if name_item else ""
                id_text = id_item.text().lower() if id_item else ""
                matches = query in name_text or query in id_text
                table.setRowHidden(row, not matches)

        search_edit.textChanged.connect(_filter_rows)

        button_box = QDialogButtonBox(QDialogButtonBox.Close, dialog)
        button_box.rejected.connect(dialog.reject)
        close_button = button_box.button(QDialogButtonBox.Close)
        if close_button is not None:
            close_button.setDefault(True)
        layout.addWidget(button_box)

        dialog.resize(900, 500)
        dialog.exec()

    def _show_microcode_details(self, payload: dict) -> None:
        """Display microcode details dialog for the given payload."""
        from ...agesa.microcode import MicrocodeParseError, parse_microcode_patch
        
        blob = self._resolve_payload_bytes(payload)
        if blob is None:
            QMessageBox.warning(
                self, "No data", "Unable to resolve payload bytes for this item."
            )
            return
        try:
            header, _body = parse_microcode_patch(blob)
        except (MicrocodeParseError, TypeError) as exc:
            QMessageBox.warning(self, "Microcode parsing failed", str(exc))
            return

        label = payload.get("label") or payload.get("name") or "Microcode"
        dialog = MicrocodeDetailsDialog(
            self,
            header=header,
            payload_size=len(blob),
            label=str(label),
        )
        dialog.resize(520, 360)
        dialog.exec()

    def _open_hex_view(self, payload: dict) -> None:
        """Open hex view for a payload."""
        blob = self._resolve_payload_bytes(payload)
        if blob is None:
            QMessageBox.warning(
                self, "No data", "Unable to resolve payload bytes for this item."
            )
            return
        base_label = str(payload.get("label", "payload"))
        title = f"HEX View - {base_label}"
        location_title = self._format_payload_location(payload)
        if location_title:
            title = f"{title} - {location_title}"
        self._show_hex_dialog(blob, title)

    def _open_decompressed_hex(self, payload: dict, *, force: bool = False) -> None:
        """Open hex view for decompressed payload data."""
        from .common import _attempt_decompress, _guess_compression_mode
        
        # Check if this is a compressed BIOS entry (type 0x62)
        # These have a 0x100-byte header, zlib stream starts at offset 0x100
        type_id = payload.get("type_id")
        directory_kind = payload.get("directory_kind") or payload.get("directory")
        is_bios_entry = (
            isinstance(type_id, int) 
            and (type_id & 0xFF) == 0x62
            and _constants.is_real_bios_dir(directory_kind)
        )
        
        decompressed = None
        blob = None
        
        if is_bios_entry:
            # For 0x62 entries, read the actual compressed size from the header
            # The size at offset 0x14 is the zlib data size, add 0x100 for header
            image_index = payload.get("image_index")
            offset = payload.get("offset")
            if image_index is not None and offset is not None:
                try:
                    image_index = int(image_index)
                    offset = int(offset)
                    if 0 <= image_index < len(self.loaded_images):
                        image = self.loaded_images[image_index]
                        # Read the compressed size from offset 0x14 in the header
                        if offset + 0x18 <= len(image.data):
                            zlib_size = int.from_bytes(
                                image.data[offset + 0x14:offset + 0x18], "little"
                            )
                            # Total size = 0x100 header + zlib_size
                            total_size = 0x100 + zlib_size
                            if zlib_size > 0 and offset + total_size <= len(image.data):
                                blob = bytes(image.data[offset:offset + total_size])
                                import zlib
                                zlib_chunk = blob[0x100:]
                                for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                                    try:
                                        decompressed = zlib.decompress(zlib_chunk, wbits)
                                        break
                                    except Exception:
                                        continue
                except Exception:
                    pass
        
        if decompressed is None:
            # Fall back to normal payload resolution and generic decompression
            if blob is None:
                blob = self._resolve_payload_bytes(payload)
            if blob is None:
                QMessageBox.warning(
                    self, "No data", "Unable to resolve payload bytes for this item."
                )
                return
            mode = payload.get("compression_mode")
            if force and not mode:
                guessed, guessed_mode = _guess_compression_mode(blob)
                if guessed:
                    mode = guessed_mode
            decompressed = _attempt_decompress(blob, mode)
        
        if decompressed is None:
            QMessageBox.warning(
                self,
                "Decompression failed",
                "Unable to decompress this payload using gzip/zlib/deflate.",
            )
            return
        label = str(payload.get("label", "payload"))
        suffix = " (decompressed)"
        title = f"HEX View - {label}{suffix}"
        location_title = self._format_payload_location(payload)
        if location_title:
            title = f"{title} - {location_title}"
        self._show_hex_dialog(decompressed, title)

    def _open_directory_table_hex(self, item) -> None:
        """Open hex view for directory table bytes."""
        from ..utils.roles import HEX_ROLE, ENTRY_LOC_ROLE
        
        blob = item.data(HEX_ROLE)
        if not blob:
            QMessageBox.information(
                self, "No data", "Directory table bytes are unavailable."
            )
            return
        label = item.text() or "Directory"
        title = f"HEX View - {label} (table)"
        locator = item.data(ENTRY_LOC_ROLE)
        location_title = self._format_payload_location(locator if isinstance(locator, dict) else None)
        if location_title:
            title = f"{title} - {location_title}"
        self._show_hex_dialog(bytes(blob), title)

    def _show_hex_context_menu(self, editor: QPlainTextEdit, pos) -> None:
        """Show context menu for hex editor with copy options."""
        menu = editor.createStandardContextMenu()
        menu.addSeparator()
        copy_hex_action = menu.addAction("Copy Hex")
        copy_ascii_action = menu.addAction("Copy ASCII")
        copy_ascii_action.setEnabled(bool(editor.property("showsAscii")))
        chosen = menu.exec_(editor.mapToGlobal(pos))
        if chosen not in (copy_hex_action, copy_ascii_action):
            return
        hex_text, ascii_text = self._extract_hex_ascii_from_editor(editor)
        if chosen == copy_hex_action and hex_text:
            QGuiApplication.clipboard().setText(hex_text)
        elif chosen == copy_ascii_action and ascii_text:
            QGuiApplication.clipboard().setText(ascii_text)

    def _extract_hex_ascii_from_editor(self, editor: QPlainTextEdit) -> tuple[str, str]:
        """Extract hex and ASCII text from editor selection."""
        _clamp_hex_editor_cursor(editor)
        selection = _hex_editor_selection_range(editor)
        blob = editor.property("hexBlob")
        normalized = _normalize_hex_blob(blob)
        if selection is None or not normalized:
            return "", ""
        start, end = selection
        if end < start:
            start, end = end, start
        end = min(end, len(normalized) - 1)
        if end < 0:
            return "", ""
        try:
            width_value = int(editor.property("hexWidth"))
        except Exception:
            width_value = 16
        width_value = max(1, width_value)
        data = normalized[start : end + 1]
        if not data:
            return "", ""
        hex_lines: List[str] = []
        ascii_lines: List[str] = []
        for offset in range(0, len(data), width_value):
            chunk = data[offset : offset + width_value]
            hex_lines.append(" ".join(f"{b:02X}" for b in chunk))
            ascii_lines.append(
                "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            )
        return "\n".join(hex_lines), "\n".join(ascii_lines)
