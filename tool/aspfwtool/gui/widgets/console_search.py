# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Console dock and firmware search utilities.

This module provides:
    - SearchDialog for firmware content searching
    - Console output pane setup and management
    - Search result formatting and navigation
    - Multi-method search (type, hex, GUID, text)
"""

from __future__ import annotations

import html
import re
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Pattern, Tuple
from urllib.parse import parse_qs, urlencode

from PySide6.QtCore import QPoint, Qt, QUrl
from PySide6.QtGui import QFontDatabase, QStandardItem, QTextCursor, QTextOption
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QTextBrowser,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..utils.roles import DETAIL_ROLE, ENTRY_LOC_ROLE, METADATA_ROLE, PAYLOAD_ROLE, SUMMARY_ROLE

SEARCH_METHOD_LABELS: Dict[str, str] = {
    "psp-all": "All PSP methods",
    "psp-type": "Entry type/name",
    "psp-hex": "HEX pattern",
    "psp-metadata": "Metadata field",
    "uefi-all": "All UEFI methods",
    "uefi-hex": "HEX pattern",
    "uefi-guid": "GUID",
    "uefi-text": "Text",
    "uefi-name": "Module name",
    "all-any": "Any (PSP + UEFI, ASCII)",
    "all-hex": "HEX pattern (all regions)",
}


@dataclass
class SearchRequest:
    target: str
    method: str
    value: str
    case_sensitive: bool = False
    encoding: str = "ascii"


@dataclass
class SearchResult:
    scheme: str
    query: Dict[str, str]
    title: str
    subtitle: Optional[str] = None


class SearchDialog(QDialog):
    def __init__(
        self,
        parent: QWidget,
        initial_request: Optional[SearchRequest] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Search firmware")
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self._request: Optional[SearchRequest] = None
        self._initial_request = initial_request

        # Build UI in Python
        wrapper = QVBoxLayout(self)
        wrapper.setContentsMargins(12, 12, 12, 12)
        wrapper.setSpacing(10)

        form_layout = QFormLayout()
        form_layout.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        self.target_combo = QComboBox(self)
        self.target_combo.setObjectName("target_combo")
        form_layout.addRow("Search in:", self.target_combo)

        self.method_combo = QComboBox(self)
        self.method_combo.setObjectName("method_combo")
        form_layout.addRow("Method:", self.method_combo)

        self.value_edit = QLineEdit(self)
        self.value_edit.setObjectName("value_edit")
        form_layout.addRow("Value:", self.value_edit)

        # text_options container with encoding and case sensitivity
        self.text_options = QWidget(self)
        self.text_options.setObjectName("text_options")
        text_opts_layout = QHBoxLayout(self.text_options)
        text_opts_layout.setContentsMargins(0, 0, 0, 0)
        text_opts_layout.setSpacing(10)

        self.encoding_combo = QComboBox(self.text_options)
        self.encoding_combo.setObjectName("encoding_combo")
        text_opts_layout.addWidget(self.encoding_combo)

        self.case_checkbox = QCheckBox("Case sensitive", self.text_options)
        self.case_checkbox.setObjectName("case_checkbox")
        text_opts_layout.addWidget(self.case_checkbox)

        text_opts_layout.addStretch()
        form_layout.addRow("Options:", self.text_options)

        wrapper.addLayout(form_layout)

        self.button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self
        )
        self.button_box.setObjectName("button_box")
        wrapper.addWidget(self.button_box)

        self.target_combo.clear()
        self.target_combo.addItem("All", "all")
        self.target_combo.addItem("PSP entries", "psp")
        self.target_combo.addItem("UEFI data", "uefi")

        self.encoding_combo.clear()
        self.encoding_combo.addItem("ASCII", "ascii")
        self.encoding_combo.addItem("UTF-16 LE", "utf-16le")
        self.case_checkbox.setChecked(False)
        self.text_options.hide()

        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

        self.target_combo.currentIndexChanged.connect(self._update_methods)
        self.method_combo.currentIndexChanged.connect(self._update_ui_state)

        self._apply_initial_request(initial_request)
        self.resize(420, 0)
        self.value_edit.setFocus(Qt.ShortcutFocusReason)

    def _apply_initial_request(self, request: Optional[SearchRequest]) -> None:
        if request is None:
            self._update_methods()
            self._update_ui_state()
            return

        target_index = self.target_combo.findData(request.target)
        if target_index < 0:
            target_index = 0
        signals_blocked = self.target_combo.blockSignals(True)
        self.target_combo.setCurrentIndex(target_index)
        self.target_combo.blockSignals(signals_blocked)

        self._update_methods()

        method_index = self.method_combo.findData(request.method)
        if method_index < 0:
            method_index = 0
        signals_blocked = self.method_combo.blockSignals(True)
        self.method_combo.setCurrentIndex(method_index)
        self.method_combo.blockSignals(signals_blocked)

        if request.value:
            self.value_edit.setText(request.value)
            self.value_edit.selectAll()

        if request.method == "uefi-text":
            encoding_index = self.encoding_combo.findData(request.encoding)
            if encoding_index < 0:
                encoding_index = self.encoding_combo.findData("ascii")
                if encoding_index < 0:
                    encoding_index = 0
            self.encoding_combo.setCurrentIndex(encoding_index)
            self.case_checkbox.setChecked(bool(request.case_sensitive))
        else:
            ascii_index = self.encoding_combo.findData("ascii")
            if ascii_index < 0:
                ascii_index = 0
            self.encoding_combo.setCurrentIndex(ascii_index)
            self.case_checkbox.setChecked(False)

        self._update_ui_state()

    def _update_methods(self) -> None:
        target = self.target_combo.currentData()
        previous = self.method_combo.currentData()
        self.method_combo.blockSignals(True)
        self.method_combo.clear()
        if target == "all":
            self.method_combo.addItem("Any (PSP + UEFI, ASCII)", "all-any")
            self.method_combo.addItem("HEX pattern", "all-hex")
        elif target == "uefi":
            self.method_combo.addItem("All methods", "uefi-all")
            self.method_combo.addItem("HEX pattern", "uefi-hex")
            self.method_combo.addItem("GUID", "uefi-guid")
            self.method_combo.addItem("Text", "uefi-text")
            self.method_combo.addItem("Module name", "uefi-name")
        else:
            self.method_combo.addItem("All methods", "psp-all")
            self.method_combo.addItem("Entry Name/TypeId", "psp-type")
            self.method_combo.addItem("HEX pattern", "psp-hex")
            self.method_combo.addItem("Metadata field", "psp-metadata")
        if previous is not None:
            index = self.method_combo.findData(previous)
            if index >= 0:
                self.method_combo.setCurrentIndex(index)
        self.method_combo.blockSignals(False)
        self._update_ui_state()

    def _update_ui_state(self) -> None:
        method = self.method_combo.currentData()
        if method == "uefi-text":
            self.text_options.show()
            self.value_edit.setPlaceholderText("Text to search in UEFI payloads")
        elif method == "uefi-guid":
            self.text_options.hide()
            self.value_edit.setPlaceholderText("GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
        elif method == "uefi-name":
            self.text_options.hide()
            self.value_edit.setPlaceholderText("Module name (partial match)")
        else:
            self.text_options.hide()
            self.value_edit.setPlaceholderText("Search value")

    def accept(self) -> None:  # type: ignore[override]
        target = self.target_combo.currentData()
        method = self.method_combo.currentData()
        value = (self.value_edit.text() or "").strip()
        if not value:
            QMessageBox.warning(self, "Missing value", "Enter a value to search for.")
            return
        encoding = self.encoding_combo.currentData() if method == "uefi-text" else "ascii"
        case_sensitive = self.case_checkbox.isChecked() if method == "uefi-text" else False
        self._request = SearchRequest(
            target=str(target),
            method=str(method),
            value=value,
            case_sensitive=bool(case_sensitive),
            encoding=str(encoding),
        )
        super().accept()

    def get_request(self) -> Optional[SearchRequest]:
        return self._request


def setup_output_pane(window) -> QDockWidget:
    """Create the console/search dock for the main window."""
    # Build UI in Python
    output_widget = QWidget(window)

    main_layout = QVBoxLayout(output_widget)
    main_layout.setContentsMargins(0, 0, 0, 0)
    main_layout.setSpacing(0)

    output_tabs = QTabWidget(output_widget)
    output_tabs.setObjectName("output_tabs")

    # Console tab
    console_tab = QWidget()
    console_tab.setObjectName("console_tab")
    console_layout = QVBoxLayout(console_tab)
    console_layout.setContentsMargins(0, 0, 0, 0)
    console_layout.setSpacing(0)

    console = QPlainTextEdit(console_tab)
    console.setObjectName("console_edit")
    console.setReadOnly(True)
    console.setPlaceholderText("Console output")
    console.setMinimumHeight(120)
    console.setLineWrapMode(QPlainTextEdit.NoWrap)
    console_layout.addWidget(console)

    output_tabs.addTab(console_tab, "Console")

    # Search tab
    search_tab = QWidget()
    search_tab.setObjectName("search_tab")
    search_layout = QVBoxLayout(search_tab)
    search_layout.setContentsMargins(0, 0, 0, 0)
    search_layout.setSpacing(0)

    search_browser = QTextBrowser(search_tab)
    search_browser.setObjectName("search_browser")
    search_browser.setOpenLinks(False)
    search_browser.setOpenExternalLinks(False)
    search_browser.setPlaceholderText("Search results")
    search_browser.setMinimumHeight(120)
    search_browser.setLineWrapMode(QTextBrowser.NoWrap)
    search_layout.addWidget(search_browser)

    output_tabs.addTab(search_tab, "Search")

    main_layout.addWidget(output_tabs)

    window.output_tabs = output_tabs
    window.console = console
    window.search_tab = search_tab
    window.search_browser = search_browser

    console.setWordWrapMode(QTextOption.NoWrap)
    console.setContextMenuPolicy(Qt.CustomContextMenu)
    console.customContextMenuRequested.connect(
        lambda point, w=window: on_console_context_menu(w, point)
    )
    try:
        console.document().setMaximumBlockCount(500)
    except Exception:
        pass

    console_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
    if console_font.pointSizeF() <= 0:
        console_font.setPointSize(10)
    console.setFont(console_font)
    search_browser.setFont(console_font)

    search_browser.setOpenLinks(False)
    search_browser.setOpenExternalLinks(False)
    search_browser.setPlaceholderText("Search results")
    search_browser.setMinimumHeight(120)
    search_browser.setWordWrapMode(QTextOption.NoWrap)
    search_browser.setContextMenuPolicy(Qt.CustomContextMenu)
    search_browser.customContextMenuRequested.connect(
        lambda point, w=window: on_search_context_menu(w, point)
    )
    window._search_placeholder_html = "<p><i>No search has been run yet.</i></p>"
    search_browser.setHtml(window._search_placeholder_html)
    window._search_has_results = False
    search_browser.anchorClicked.connect(
        lambda url, w=window: on_search_anchor_clicked(w, url)
    )

    dock = QDockWidget("Console / Search", window)
    dock.setObjectName("ConsoleDock")
    dock.setWidget(output_widget)
    dock.setAllowedAreas(Qt.BottomDockWidgetArea | Qt.TopDockWidgetArea)
    dock.setFeatures(
        QDockWidget.DockWidgetClosable
        | QDockWidget.DockWidgetMovable
        | QDockWidget.DockWidgetFloatable
    )
    return dock


def append_console(window, message: str) -> None:
    if not message:
        return
    console = getattr(window, "console", None)
    if console is None:
        return
    timestamp = datetime.now().strftime("%H:%M:%S")
    console.appendPlainText(f"[{timestamp}] {message}")
    cursor = console.textCursor()
    cursor.movePosition(QTextCursor.End)
    console.setTextCursor(cursor)
    console.ensureCursorVisible()


def on_console_context_menu(window, point: QPoint) -> None:
    console = getattr(window, "console", None)
    if console is None:
        return
    menu = console.createStandardContextMenu()
    menu.addSeparator()
    clear_action = menu.addAction("Clear")
    try:
        document_empty = console.document().isEmpty()
    except Exception:
        document_empty = False
    clear_action.setEnabled(not document_empty)
    clear_action.triggered.connect(console.clear)
    menu.exec(console.mapToGlobal(point))


def on_search_context_menu(window, point: QPoint) -> None:
    browser = getattr(window, "search_browser", None)
    if browser is None:
        return
    menu = browser.createStandardContextMenu()
    menu.addSeparator()
    clear_action = menu.addAction("Clear")
    clear_action.setEnabled(bool(getattr(window, "_search_has_results", False)))
    clear_action.triggered.connect(
        lambda checked=False, w=window: clear_search_results_view(w)
    )
    menu.exec(browser.mapToGlobal(point))


def clear_search_results_view(window) -> None:
    browser = getattr(window, "search_browser", None)
    if browser is None:
        return
    placeholder = getattr(window, "_search_placeholder_html", "")
    if placeholder:
        browser.setHtml(placeholder)
    else:
        browser.clear()
    window._search_has_results = False


def describe_search_request(request: SearchRequest) -> str:
    target_label = "PSP" if request.target == "psp" else "UEFI"
    method_label = SEARCH_METHOD_LABELS.get(request.method, request.method)
    return f"{target_label} {method_label} ({request.value})"


def _iter_psp_entries(window) -> Iterator[QStandardItem]:
    def _walk(item: Optional[QStandardItem]):
        if item is None:
            return
        locator = item.data(ENTRY_LOC_ROLE)
        if isinstance(locator, dict) and locator.get("entry_index") is not None:
            yield item
        for row in range(item.rowCount()):
            child = item.child(row, 0)
            yield from _walk(child)

    for row in range(window.psp_model.rowCount()):
        yield from _walk(window.psp_model.item(row, 0))


def _iter_uefi_items(window) -> Iterator[QStandardItem]:
    def _walk(item: Optional[QStandardItem]):
        if item is None:
            return
        payload = item.data(PAYLOAD_ROLE)
        if isinstance(payload, dict) and payload.get("image_index") is not None:
            yield item
        for row in range(item.rowCount()):
            child = item.child(row, 0)
            yield from _walk(child)

    for row in range(window.uefi_model.rowCount()):
        yield from _walk(window.uefi_model.item(row, 0))


def _build_psp_query(locator: dict) -> Dict[str, str]:
    query: Dict[str, str] = {}
    image_index = locator.get("image_index")
    directory_index = locator.get("directory_index")
    entry_index = locator.get("entry_index")
    if image_index is not None:
        query["image"] = str(image_index)
    if directory_index is not None:
        query["directory"] = str(directory_index)
    if entry_index is not None:
        query["entry"] = str(entry_index)
    return query

def _build_uefi_query(payload: dict) -> Dict[str, str]:
    query: Dict[str, str] = {}
    image_index = payload.get("image_index")
    offset = payload.get("offset")
    size = payload.get("size")
    guid_val = payload.get("guid")
    volume_index = payload.get("volume_index")
    root_index = payload.get("root_index")
    if image_index is not None:
        query["image"] = str(image_index)
    if offset is not None:
        try:
            query["offset"] = hex(int(offset))
        except Exception:
            query["offset"] = str(offset)
    if size is not None:
        try:
            query["size"] = hex(int(size))
        except Exception:
            query["size"] = str(size)
    if guid_val is not None:
        query["guid"] = str(guid_val)
    # Include volume/root index for unique identification when offset is None
    if volume_index is not None:
        query["volume"] = str(volume_index)
    if root_index is not None:
        query["root"] = str(root_index)
    return query


def _format_psp_result(window, locator: dict, item: QStandardItem, detail: Optional[str] = None) -> Tuple[str, Optional[str]]:
    dir_label = "Directory"
    image_index = locator.get("image_index")
    directory_index = locator.get("directory_index")
    if (
        isinstance(image_index, int)
        and 0 <= image_index < len(window.loaded_images)
        and isinstance(directory_index, int)
    ):
        directories = window.loaded_images[image_index].directories
        if 0 <= directory_index < len(directories):
            dir_label = f"{directories[directory_index].kind.value} {directory_index:02d}"
        else:
            dir_label = f"Directory {directory_index}"
    title = f"{dir_label} -> {item.text()}"
    summary = item.data(SUMMARY_ROLE)
    subtitle = detail or (str(summary) if summary else None)
    return title, subtitle


def _format_uefi_result(window, item: QStandardItem, payload: dict, detail: Optional[str] = None) -> Tuple[str, Optional[str]]:
    image_index = payload.get("image_index")
    image_count = len(window.loaded_images) if hasattr(window, "loaded_images") else 0
    if image_index is None or image_count <= 1:
        title = f"UEFI -> {item.text()}"
    else:
        title = f"UEFI image {image_index} -> {item.text()}"
    summary = item.data(SUMMARY_ROLE)
    subtitle = detail or (str(summary) if summary else None)
    return title, subtitle


def _read_image_bytes(window, image_index: Optional[int], offset: int, size: int) -> Optional[bytes]:
    if not isinstance(image_index, int):
        return None
    if not (0 <= image_index < len(window.loaded_images)):
        return None
    if size <= 0 or offset < 0:
        return None
    data = window.loaded_images[image_index].data
    end = offset + size
    if end > len(data):
        return None
    return bytes(data[offset:end])


@dataclass
class CompiledSearchPattern:
    mode: str  # "hex" or "regex"
    pattern: bytes
    mask: Optional[bytes] = None
    regex: Optional[Pattern[bytes]] = None


_HEX_INPUT_RE = re.compile(r"^[0-9A-Fa-f?\s,_:-]*$")


def _looks_like_hex_pattern(text: str) -> bool:
    return bool(_HEX_INPUT_RE.fullmatch(text))


def _compile_hex_pattern(text: str) -> Tuple[bytes, Optional[bytes]]:
    cleaned = re.sub(r"[^0-9A-Fa-f?]", "", text)
    if not cleaned:
        raise ValueError("Enter at least one HEX byte.")
    if len(cleaned) % 2:
        raise ValueError("HEX pattern must contain whole bytes.")
    pattern_bytes = bytearray()
    mask_bytes = bytearray()
    has_wildcards = False
    for index in range(0, len(cleaned), 2):
        pair = cleaned[index : index + 2]
        if pair == "??":
            has_wildcards = True
            pattern_bytes.append(0)
            mask_bytes.append(0)
            continue
        if not re.fullmatch(r"[0-9A-Fa-f]{2}", pair):
            raise ValueError("Use pairs of HEX digits or '??' wildcards.")
        pattern_bytes.append(int(pair, 16))
        mask_bytes.append(0xFF)
    return bytes(pattern_bytes), bytes(mask_bytes) if has_wildcards else None


def _compile_ascii_regex(text: str) -> Pattern[bytes]:
    if not text:
        raise ValueError("Enter a pattern to search.")
    try:
        pattern_bytes = text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("ASCII regex must use ASCII characters only.") from exc
    try:
        return re.compile(pattern_bytes, re.DOTALL)
    except re.error as exc:
        raise ValueError(f"Invalid regular expression: {exc}") from exc


def _compile_search_pattern(value: str) -> CompiledSearchPattern:
    text = value.strip()
    if not text:
        raise ValueError("Enter a value to search for.")
    if text.lower().startswith("regex:"):
        regex_body = text[6:].lstrip()
        if not regex_body:
            raise ValueError("Enter a regular expression after 'regex:'.")
        regex = _compile_ascii_regex(regex_body)
        return CompiledSearchPattern("regex", b"", regex=regex)
    if _looks_like_hex_pattern(text):
        pattern, mask = _compile_hex_pattern(text)
        return CompiledSearchPattern("hex", pattern, mask=mask)
    regex = _compile_ascii_regex(text)
    return CompiledSearchPattern("regex", b"", regex=regex)


def _find_with_mask(blob: bytes, pattern: bytes, mask: bytes) -> Optional[int]:
    length = len(pattern)
    if length == 0 or len(mask) != length:
        return None
    view = memoryview(blob)
    for start in range(0, len(blob) - length + 1):
        segment = view[start : start + length]
        for segment_byte, pattern_byte, mask_byte in zip(segment, pattern, mask):
            if mask_byte == 0:
                continue
            if segment_byte != pattern_byte:
                break
        else:
            return start
    return None


def _find_compiled_pattern(blob: bytes, compiled: CompiledSearchPattern) -> Optional[int]:
    if compiled.mode == "regex":
        if compiled.regex is None:
            return None
        match = compiled.regex.search(blob)
        if match is None:
            return None
        return match.start()
    if not compiled.pattern:
        return None
    if not compiled.mask:
        pos = blob.find(compiled.pattern)
        return pos if pos >= 0 else None
    return _find_with_mask(blob, compiled.pattern, compiled.mask)


def _search_psp_type(window, value: str) -> List[SearchResult]:
    term = value.strip()
    if not term:
        raise ValueError("Enter a type ID or name to search.")
    # Try to parse as hex type ID
    term_value = None
    try:
        term_value = int(term, 0)
    except ValueError:
        pass
    term_lower = term.lower()
    results: List[SearchResult] = []
    for item in _iter_psp_entries(window):
        locator = item.data(ENTRY_LOC_ROLE)
        if not isinstance(locator, dict):
            continue
        match = False
        payload = item.data(PAYLOAD_ROLE)
        # Match by type ID (hex value)
        if term_value is not None and isinstance(payload, dict):
            type_id = payload.get("type_id")
            if isinstance(type_id, int) and (type_id & 0xFF) == (term_value & 0xFF):
                match = True
        # Match by decoded entry name (type_label) only - not in summary/detail
        if not match and isinstance(payload, dict):
            type_label = payload.get("type_label")
            if type_label and term_lower in str(type_label).lower():
                match = True
        if match:
            title, subtitle = _format_psp_result(window, locator, item)
            results.append(
                SearchResult("psp", _build_psp_query(locator), title, subtitle)
            )
    return results


def _search_psp_hex(window, value: str) -> List[SearchResult]:
    compiled = _compile_search_pattern(value)
    match_label = "Regex match" if compiled.mode == "regex" else "Match"
    results: List[SearchResult] = []
    for item in _iter_psp_entries(window):
        locator = item.data(ENTRY_LOC_ROLE)
        payload = item.data(PAYLOAD_ROLE)
        if not isinstance(locator, dict) or not isinstance(payload, dict):
            continue
        image_index = locator.get("image_index")
        offset = payload.get("offset")
        size = payload.get("size") or payload.get("declared_size")
        try:
            start = int(offset)
            length = int(size)
        except Exception:
            continue
        blob = _read_image_bytes(window, image_index, start, length)
        if not blob:
            continue
        pos = _find_compiled_pattern(blob, compiled)
        if pos is not None:
            absolute = start + pos
            detail = f"{match_label} at 0x{absolute:08X} (+0x{pos:X})"
            title, subtitle = _format_psp_result(window, locator, item, detail)
            results.append(
                SearchResult("psp", _build_psp_query(locator), title, subtitle)
            )
    return results


def _search_psp_metadata(window, value: str) -> List[SearchResult]:
    term = value.strip().lower()
    if not term:
        raise ValueError("Enter metadata text to search.")
    results: List[SearchResult] = []
    for item in _iter_psp_entries(window):
        locator = item.data(ENTRY_LOC_ROLE)
        metadata = item.data(METADATA_ROLE)
        if not isinstance(locator, dict) or not isinstance(metadata, OrderedDict):
            continue
        match_detail: Optional[str] = None
        for key, field_value in metadata.items():
            combined = f"{key}: {field_value}"
            if term in combined.lower():
                match_detail = combined
                break
        if match_detail:
            title, subtitle = _format_psp_result(window, locator, item, match_detail)
            results.append(
                SearchResult("psp", _build_psp_query(locator), title, subtitle)
            )
    return results


def _search_uefi_hex(window, value: str) -> List[SearchResult]:
    compiled = _compile_search_pattern(value)
    match_label = "Regex match" if compiled.mode == "regex" else "Match"
    results: List[SearchResult] = []
    for item in _iter_uefi_items(window):
        payload = item.data(PAYLOAD_ROLE)
        if not isinstance(payload, dict):
            continue
        image_index = payload.get("image_index")
        offset = payload.get("offset")
        size = payload.get("size")
        try:
            image_idx = int(image_index)
            start = int(offset)
            length = int(size)
        except Exception:
            continue
        blob = _read_image_bytes(window, image_idx, start, length)
        if not blob:
            continue
        pos = _find_compiled_pattern(blob, compiled)
        if pos is not None:
            absolute = start + pos
            detail = f"{match_label} at 0x{absolute:08X} (+0x{pos:X})"
            title, subtitle = _format_uefi_result(window, item, payload, detail)
            results.append(
                SearchResult("uefi", _build_uefi_query(payload), title, subtitle)
            )
    return results


def _search_uefi_guid(window, value: str) -> List[SearchResult]:
    text = value.strip().strip("{}")
    if not text:
        raise ValueError("Enter a GUID to search for.")
    try:
        target_guid = uuid.UUID(text)
    except ValueError as exc:
        raise ValueError("Enter a valid GUID.") from exc
    target_text = str(target_guid).lower()
    results: List[SearchResult] = []
    for item in _iter_uefi_items(window):
        payload = item.data(PAYLOAD_ROLE)
        if not isinstance(payload, dict):
            continue
        # Check both 'guid' (primary) and 'filesystem_guid' (for volumes)
        guids_to_check = []
        item_guid = payload.get("guid")
        if item_guid is not None:
            guids_to_check.append(item_guid)
        fs_guid = payload.get("filesystem_guid")
        if fs_guid is not None and fs_guid != item_guid:
            guids_to_check.append(fs_guid)
        if not guids_to_check:
            continue
        matched = False
        for check_guid in guids_to_check:
            try:
                guid_text = str(check_guid).lower()
            except Exception:
                continue
            if guid_text == target_text:
                matched = True
                break
        if not matched:
            continue
        detail = f"GUID {target_guid}"
        if payload.get("offset") is not None:
            detail += f" @ 0x{int(payload.get('offset') or 0):08X}"
        title, subtitle = _format_uefi_result(window, item, payload, detail)
        results.append(
            SearchResult("uefi", _build_uefi_query(payload), title, subtitle)
        )
    return results


def _find_text_in_blob(blob: bytes, text: str, encoding: str, case_sensitive: bool) -> int:
    encoding_lower = encoding.lower()
    if encoding_lower == "ascii":
        try:
            pattern = text.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("Text cannot be encoded as ASCII.") from exc
        if case_sensitive:
            return blob.find(pattern)
        return blob.lower().find(pattern.lower())
    if encoding_lower == "utf-16le":
        try:
            pattern = text.encode("utf-16le")
        except UnicodeEncodeError as exc:
            raise ValueError("Text cannot be encoded as UTF-16LE.") from exc
        if case_sensitive:
            return blob.find(pattern)
        try:
            decoded = blob.decode("utf-16le", errors="ignore")
        except Exception:
            return -1
        pos = decoded.lower().find(text.lower())
        if pos < 0:
            return -1
        return pos * 2
    raise ValueError(f"Unsupported encoding: {encoding}")


def _search_uefi_text(window, request: SearchRequest) -> List[SearchResult]:
    term = request.value
    if not term:
        raise ValueError("Enter text to search.")
    results: List[SearchResult] = []
    for item in _iter_uefi_items(window):
        payload = item.data(PAYLOAD_ROLE)
        if not isinstance(payload, dict):
            continue
        image_index = payload.get("image_index")
        offset = payload.get("offset")
        size = payload.get("size")
        try:
            image_idx = int(image_index)
            start = int(offset)
            length = int(size)
        except Exception:
            continue
        blob = _read_image_bytes(window, image_idx, start, length)
        if not blob:
            continue
        pos = _find_text_in_blob(blob, term, request.encoding, request.case_sensitive)
        if pos >= 0:
            absolute = start + pos
            detail = f"Text match at 0x{absolute:08X}"
            title, subtitle = _format_uefi_result(window, item, payload, detail)
            results.append(
                SearchResult("uefi", _build_uefi_query(payload), title, subtitle)
            )
    return results


def _search_uefi_name(window, value: str) -> List[SearchResult]:
    """Search UEFI modules by name (case-insensitive partial match)."""
    term = value.strip().lower()
    if not term:
        raise ValueError("Enter a module name to search for.")
    results: List[SearchResult] = []
    for item in _iter_uefi_items(window):
        payload = item.data(PAYLOAD_ROLE)
        if not isinstance(payload, dict):
            continue
        name = payload.get("name")
        if not name:
            continue
        if term not in str(name).lower():
            continue
        detail = f"Name: {name}"
        if payload.get("offset") is not None:
            detail += f" @ 0x{int(payload.get('offset') or 0):08X}"
        title, subtitle = _format_uefi_result(window, item, payload, detail)
        results.append(
            SearchResult("uefi", _build_uefi_query(payload), title, subtitle)
        )
    return results


def perform_search(window, request: SearchRequest) -> List[SearchResult]:
    results: List[SearchResult] = []

    # Handle "all" target - search both PSP and UEFI
    if request.target == "all":
        if request.method == "all-any":
            # Run all PSP methods
            results.extend(_search_psp_type(window, request.value))
                #results.extend(_search_psp_hex(window, request.value))
            results.extend(_search_psp_metadata(window, request.value))
            # Run all UEFI methods
                #results.extend(_search_uefi_hex(window, request.value))
                #results.extend(_search_uefi_guid(window, request.value))
            results.extend(_search_uefi_text(window, request))
            results.extend(_search_uefi_name(window, request.value))
            return results
        if request.method == "all-hex":
            # Search HEX pattern across both PSP and UEFI
            results.extend(_search_psp_hex(window, request.value))
            results.extend(_search_uefi_hex(window, request.value))
            return results
        raise ValueError("Unsupported search method for 'all' target.")

    # Handle PSP target
    if request.target == "psp":
        if request.method == "psp-all":
            # Run all PSP methods
            results.extend(_search_psp_type(window, request.value))
            results.extend(_search_psp_hex(window, request.value))
            results.extend(_search_psp_metadata(window, request.value))
            return results
        if request.method == "psp-type":
            return _search_psp_type(window, request.value)
        if request.method == "psp-hex":
            return _search_psp_hex(window, request.value)
        if request.method == "psp-metadata":
            return _search_psp_metadata(window, request.value)

    # Handle UEFI target
    elif request.target == "uefi":
        if request.method == "uefi-all":
            # Run all UEFI methods
            results.extend(_search_uefi_hex(window, request.value))
                #results.extend(_search_uefi_guid(window, request.value))
            results.extend(_search_uefi_text(window, request))
            results.extend(_search_uefi_name(window, request.value))
            return results
        if request.method == "uefi-hex":
            return _search_uefi_hex(window, request.value)
        if request.method == "uefi-guid":
            return _search_uefi_guid(window, request.value)
        if request.method == "uefi-text":
            return _search_uefi_text(window, request)
        if request.method == "uefi-name":
            return _search_uefi_name(window, request.value)

    raise ValueError("Unsupported search method.")


def display_search_results(window, request: SearchRequest, results: List[SearchResult]) -> None:
    description = describe_search_request(request)
    html_lines = [
        "<div class='search-results'>",
        f"<p><b>{html.escape(description)}</b> - {len(results)} match(es)</p>",
    ]
    if results:
        html_lines.append("<ol>")
        for result in results:
            query = urlencode(result.query)
            href = f"{result.scheme}:"
            if query:
                href = f"{href}?{query}"
            title = html.escape(result.title)
            html_lines.append(
                f"<li><a href=\"{html.escape(href)}\">{title}</a>"
            )
            if result.subtitle:
                html_lines.append(
                    f"<br/><span>{html.escape(str(result.subtitle))}</span>"
                )
            html_lines.append("</li>")
        html_lines.append("</ol>")
    else:
        html_lines.append("<p><i>No matches found.</i></p>")
    html_lines.append("</div>")
    window.search_browser.setHtml("\n".join(html_lines))
    window._search_has_results = True
    if results and getattr(window, "output_tabs", None) is not None:
        search_tab = getattr(window, "search_tab", None)
        target_widget = search_tab if search_tab is not None else window.search_browser
        window.output_tabs.setCurrentWidget(target_widget)
    if results and getattr(window, "console_dock", None) is not None:
        try:
            window.console_dock.raise_()
        except Exception:
            pass


def _parse_int_param(values: Optional[List[str]]) -> Optional[int]:
    if not values:
        return None
    value = values[0]
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return None


def on_search_anchor_clicked(window, url: QUrl) -> None:
    scheme = url.scheme()
    params = parse_qs(url.query())
    if scheme == "psp":
        image_index = _parse_int_param(params.get("image"))
        directory_index = _parse_int_param(params.get("directory"))
        entry_index = _parse_int_param(params.get("entry"))
        window.tabs.setCurrentWidget(window.psp_tab)
        window._focus_psp_item(image_index, directory_index, entry_index)
    elif scheme == "uefi":
        image_index = _parse_int_param(params.get("image"))
        offset = _parse_int_param(params.get("offset"))
        size = _parse_int_param(params.get("size"))
        guid_vals = params.get("guid")
        guid_text = guid_vals[0] if guid_vals else None
        volume_index = _parse_int_param(params.get("volume"))
        root_index = _parse_int_param(params.get("root"))
        window.tabs.setCurrentWidget(window.uefi_tab)
        window.uefi_tab_controller.focus_item(
            image_index, offset, size, guid_text,
            volume_index=volume_index, root_index=root_index
        )


def show_search_dialog(window) -> None:
    if not window.loaded_images:
        QMessageBox.information(
            window,
            "No firmware loaded",
            "Load a firmware image before running a search.",
        )
        return
    last_request = getattr(window, "_last_search_request", None)
    dialog = SearchDialog(window, last_request)
    result = dialog.exec()
    if result != QDialog.Accepted:
        return
    request = dialog.get_request()
    if request is None:
        return
    window._last_search_request = request
    window._last_search_value = request.value
    try:
        matches = perform_search(window, request)
    except ValueError as exc:
        QMessageBox.warning(window, "Search failed", str(exc))
        return
    display_search_results(window, request, matches)
    description = describe_search_request(request)
    append_console(
        window, f"Search '{description}' returned {len(matches)} match(es)"
    )
