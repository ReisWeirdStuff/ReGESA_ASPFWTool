# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Hex viewer widget utilities for displaying binary data.

This module provides:
    - Hex dump formatting functions
    - Hex editor configuration and cursor handling
    - Byte-to-position mapping for selection
"""

from typing import List, Optional, Tuple
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette, QTextCharFormat, QTextCursor, QTextOption
from PySide6.QtWidgets import QPlainTextEdit, QTextEdit

def _hex_dump(data: bytes, width: int = 16, *, include_ascii: bool = True) -> str:
    header = " ".join(f"{i:02X}" for i in range(width))
    if include_ascii:
        header_line = f"Offset    {header}    0123456789ABCDEF"
    else:
        header_line = f"Offset    {header}"
    separator = "-" * len(header_line)
    lines: List[str] = [header_line, separator]
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        hex_field = hex_bytes.ljust(width * 3 - 1)
        if include_ascii:
            ascii_field = ascii_part.ljust(width)
            lines.append(f"{offset:08X}  {hex_field}    {ascii_field}")
        else:
            lines.append(f"{offset:08X}  {hex_field}")
    return "\n".join(lines)


def _normalize_hex_blob(blob: Optional[object]) -> Optional[bytes]:
    if blob is None:
        return None
    if isinstance(blob, bytes):
        return blob
    if isinstance(blob, (bytearray, memoryview)):
        return bytes(blob)
    return None


def _auto_hex_width(length: int) -> int:
    # Always show 16 bytes per row (0x00..0x0F)
    return 16


def _configure_hex_editor(
    editor: Optional[QPlainTextEdit],
    *,
    blob: Optional[object],
    width: int,
    include_ascii: bool,
) -> int:
    if editor is None:
        return width if width > 0 else 16
    normalized = _normalize_hex_blob(blob)
    try:
        width_value = int(width)
    except Exception:
        width_value = 16
    if width_value <= 0:
        width_value = _auto_hex_width(len(normalized) if normalized else 0)
    # Force 16 bytes per row regardless of input or size
    width_value = 16
    editor.setProperty("hexBlob", normalized)
    editor.setProperty("hexWidth", width_value)
    editor.setProperty("showsAscii", bool(include_ascii))
    editor.setWordWrapMode(QTextOption.NoWrap)
    try:
        editor.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    except Exception:
        pass
    if not normalized or not include_ascii:
        try:
            editor.setExtraSelections([])
        except Exception:
            pass
    return width_value


def _hex_editor_position_to_byte(
    editor: Optional[QPlainTextEdit], pos: int, width: int, blob_len: int
) -> Optional[int]:
    if editor is None or blob_len <= 0:
        return None
    doc = editor.document()
    if doc is None or pos < 0 or pos > doc.characterCount():
        return None
    cursor = QTextCursor(doc)
    cursor.setPosition(pos)
    block = cursor.block()
    block_number = block.blockNumber()
    if block_number < 2:
        return None
    base_offset = (block_number - 2) * width
    if base_offset >= blob_len:
        return None
    column = pos - block.position()
    chunk_len = min(width, blob_len - base_offset)
    if chunk_len <= 0:
        return None
    hex_start = 10
    hex_limit = hex_start + max(chunk_len * 3 - 1, 0)
    ascii_start = 13 + width * 3
    ascii_limit = ascii_start + chunk_len
    if ascii_start <= column < ascii_limit:
        return base_offset + (column - ascii_start)
    if hex_start <= column <= hex_limit:
        rel = column - hex_start
        idx = rel // 3
        if idx >= chunk_len:
            return None
        return base_offset + idx
    return None


def _hex_editor_byte_to_selection(
    editor: Optional[QPlainTextEdit],
    byte_index: int,
    ascii_column: bool,
    fmt: QTextCharFormat,
    width: int,
    blob_len: int,
) -> Optional[QTextEdit.ExtraSelection]:
    if editor is None or blob_len <= 0:
        return None
    if byte_index < 0 or byte_index >= blob_len:
        return None
    doc = editor.document()
    if doc is None:
        return None
    row = byte_index // width
    column = byte_index % width
    block = doc.findBlockByNumber(row + 2)
    if not block.isValid():
        return None
    base_pos = block.position()
    if ascii_column:
        column_pos = 13 + width * 3 + column
        length = 1
    else:
        column_pos = 10 + column * 3
        length = 2
    start_pos = base_pos + column_pos
    block_end = base_pos + block.length() - 1
    if start_pos >= block_end:
        return None
    end_pos = min(start_pos + length, block_end)
    if end_pos <= start_pos:
        return None
    cursor = QTextCursor(doc)
    cursor.setPosition(start_pos)
    cursor.setPosition(end_pos, QTextCursor.KeepAnchor)
    selection = QTextEdit.ExtraSelection()
    selection.cursor = cursor
    selection.format = fmt
    return selection


def _clamp_hex_editor_cursor(editor: Optional[QPlainTextEdit]) -> None:
    if editor is None:
        return
    doc = editor.document()
    if doc is None:
        return
    data_block = doc.findBlockByNumber(2)
    if not data_block.isValid():
        return
    minimum = data_block.position()
    cursor = editor.textCursor()
    if cursor is None:
        return
    position = cursor.position()
    anchor = cursor.anchor()
    changed = False
    if position < minimum:
        position = minimum
        changed = True
    if anchor < minimum:
        anchor = minimum
        changed = True
    if not changed:
        return
    clamped = QTextCursor(doc)
    clamped.setPosition(anchor)
    if position != anchor:
        clamped.setPosition(position, QTextCursor.KeepAnchor)
    editor.setTextCursor(clamped)


def _update_hex_editor_selection(editor: Optional[QPlainTextEdit]) -> None:
    if editor is None:
        return
    _clamp_hex_editor_cursor(editor)
    if not bool(editor.property("showsAscii")):
        editor.setExtraSelections([])
        return
    blob = editor.property("hexBlob")
    normalized = _normalize_hex_blob(blob)
    if not normalized:
        editor.setExtraSelections([])
        return
    try:
        width_value = int(editor.property("hexWidth"))
    except Exception:
        width_value = 16
    width_value = max(1, width_value)
    cursor = editor.textCursor()
    doc = editor.document()
    if cursor is None or doc is None:
        editor.setExtraSelections([])
        return
    if cursor.hasSelection():
        start_pos = cursor.selectionStart()
        end_pos = cursor.selectionEnd() - 1
    else:
        pos = cursor.position()
        start_pos = pos
        end_pos = pos
    blob_len = len(normalized)
    start_byte = _hex_editor_position_to_byte(editor, start_pos, width_value, blob_len)
    end_byte = _hex_editor_position_to_byte(editor, end_pos, width_value, blob_len)
    if start_byte is None or end_byte is None:
        editor.setExtraSelections([])
        return
    if end_byte < start_byte:
        start_byte, end_byte = end_byte, start_byte
    highlight = editor.palette().color(QPalette.Highlight)
    mirror_color = QColor(highlight)
    if mirror_color.alpha() >= 200:
        mirror_color.setAlpha(120)
    elif mirror_color.alpha() == 0:
        mirror_color.setAlpha(80)
    fmt = QTextCharFormat()
    fmt.setBackground(mirror_color)
    extras: List[QTextEdit.ExtraSelection] = []
    for byte_index in range(start_byte, end_byte + 1):
        ascii_sel = _hex_editor_byte_to_selection(
            editor, byte_index, True, fmt, width_value, blob_len
        )
        if ascii_sel is not None:
            extras.append(ascii_sel)
        hex_sel = _hex_editor_byte_to_selection(
            editor, byte_index, False, fmt, width_value, blob_len
        )
        if hex_sel is not None:
            extras.append(hex_sel)
    editor.setExtraSelections(extras)


def _hex_editor_selection_range(
    editor: Optional[QPlainTextEdit],
) -> Optional[Tuple[int, int]]:
    if editor is None:
        return None
    blob = editor.property("hexBlob")
    normalized = _normalize_hex_blob(blob)
    if not normalized:
        return None
    try:
        width_value = int(editor.property("hexWidth"))
    except Exception:
        width_value = 16
    width_value = max(1, width_value)
    cursor = editor.textCursor()
    doc = editor.document()
    if cursor is None or doc is None:
        return None
    if cursor.hasSelection():
        start_pos = cursor.selectionStart()
        end_pos = cursor.selectionEnd() - 1
    else:
        pos = cursor.position()
        start_pos = pos
        end_pos = pos
    blob_len = len(normalized)
    start_byte = _hex_editor_position_to_byte(editor, start_pos, width_value, blob_len)
    end_byte = _hex_editor_position_to_byte(editor, end_pos, width_value, blob_len)
    if start_byte is None or end_byte is None:
        return 0, max(blob_len - 1, 0)
    if end_byte < start_byte:
        start_byte, end_byte = end_byte, start_byte
    return start_byte, end_byte
