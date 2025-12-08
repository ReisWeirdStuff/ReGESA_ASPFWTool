# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Reusable widget modules for the GUI.

This package provides reusable widgets:
    - DetailPane: Entry detail display widget
    - NoScrollComboBox: Wheel-scroll-ignoring combo box
    - Hex viewer utilities: _hex_dump, _configure_hex_editor, etc.
    - Console/search utilities: SearchDialog, append_console, etc.
"""

from .detail_pane import DetailPane, NoScrollComboBox
from .hex_viewer import (
    _hex_dump,
    _configure_hex_editor,
    _update_hex_editor_selection,
    _normalize_hex_blob,
    _auto_hex_width,
)
from .console_search import (
    SearchDialog,
    append_console,
    setup_output_pane,
    show_search_dialog,
    SEARCH_METHOD_LABELS,
)

__all__ = [
    # detail_pane
    "DetailPane",
    "NoScrollComboBox",
    # hex_viewer
    "_hex_dump",
    "_configure_hex_editor",
    "_update_hex_editor_selection",
    "_normalize_hex_blob",
    "_auto_hex_width",
    # console_search
    "SearchDialog",
    "append_console",
    "setup_output_pane",
    "show_search_dialog",
    "SEARCH_METHOD_LABELS",
]
