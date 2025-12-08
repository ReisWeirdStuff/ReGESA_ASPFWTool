# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
GUI components for the AMD firmware analysis tool.

This package provides a PySide6-based graphical interface for viewing
and editing AMD PSP/BIOS firmware images.

Package Structure:
    gui/
    |-- tabs/           - Tab controllers (psp, uefi, efs, summary)
    |-- widgets/        - Reusable widgets (detail_pane, hex_viewer, console)
    |-- dialogs/        - Standalone dialogs (directory editor, entry config)
    |-- utils/          - Shared utilities (roles, diff_utils)
    |-- mainwindow_components/  - MainWindow implementation (mixins)

Public API:
    - MainWindow: Main application window class.
    - launch_gui: Function to start the GUI application.
"""

from .mainwindow_components.controller import MainWindow, launch_gui

# Re-export commonly used items for convenience
from .utils.roles import (
    DETAIL_ROLE,
    SUMMARY_ROLE,
    PAYLOAD_ROLE,
    CHAIN_ROLE,
    METADATA_ROLE,
    KEY_TABLE_ROLE,
    ENTRY_LOC_ROLE,
    OFFSET_ROLE,
    HEX_ROLE,
    PENDING_ACTION_ROLE,
)

__all__ = [
    # Main entry points
    "MainWindow",
    "launch_gui",
    # Roles (commonly imported)
    "DETAIL_ROLE",
    "SUMMARY_ROLE",
    "PAYLOAD_ROLE",
    "CHAIN_ROLE",
    "METADATA_ROLE",
    "KEY_TABLE_ROLE",
    "ENTRY_LOC_ROLE",
    "OFFSET_ROLE",
    "HEX_ROLE",
    "PENDING_ACTION_ROLE",
]