# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Dialog modules for the GUI.

This package provides standalone dialog widgets:
    - DirectoryEditDialog: PSP directory entry viewer/editor
    - EntryEditDialog: Entry configuration for replace/insert operations
"""

from .psp_directory_editor import DirectoryEditDialog

# Entry edit dialog is in mainwindow_components
from ..mainwindow_components.dialogs import EntryEditDialog

__all__ = [
    "DirectoryEditDialog",
    "EntryEditDialog",
]
