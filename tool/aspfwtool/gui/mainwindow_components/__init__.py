# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Main window component modules package.

This package contains the refactored main window implementation, organized
into focused modules for better maintainability.

Module Structure:
    controller.py: Main MainWindow class and launch_gui function
    theme.py: Theme/palette management mixin (ThemeMixin)
    hex_dialogs.py: Hex view dialog functionality (HexDialogsMixin)
    export_operations.py: Export functionality (ExportOperationsMixin)
    xml_export.py: XML export operations (XmlExportMixin)
    actions.py: Menu/action creation (ActionsMixin)
    uefi_operations.py: UEFI firmware operations (UefiOperationsMixin)
    psp_entry_operations.py: PSP entry manipulation (PspEntryOperationsMixin)
    file_operations.py: File I/O operations (FileOperationsMixin)
    tree_operations.py: Tree view management (TreeOperationsMixin)
    image_operations.py: Image modification tracking (ImageModificationMixin)
    common.py: Shared utilities and constants
    models.py: Data models (LoadedImage, etc.)
    dialogs.py: Entry edit dialogs
    tree_builder.py: Tree view construction
    tooltips.py: Tree tooltip handling
    qt.py: Qt imports abstraction
"""

from .controller import MainWindow, launch_gui
from .theme import ThemeMixin, create_light_palette
from .hex_dialogs import HexDialogsMixin
from .export_operations import ExportOperationsMixin
from .actions import ActionsMixin
from .uefi_operations import UefiOperationsMixin
from .psp_entry_operations import PspEntryOperationsMixin
from .file_operations import FileOperationsMixin
from .tree_operations import TreeOperationsMixin
from .image_operations import ImageModificationMixin
