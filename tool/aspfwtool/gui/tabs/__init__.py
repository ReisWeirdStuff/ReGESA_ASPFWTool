# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Tab controller modules for the main window.

This package provides tab controllers for different firmware views:
    - PspTabController: PSP/BIOS directory tree tab
    - UefiTabController: UEFI firmware tree tab
    - EfsTabController: EFS configuration tab
    - SummaryTabController: Firmware summary tab
"""

from .psp_tab import PspTabController, PSP_ACTION_COLUMN, PSP_LOCATION_COLUMN
from .uefi_tab import UefiTabController
from .efs_tab import EfsTabController, EFS_POINTER_FIELDS
from .summary_tab import SummaryTabController

__all__ = [
    "PspTabController",
    "PSP_ACTION_COLUMN",
    "PSP_LOCATION_COLUMN",
    "UefiTabController",
    "EfsTabController",
    "EFS_POINTER_FIELDS",
    "SummaryTabController",
]
