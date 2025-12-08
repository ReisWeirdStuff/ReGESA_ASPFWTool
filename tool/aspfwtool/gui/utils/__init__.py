# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Utility modules for the GUI.

This package provides shared utilities:
    - roles: Qt custom item data roles
    - diff_utils: Tree comparison and diff computation
"""

from .roles import (
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

from .diff_utils import (
    iter_tree_items,
    compute_diff_statuses,
)

__all__ = [
    # roles
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
    # diff_utils
    "iter_tree_items",
    "compute_diff_statuses",
]
