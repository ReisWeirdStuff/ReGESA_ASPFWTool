# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Shared Qt item role constants used across GUI modules.

These custom roles are used to store structured data in QStandardItem
objects within the tree views.
"""

from PySide6.QtCore import Qt


# Custom Item Data Roles


DETAIL_ROLE = Qt.UserRole + 1       # Detailed information dictionary
SUMMARY_ROLE = Qt.UserRole + 2      # Summary text for display
PAYLOAD_ROLE = Qt.UserRole + 3      # Entry payload data
CHAIN_ROLE = Qt.UserRole + 4        # Parent chain for navigation
METADATA_ROLE = Qt.UserRole + 5     # Additional metadata
KEY_TABLE_ROLE = Qt.UserRole + 6    # Key table data
ENTRY_LOC_ROLE = Qt.UserRole + 7    # Entry location information
OFFSET_ROLE = Qt.UserRole + 8       # Byte offset in image
HEX_ROLE = Qt.UserRole + 9          # Hex display data
PENDING_ACTION_ROLE = Qt.UserRole + 10  # Pending modification action
