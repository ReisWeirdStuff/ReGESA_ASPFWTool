# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
AGESA PSP Configuration Block (APCB) parsing package.

This package provides read-only inspection helpers for APCB data structures
found in AMD firmware images. It supports both V2 and V3
APCB formats.

Public API:
    - ApcbParseError: Exception raised on parsing failures.
    - ApcbParseResult: Container for parsed APCB data.
    - ApcbTokenRecord: Individual token data record.
    - lookup_token_metadata: Get metadata for a token UID.
    - lookup_token_name: Get the name for a token UID.
    - parse_apcb_tokens: Parse tokens from APCB binary data.
"""

from __future__ import annotations

from .parser import (
    ApcbParseError,
    ApcbParseResult,
    ApcbTokenRecord,
    lookup_token_metadata,
    lookup_token_name,
    parse_apcb_tokens,
)
