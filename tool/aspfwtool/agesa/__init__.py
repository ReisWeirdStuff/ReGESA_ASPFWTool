# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
ASPFWTool package.

This package provides utilities for parsing AMD Platform Security Processor (PSP)
and BIOS firmware structures, including:

    - Directory parsing (PSP, BIOS, combo formats)
    - Entry type identification and metadata lookup
    - Cryptographic verification utilities
    - Version extraction and AGESA version matching
    - EFS (Embedded Firmware Structure) parsing
    - ISH (Image Slot Header) handling
"""

from .agesa import *
