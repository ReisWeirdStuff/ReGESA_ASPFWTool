# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
from __future__ import annotations

import argparse
from pathlib import Path

from aspfwtool.gui import launch_gui
from aspfwtool.utils.debug_logger import set_log_level, LogLevel


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch the ReGESA GUI")
    parser.add_argument(
        "paths",
        nargs="*",
        help="Firmware image paths or directories to open",
    )
    parser.add_argument(
        "--maintenance",
        action="store_true",
        help="Enable maintenance utilities (GUID import/export helpers, Firmware bulk export, AGESA Version Database update etc...)",
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default="warning",
        metavar="LEVEL",
        help="Set logging level: debug, info, warning, error (default: warning)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (shortcut for --log-level debug)",
    )
    args = parser.parse_args()

    # Set log level based on arguments
    if args.debug:
        set_log_level(LogLevel.DEBUG)
    elif args.log_level:
        level_map = {
            "debug": LogLevel.DEBUG,
            "info": LogLevel.INFO,
            "warning": LogLevel.WARNING,
            "error": LogLevel.ERROR,
        }
        set_log_level(level_map[args.log_level])

    inputs = [Path(arg) for arg in args.paths] if args.paths else None
    launch_gui(inputs, maintenance_mode=args.maintenance)


if __name__ == "__main__":
    main()
