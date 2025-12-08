# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Debug logging utility for firmware parsing operations.

This module provides a simple singleton-pattern logger for debug output
during firmware parsing. Set the log level via set_log_level() to control
which messages are displayed.

Log levels (from most to least verbose):
    DEBUG   - Detailed debugging information
    INFO    - General information messages  
    WARNING - Warning messages (default when enabled)
    ERROR   - Error messages only

Example:
    from aspfwtool.utils.debug_logger import set_log_level, get_logger, LogLevel
    
    set_log_level(LogLevel.DEBUG)  # Show all messages
    set_log_level(LogLevel.INFO)   # Show info, warning, error
    set_log_level(LogLevel.WARNING)  # Show warning, error only
    
    logger = get_logger()
    logger.info("Starting firmware parse")
"""

from __future__ import annotations

import sys
from datetime import datetime
from enum import IntEnum
from typing import Optional

__all__ = ["LogLevel", "DebugLogger", "get_logger", "set_debug_mode", "set_log_level"]



# Log Level Enumeration



class LogLevel(IntEnum):
    """Log message severity levels (lower value = more verbose)."""

    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    OFF = 100  # Disable all logging

    @property
    def label(self) -> str:
        """Get the display label for this level."""
        return self.name.capitalize()



# Debug Logger Class



class DebugLogger:
    """Simple debug logger that prints to console based on log level."""

    _instance: Optional["DebugLogger"] = None

    def __init__(self) -> None:
        self._level = LogLevel.OFF  # Disabled by default
        self._show_timestamp = True

    @classmethod
    def get_instance(cls) -> "DebugLogger":
        """Get or create the singleton logger instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def enabled(self) -> bool:
        """Check if debug logging is enabled (any level other than OFF)."""
        return self._level != LogLevel.OFF

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable or disable debug logging (sets to DEBUG or OFF)."""
        self._level = LogLevel.DEBUG if value else LogLevel.OFF

    @property
    def level(self) -> LogLevel:
        """Get the current log level."""
        return self._level

    @level.setter
    def level(self, value: LogLevel) -> None:
        """Set the log level."""
        self._level = value

    def _format_message(self, level: LogLevel, message: str) -> str:
        """Format a log message with level and optional timestamp."""
        prefix = f"[{level.label}]"
        if self._show_timestamp:
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            return f"{ts} {prefix} {message}"
        return f"{prefix} {message}"

    def _print(self, level: LogLevel, message: str) -> None:
        """Print a formatted message to stderr if level is enabled."""
        if level < self._level:
            return
        formatted = self._format_message(level, message)
        print(formatted, file=sys.stderr, flush=True)

    def debug(self, message: str) -> None:
        """Log a debug-level message."""
        self._print(LogLevel.DEBUG, message)

    def info(self, message: str) -> None:
        """Log an info-level message."""
        self._print(LogLevel.INFO, message)

    def warning(self, message: str) -> None:
        """Log a warning-level message."""
        self._print(LogLevel.WARNING, message)

    def error(self, message: str) -> None:
        """Log an error-level message."""
        self._print(LogLevel.ERROR, message)

    def log(self, level: LogLevel, message: str) -> None:
        """Log a message at the specified level."""
        self._print(level, message)


def get_logger() -> DebugLogger:
    """Get the global debug logger instance."""
    return DebugLogger.get_instance()


def set_debug_mode(enabled: bool) -> None:
    """
    Enable or disable debug mode globally.
    
    When enabled, sets log level to DEBUG (shows all messages).
    When disabled, sets log level to OFF (no messages).
    """
    get_logger().level = LogLevel.DEBUG if enabled else LogLevel.OFF


def set_log_level(level: LogLevel) -> None:
    """
    Set the global log level.
    
    Args:
        level: The minimum log level to display.
               Messages with severity >= level will be shown.
    """
    get_logger().level = level