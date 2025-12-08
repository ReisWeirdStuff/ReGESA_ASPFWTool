# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Qt imports abstraction layer.

This module centralizes all PySide6 imports used by the main window components,
making it easier to manage dependencies and potentially support alternative
Qt bindings in the future.
"""

from __future__ import annotations

try:
    from PySide6.QtCore import (
        QDir,
        QEvent,
        QModelIndex,
        QObject,
        QPoint,
        Qt,
        QTimer,
        QUrl,
        QFile,
        QRegularExpression,
        QThread,
        Signal,
    )
    from PySide6.QtGui import (
        QAction,
        QActionGroup,
        QColor,
        QFont,
        QFontDatabase,
        QFontMetrics,
        QGuiApplication,
        QKeySequence,
        QPalette,
        QStandardItem,
        QStandardItemModel,
        QTextCursor,
        QTextOption,
        QRegularExpressionValidator,
    )
    from PySide6.QtWidgets import (
        QAbstractItemView,
        QAbstractScrollArea,
        QApplication,
        QCheckBox,
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QDockWidget,
        QFileDialog,
        QFormLayout,
        QGroupBox,
        QHeaderView,
        QHBoxLayout,
        QInputDialog,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMenu,
        QMessageBox,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QScrollArea,
        QSpinBox,
        QSplitter,
        QStackedWidget,
        QTabBar,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QTextBrowser,
        QToolTip,
        QTreeView,
        QVBoxLayout,
        QWidget,
        QSizePolicy,
        QListWidget,
        QListWidgetItem,
    )
    from PySide6.QtUiTools import QUiLoader
except Exception as exc:  # pragma: no cover - hard failure when Qt bindings missing
    raise RuntimeError(
        "PySide6 is required to launch the GUI. Please install PySide6 before running this tool."
    ) from exc
