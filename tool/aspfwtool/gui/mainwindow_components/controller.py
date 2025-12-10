# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Main window controller and application entry point.

This module provides:
    - MainWindow class combining all operation mixins
    - launch_gui function to start the application
    - Window initialization and state management
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .qt import (
    QAction,
    QActionGroup,
    QApplication,
    QComboBox,
    QDialog,
    QDockWidget,
    QGuiApplication,
    QHeaderView,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QScrollArea,
    QPalette,
    QProgressBar,
    QStackedWidget,
    QTabBar,
    QStandardItem,
    QStandardItemModel,
    QTabWidget,
    QTreeView,
    QVBoxLayout,
    QWidget,
    Qt,
    QFont,
)

# Import mixins for modular functionality
from .theme import ThemeMixin, create_light_palette
from .hex_dialogs import HexDialogsMixin
from .export_operations import ExportOperationsMixin
from .xml_export import XmlExportMixin
from .actions import ActionsMixin
from .uefi_operations import UefiOperationsMixin
from .psp_entry_operations import PspEntryOperationsMixin
from .file_operations import FileOperationsMixin
from .tree_operations import TreeOperationsMixin
from .image_operations import ImageModificationMixin
from .common import (
    _container_get,
    _format_bytes,
    _format_optional_hex,
    _mask_u64,
    _to_signed_64,
)
from .models import LoadedImage
from .tooltips import TreeToolTipFilter
from .tree_builder import FirmwareTreeBuilder
from ..widgets.detail_pane import DetailPane
from ..widgets.console_search import append_console, setup_output_pane
from ..tabs.psp_tab import PSP_ACTION_COLUMN, PspTabController
from ..tabs.uefi_tab import UefiTabController
from ..tabs.summary_tab import SummaryTabController
from ..tabs.efs_tab import EfsTabController
from ..utils.roles import (
    DETAIL_ROLE,
    SUMMARY_ROLE,
    CHAIN_ROLE,
    METADATA_ROLE,
    KEY_TABLE_ROLE,
    HEX_ROLE,
)
from ..utils.diff_utils import iter_tree_items, compute_diff_statuses
from ...agesa.directory import Directory, detect_directory_checksum_seed, compute_directory_checksum
from ...agesa import softfuse as _softfuse
from ...agesa import constants as _constants

PSP_DIFF_COLUMN = 5
UEFI_DIFF_COLUMN = 5

_MODULE_ROOT = Path(__file__).resolve().parent.parent.parent
_UPDATABLE_DIR = _MODULE_ROOT.parent / "Updatable"
_GUID_DATA_PATH = _UPDATABLE_DIR / "guid_names.json"

_PEI_FILE_TYPES = {0x04, 0x06, 0x08}
# Treat any executable DXE-class module as exportable, including SMM/MM
# variants, combined PEI/DXE drivers, and applications.  AMD firmware packs
# a number of DXE components with the "MM" file type (0x0A) which still carry
# the familiar `Amd*Dxe` naming convention in the UEFI tab, so include those
# as DXE-style exports as well.
_DXE_FILE_TYPES = {0x05, 0x07, 0x09, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F}

_QT_BINDING = "PySide6"


class MainWindow(
    ThemeMixin,
    HexDialogsMixin,
    ExportOperationsMixin,
    XmlExportMixin,
    ActionsMixin,
    UefiOperationsMixin,
    PspEntryOperationsMixin,
    FileOperationsMixin,
    TreeOperationsMixin,
    ImageModificationMixin,
    QMainWindow,
):
    """
    Main application window for the firmware analysis tool.
    
    Inherits from multiple mixins to provide modular functionality:
        - ThemeMixin: Theme/palette management
        - HexDialogsMixin: Hex view dialogs
        - ExportOperationsMixin: Export functionality
        - XmlExportMixin: XML export for PSP/BIOS firmware
        - ActionsMixin: Menu/action creation
        - UefiOperationsMixin: UEFI firmware operations
        - TreeOperationsMixin: Tree view management
        - ImageModificationMixin: Image modification tracking
        - PspEntryOperationsMixin: PSP entry manipulation
        - FileOperationsMixin: File I/O operations
    """
    
    def __init__(
        self,
        *,
        discovery_mode: str = "auto",
        efs_offset: Optional[int] = None,
        include_uefi: bool = True,
        maintenance_mode: bool = False,
    ) -> None:
        super().__init__()
        self._base_title = "ReGESA - ASPFWTool (File Explorer)"
        self.setWindowTitle(self._base_title)
        self.resize(1280, 720)
        self.setAcceptDrops(True)

        self.discovery_mode = discovery_mode
        self.efs_offset = efs_offset
        self.include_uefi = include_uefi
        self.maintenance_mode = bool(maintenance_mode)
        self.current_inputs: List[Path] = []
        self.loaded_images: List[LoadedImage] = []
        self._active_image_index: Optional[int] = None
        self._uefi_selection_by_image: Dict[int, dict] = {}
        self._psp_selection_by_image: Dict[int, dict] = {}
        self.diff_mode: bool = False
        self._save_as_action: Optional[QAction] = None
        self._export_capsule_action: Optional[QAction] = None
        self._diff_action: Optional[QAction] = None
        self._hex_dialogs: List[QDialog] = []
        self._next_action_id = 1

        self._builder = FirmwareTreeBuilder(
            discovery_mode=self.discovery_mode,
            efs_offset=self.efs_offset,
            include_uefi=self.include_uefi,
        )
        # Ensure tree rows are padded to match model column counts
        self._builder.set_column_counts(
            psp_columns=len(["Firmware Entries", "Location", "Size", "Action", "Metadata", "Diff"]),
            uefi_columns=len(["Name", "Type", "Size", "Action", "Info", "Diff"]),
        )

        self._base_font = QApplication.font(self)
        if self._base_font.pointSizeF() <= 0:
            self._base_font = QApplication.font()
        self._display_scale = 1.0
        app_instance = QApplication.instance()
        self._default_palette = (
            QPalette(app_instance.palette()) if app_instance else None
        )
        style_obj = app_instance.style() if app_instance else None
        self._default_style_name = style_obj.objectName() if style_obj else None
        self._light_palette = create_light_palette()
        self._light_style_name = "Fusion"
        self._dark_style_name = "Fusion"
        system_pref = self._system_prefers_dark()
        self._system_theme_preference = system_pref
        default_dark = bool(system_pref) if system_pref is not None else False
        self.dark_theme_enabled = default_dark
        self._override_system_theme = False
        self._manual_dark_theme = (
            (not default_dark) if system_pref is not None else default_dark
        )
        self.dark_theme_action: Optional[QAction] = None
        self._menu_palette: Optional[QPalette] = None

        central_widget = self._load_central_ui()
        self.tabs = central_widget.findChild(QTabWidget, "tabs")
        if self.tabs is None:
            raise RuntimeError("Failed to load tab widget from UI definition.")

        self.uefi_image_bar = self._ensure_uefi_image_bar(central_widget)

        summary_scroll = self.tabs.findChild(QScrollArea, "summary_scroll")
        if summary_scroll is None:
            raise RuntimeError("Summary scroll area missing from UI definition.")
        self.summary_scroll = summary_scroll
        self.summary_scroll.setWidgetResizable(True)
        summary_container = summary_scroll.widget()
        if summary_container is None:
            summary_container = QWidget(summary_scroll)
            summary_scroll.setWidget(summary_container)
        self.summary_container = summary_container
        summary_layout = summary_container.layout()
        if not isinstance(summary_layout, QVBoxLayout):
            summary_layout = QVBoxLayout(summary_container)
        self.summary_layout = summary_layout
        self.summary_controller = SummaryTabController(
            self,
            self.summary_scroll,
            summary_layout,
            container_get=_container_get,
            format_bytes=_format_bytes,
            format_optional_hex=_format_optional_hex,
        )

        self.efs_tab = self.tabs.findChild(QWidget, "efs_tab")
        if self.efs_tab is None:
            raise RuntimeError("EFS tab widget missing from UI definition.")
        self.efs_scroll = self.efs_tab.findChild(QScrollArea, "efs_scroll")
        if self.efs_scroll is None:
            raise RuntimeError("EFS scroll area missing from UI definition.")
        self.efs_scroll.setWidgetResizable(True)
        efs_container = self.efs_scroll.widget()
        if efs_container is None:
            efs_container = QWidget(self.efs_scroll)
            self.efs_scroll.setWidget(efs_container)
        self.efs_container = efs_container
        efs_layout = efs_container.layout()
        if not isinstance(efs_layout, QVBoxLayout):
            efs_layout = QVBoxLayout(efs_container)
        self.efs_layout = efs_layout
        self.efs_tab_controller = EfsTabController(
            self,
            self.efs_scroll,
            efs_layout,
            container_get=_container_get,
            format_optional_hex=_format_optional_hex,
        )

        self.psp_tab = self.tabs.findChild(QWidget, "psp_tab")
        if self.psp_tab is None:
            raise RuntimeError("PSP tab widget missing from UI definition.")
        self.psp_tree = self.psp_tab.findChild(QTreeView, "psp_tree")
        if self.psp_tree is None:
            raise RuntimeError("PSP tree view missing from UI definition.")

        self.uefi_tab = self.tabs.findChild(QWidget, "uefi_tab")
        if self.uefi_tab is None:
            raise RuntimeError("UEFI tab widget missing from UI definition.")
        self.uefi_tree = self.uefi_tab.findChild(QTreeView, "uefi_tree")
        if self.uefi_tree is None:
            raise RuntimeError("UEFI tree view missing from UI definition.")

        self.console_dock = setup_output_pane(self)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.console_dock)

        (
            self.psp_tab,
            self.psp_tree,
            self.psp_detail,
            self.psp_model,
        ) = self._create_tree_tab(
            ["Firmware Entries", "Location", "Size", "Action", "Metadata", "Diff"],
            context="psp",
            container=self.psp_tab,
            tree=self.psp_tree,
        )
        self.psp_tree.setColumnHidden(PSP_ACTION_COLUMN, True)
        self.psp_detail.set_soft_fuse_handler(self._handle_soft_fuse_update)
        self.psp_detail.set_status_callback(self._status_message)
        self.psp_tab_controller = PspTabController(self)

        (
            self.uefi_tab,
            self.uefi_tree,
            self.uefi_detail,
            self.uefi_model,
        ) = self._create_tree_tab(
            ["Name", "Type", "Size", "Action", "Info", "Diff"],
            context="uefi",
            container=self.uefi_tab,
            tree=self.uefi_tree,
        )
        self.uefi_tree.setColumnHidden(3, True)
        self.uefi_detail.set_status_callback(self._status_message)
        self.uefi_tab_controller = UefiTabController(self)

        self.detail_stack = QStackedWidget(self)
        self.empty_detail = QWidget(self.detail_stack)
        self.detail_stack.addWidget(self.psp_detail)
        self.detail_stack.addWidget(self.uefi_detail)
        self.detail_stack.addWidget(self.empty_detail)
        self.detail_stack.setCurrentWidget(self.psp_detail)

        self.psp_hex_widget = self.psp_detail.detach_hex_view()
        self.uefi_hex_widget = self.uefi_detail.detach_hex_view()
        self.empty_hex = QWidget(self)
        self.hex_stack = QStackedWidget(self)
        self.hex_stack.addWidget(self.psp_hex_widget)
        self.hex_stack.addWidget(self.uefi_hex_widget)
        self.hex_stack.addWidget(self.empty_hex)
        self.hex_stack.setCurrentWidget(self.psp_hex_widget)

        for editor in (self.psp_hex_widget, self.uefi_hex_widget):
            editor.setContextMenuPolicy(Qt.CustomContextMenu)
            editor.customContextMenuRequested.connect(
                lambda pos, ed=editor: self._show_hex_context_menu(ed, pos)
            )

        self.detail_dock = QDockWidget("Details", self)
        self.detail_dock.setObjectName("DetailDock")
        self.detail_dock.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        self.detail_dock.setFeatures(
            QDockWidget.DockWidgetClosable
            | QDockWidget.DockWidgetMovable
            | QDockWidget.DockWidgetFloatable
        )
        self.detail_dock.setWidget(self.detail_stack)
        self.addDockWidget(Qt.RightDockWidgetArea, self.detail_dock)

        self.hex_dock = QDockWidget("Hex View", self)
        self.hex_dock.setObjectName("HexDock")
        self.hex_dock.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        self.hex_dock.setFeatures(
            QDockWidget.DockWidgetClosable
            | QDockWidget.DockWidgetMovable
            | QDockWidget.DockWidgetFloatable
        )
        self.hex_dock.setWidget(self.hex_stack)
        self.addDockWidget(Qt.RightDockWidgetArea, self.hex_dock)
        self.tabifyDockWidget(self.detail_dock, self.hex_dock)
        self.detail_dock.raise_()

        self.tabs.setCurrentWidget(self.psp_tab)
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self._on_tab_changed(self.tabs.currentIndex())

        self._pending_summary_scroll: Optional[int] = None
        self._pending_efs_scroll: Optional[int] = None
        self._pending_efs_focus: Optional[tuple[int, int, str, str]] = None
        self._psp_columns_initialized = False
        self._uefi_columns_initialized = False
        self._scale_actions: Dict[int, QAction] = {}
        self._scale_group: Optional[QActionGroup] = None

        self._create_actions()
        self._apply_system_theme(force=True)

        self._update_uefi_tab_state()
        self.summary_controller.refresh_summary()
        self.efs_tab_controller.refresh()

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.statusBar().addPermanentWidget(self.progress_bar, 0)

        self.statusBar().showMessage("Ready")
        self._set_diff_column_visibility()

    def _load_central_ui(self) -> QWidget:
        # Build UI in Python
        widget = QWidget(self)

        central_layout = QVBoxLayout(widget)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)

        tabs = QTabWidget(widget)
        tabs.setObjectName("tabs")

        # Summary tab
        summary_tab = QWidget()
        summary_tab.setObjectName("summary_tab")
        summary_tab_layout = QVBoxLayout(summary_tab)
        summary_tab_layout.setContentsMargins(0, 0, 0, 0)
        summary_tab_layout.setSpacing(0)

        summary_scroll = QScrollArea(summary_tab)
        summary_scroll.setObjectName("summary_scroll")
        summary_scroll.setWidgetResizable(True)

        summary_container = QWidget()
        summary_container.setObjectName("summary_container")
        summary_layout = QVBoxLayout(summary_container)
        summary_layout.setSpacing(12)
        summary_layout.setContentsMargins(12, 12, 12, 12)

        summary_scroll.setWidget(summary_container)
        summary_tab_layout.addWidget(summary_scroll)
        tabs.addTab(summary_tab, "Summary")

        # EFS tab
        efs_tab = QWidget()
        efs_tab.setObjectName("efs_tab")
        efs_tab_layout = QVBoxLayout(efs_tab)
        efs_tab_layout.setContentsMargins(0, 0, 0, 0)
        efs_tab_layout.setSpacing(0)

        efs_scroll = QScrollArea(efs_tab)
        efs_scroll.setObjectName("efs_scroll")
        efs_scroll.setWidgetResizable(True)

        efs_container = QWidget()
        efs_container.setObjectName("efs_container")
        efs_layout = QVBoxLayout(efs_container)
        efs_layout.setSpacing(12)
        efs_layout.setContentsMargins(12, 12, 12, 12)

        efs_scroll.setWidget(efs_container)
        efs_tab_layout.addWidget(efs_scroll)
        tabs.addTab(efs_tab, "EFS")

        # PSP tab
        psp_tab = QWidget()
        psp_tab.setObjectName("psp_tab")
        psp_layout = QVBoxLayout(psp_tab)
        psp_layout.setContentsMargins(0, 0, 0, 0)
        psp_layout.setSpacing(0)

        psp_tree = QTreeView(psp_tab)
        psp_tree.setObjectName("psp_tree")
        psp_layout.addWidget(psp_tree)
        tabs.addTab(psp_tab, "PSP")

        # UEFI tab
        uefi_tab = QWidget()
        uefi_tab.setObjectName("uefi_tab")
        uefi_layout = QVBoxLayout(uefi_tab)
        uefi_layout.setContentsMargins(0, 0, 0, 0)
        uefi_layout.setSpacing(0)

        uefi_tree = QTreeView(uefi_tab)
        uefi_tree.setObjectName("uefi_tree")
        uefi_layout.addWidget(uefi_tree)
        tabs.addTab(uefi_tab, "UEFI")

        central_layout.addWidget(tabs)

        self.setCentralWidget(widget)
        return widget

    def _ensure_uefi_image_bar(self, container: QWidget) -> QTabBar:
        bar = container.findChild(QTabBar, "uefi_image_bar")
        if bar is None:
            layout = container.layout()
            if not isinstance(layout, QVBoxLayout):
                layout = QVBoxLayout(container)
                layout.setContentsMargins(0, 0, 0, 0)
                layout.setSpacing(0)
            bar = QTabBar(container)
            bar.setObjectName("uefi_image_bar")
            bar.setExpanding(False)
            layout.insertWidget(0, bar)
        bar.setVisible(False)
        if not bar.property("_uefi_tab_handler_connected"):
            bar.currentChanged.connect(self._on_uefi_image_tab_changed)
            bar.setProperty("_uefi_tab_handler_connected", True)
        return bar

    def _allocate_action_id(self) -> int:
        value = self._next_action_id
        self._next_action_id += 1
        return value

    def _create_tree_tab(
        self,
        column_labels: Sequence[str],
        *,
        context: str,
        container: Optional[QWidget] = None,
        tree: Optional[QTreeView] = None,
    ) -> tuple[QWidget, QTreeView, DetailPane, QStandardItemModel]:
        if container is None:
            container = QWidget(self)

        layout = container.layout()
        if not isinstance(layout, QVBoxLayout):
            layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        if tree is None:
            tree = QTreeView(container)
        if tree.parent() is None:
            tree.setParent(container)
        if layout.indexOf(tree) == -1:
            layout.addWidget(tree)

        tree.setAlternatingRowColors(True)
        tree.setUniformRowHeights(True)
        tree.setContextMenuPolicy(Qt.CustomContextMenu)
        tree.setProperty("context", context)

        detail = DetailPane(self)

        model = QStandardItemModel(self)
        model.setHorizontalHeaderLabels(list(column_labels))
        tree.setModel(model)

        header = tree.header()
        header.setStretchLastSection(True)
        try:
            header.setSectionsMovable(False)  # type: ignore[attr-defined]
            for section in range(len(column_labels)):
                header.setSectionResizeMode(section, QHeaderView.Interactive)  # type: ignore[attr-defined]
            header.setMinimumSectionSize(60)  # type: ignore[attr-defined]
        except Exception:
            pass

        tree.selectionModel().selectionChanged.connect(
            lambda selected, _deselected, view=detail: self._on_tree_selection_changed(
                selected, view
            )
        )
        tree.customContextMenuRequested.connect(
            lambda pos, t=tree: self._show_context_menu(t, pos)
        )
        tree.doubleClicked.connect(
            lambda index, t=tree: self._on_tree_double_clicked(t, index)
        )
        tree.expanded.connect(
            lambda index, t=tree: self._on_tree_expanded(t, index)
        )
        tooltip_filter = TreeToolTipFilter(tree)
        tree.viewport().installEventFilter(tooltip_filter)
        tree.setProperty("_tooltip_filter", tooltip_filter)

        return container, tree, detail, model

    def _on_tab_changed(self, index: int) -> None:
        if not hasattr(self, "detail_stack"):
            return
        widget = self.tabs.widget(index)
        if widget is self.psp_tab:
            self.detail_stack.setCurrentWidget(self.psp_detail)
            if hasattr(self, "hex_stack"):
                self.hex_stack.setCurrentWidget(self.psp_hex_widget)
        elif widget is self.uefi_tab:
            self.detail_stack.setCurrentWidget(self.uefi_detail)
            if hasattr(self, "hex_stack"):
                self.hex_stack.setCurrentWidget(self.uefi_hex_widget)
        else:
            self.detail_stack.setCurrentWidget(self.empty_detail)
            if hasattr(self, "hex_stack"):
                self.hex_stack.setCurrentWidget(self.empty_hex)

    # Tree selection/filtering methods are provided by TreeOperationsMixin:
    # _remember_active_psp_selection, _remember_active_uefi_selection,
    # _apply_uefi_tree_filter, _apply_psp_tree_filter,
    # _restore_active_uefi_selection, _select_first_visible_uefi_item,
    # _restore_active_psp_selection, _select_first_visible_psp_item,
    # _focus_tree_item, _on_tree_double_clicked, _on_tree_expanded,
    # _show_context_menu, _handle_context_menu_action

    # Image tab/modification methods are provided by ImageModificationMixin:
    # _sync_uefi_image_tab_selection, _refresh_uefi_image_tabs,
    # _set_active_image, _on_uefi_image_tab_changed, _set_diff_column_visibility,
    # _toggle_diff_mode, _clear_diff_highlights, _apply_diff_highlights,
    # _update_diff_action_state, _record_psp_modification, _clear_psp_modification,
    # _shift_pending_entry_indices, _remove_change_log_entry, _refresh_image_dirty_state,
    # _record_modified_range, _update_directory_checksum, _apply_modified_markers,
    # _mark_image_dirty, _update_capsule_export_state, _update_window_title,
    # _reprocess_image, _rebuild_from_loaded_images, _reload_model

    def _initialize_tree_columns(self) -> None:
        if (
            not getattr(self, "_psp_columns_initialized", False)
            and self.psp_model.columnCount()
        ):
            header = self.psp_tree.header()
            try:
                # Resize all columns to fit content
                for section in range(header.count()):
                    self.psp_tree.resizeColumnToContents(section)
                # Allow user to manually resize after initial fit
                for section in range(header.count()):
                    header.setSectionResizeMode(section, QHeaderView.Interactive)
                header.setStretchLastSection(True)
            except Exception:
                pass
            self._psp_columns_initialized = True
        if (
            self.include_uefi
            and not getattr(self, "_uefi_columns_initialized", False)
            and self.uefi_model.columnCount()
        ):
            header = self.uefi_tree.header()
            try:
                # Resize all columns to fit content
                for section in range(header.count()):
                    self.uefi_tree.resizeColumnToContents(section)
                # Allow user to manually resize after initial fit
                for section in range(header.count()):
                    header.setSectionResizeMode(section, QHeaderView.Interactive)
                header.setStretchLastSection(True)
            except Exception:
                pass
            self._uefi_columns_initialized = True

    def _find_psp_item(
        self,
        image_index: int,
        directory_index: Optional[int],
        entry_index: Optional[int],
    ):
        return self.psp_tab_controller.find_item(
            image_index, directory_index, entry_index
        )


    def _focus_psp_item(
        self,
        image_index: Optional[int],
        directory_index: Optional[int],
        entry_index: Optional[int],
    ) -> None:
        self.psp_tab_controller.focus_item(
            image_index, directory_index, entry_index
        )

    def _set_tree_item_action(
        self, tree: QTreeView, item: Optional[QStandardItem], column: int, text: str
    ) -> None:
        if item is None:
            return
        index = item.index()
        if not index.isValid():
            return
        model = tree.model()
        if model is None:
            return
        try:
            action_index = index.sibling(index.row(), column)
            action_item = model.itemFromIndex(action_index)  # type: ignore[attr-defined]
        except Exception:
            action_item = None
        changed = False
        if action_item is not None:
            new_text = text if text else ""
            if action_item.text() != new_text:
                action_item.setText(new_text)
                changed = True
        if text:
            parent = item.parent()
            while parent is not None:
                parent_index = parent.index()
                if not parent_index.isValid():
                    break
                try:
                    parent_action_index = parent_index.sibling(
                        parent_index.row(), column
                    )
                    parent_action = model.itemFromIndex(parent_action_index)  # type: ignore[attr-defined]
                except Exception:
                    parent_action = None
                if parent_action is not None and not parent_action.text():
                    parent_action.setText(text)
                parent = parent.parent()
        if changed:
            self._update_tree_action_column_state(tree, column)

    def _update_tree_action_column_state(
        self, tree: Optional[QTreeView], column: int
    ) -> None:
        if tree is None:
            return
        model = tree.model()
        if model is None:
            return

        def _has_text(item: Optional[QStandardItem]) -> bool:
            if item is None:
                return False
            text = item.text()
            if text and text.strip():
                return True
            for row in range(item.rowCount()):
                if _has_text(item.child(row, column)):
                    return True
            return False

        has_actions = False
        for row in range(model.rowCount()):
            if _has_text(model.item(row, column)):
                has_actions = True
                break
        tree.setColumnHidden(column, not has_actions)

    def _update_action_column_visibility(self) -> None:
        self._update_tree_action_column_state(self.psp_tree, PSP_ACTION_COLUMN)
        self._update_tree_action_column_state(self.uefi_tree, 3)

    def _set_diff_column_visibility(self) -> None:
        diff_visible = self.diff_mode and len(self.loaded_images) > 1
        for tree, column in (
            (self.psp_tree, PSP_DIFF_COLUMN),
            (self.uefi_tree, UEFI_DIFF_COLUMN),
        ):
            if tree is None:
                continue
            try:
                tree.setColumnHidden(column, not diff_visible)
            except Exception:
                pass
        if diff_visible:
            self._initialize_tree_columns()

    def _toggle_diff_mode(self, checked: bool) -> None:
        desired = bool(checked) and len(self.loaded_images) > 1
        self.diff_mode = desired
        if self._diff_action and self._diff_action.isChecked() != desired:
            try:
                self._diff_action.blockSignals(True)
                self._diff_action.setChecked(desired)
            finally:
                try:
                    self._diff_action.blockSignals(False)
                except Exception:
                    pass
        self._set_diff_column_visibility()
        self._apply_diff_highlights()

    def _clear_diff_highlights(self) -> None:
        for model in (self.psp_model, self.uefi_model):
            if model is None:
                continue
            for item in iter_tree_items(model):
                idx = item.index()
                diff_col = (
                    PSP_DIFF_COLUMN if model is self.psp_model else UEFI_DIFF_COLUMN
                )
                model_item = model.itemFromIndex(idx.sibling(idx.row(), diff_col))  # type: ignore[attr-defined]
                if model_item is not None:
                    model_item.setText("")

    def _apply_diff_highlights(self) -> None:
        if not self.diff_mode or len(self.loaded_images) < 2:
            self._clear_diff_highlights()
            self._set_diff_column_visibility()
            return
        statuses = compute_diff_statuses(
            self.psp_model, self.uefi_model, self.loaded_images
        )
        self._clear_diff_highlights()
        for item, status in statuses.values():
            model = item.model()
            if model is None:
                continue
            idx = item.index()
            diff_col = (
                PSP_DIFF_COLUMN if model is self.psp_model else UEFI_DIFF_COLUMN
            )
            diff_item = model.itemFromIndex(idx.sibling(idx.row(), diff_col))  # type: ignore[attr-defined]
            if diff_item is not None:
                diff_item.setText(status)
        self._set_diff_column_visibility()

    def _update_diff_action_state(self) -> None:
        if self._diff_action is None:
            return
        enabled = len(self.loaded_images) > 1
        self._diff_action.setEnabled(enabled)
        if not enabled and self.diff_mode:
            try:
                self._diff_action.blockSignals(True)
                self._diff_action.setChecked(False)
            except Exception:
                pass
            finally:
                try:
                    self._diff_action.blockSignals(False)
                except Exception:
                    pass
            self.diff_mode = False
            self._clear_diff_highlights()
            self._set_diff_column_visibility()
        if enabled and self._diff_action.isChecked() != self.diff_mode:
            self._diff_action.setChecked(self.diff_mode)

    def _record_psp_modification(
        self,
        image_index: int,
        directory_index: Optional[int],
        entry_index: Optional[int] = None,
        *,
        action_text: str = "modify",
        mark_directory: bool = True,
    ) -> None:
        self.psp_tab_controller.record_modification(
            image_index,
            directory_index,
            entry_index,
            action_text=action_text,
            mark_directory=mark_directory,
        )

    def _clear_psp_modification(
        self,
        image_index: int,
        directory_index: Optional[int],
        entry_index: Optional[int],
    ) -> None:
        self.psp_tab_controller.clear_modification(
            image_index, directory_index, entry_index
        )

    def _shift_pending_entry_indices(
        self,
        image: LoadedImage,
        directory_index: int,
        start_index: int,
        delta: int,
        *,
        skip: Optional[Set[Tuple[int, Optional[int]]]] = None,
    ) -> None:
        self.psp_tab_controller.shift_pending_entry_indices(
            image, directory_index, start_index, delta, skip=skip
        )

    def _remove_change_log_entry(self, image: LoadedImage, change_desc: str) -> None:
        try:
            image.change_log.remove(change_desc)
        except ValueError:
            pass

    def _refresh_image_dirty_state(self, image_index: int) -> None:
        if not (0 <= image_index < len(self.loaded_images)):
            return
        image = self.loaded_images[image_index]
        dirty = bool(
            image.change_log
            or image.pending_entry_actions
            or image.modified_ranges
        )
        self._mark_image_dirty(image_index, dirty)

    def _record_modified_range(self, image_index: int, start: int, length: int) -> None:
        if length is None or length <= 0:
            return
        if not (0 <= image_index < len(self.loaded_images)):
            return
        try:
            begin = int(start)
            span = int(length)
        except Exception:
            return
        if span <= 0:
            return
        end = begin + span
        image = self.loaded_images[image_index]
        merged: List[Tuple[int, int]] = []
        new_start, new_end = begin, end
        for existing_start, existing_end in getattr(image, "modified_ranges", []):
            if existing_end < new_start or existing_start > new_end:
                merged.append((existing_start, existing_end))
            else:
                new_start = min(new_start, existing_start)
                new_end = max(new_end, existing_end)
        merged.append((new_start, new_end))
        merged.sort()
        collapsed: List[Tuple[int, int]] = []
        for rng_start, rng_end in merged:
            if not collapsed or rng_start > collapsed[-1][1]:
                collapsed.append((rng_start, rng_end))
            else:
                last_start, last_end = collapsed[-1]
                collapsed[-1] = (last_start, max(last_end, rng_end))
        image.modified_ranges = collapsed
        self.uefi_tab_controller.mark_items_by_range(
            image_index, new_start, new_end - new_start
        )

    def _update_directory_checksum(
        self, image: LoadedImage, directory: Optional[Directory]
    ) -> None:
        if directory is None or directory.offset is None:
            return
        seed = detect_directory_checksum_seed(image.data, directory)
        checksum = compute_directory_checksum(image.data, directory, seed)
        if checksum is None:
            return
        crc_off = int(directory.offset) + 4
        if 0 <= crc_off <= len(image.data) - 4:
            image.data[crc_off : crc_off + 4] = int(checksum).to_bytes(4, "little")

    def _apply_modified_markers(self) -> None:
        for image_index, image in enumerate(self.loaded_images):
            if getattr(image, "psp_entry_actions", None):
                for (directory_index, entry_index), action_text in (
                    image.psp_entry_actions.items()
                ):
                    item = self._find_psp_item(image_index, directory_index, entry_index)
                    self._set_tree_item_action(
                        self.psp_tree,
                        item,
                        PSP_ACTION_COLUMN,
                        action_text or "modify",
                    )
            else:
                for directory_index, entry_index in getattr(
                    image, "psp_modified_entries", set()
                ):
                    item = self._find_psp_item(image_index, directory_index, entry_index)
                    self._set_tree_item_action(
                        self.psp_tree, item, PSP_ACTION_COLUMN, "modify"
                    )
            for rng in getattr(image, "modified_ranges", []):
                start, end = rng
                self.uefi_tab_controller.mark_items_by_range(
                    image_index, start, end - start
                )

    def _set_display_scale(self, factor: float) -> None:
        try:
            value = float(factor)
        except Exception:
            return
        value = max(1.0, min(3.0, value))
        if abs(value - self._display_scale) < 0.01:
            return
        self._display_scale = value
        font = QFont(self._base_font)
        base_size = font.pointSizeF()
        if base_size <= 0:
            base_size = float(font.pointSize() or 9)
        font.setPointSizeF(base_size * value)
        app = QApplication.instance()
        if app is not None:
            app.setFont(font)
        self.setFont(font)
        self._psp_columns_initialized = False
        self._uefi_columns_initialized = False
        self._initialize_tree_columns()
        target_pct = int(round(value * 100))
        action = self._scale_actions.get(target_pct)
        if action is not None and not action.isChecked():
            action.blockSignals(True)
            action.setChecked(True)
            action.blockSignals(False)
        self._status_message(f"Display scale set to {int(value * 100)}%")

    def _system_prefers_dark(self) -> Optional[bool]:
        app = QGuiApplication.instance()
        if app is None:
            return None
        hints = app.styleHints()
        if hints is None:
            return None
        color_scheme = None
        try:
            color_scheme = hints.colorScheme()
        except Exception:
            color_scheme = None
        color_enum = getattr(Qt, "ColorScheme", None)
        if color_enum is not None:
            if color_scheme == getattr(color_enum, "Dark", None):
                return True
            if color_scheme == getattr(color_enum, "Light", None):
                return False
        return None

    # Theme methods are provided by ThemeMixin:
    # _apply_theme, _refresh_menu_palette, _apply_system_theme,
    # _sync_theme_actions, _update_theme_toggle_label, _toggle_theme_override

    def _on_tree_selection_changed(self, selected, detail_view: DetailPane) -> None:
        if not selected.indexes():
            detail_view.clear()
            self.statusBar().showMessage("Ready")
            return
        index = selected.indexes()[0]
        index0 = index.sibling(index.row(), 0)
        model = index.model()
        item = model.itemFromIndex(index0) if hasattr(model, "itemFromIndex") else None
        detail = None
        summary = None
        display = None
        if item is not None:
            detail = item.data(DETAIL_ROLE)
            summary = item.data(SUMMARY_ROLE)
            display = item.data()
            chain = item.data(CHAIN_ROLE)
            metadata = item.data(METADATA_ROLE)
            key_entries = item.data(KEY_TABLE_ROLE)
            hex_blob = item.data(HEX_ROLE)
        else:
            chain = None
            metadata = None
            key_entries = None
            hex_blob = None
        if detail is None:
            detail = index0.data(DETAIL_ROLE) or index0.data()
        detail_view.update(
            str(detail),
            metadata if isinstance(metadata, dict) else None,
            chain if isinstance(chain, dict) else None,
            key_entries if isinstance(key_entries, list) else None,
            hex_blob if isinstance(hex_blob, (bytes, bytearray)) else None,
        )
        if summary:
            self.statusBar().showMessage(str(summary))
        elif display is not None:
            self.statusBar().showMessage(str(display))

    def _resolve_payload_bytes(self, payload: dict) -> Optional[bytes]:
        image_index = payload.get("image_index")
        if image_index is None:
            blob = payload.get("hex_blob")
            if isinstance(blob, (bytes, bytearray)):
                return bytes(blob)
            return None
        try:
            image_index = int(image_index)
        except Exception:
            return None
        if not (0 <= image_index < len(self.loaded_images)):
            return None
        image = self.loaded_images[image_index]
        blob_override = payload.get("hex_blob")
        if (payload.get("offset") is None or payload.get("size") in (None, 0)) and isinstance(
            blob_override, (bytes, bytearray)
        ):
            try:
                return bytes(blob_override)
            except Exception:
                pass
        offset = payload.get("offset")
        size = payload.get("size")
        if (size is None or int(size) <= 0) and payload.get("declared_size"):
            try:
                declared_size = int(payload.get("declared_size"))
            except Exception:
                declared_size = 0
            else:
                if declared_size > 0:
                    size = declared_size
        if offset is None or size is None:
            return None
        try:
            offset = int(offset)
            size = int(size)
        except Exception:
            return None
        if offset < 0 or size <= 0:
            return None
        end = offset + size
        if end > len(image.data):
            end = len(image.data)
        if end <= offset:
            return None
        return bytes(image.data[offset:end])

    def _configure_hex_input(
        self, widget: QLineEdit, digits: int, initial_value: Optional[int]
    ) -> None:
        """Normalize a QLineEdit to enforce a 0x-prefixed hexadecimal value."""

        max_len = max(int(digits), 1)

        def _normalize() -> None:
            text = widget.text() or ""
            if text.lower().startswith("0x"):
                raw = text[2:]
            else:
                raw = text
            filtered = re.sub(r"[^0-9a-fA-F]", "", raw.upper())[:max_len]
            normalized = "0x" + filtered
            if not filtered:
                normalized = "0x"
            if widget.text() != normalized:
                cursor = max(widget.cursorPosition(), 2)
                widget.blockSignals(True)
                widget.setText(normalized)
                widget.blockSignals(False)
                widget.setCursorPosition(min(max(cursor, 2), len(normalized)))
            elif widget.cursorPosition() < 2:
                widget.setCursorPosition(2)

        def _ensure_cursor(_old: int, _new: int) -> None:
            if widget.cursorPosition() < 2:
                widget.setCursorPosition(2)

        widget.setMaxLength(2 + max_len)
        if initial_value is None:
            display_value = "0x"
        else:
            mask = (1 << (4 * max_len)) - 1
            digits_text = f"{int(initial_value) & mask:X}".lstrip("0")
            display_value = f"0x{digits_text or '0'}"
        widget.setText(display_value)
        widget.cursorPositionChanged.connect(_ensure_cursor)
        widget.textEdited.connect(lambda _text: _normalize())
        widget.editingFinished.connect(_normalize)
        _normalize()

    # Hex dialog methods are provided by HexDialogsMixin:
    # _show_hex_dialog, _on_hex_dialog_closed, _show_apcb_tokens,
    # _show_microcode_details, _open_hex_view, _open_decompressed_hex,
    # _open_directory_table_hex, _show_hex_context_menu, _extract_hex_ascii_from_editor

    def _status_message(self, message: str) -> None:
        if not message:
            return
        self._append_console(str(message))
        self.statusBar().showMessage(str(message), 5000)

    def _append_console(self, message: str) -> None:
        append_console(self, message)

    def _handle_soft_fuse_update(
        self,
        context: dict,
        new_raw: int,
        bit: Optional[int] = None,
        old_value: Optional[int] = None,
        new_value: Optional[int] = None,
        label: Optional[str] = None,
    ) -> None:
        image_index = context.get("image_index")
        entry_offset = context.get("entry_offset")
        if image_index is None or entry_offset is None:
            self._status_message("Unable to update Soft Fuse: missing context")
            return
        try:
            idx = int(image_index)
            offset = int(entry_offset)
        except Exception:
            self._status_message("Unable to update Soft Fuse: invalid offsets")
            return
        if not (0 <= idx < len(self.loaded_images)):
            self._status_message("Unable to update Soft Fuse: image index out of range")
            return
        image = self.loaded_images[idx]
        dir_index = context.get("directory_index")
        directory_obj = None
        try:
            dir_idx = int(dir_index) if dir_index is not None else None
        except Exception:
            dir_idx = None
        if dir_idx is not None and 0 <= dir_idx < len(image.directories):
            directory_obj = image.directories[dir_idx]
        start = offset + 8
        end = start + 8
        if start < 0 or end > len(image.data):
            self._status_message("Unable to update Soft Fuse: offset outside image")
            return
        previous_raw = _mask_u64(
            context.pop("previous_raw", context.get("raw_u64", context.get("raw", 0)))
        )
        raw_value = _mask_u64(new_raw)
        image.data[start:end] = raw_value.to_bytes(8, "little")
        context["raw_u64"] = raw_value
        context["raw"] = _to_signed_64(raw_value)
        try:
            updated_chain = _softfuse.parse_soft_fuse_chain(raw_value)
        except Exception:
            updated_chain = None
        if updated_chain is not None:
            context["chain"] = updated_chain
            context["fields"] = list(updated_chain.fields)
        if directory_obj is not None:
            self._update_directory_checksum(image, directory_obj)
            crc_off = int(directory_obj.offset) + 4
            self._record_modified_range(idx, crc_off, 4)
        image.needs_reparse = True
        self._mark_image_dirty(idx)
        self._record_modified_range(idx, start, 8)

        entry_index = context.get("entry_index")
        try:
            entry_idx = int(entry_index)
        except Exception:
            entry_idx = None
        if dir_idx is not None:
            self._record_psp_modification(idx, dir_idx, entry_idx)
        dir_part = f"d{dir_idx:02X}" if dir_idx is not None else "d--"
        entry_part = f"e{entry_idx:02X}" if entry_idx is not None else "e--"
        range_label = f"{dir_part}-{entry_part}"

        message: Optional[str] = None
        if bit is not None:
            real_old = 1 if previous_raw & (1 << bit) else 0
            real_new = 1 if raw_value & (1 << bit) else 0
            effective_old = real_old
            if old_value is not None:
                try:
                    effective_old = int(old_value) & 1
                except Exception:
                    effective_old = real_old
            if effective_old != real_old:
                effective_old = real_old
            effective_new = real_new
            if new_value is not None:
                try:
                    effective_new = int(new_value) & 1
                except Exception:
                    effective_new = real_new
            if effective_new != real_new:
                effective_new = real_new
            bit_label = label or f"Bit {bit}"
            message = (
                f"{range_label}: Soft Fuse Chain change queued "
                f"({bit_label}: {effective_old} -> {effective_new})"
            )
            log_entry = (
                f"{range_label} {bit_label}: {effective_old} -> {effective_new} "
                f"(raw 0x{previous_raw:016X} -> 0x{raw_value:016X})"
            )
        else:
            message = (
                f"{range_label}: Soft Fuse Chain change queued "
                f"(raw 0x{previous_raw:016X} -> 0x{raw_value:016X})"
            )
            log_entry = message

        image.change_log.append(log_entry)

        selection = self.psp_tree.selectionModel().currentIndex()
        if selection.isValid():
            item = self.psp_model.itemFromIndex(selection.sibling(selection.row(), 0))
            if item is not None:
                item.setData(context, CHAIN_ROLE)
        self._status_message(message)

    def _mark_image_dirty(self, image_index: int, dirty: bool = True) -> None:
        if not (0 <= image_index < len(self.loaded_images)):
            return
        image = self.loaded_images[image_index]
        image.dirty = dirty
        if self._save_as_action is not None:
            self._save_as_action.setEnabled(
                any(img.dirty for img in self.loaded_images)
            )
        self._update_window_title()

    def _update_capsule_export_state(self) -> None:
        if self._export_capsule_action is None:
            return
        enabled = any(img.was_capsule for img in self.loaded_images)
        self._export_capsule_action.setEnabled(enabled)

    def _update_window_title(self) -> None:
        names = [str(img.path.name) for img in self.loaded_images if img.path]
        title = self._base_title
        if names:
            suffix = names[0]
            if len(names) > 1:
                suffix += f" (+{len(names) - 1})"
            title = f"{self._base_title} - {suffix}"
        if any(img.dirty for img in self.loaded_images):
            title += " *"
        self.setWindowTitle(title)

    def _reprocess_image(self, image_index: int) -> None:
        """Re-parse an image after modifications."""
        # Delegate to the ImageModificationMixin implementation so queued 0x62
        # actions (compressed BIOS edits) survive the reparse.
        super()._reprocess_image(image_index)

    def _capture_psp_selection(self) -> Optional[dict]:
        return self.psp_tab_controller.capture_selection()

    def _restore_psp_selection(self, locator: Optional[dict]) -> None:
        self.psp_tab_controller.restore_selection(locator)

    def _rebuild_from_loaded_images(self) -> None:
        # Capture expanded state before rebuilding
        psp_expanded = self._capture_tree_expanded_state(self.psp_tree)
        uefi_expanded = self._capture_tree_expanded_state(self.uefi_tree) if self.include_uefi else set()

        locator = self._capture_psp_selection()
        uefi_locator = self.uefi_tab_controller.capture_selection()
        self._remember_active_psp_selection()
        self._remember_active_uefi_selection()
        self.psp_model.removeRows(0, self.psp_model.rowCount())
        self.uefi_model.removeRows(0, self.uefi_model.rowCount())
        psp_rows = self._builder.build_psp_rows(self.loaded_images)
        for row in psp_rows:
            self.psp_model.appendRow(row)
        # Restore expanded state instead of collapsing
        self._restore_tree_expanded_state(self.psp_tree, psp_expanded)

        if self.include_uefi:
            uefi_rows = self._builder.build_uefi_rows(self.loaded_images)
            for row in uefi_rows:
                self.uefi_model.appendRow(row)
            # Restore expanded state instead of collapsing
            self._restore_tree_expanded_state(self.uefi_tree, uefi_expanded)
            fallback_locator = uefi_locator or locator
            self._refresh_uefi_image_tabs(fallback_locator=fallback_locator)
        else:
            self._refresh_uefi_image_tabs()
        self._apply_psp_tree_filter()
        self._restore_active_psp_selection(fallback_locator=locator)
        self._update_uefi_tab_state()
        self.summary_controller.refresh_summary()
        self.efs_tab_controller.refresh()
        self._restore_efs_focus()
        self._initialize_tree_columns()
        self._apply_modified_markers()
        self._update_action_column_visibility()
        self._set_diff_column_visibility()
        self._update_diff_action_state()
        self._apply_diff_highlights()

    def _restore_efs_focus(self) -> None:
        summary_scroll_value = self._pending_summary_scroll
        efs_scroll_value = self._pending_efs_scroll
        focus_info = self._pending_efs_focus
        self._pending_summary_scroll = None
        self._pending_efs_scroll = None
        self._pending_efs_focus = None
        if summary_scroll_value is not None:
            try:
                bar = self.summary_scroll.verticalScrollBar()
                if bar is not None:
                    bar.setValue(summary_scroll_value)
            except Exception:
                pass
        if efs_scroll_value is not None:
            try:
                bar = self.efs_scroll.verticalScrollBar()
                if bar is not None:
                    bar.setValue(efs_scroll_value)
            except Exception:
                pass
        if not focus_info:
            return
        image_index, efs_offset, field_name, kind = focus_info
        bundle = self.efs_tab_controller.get_field_widgets(image_index, efs_offset)
        if not bundle:
            return
        widget = None
        if kind == "pointer":
            widget = bundle.get("pointers", {}).get(field_name)
        else:
            combo = bundle.get("spi", {}).get(field_name)
            if isinstance(combo, QComboBox):
                if combo.isEditable() and combo.lineEdit() is not None:
                    widget = combo.lineEdit()
                else:
                    widget = combo
        if widget is None:
            return
        try:
            widget.setFocus()
        except Exception:
            return
        if hasattr(widget, "selectAll"):
            try:
                widget.selectAll()
            except Exception:
                pass

    # PSP entry operations methods are provided by PspEntryOperationsMixin:
    # _format_psp_location_title, _format_payload_location,
    # _prompt_entry_configuration, _collect_ish_presets, _collect_directory_entry_snapshots,
    # _edit_psp_directory, _remove_psp_entry, _replace_psp_entry, _edit_psp_entry, _insert_psp_entry

    def _export_guid_catalog(self) -> None:
        self.uefi_tab_controller.export_guid_catalog()

    def _export_psp_structure(self) -> None:
        self.psp_tab_controller.export_structure()

    # Export operation methods are provided by ExportOperationsMixin:
    # _export_amd_modules, _collect_amd_module_exports, _iter_uefi_files,
    # _iter_section_descendants, _prepare_module_export, _module_extension,
    # _module_filename, _extract_module_blob, _extract_pe_image_from_sections,
    # _write_named_blob, _load_guid_csv, _import_guid_csv, _collect_guid_map,
    # _collect_tree_lines

    def _update_uefi_tab_state(self) -> None:
        tab_index = self.tabs.indexOf(self.uefi_tab)
        if tab_index >= 0:
            self.tabs.setTabEnabled(tab_index, self.include_uefi)
            if not self.include_uefi:
                self.uefi_detail.clear()
        if hasattr(self, "uefi_image_bar"):
            visible = self.uefi_image_bar.count() > 1
            self.uefi_image_bar.setVisible(visible)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if any(img.dirty for img in self.loaded_images):
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Warning)
            box.setWindowTitle("Unsaved changes")
            box.setText("There are unsaved firmware modifications.")
            box.setInformativeText("Save changes before exiting?")
            box.setStandardButtons(
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel
            )
            box.setDefaultButton(QMessageBox.Save)
            exec_fn = getattr(box, "exec", None) or getattr(box, "exec_", None)
            result = exec_fn() if exec_fn else QMessageBox.Cancel
            if result == QMessageBox.Save:
                self._save_as()
                if any(img.dirty for img in self.loaded_images):
                    event.ignore()
                    return
            elif result == QMessageBox.Cancel or result == QMessageBox.Close:
                event.ignore()
                return
        super().closeEvent(event)

    def _select_first_item(self, tree: QTreeView, model: QStandardItemModel) -> None:
        if model.rowCount() == 0:
            return
        index = model.index(0, 0)
        if index.isValid():
            tree.setCurrentIndex(index)

    def dragEnterEvent(self, event) -> None:  # type: ignore[override]
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:  # type: ignore[override]
        urls = event.mimeData().urls()
        paths: List[Path] = []
        for url in urls:
            if url.isLocalFile():
                try:
                    candidate = Path(url.toLocalFile())
                    if candidate.is_file():
                        paths.append(candidate)
                except Exception:
                    continue
        if paths:
            self.load_inputs(paths)
            event.acceptProposedAction()
        else:
            event.ignore()

    # Action and menu methods are provided by ActionsMixin:
    # _create_actions, _show_about_dialog, _show_license_dialog,
    # _show_about_pyside_dialog, _open_qrh_html, _open_qrh_ui,
    # _show_search_dialog, _open_files, _toggle_include_uefi, _set_mode,
    # _export_capsule_image, _prompt_efs_offset

    def load_inputs(self, inputs: Sequence[Path | str]) -> None:
        paths: List[Path] = []
        for raw in inputs:
            if not raw:
                continue
            try:
                candidate = Path(raw)
            except Exception:
                continue
            if candidate not in paths:
                paths.append(candidate)
        if not paths:
            return
        if len(paths) > 2:
            QMessageBox.information(
                self,
                "Too many files",
                "Please select up to two firmware images. Loading the first two.",
            )
            paths = paths[:2]
        self.current_inputs = paths
        self._uefi_selection_by_image.clear()
        self._psp_selection_by_image.clear()
        self._active_image_index = None
        self._reload_model()

    def _loading_progress(self, stage: str, index: int, total: int, path) -> None:
        if not hasattr(self, "progress_bar") or self.progress_bar is None:
            return
        # Update progress bar value
        if total > 0:
            self.progress_bar.setRange(0, total)
            clamped = max(0, min(index, total))
            self.progress_bar.setValue(clamped)
        # Update status message
        path_name = path.name if hasattr(path, 'name') else str(path)
        if stage == "finished":
            if total > 0:
                message = f"Loaded {path_name} ({index}/{total})"
            else:
                message = f"Loaded {path_name}"
        elif stage == "parsing":
            message = f"Parsing {path_name}..."
        else:
            message = f"Reading {path_name}..."
        self.statusBar().showMessage(message)
        QApplication.processEvents()  # Keep UI responsive

    def _tree_build_progress(self, current: int, total: int, message: str) -> None:
        """Handle progress updates from tree builder."""
        if not hasattr(self, "progress_bar") or self.progress_bar is None:
            return
        if total <= 0:
            self.progress_bar.setRange(0, 0)
        else:
            self.progress_bar.setRange(0, total)
            clamped = max(0, min(current, total))
            self.progress_bar.setValue(clamped)
        if message:
            self.statusBar().showMessage(message)
        QApplication.processEvents()

    def _tree_progress(
        self, stage: str, current: int, total: int, context: dict
    ) -> None:
        """Handle progress callback from FirmwareTreeBuilder."""
        # Always process events on heartbeat to prevent UI freeze
        if stage == "heartbeat":
            QApplication.processEvents()
            return
        
        if not hasattr(self, "progress_bar") or self.progress_bar is None:
            return
        
        if stage in ("building_directories", "building_entries"):
            if total <= 0:
                self.progress_bar.setRange(0, 0)
            else:
                self.progress_bar.setRange(0, total)
                clamped = max(0, min(current, total))
                self.progress_bar.setValue(clamped)
            image_name = context.get("image", "") if isinstance(context, dict) else ""
            dir_index = context.get("dir_index", "") if isinstance(context, dict) else ""
            if image_name:
                msg = f"Building tree: {image_name} (entry {current}/{total})"
            else:
                msg = f"Building tree ({current}/{total})..."
            self.statusBar().showMessage(msg)
            QApplication.processEvents()  # Keep UI responsive

    def _relay_loader_message(self, message: str) -> None:
        if not message:
            return
        for line in str(message).splitlines() or [str(message)]:
            self._append_console(line)

    def _reload_model(self) -> None:
        # Reload JSON-based data to pick up any updates
        _softfuse.reload_fields()
        _constants.reload_program_table()
        _constants.reload_type_names()
        
        uefi_locator = self.uefi_tab_controller.capture_selection()
        psp_locator = self._capture_psp_selection()
        self._remember_active_psp_selection()
        self._remember_active_uefi_selection()
        self.psp_model.removeRows(0, self.psp_model.rowCount())
        self.uefi_model.removeRows(0, self.uefi_model.rowCount())
        self.psp_detail.clear()
        self.uefi_detail.clear()
        self.efs_tab_controller.clear_field_widgets()
        self._psp_columns_initialized = False
        self._uefi_columns_initialized = False
        self.loaded_images = []
        self._update_capsule_export_state()
        if not self.current_inputs:
            self._active_image_index = None
            self._uefi_selection_by_image.clear()
            self._psp_selection_by_image.clear()
            self._refresh_uefi_image_tabs()
        else:
            self._apply_psp_tree_filter()
            self._apply_uefi_tree_filter()

        if not self.current_inputs:
            self.summary_controller.refresh_summary()
            self.efs_tab_controller.refresh()
            self.statusBar().showMessage("No input selected")
            self._update_window_title()
            self._update_diff_action_state()
            return

        if hasattr(self, "progress_bar") and self.progress_bar is not None:
            total_hint = len(self.current_inputs)
            if total_hint <= 0:
                self.progress_bar.setRange(0, 0)
            else:
                self.progress_bar.setRange(0, total_hint)
                self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
            QApplication.processEvents()

        # Synchronous loading with processEvents for UI responsiveness
        try:
            images = self._builder.load_images(
                self.current_inputs,
                self._loading_progress,
                log_callback=self._relay_loader_message,
                max_images=2,
            )
        except Exception as exc:
            QMessageBox.critical(self, "Failed to load", str(exc))
            self.statusBar().showMessage("Failed to load inputs")
            self.summary_controller.refresh_summary()
            self.efs_tab_controller.refresh()
            if hasattr(self, "progress_bar") and self.progress_bar is not None:
                self.progress_bar.setVisible(False)
            self._update_capsule_export_state()
            return

        self.loaded_images = images
        self._update_window_title()
        self._update_capsule_export_state()
        self._update_diff_action_state()

        # Build tree rows with progress callback
        self._builder.progress_callback = self._tree_progress
        psp_rows = self._builder.build_psp_rows(images)
        for row in psp_rows:
            self.psp_model.appendRow(row)
        if psp_rows:
            self._select_first_item(self.psp_tree, self.psp_model)
            self.psp_tree.collapseAll()

        if self.include_uefi:
            uefi_rows = self._builder.build_uefi_rows(images)
        else:
            uefi_rows = []
        for row in uefi_rows:
            self.uefi_model.appendRow(row)
        if self.include_uefi and uefi_rows:
            self.uefi_tree.collapseAll()

        # Restore selection
        fallback_locator = uefi_locator or psp_locator
        self._refresh_uefi_image_tabs(fallback_locator=fallback_locator)

        # Hide progress bar
        if hasattr(self, "progress_bar") and self.progress_bar is not None:
            self.progress_bar.setVisible(False)

        self._update_uefi_tab_state()
        self.summary_controller.refresh_summary()
        self.efs_tab_controller.refresh()
        self._initialize_tree_columns()
        self._set_diff_column_visibility()
        self._apply_diff_highlights()

        if images:
            self.statusBar().showMessage(
                f"Loaded {len(images)} file(s) using {self.discovery_mode.upper()} mode"
            )
        else:
            self.statusBar().showMessage("No directories discovered")


def launch_gui(
    inputs: Sequence[Path | str] | None = None,
    *,
    mode: str = "auto",
    efs_offset: Optional[int] = None,
    include_uefi: bool = True,
    maintenance_mode: bool = False,
) -> None:
    # Launch the Qt GUI. When inputs are supplied they are opened after window shows.
    from .qt import QTimer

    app = QApplication.instance()
    owns_app = False
    if app is None:
        app = QApplication(sys.argv)
        owns_app = True

    window = MainWindow(
        discovery_mode=mode,
        efs_offset=efs_offset,
        include_uefi=include_uefi,
        maintenance_mode=maintenance_mode,
    )
    window.show()

    # Defer file loading until after the window is shown and event loop starts
    if inputs:
        QTimer.singleShot(0, lambda: window.load_inputs(inputs))

    exec_fn = getattr(app, "exec", None) or getattr(app, "exec_", None)
    if exec_fn is None:  # pragma: no cover - extremely defensive
        raise RuntimeError("Qt application object does not provide an exec() method")
    if owns_app:
        exec_fn()
