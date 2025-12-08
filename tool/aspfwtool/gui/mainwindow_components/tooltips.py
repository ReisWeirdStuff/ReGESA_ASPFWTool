# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Tree view tooltip event filter.

This module provides:
    - TreeToolTipFilter: Event filter that offsets tree tooltips to avoid
      cursor overlap and improve readability.
"""

from __future__ import annotations

from .qt import QEvent, QPoint, QToolTip, QTreeView, QObject


class TreeToolTipFilter(QObject):
    """Event filter that offsets tree tooltips to avoid cursor overlap."""

    def __init__(self, tree: QTreeView) -> None:
        super().__init__(tree)
        self._tree = tree

    def eventFilter(self, obj, event):  # type: ignore[override]
        if event.type() == QEvent.ToolTip:
            index = self._tree.indexAt(event.pos())
            if not index.isValid():
                return False
            index0 = index.sibling(index.row(), 0)
            model = self._tree.model()
            item = (
                model.itemFromIndex(index0) if hasattr(model, "itemFromIndex") else None
            )
            if item is None:
                return False
            text = item.toolTip()
            if not text:
                return False
            global_pos = self._tree.viewport().mapToGlobal(event.pos() + QPoint(28, 0))
            rect = self._tree.visualRect(index)
            QToolTip.showText(global_pos, text, self._tree, rect)
            return True
        return super().eventFilter(obj, event)
