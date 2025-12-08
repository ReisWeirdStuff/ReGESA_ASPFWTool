# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
Theme management mixin for MainWindow.

This module provides:
    - Light/dark theme switching
    - Palette creation and management
    - System theme detection and synchronization
"""

from typing import Optional

from .qt import (
    QApplication,
    QColor,
    QGuiApplication,
    QPalette,
    Qt,
)
from ...utils.debug_logger import get_logger


def create_light_palette() -> QPalette:
    """
    Construct a bright, neutral gray palette for the light theme.

    Qt styles mutate palette instances in-place, so callers should copy
    the result before applying it to widgets.

    Returns:
        A new QPalette configured for the light theme.
    """
    palette = QPalette()
    window = QColor(248, 248, 248)
    base = QColor(255, 255, 255)
    alternate = QColor(240, 240, 240)
    button = QColor(245, 245, 245)
    text = QColor(25, 25, 25)
    disabled_text = QColor(140, 140, 140)
    highlight = QColor(53, 132, 228)
    highlight_disabled = QColor(200, 200, 200)
    link = QColor(0, 102, 204)
    shadow = QColor(200, 200, 200)
    dark = QColor(210, 210, 210)
    mid = QColor(225, 225, 225)
    light = QColor(255, 255, 255)

    for group in (QPalette.Active, QPalette.Inactive):
        palette.setColor(group, QPalette.Window, window)
        palette.setColor(group, QPalette.WindowText, text)
        palette.setColor(group, QPalette.Base, base)
        palette.setColor(group, QPalette.AlternateBase, alternate)
        palette.setColor(group, QPalette.ToolTipBase, base)
        palette.setColor(group, QPalette.ToolTipText, text)
        palette.setColor(group, QPalette.Text, text)
        palette.setColor(group, QPalette.Button, button)
        palette.setColor(group, QPalette.ButtonText, text)
        palette.setColor(group, QPalette.Highlight, highlight)
        palette.setColor(group, QPalette.HighlightedText, QColor(Qt.white))
        palette.setColor(group, QPalette.Link, link)
        palette.setColor(group, QPalette.LinkVisited, link.darker(115))
        palette.setColor(group, QPalette.Mid, mid)
        palette.setColor(group, QPalette.Dark, dark)
        palette.setColor(group, QPalette.Midlight, mid.lighter(110))
        palette.setColor(group, QPalette.Light, light)
        palette.setColor(group, QPalette.Shadow, shadow)

    palette.setColor(QPalette.Disabled, QPalette.Window, window)
    palette.setColor(QPalette.Disabled, QPalette.WindowText, disabled_text)
    palette.setColor(QPalette.Disabled, QPalette.Base, alternate)
    palette.setColor(QPalette.Disabled, QPalette.AlternateBase, alternate)
    palette.setColor(QPalette.Disabled, QPalette.Text, disabled_text)
    palette.setColor(QPalette.Disabled, QPalette.Button, button)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled_text)
    palette.setColor(QPalette.Disabled, QPalette.Highlight, highlight_disabled)
    palette.setColor(QPalette.Disabled, QPalette.HighlightedText, QColor(90, 90, 90))
    palette.setColor(QPalette.Disabled, QPalette.Link, link)
    palette.setColor(QPalette.Disabled, QPalette.LinkVisited, link)

    if hasattr(QPalette, "PlaceholderText"):
        palette.setColor(QPalette.PlaceholderText, QColor(150, 150, 150))

    return palette


class ThemeMixin:
    """
    Mixin class providing theme management functionality.
    
    Requires the host class to have:
    - menuBar() method
    - statusBar() method  
    - _append_console() method
    - _dark_theme_action, _light_theme_action, _system_theme_action attributes
    """

    # Theme-related attributes (initialized by MainWindow.__init__)
    dark_theme_enabled: bool
    _override_system_theme: bool
    _manual_dark_theme: bool
    _system_theme_preference: Optional[bool]
    _default_palette: Optional[QPalette]
    _default_style_name: Optional[str]
    _light_palette: Optional[QPalette]
    _light_style_name: str
    _dark_style_name: str
    _menu_palette: Optional[QPalette]

    def _init_theme_attributes(self) -> None:
        """Initialize theme-related attributes. Call from MainWindow.__init__."""
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
        self._menu_palette = None

    def _system_prefers_dark(self) -> Optional[bool]:
        """Detect system color scheme preference."""
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
            pass
        color_enum = getattr(Qt, "ColorScheme", None)
        if color_enum is not None:
            if color_scheme == getattr(color_enum, "Dark", None):
                return True
            if color_scheme == getattr(color_enum, "Light", None):
                return False
        return None

    def _apply_theme(self, dark: bool) -> None:
        """Apply light or dark theme to the application."""
        app = QApplication.instance()
        if app is None:
            self.dark_theme_enabled = bool(dark)
            return
        if self._default_palette is None:
            self._default_palette = QPalette(app.palette())
        if self._default_style_name is None:
            style_obj = app.style()
            if style_obj is not None:
                self._default_style_name = style_obj.objectName()
        self.dark_theme_enabled = bool(dark)
        if dark:
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(35, 35, 35))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, Qt.white)
            palette.setColor(QPalette.ToolTipText, Qt.white)
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            palette.setColor(QPalette.BrightText, Qt.red)
            palette.setColor(QPalette.Highlight, QColor(102, 178, 255))
            palette.setColor(QPalette.HighlightedText, Qt.white)
            if self._dark_style_name:
                try:
                    app.setStyle(self._dark_style_name)
                except Exception:
                    app.setStyle("Fusion")
            else:
                app.setStyle("Fusion")
            app.setPalette(palette)
        else:
            style_to_use = (
                self._light_style_name
                or self._default_style_name
                or "Fusion"
            )
            try:
                app.setStyle(style_to_use)
            except Exception:
                app.setStyle("Fusion")
            if self._light_palette is not None:
                app.setPalette(QPalette(self._light_palette))
            elif self._default_palette is not None:
                app.setPalette(QPalette(self._default_palette))
            else:
                style = app.style()
                if style is not None:
                    app.setPalette(style.standardPalette())
                else:
                    app.setPalette(QPalette())
        self._refresh_menu_palette(app)
        note = "Dark theme enabled" if self.dark_theme_enabled else "Dark theme disabled"
        self.statusBar().showMessage(note, 5000)
        logger = get_logger()
        logger.debug(note)

    def _refresh_menu_palette(self, app: QApplication) -> None:
        """Refresh menu bar colors to match current theme."""
        menu_bar = self.menuBar()
        if menu_bar is None:
            return
        menu_palette = QPalette(app.palette())
        if not self.dark_theme_enabled and self._light_palette is not None:
            reference = QPalette(self._light_palette)
        else:
            reference = QPalette(app.palette())
        bg = reference.color(QPalette.Active, QPalette.Window)
        fg = reference.color(QPalette.Active, QPalette.WindowText)
        highlight = reference.color(QPalette.Active, QPalette.Highlight)
        highlight_text = reference.color(QPalette.Active, QPalette.HighlightedText)
        for group in (QPalette.Active, QPalette.Inactive, QPalette.Disabled):
            menu_palette.setColor(group, QPalette.Window, bg)
            menu_palette.setColor(group, QPalette.Base, bg)
            menu_palette.setColor(group, QPalette.AlternateBase, bg)
            menu_palette.setColor(group, QPalette.Button, bg)
            menu_palette.setColor(group, QPalette.Text, fg)
            menu_palette.setColor(group, QPalette.WindowText, fg)
            menu_palette.setColor(group, QPalette.ButtonText, fg)
            menu_palette.setColor(group, QPalette.Highlight, highlight)
            menu_palette.setColor(group, QPalette.HighlightedText, highlight_text)
        menu_bar.setPalette(menu_palette)
        menu_bar.setAutoFillBackground(True)
        menu_bar.setStyleSheet(
            "QMenuBar {"
            f" background-color: {bg.name()};"
            f" color: {fg.name()};"
            " }"
            " QMenuBar::item {"
            " background-color: transparent;"
            " }"
            " QMenuBar::item:selected {"
            f" background-color: {highlight.name()};"
            f" color: {highlight_text.name()};"
            " }"
        )
        menu_css = (
            "QMenu {"
            f" background-color: {bg.name()};"
            f" color: {fg.name()};"
            " }"
            " QMenu::item:selected {"
            f" background-color: {highlight.name()};"
            f" color: {highlight_text.name()};"
            " }"
        )
        for action in menu_bar.actions() or []:
            menu = action.menu()
            if menu is not None:
                menu.setPalette(menu_palette)
                menu.setAutoFillBackground(True)
                menu.setStyleSheet(menu_css)
        self._menu_palette = menu_palette

    def _apply_system_theme(self, *, force: bool = False) -> None:
        """Apply theme based on system preference."""
        if self._override_system_theme and not force:
            return
        system_pref = self._system_prefers_dark()
        if system_pref is not None:
            self._system_theme_preference = system_pref
        else:
            system_pref = (
                self._system_theme_preference
                if self._system_theme_preference is not None
                else self._manual_dark_theme
            )
        self._apply_theme(bool(system_pref))
        if not self._override_system_theme:
            self._manual_dark_theme = bool(system_pref)
        self._sync_theme_menu()

    def _sync_theme_menu(self) -> None:
        """Synchronize theme menu radio button states with current theme settings."""
        dark_action = getattr(self, "_dark_theme_action", None)
        light_action = getattr(self, "_light_theme_action", None)
        system_action = getattr(self, "_system_theme_action", None)
        
        if dark_action is None or light_action is None or system_action is None:
            return
        
        # Block signals while updating to prevent recursive calls
        for action in (dark_action, light_action, system_action):
            action.blockSignals(True)
        
        if not self._override_system_theme:
            # Following system
            system_action.setChecked(True)
        elif self._manual_dark_theme:
            # Manual dark theme
            dark_action.setChecked(True)
        else:
            # Manual light theme
            light_action.setChecked(True)
        
        for action in (dark_action, light_action, system_action):
            action.blockSignals(False)

    def _set_theme_mode(self, mode: str) -> None:
        """Set theme mode explicitly.
        
        Args:
            mode: One of 'dark', 'light', or 'system'
        """
        if mode == "system":
            self._override_system_theme = False
            self._apply_system_theme(force=True)
        elif mode == "dark":
            self._override_system_theme = True
            self._manual_dark_theme = True
            self._apply_theme(True)
        elif mode == "light":
            self._override_system_theme = True
            self._manual_dark_theme = False
            self._apply_theme(False)
        self._sync_theme_menu()

    # Legacy methods kept for backwards compatibility
    def _sync_theme_actions(self) -> None:
        """Synchronize theme action states (legacy, calls _sync_theme_menu)."""
        self._sync_theme_menu()

    def _update_theme_toggle_label(self) -> None:
        """Update theme toggle action text (legacy, no-op with new menu)."""
        pass

    def _toggle_theme_override(self, enabled: bool) -> None:
        """Handle theme override toggle action (legacy)."""
        if enabled:
            self._set_theme_mode("dark" if not self.dark_theme_enabled else "light")
        else:
            self._set_theme_mode("system")
