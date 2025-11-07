#!/usr/bin/env python3
"""
Host Triage Analysis Tool
A Python-based application using Qt framework for conducting triage analysis on a Windows host.
"""

import sys
import platform
from PySide6.QtWidgets import QApplication, QMessageBox
from main_window import MainWindow


def main():
    """Main entry point for the application."""
    # Check if running on Windows
    if platform.system() != 'Windows':
        print("Error: This tool is designed exclusively for Windows operating system.")
        print(f"Detected OS: {platform.system()}")
        # Try to show a message box if possible, otherwise just exit
        try:
            app = QApplication(sys.argv)
            QMessageBox.critical(
                None,
                "Unsupported Operating System",
                f"This tool is designed exclusively for Windows.\n\n"
                f"Detected OS: {platform.system()}\n"
                f"Please run this tool on a Windows system."
            )
        except:
            pass
        sys.exit(1)
    
    app = QApplication(sys.argv)
    app.setApplicationName("Host Triage Analysis")
    app.setOrganizationName("Security Tools")
    
    # Apply "Flight Deck" themed stylesheet inspired by modern aircraft cockpits
    app.setStyleSheet("""
        /* Global Styles - Flight Deck Theme */
        QMainWindow {
            background-color: #080d14;
        }

        QWidget {
            background-color: #0f1824;
            color: #cfe9ff;
            font-family: 'Segoe UI', 'Roboto', 'DIN Alternate', sans-serif;
            font-size: 10pt;
        }

        /* Accent separators mimic illuminated panel edges */
        QFrame[frameShape="HLine"],
        QFrame[frameShape="VLine"] {
            border: none;
            background-color: #132235;
        }

        /* Buttons */
        QPushButton {
            background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #1b2839, stop:1 #101926);
            color: #d0f4ff;
            border: 1px solid #1e88a8;
            border-radius: 4px;
            padding: 6px 14px;
            font-weight: 600;
            min-height: 28px;
        }

        QPushButton:hover {
            background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #24374d, stop:1 #132235);
            border: 1px solid #29b6d3;
            color: #f4ffff;
        }

        QPushButton:pressed {
            background-color: #152334;
            border: 1px solid #0daedb;
            color: #e0faff;
        }

        QPushButton:disabled {
            background-color: #1a222d;
            color: #56697a;
            border: 1px solid #263340;
        }

        /* Primary action buttons */
        QPushButton[role="primary"] {
            background-color: #1c3a4f;
            border: 1px solid #0daedb;
            color: #e3fcff;
        }

        QPushButton[role="caution"] {
            background-color: #472c17;
            border: 1px solid #f6a623;
            color: #ffd27b;
        }

        QPushButton[role="caution"]:hover {
            background-color: #5d3413;
            border: 1px solid #ffc862;
            color: #ffefc4;
        }

        /* Tabs */
        QTabWidget::pane {
            border: 1px solid #1e2d40;
            border-radius: 6px;
            background-color: #101a27;
            top: -2px;
            padding: 6px;
        }

        QTabBar::tab {
            background-color: #142030;
            color: #9ed5ff;
            border: 1px solid transparent;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            padding: 6px 18px;
            margin-right: 2px;
            font-weight: 600;
        }

        QTabBar::tab:selected {
            background-color: #1b2d43;
            color: #e5f8ff;
            border: 1px solid #29b6d3;
            border-bottom-color: #1b2d43;
        }

        QTabBar::tab:hover:!selected {
            background-color: #162435;
            color: #c2eafd;
        }

        /* Tables */
        QTableWidget {
            background-color: #101b27;
            border: 1px solid #1f2f42;
            border-radius: 6px;
            gridline-color: #1f3246;
            selection-background-color: #21405a;
            selection-color: #e9faff;
            alternate-background-color: #0d1520;
        }

        QTableWidget::item {
            padding: 4px 8px;
            border-bottom: 1px solid #182636;
            color: #b6ddff;
        }

        QTableWidget::item:selected {
            background-color: #21405a;
            color: #ffffff;
        }

        QHeaderView::section {
            background-color: #1b2e42;
            color: #a6d4f7;
            padding: 6px 10px;
            border: none;
            border-right: 1px solid #253a52;
            font-weight: 700;
        }

        QHeaderView::section:first {
            border-top-left-radius: 6px;
        }

        QHeaderView::section:last {
            border-top-right-radius: 6px;
            border-right: none;
        }

        /* Tree Widget */
        QTreeWidget {
            background-color: #101b27;
            border: 1px solid #1f2f42;
            border-radius: 6px;
            selection-background-color: #21405a;
            selection-color: #e9faff;
            alternate-background-color: #0d1520;
            padding: 2px;
        }

        QTreeWidget::item {
            padding: 4px 8px;
            border-bottom: 1px solid #182636;
            color: #b6ddff;
        }

        QTreeWidget::item:hover {
            background-color: #17273a;
        }

        /* Input Fields */
        QLineEdit,
        QTextEdit,
        QPlainTextEdit,
        QSpinBox,
        QComboBox {
            background-color: #0b141f;
            border: 1px solid #1e2f42;
            border-radius: 4px;
            padding: 6px 8px;
            selection-background-color: #1e536d;
            selection-color: #e6fbff;
            color: #e0f6ff;
        }

        QLineEdit:focus,
        QTextEdit:focus,
        QPlainTextEdit:focus,
        QSpinBox:focus,
        QComboBox:focus {
            border: 1px solid #29b6d3;
            background-color: #111d2b;
        }

        QComboBox QAbstractItemView {
            background-color: #111c29;
            border: 1px solid #29b6d3;
            selection-background-color: #21405a;
            selection-color: #ffffff;
        }

        /* Progress Bar */
        QProgressBar {
            border: 1px solid #1e2f42;
            border-radius: 4px;
            text-align: center;
            background-color: #0b141f;
            color: #bce7f6;
            font-weight: 600;
            min-height: 20px;
        }

        QProgressBar::chunk {
            background-color: #29b6d3;
            border-radius: 4px;
        }

        /* Status Bar */
        QStatusBar {
            background-color: #101a27;
            color: #8fbad6;
            border-top: 1px solid #1e2d40;
            padding: 4px 8px;
            font-size: 9pt;
        }

        QStatusBar::item {
            border: none;
        }

        /* Group Box */
        QGroupBox {
            border: 1px solid #1e2f42;
            border-radius: 6px;
            margin-top: 10px;
            padding: 8px 12px 12px 12px;
            font-weight: 700;
            color: #9fd1f5;
            background-color: #121f2d;
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            padding: 0 8px;
            background-color: transparent;
            color: #29b6d3;
        }

        /* Labels */
        QLabel[role="heading"] {
            color: #29b6d3;
            font-size: 11pt;
            font-weight: 700;
        }

        QLabel {
            color: #cfe9ff;
        }

        QLabel[role="warning"] {
            color: #f6a623;
        }

        QLabel[role="caution"] {
            color: #ff6f00;
        }

        /* Radio Buttons & Checkboxes */
        QRadioButton,
        QCheckBox {
            color: #cfe9ff;
            spacing: 8px;
        }

        QRadioButton::indicator,
        QCheckBox::indicator {
            width: 16px;
            height: 16px;
            border-radius: 3px;
            border: 1px solid #29b6d3;
            background-color: #0b141f;
        }

        QRadioButton::indicator:hover,
        QCheckBox::indicator:hover {
            border: 1px solid #55c7df;
        }

        QRadioButton::indicator:checked,
        QCheckBox::indicator:checked {
            background-color: qradialgradient(cx:0.5, cy:0.5, radius:0.6,
                              fx:0.5, fy:0.5,
                              stop:0 #7be9ff,
                              stop:1 #29b6d3);
        }

        /* Scroll Bars */
        QScrollBar:vertical {
            border: none;
            background-color: #111c29;
            width: 14px;
            margin: 0;
        }

        QScrollBar::handle:vertical {
            background-color: #1f364d;
            border-radius: 6px;
            min-height: 24px;
            margin: 2px;
        }

        QScrollBar::handle:vertical:hover {
            background-color: #29b6d3;
        }

        QScrollBar:horizontal {
            border: none;
            background-color: #111c29;
            height: 14px;
            margin: 0;
        }

        QScrollBar::handle:horizontal {
            background-color: #1f364d;
            border-radius: 6px;
            min-width: 24px;
            margin: 2px;
        }

        QScrollBar::handle:horizontal:hover {
            background-color: #29b6d3;
        }

        /* Splitter */
        QSplitter::handle {
            background-color: #142235;
        }

        QSplitter::handle:horizontal {
            width: 4px;
        }

        QSplitter::handle:vertical {
            height: 4px;
        }

        /* Tooltips */
        QToolTip {
            background-color: #1c2c3f;
            color: #e5f4ff;
            border: 1px solid #29b6d3;
            padding: 6px;
            font-size: 9pt;
        }

        /* Dialog Buttons */
        QDialogButtonBox QPushButton {
            min-width: 96px;
        }

        /* Message Box */
        QMessageBox {
            background-color: #101a27;
            color: #cfe9ff;
        }

        QMessageBox QPushButton {
            min-width: 96px;
        }
    """)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

