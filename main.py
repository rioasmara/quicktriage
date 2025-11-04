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
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

