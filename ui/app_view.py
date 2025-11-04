"""
Application view widget for displaying installed application information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel
)
from PySide6.QtCore import Qt


class AppView(QWidget):
    """Widget for displaying installed application information."""
    
    def __init__(self):
        super().__init__()
        self.app_data = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Control bar
        control_layout = QHBoxLayout()
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search applications...")
        self.search_box.textChanged.connect(self.filter_apps)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_data)
        
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)
        control_layout.addStretch()
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Name", "Version", "Publisher", "Install Date",
            "Install Location", "Size (MB)", "Uninstall String", "Registry Key"
        ])
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.resizeColumnsToContents()
        
        layout.addWidget(self.table)
    
    def update_data(self, data):
        """Update the view with new application data."""
        if not data:
            self.app_data = []
            self.populate_table([])
            return
        
        apps_list = data.get('applications', []) or []
        self.app_data = apps_list
        self.populate_table(apps_list)
    
    def populate_table(self, apps):
        """Populate the table with application data."""
        self.table.setRowCount(len(apps))
        
        for row, app in enumerate(apps):
            try:
                # Safely convert all values to strings
                name = str(app.get('name', 'N/A'))
                version = str(app.get('version', 'N/A'))
                publisher = str(app.get('publisher', 'N/A'))
                install_date = str(app.get('install_date', 'N/A'))
                install_location = str(app.get('install_location', 'N/A'))
                size_mb = str(app.get('size_mb', 'N/A'))
                uninstall_string = str(app.get('uninstall_string', 'N/A'))
                registry_key = str(app.get('registry_key', 'N/A'))
                
                self.table.setItem(row, 0, QTableWidgetItem(name))
                self.table.setItem(row, 1, QTableWidgetItem(version))
                self.table.setItem(row, 2, QTableWidgetItem(publisher))
                self.table.setItem(row, 3, QTableWidgetItem(install_date))
                
                location_item = QTableWidgetItem(install_location)
                if len(install_location) > 50:
                    location_item.setToolTip(install_location)
                self.table.setItem(row, 4, location_item)
                
                self.table.setItem(row, 5, QTableWidgetItem(str(size_mb)))
                
                uninstall_item = QTableWidgetItem(uninstall_string)
                if len(uninstall_string) > 50:
                    uninstall_item.setToolTip(uninstall_string)
                self.table.setItem(row, 6, uninstall_item)
                
                self.table.setItem(row, 7, QTableWidgetItem(registry_key))
                
            except Exception as e:
                # Still add the row with error info
                self.table.setItem(row, 0, QTableWidgetItem(app.get('name', f'App {row}')))
                self.table.setItem(row, 1, QTableWidgetItem('Error'))
                self.table.setItem(row, 2, QTableWidgetItem('N/A'))
                self.table.setItem(row, 3, QTableWidgetItem('N/A'))
                self.table.setItem(row, 4, QTableWidgetItem('N/A'))
                self.table.setItem(row, 5, QTableWidgetItem('N/A'))
                self.table.setItem(row, 6, QTableWidgetItem('N/A'))
                self.table.setItem(row, 7, QTableWidgetItem(f'Error: {str(e)}'))
        
        self.table.resizeColumnsToContents()
    
    def filter_apps(self, text):
        """Filter applications based on search text."""
        if not self.app_data:
            return
        
        if not text:
            self.populate_table(self.app_data)
            return
        
        # Filter by text
        filtered = []
        search_lower = text.lower()
        for app in self.app_data:
            if (search_lower in app.get('name', '').lower() or
                search_lower in app.get('publisher', '').lower() or
                search_lower in app.get('version', '').lower()):
                filtered.append(app)
        
        self.populate_table(filtered)
    
    def export_data(self):
        """Export application data to a file."""
        if not self.app_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Application Data", "applications.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.app_data, f, indent=2)



