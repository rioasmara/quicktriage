"""
File view widget for displaying file system information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel
)
from PySide6.QtCore import Qt, QTimer


class FileView(QWidget):
    """Widget for displaying file system information."""
    
    def __init__(self):
        super().__init__()
        self.file_data = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        
        # Control bar
        control_layout = QHBoxLayout()
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(4)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search files...")
        self.search_box.textChanged.connect(self.filter_files)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_data)
        
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)
        control_layout.addStretch()
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Path", "Name", "Size (bytes)", "Modified", "Created", "SHA256"
        ])
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        # Performance optimizations
        self.table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)  # Smoother scrolling
        self.table.resizeColumnsToContents()
        
        layout.addWidget(self.table)
    
    def update_data(self, data):
        """Update the view with new file data."""
        if not data or 'files' not in data:
            return
        
        self.file_data = data['files']
        # Defer heavy work to make UI responsive
        QTimer.singleShot(0, lambda: self.populate_table(self.file_data))
    
    def populate_table(self, files):
        """Populate the table with file data."""
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        
        try:
            self.table.setRowCount(len(files))
            
            for row, file_info in enumerate(files):
                path_item = QTableWidgetItem(file_info['path'])
                if len(file_info['path']) > 100:
                    path_item.setToolTip(file_info['path'])
                self.table.setItem(row, 0, path_item)
                
                self.table.setItem(row, 1, QTableWidgetItem(file_info['name']))
                self.table.setItem(row, 2, QTableWidgetItem(str(file_info['size'])))
                self.table.setItem(row, 3, QTableWidgetItem(file_info['modified']))
                self.table.setItem(row, 4, QTableWidgetItem(file_info['created']))
                
                # SHA256 hash column
                sha256 = file_info.get('sha256', 'N/A')
                sha256_item = QTableWidgetItem(sha256)
                if len(sha256) > 64:
                    sha256_item.setToolTip(sha256)
                self.table.setItem(row, 5, sha256_item)
            
            # Resize columns only once after all rows are populated
            self.table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            self.table.setUpdatesEnabled(True)
            self.table.setSortingEnabled(was_sorting)
    
    def filter_files(self, text):
        """Filter files based on search text."""
        if not self.file_data:
            return
        
        filtered = [
            f for f in self.file_data
            if text.lower() in f['name'].lower() or
            text.lower() in f['path'].lower() or
            text.lower() in f.get('sha256', '').lower()
        ]
        
        self.populate_table(filtered)
    
    def export_data(self):
        """Export file data to a file."""
        if not self.file_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export File Data", "files.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.file_data, f, indent=2)

