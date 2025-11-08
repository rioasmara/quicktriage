"""
System view widget for displaying system information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLabel, QGroupBox, QGridLayout, QTextEdit,
    QScrollArea, QFrame
)
from PySide6.QtCore import Qt, QTimer


class SystemView(QWidget):
    """Widget for displaying system information."""
    
    def __init__(self):
        super().__init__()
        self.system_data = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(4)
        
        # Export button (outside scroll area)
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(4)
        button_layout.addStretch()
        self.export_btn = QPushButton("Export All Data")
        self.export_btn.clicked.connect(self.export_data)
        button_layout.addWidget(self.export_btn)
        main_layout.addLayout(button_layout)
        
        # Create scroll area for scrollable content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        
        # Create scrollable widget
        scrollable_widget = QWidget()
        layout = QVBoxLayout(scrollable_widget)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        
        # System Information
        system_group = QGroupBox("System Information")
        system_layout = QGridLayout()
        self.system_labels = {}
        system_group.setLayout(system_layout)
        layout.addWidget(system_group)
        
        # CPU Information
        cpu_group = QGroupBox("CPU Information")
        cpu_layout = QGridLayout()
        self.cpu_labels = {}
        cpu_group.setLayout(cpu_layout)
        layout.addWidget(cpu_group)
        
        # Memory Information
        memory_group = QGroupBox("Memory Information")
        memory_layout = QGridLayout()
        self.memory_labels = {}
        memory_group.setLayout(memory_layout)
        layout.addWidget(memory_group)
        
        # Disk Information
        disk_group = QGroupBox("Disk Information")
        self.disk_table = QTableWidget()
        self.disk_table.setColumnCount(6)
        self.disk_table.setHorizontalHeaderLabels([
            "Device", "Mountpoint", "File System", "Total (GB)",
            "Used (GB)", "Free (GB)"
        ])
        self.disk_table.setSortingEnabled(True)
        self.disk_table.setAlternatingRowColors(True)
        disk_layout = QVBoxLayout()
        disk_layout.addWidget(self.disk_table)
        disk_group.setLayout(disk_layout)
        layout.addWidget(disk_group)
        
        # Add stretch at the end to push content to top
        layout.addStretch()
        
        # Set the scrollable widget as the scroll area's widget
        scroll_area.setWidget(scrollable_widget)
        
        # Add scroll area to main layout
        main_layout.addWidget(scroll_area)
        
        # Store layouts for later use
        self.system_layout = system_layout
        self.cpu_layout = cpu_layout
        self.memory_layout = memory_layout
    
    def update_data(self, data):
        """Update the view with new system data."""
        if not data:
            return
        
        self.system_data = data
        
        # Defer heavy work to make UI responsive
        def update_all():
            # Update system information
            if 'system' in data:
                self._update_system_info(data['system'])
            
            # Update CPU information
            if 'cpu' in data:
                self._update_cpu_info(data['cpu'])
            
            # Update memory information
            if 'memory' in data:
                self._update_memory_info(data['memory'])
            
            # Update disk information
            if 'disk' in data:
                self._update_disk_info(data['disk'])
        
        QTimer.singleShot(0, update_all)
    
    def _update_system_info(self, system_info):
        """Update system information labels."""
        self._clear_layout(self.system_layout)
        
        row = 0
        for key, value in system_info.items():
            label = QLabel(f"<b>{key.replace('_', ' ').title()}:</b> {value}")
            self.system_layout.addWidget(label, row, 0)
            row += 1
    
    def _update_cpu_info(self, cpu_info):
        """Update CPU information labels."""
        self._clear_layout(self.cpu_layout)
        
        row = 0
        for key, value in cpu_info.items():
            if key == 'cpu_per_core':
                continue
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    label = QLabel(f"<b>{sub_key.replace('_', ' ').title()}:</b> {sub_value}")
                    self.cpu_layout.addWidget(label, row, 0)
                    row += 1
            else:
                label = QLabel(f"<b>{key.replace('_', ' ').title()}:</b> {value}")
                self.cpu_layout.addWidget(label, row, 0)
                row += 1
    
    def _update_memory_info(self, memory_info):
        """Update memory information labels."""
        self._clear_layout(self.memory_layout)
        
        row = 0
        for key, value in memory_info.items():
            if isinstance(value, float):
                value = f"{value:.2f}"
            label = QLabel(f"<b>{key.replace('_', ' ').title()}:</b> {value}")
            self.memory_layout.addWidget(label, row, 0)
            row += 1
    
    def _update_disk_info(self, disk_info):
        """Update disk information table."""
        self.disk_table.setRowCount(len(disk_info))
        
        for row, disk in enumerate(disk_info):
            self.disk_table.setItem(row, 0, QTableWidgetItem(disk['device']))
            self.disk_table.setItem(row, 1, QTableWidgetItem(disk['mountpoint']))
            self.disk_table.setItem(row, 2, QTableWidgetItem(disk['fstype']))
            self.disk_table.setItem(row, 3, QTableWidgetItem(f"{disk['total_gb']:.2f}"))
            self.disk_table.setItem(row, 4, QTableWidgetItem(f"{disk['used_gb']:.2f}"))
            self.disk_table.setItem(row, 5, QTableWidgetItem(f"{disk['free_gb']:.2f}"))
        
        self.disk_table.resizeColumnsToContents()
    
    def _clear_layout(self, layout):
        """Clear all widgets from a layout."""
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
    
    def export_data(self):
        """Export system data to a file."""
        if not self.system_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export System Data", "system.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.system_data, f, indent=2)





