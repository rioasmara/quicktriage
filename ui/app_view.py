"""
Application view widget for displaying installed application information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QSplitter,
    QMenu, QDialog, QDialogButtonBox, QMessageBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
import os
import subprocess


class AppView(QWidget):
    """Widget for displaying installed application information."""
    
    def __init__(self):
        super().__init__()
        self.app_data = None
        self.binary_data = None
        self.filtered_binary_data = None  # Store filtered data for context menu
        # Batching for incremental binary updates
        self.binary_incremental_batch = []  # Queue for batched incremental updates
        self.batch_size = 150  # Number of records to batch before adding to grid
        self.binary_batch_timer = QTimer(self)
        self.binary_batch_timer.setSingleShot(True)
        self.binary_batch_timer.timeout.connect(self._flush_binary_incremental_batch)
        self.notification_callback = None  # Callback for notifications
        # Store process and persistence data for correlation
        self.process_data = None
        self.persistence_data = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        
        # Splitter to separate applications and binaries sections
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Applications section
        apps_widget = QWidget()
        apps_layout = QVBoxLayout(apps_widget)
        apps_layout.setContentsMargins(2, 2, 2, 2)
        apps_layout.setSpacing(4)
        
        # Applications control bar
        apps_control_layout = QHBoxLayout()
        apps_control_layout.setContentsMargins(0, 0, 0, 0)
        apps_control_layout.setSpacing(4)
        
        apps_label = QLabel("Installed Applications:")
        apps_label.setStyleSheet("font-weight: 600; font-size: 10pt; color: rgb(0, 255, 0);")
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search applications...")
        self.search_box.textChanged.connect(self.filter_apps)
        
        apps_control_layout.addWidget(apps_label)
        apps_control_layout.addStretch()
        apps_control_layout.addWidget(QLabel("Search:"))
        apps_control_layout.addWidget(self.search_box)
        
        apps_layout.addLayout(apps_control_layout)
        
        # Applications table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Name", "Version", "Publisher", "Install Date",
            "Install Location", "Size (MB)", "Uninstall String", "Registry Key"
        ])
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        # Performance optimizations
        self.table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)  # Smoother scrolling
        self.table.resizeColumnsToContents()
        
        # Set row height for better readability when editing
        self.table.verticalHeader().setDefaultSectionSize(52)
        
        apps_layout.addWidget(self.table)
        
        # Binaries section
        binaries_widget = QWidget()
        binaries_layout = QVBoxLayout(binaries_widget)
        binaries_layout.setContentsMargins(2, 2, 2, 2)
        binaries_layout.setSpacing(4)
        
        # Binaries control bar
        binaries_control_layout = QHBoxLayout()
        binaries_control_layout.setContentsMargins(0, 0, 0, 0)
        binaries_control_layout.setSpacing(4)
        
        binaries_label = QLabel("Discovered Binaries (All Users' Directories):")
        binaries_label.setStyleSheet("font-weight: 600; font-size: 10pt; color: rgb(0, 255, 0);")
        
        self.binary_search_box = QLineEdit()
        self.binary_search_box.setPlaceholderText("Search binaries...")
        self.binary_search_box.textChanged.connect(self.filter_binaries)
        
        self.export_btn = QPushButton("Export All")
        self.export_btn.clicked.connect(self.export_data)
        
        binaries_control_layout.addWidget(binaries_label)
        binaries_control_layout.addStretch()
        binaries_control_layout.addWidget(QLabel("Search:"))
        binaries_control_layout.addWidget(self.binary_search_box)
        binaries_control_layout.addWidget(self.export_btn)
        
        binaries_layout.addLayout(binaries_control_layout)
        
        # Binaries table
        self.binary_table = QTableWidget()
        self.binary_table.setColumnCount(8)
        self.binary_table.setHorizontalHeaderLabels([
            "Name", "Path", "Extension", "Size (MB)", "Modified", "Created", "User Directory", "SHA256"
        ])
        self.binary_table.setSortingEnabled(True)
        self.binary_table.setAlternatingRowColors(True)
        self.binary_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.binary_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.binary_table.customContextMenuRequested.connect(self.show_binary_context_menu)
        # Performance optimizations
        self.binary_table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)  # Smoother scrolling
        self.binary_table.resizeColumnsToContents()
        
        # Set row height for better readability when editing
        self.binary_table.verticalHeader().setDefaultSectionSize(52)
        
        binaries_layout.addWidget(self.binary_table)
        
        # Add widgets to splitter
        splitter.addWidget(apps_widget)
        splitter.addWidget(binaries_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter)
    
    def clear_binary_data(self):
        """Clear binary table before starting new collection."""
        self.binary_data = []
        self.filtered_binary_data = []
        self.binary_incremental_batch.clear()
        self.binary_batch_timer.stop()
        self.binary_table.setRowCount(0)
    
    def add_binary_incremental(self, binary_info):
        """Add a single binary entry incrementally to the table (batched)."""
        # Add to batch queue
        self.binary_incremental_batch.append(binary_info)
        
        # Only flush when batch reaches 50 records
        if len(self.binary_incremental_batch) >= self.batch_size:
            self._flush_binary_incremental_batch()
    
    def _flush_binary_incremental_batch(self):
        """Flush the batched incremental binary updates to the table."""
        if not self.binary_incremental_batch:
            return
        
        # Get all items in batch
        batch = self.binary_incremental_batch[:]
        self.binary_incremental_batch.clear()
        
        # Initialize data lists if needed
        if not self.binary_data:
            self.binary_data = []
        if not self.filtered_binary_data:
            self.filtered_binary_data = []
        
        # Add to data lists
        for binary_info in batch:
            self.binary_data.append(binary_info)
            self.filtered_binary_data.append(binary_info)
        
        # Disable sorting and updates for better performance
        was_sorting = self.binary_table.isSortingEnabled()
        self.binary_table.setSortingEnabled(False)
        self.binary_table.setUpdatesEnabled(False)
        
        try:
            # Get current row count
            current_row_count = self.binary_table.rowCount()
            
            # Add all rows at once by setting the new row count
            new_row_count = current_row_count + len(batch)
            self.binary_table.setRowCount(new_row_count)
            
            # Populate all rows at once
            for i, binary_info in enumerate(batch):
                row = current_row_count + i
                
                try:
                    # Safely convert all values to strings
                    name = str(binary_info.get('name', 'N/A'))
                    path = str(binary_info.get('path', 'N/A'))
                    extension = str(binary_info.get('extension', 'N/A'))
                    size_mb = str(binary_info.get('size_mb', 'N/A'))
                    modified = str(binary_info.get('modified', 'N/A'))
                    created = str(binary_info.get('created', 'N/A'))
                    user_dir = str(binary_info.get('user_directory', 'N/A'))
                    sha256 = str(binary_info.get('sha256', 'N/A'))
                    
                    self.binary_table.setItem(row, 0, QTableWidgetItem(name))
                    
                    path_item = QTableWidgetItem(path)
                    if len(path) > 50:
                        path_item.setToolTip(path)
                    self.binary_table.setItem(row, 1, path_item)
                    
                    self.binary_table.setItem(row, 2, QTableWidgetItem(extension))
                    self.binary_table.setItem(row, 3, QTableWidgetItem(str(size_mb)))
                    self.binary_table.setItem(row, 4, QTableWidgetItem(modified))
                    self.binary_table.setItem(row, 5, QTableWidgetItem(created))
                    self.binary_table.setItem(row, 6, QTableWidgetItem(user_dir))
                    
                    sha256_item = QTableWidgetItem(sha256)
                    if len(sha256) > 50:
                        sha256_item.setToolTip(sha256)
                    self.binary_table.setItem(row, 7, sha256_item)
                    
                    # Handle exports column
                    exports = binary_info.get('exports', [])
                    export_count = len(exports)
                    if export_count > 0:
                        # Show count and first few exports
                        if export_count <= 3:
                            exports_text = f"{export_count}: {', '.join(exports)}"
                        else:
                            exports_text = f"{export_count}: {', '.join(exports[:3])}..."
                        exports_item = QTableWidgetItem(exports_text)
                        # Set tooltip with all exports
                        all_exports = ', '.join(exports)
                        exports_item.setToolTip(all_exports)
                        self.binary_table.setItem(row, 8, exports_item)
                    else:
                        self.binary_table.setItem(row, 8, QTableWidgetItem('N/A'))
                except Exception as e:
                    # Still add the row with error info
                    self.binary_table.setItem(row, 0, QTableWidgetItem(binary_info.get('name', f'Binary {row}')))
                    self.binary_table.setItem(row, 1, QTableWidgetItem('Error'))
                    self.binary_table.setItem(row, 2, QTableWidgetItem('N/A'))
                    self.binary_table.setItem(row, 3, QTableWidgetItem('N/A'))
                    self.binary_table.setItem(row, 4, QTableWidgetItem('N/A'))
                    self.binary_table.setItem(row, 5, QTableWidgetItem('N/A'))
                    self.binary_table.setItem(row, 6, QTableWidgetItem('N/A'))
                    self.binary_table.setItem(row, 7, QTableWidgetItem(f'Error: {str(e)}'))
                    self.binary_table.setItem(row, 8, QTableWidgetItem('N/A'))
        finally:
            # Re-enable updates and sorting
            self.binary_table.setUpdatesEnabled(True)
            self.binary_table.setSortingEnabled(was_sorting)
        
        # Show notification only for batches of 50 (or final batch)
        total = len(self.binary_data)
        if self.notification_callback and len(batch) > 0:
            # Only show notification for batches of 150 (or final batch)
            if len(batch) >= 150 or len(self.binary_incremental_batch) == 0:
                self.notification_callback(f"Binary table updated: +{len(batch)} records (Total: {total})")
    
    def update_data(self, data):
        """Update the view with new application data."""
        if not data:
            self.app_data = []
            QTimer.singleShot(0, lambda: self.populate_table([]))
            return
        
        apps_list = data.get('applications', []) or []
        self.app_data = apps_list
        # Defer heavy work to make UI responsive
        QTimer.singleShot(0, lambda: self.populate_table(apps_list))
    
    def update_process_data(self, process_data):
        """Update process data for correlation with applications."""
        self.process_data = process_data
        # Refresh the table if app data is already loaded
        if self.app_data:
            QTimer.singleShot(0, lambda: self.populate_table(self.app_data))
    
    def update_persistence_data(self, persistence_data):
        """Update persistence data for correlation with applications."""
        self.persistence_data = persistence_data
        # Refresh the table if app data is already loaded
        if self.app_data:
            QTimer.singleShot(0, lambda: self.populate_table(self.app_data))
    
    def update_binary_data(self, data):
        """Update the view with new binary data."""
        if not data:
            self.binary_data = []
            self.filtered_binary_data = []
            QTimer.singleShot(0, lambda: self.populate_binary_table([]))
            return
        
        binaries_list = data.get('binaries', []) or []
        self.binary_data = binaries_list
        self.filtered_binary_data = binaries_list  # Initialize filtered data
        # Defer heavy work to make UI responsive
        QTimer.singleShot(0, lambda: self.populate_binary_table(binaries_list))
    
    def _is_app_running(self, app):
        """Check if an application is currently running based on process data."""
        if not self.process_data or 'processes' not in self.process_data:
            return False
        
        processes = self.process_data.get('processes', [])
        if not processes:
            return False
        
        # Get application paths to match against
        install_location = app.get('install_location', '').strip()
        uninstall_string = app.get('uninstall_string', '').strip()
        app_name = app.get('name', '').strip()
        
        # Extract executable paths and names
        exe_paths = []
        exe_names = []
        app_name_variations = []
        
        # Add application name variations
        if app_name and app_name != 'N/A':
            app_name_lower = app_name.lower()
            app_name_variations.append(app_name_lower)
            # Remove common suffixes and add .exe
            if not app_name_lower.endswith('.exe'):
                app_name_variations.append(app_name_lower + '.exe')
            # Also try without spaces and special chars
            app_name_clean = app_name_lower.replace(' ', '').replace('-', '').replace('_', '')
            if app_name_clean:
                app_name_variations.append(app_name_clean)
                if not app_name_clean.endswith('.exe'):
                    app_name_variations.append(app_name_clean + '.exe')
        
        if install_location and install_location != 'N/A':
            # Normalize path
            install_location = os.path.normpath(install_location)
            exe_paths.append(install_location.lower())
            # Extract executable name from install location if it's a file
            if os.path.isfile(install_location):
                exe_names.append(os.path.basename(install_location).lower())
            # Also check subdirectories
            if os.path.isdir(install_location):
                exe_paths.append(install_location.lower())
        
        if uninstall_string and uninstall_string != 'N/A':
            # Uninstall string often contains the executable path
            # Try to extract it (format: "path\to\uninstaller.exe" /S or similar)
            parts = uninstall_string.split()
            if parts:
                potential_path = parts[0].strip('"')
                if potential_path:
                    # Check if it's a valid path
                    if os.path.exists(potential_path) or os.path.isabs(potential_path):
                        exe_dir = os.path.dirname(os.path.normpath(potential_path))
                        exe_paths.append(exe_dir.lower())
                        exe_name = os.path.basename(potential_path).lower()
                        if exe_name:
                            exe_names.append(exe_name)
        
        # Check if any process matches
        for process in processes:
            # Check if status is running first
            status = process.get('status', '').lower()
            if status != 'running':
                continue
            
            # Get process name and executable path
            process_name = process.get('name', '').strip().lower()
            exe = process.get('exe', '').strip()
            
            # Check by process name first (most direct match)
            if process_name:
                # Direct match with application name variations
                for app_name_var in app_name_variations:
                    if app_name_var == process_name or process_name == app_name_var:
                        return True
                    # Also check if one contains the other (for partial matches)
                    if app_name_var in process_name or process_name in app_name_var:
                        return True
                
                # Check with executable names extracted from app data
                for app_exe_name in exe_names:
                    if app_exe_name == process_name or process_name == app_exe_name:
                        return True
                    if app_exe_name in process_name or process_name in app_exe_name:
                        return True
            
            # Check by executable path
            if exe and exe != 'N/A':
                exe_normalized = os.path.normpath(exe).lower()
                exe_dir = os.path.dirname(exe_normalized)
                exe_name = os.path.basename(exe_normalized)
                
                # Check by executable name
                for app_exe_name in exe_names:
                    if app_exe_name == exe_name or exe_name == app_exe_name:
                        return True
                    if app_exe_name in exe_name or exe_name in app_exe_name:
                        return True
                
                # Check by path - if process executable is in the application's install location
                for app_path in exe_paths:
                    if app_path and (exe_dir.startswith(app_path) or app_path in exe_dir):
                        return True
        
        return False
    
    def _is_app_in_persistence(self, app):
        """Check if an application is involved in any type of persistence."""
        if not self.persistence_data or 'mechanisms' not in self.persistence_data:
            return False
        
        mechanisms = self.persistence_data.get('mechanisms', {})
        if not mechanisms:
            return False
        
        # Get application paths to match against
        install_location = app.get('install_location', '').strip()
        uninstall_string = app.get('uninstall_string', '').strip()
        app_name = app.get('name', '').strip()
        
        # Extract executable paths and names
        exe_paths = []
        exe_names = []
        app_name_variations = []
        
        # Add application name variations
        if app_name and app_name != 'N/A':
            app_name_lower = app_name.lower()
            app_name_variations.append(app_name_lower)
            exe_names.append(app_name_lower)
            # Remove common suffixes and add .exe
            if not app_name_lower.endswith('.exe'):
                app_name_variations.append(app_name_lower + '.exe')
                exe_names.append(app_name_lower + '.exe')
            # Also try without spaces and special chars
            app_name_clean = app_name_lower.replace(' ', '').replace('-', '').replace('_', '')
            if app_name_clean:
                app_name_variations.append(app_name_clean)
                exe_names.append(app_name_clean)
                if not app_name_clean.endswith('.exe'):
                    app_name_variations.append(app_name_clean + '.exe')
                    exe_names.append(app_name_clean + '.exe')
        
        if install_location and install_location != 'N/A':
            install_location_norm = os.path.normpath(install_location).lower()
            exe_paths.append(install_location_norm)
            # Extract executable name from install location if it's a file
            if os.path.isfile(install_location):
                exe_names.append(os.path.basename(install_location_norm))
            # Also check parent directory
            if os.path.isdir(install_location):
                exe_paths.append(install_location_norm)
        
        if uninstall_string and uninstall_string != 'N/A':
            # Extract path from uninstall string
            parts = uninstall_string.split()
            if parts:
                potential_path = parts[0].strip('"')
                if potential_path:
                    # Check if it's a valid path
                    if os.path.exists(potential_path) or os.path.isabs(potential_path):
                        exe_dir = os.path.dirname(os.path.normpath(potential_path)).lower()
                        exe_paths.append(exe_dir)
                        exe_name = os.path.basename(potential_path).lower()
                        if exe_name:
                            exe_names.append(exe_name)
        
        # Check all persistence mechanisms
        for mechanism_type, mechanism_data in mechanisms.items():
            if not mechanism_data:
                continue
            
            # Handle different mechanism structures
            if mechanism_type in ['registry_run_keys', 'registry_logon_keys', 
                                 'registry_policies', 'registry_image_hijack', 
                                 'registry_appinit']:
                # These are lists of registry entries
                if isinstance(mechanism_data, list):
                    for entry in mechanism_data:
                        if isinstance(entry, dict):
                            # Check values in the entry
                            values = entry.get('values', [])
                            if isinstance(values, list):
                                for value_item in values:
                                    value_str = str(value_item.get('value', '')).lower()
                                    # Check if any application path/name matches
                                    for exe_path in exe_paths:
                                        if exe_path and (exe_path in value_str or value_str in exe_path):
                                            return True
                                    for exe_name in exe_names:
                                        if exe_name and (exe_name in value_str or value_str in exe_name):
                                            return True
                                    # Also check application name variations
                                    for app_name_var in app_name_variations:
                                        if app_name_var and (app_name_var in value_str or value_str in app_name_var):
                                            return True
            
            elif mechanism_type == 'startup_folders':
                # List of startup folder entries
                if isinstance(mechanism_data, list):
                    for entry in mechanism_data:
                        if isinstance(entry, dict):
                            file_path = str(entry.get('file_path', '')).lower()
                            for exe_path in exe_paths:
                                if exe_path and (exe_path in file_path or file_path in exe_path):
                                    return True
                            for exe_name in exe_names:
                                if exe_name and (exe_name in file_path or file_path in exe_name):
                                    return True
                            # Also check application name variations
                            for app_name_var in app_name_variations:
                                if app_name_var and (app_name_var in file_path or file_path in app_name_var):
                                    return True
            
            elif mechanism_type == 'scheduled_tasks':
                # List of scheduled tasks
                if isinstance(mechanism_data, list):
                    for entry in mechanism_data:
                        if isinstance(entry, dict):
                            # Check various fields that might contain executable paths
                            for field in ['command', 'action', 'executable', 'file_path']:
                                field_value = str(entry.get(field, '')).lower()
                                for exe_path in exe_paths:
                                    if exe_path and (exe_path in field_value or field_value in exe_path):
                                        return True
                                for exe_name in exe_names:
                                    if exe_name and (exe_name in field_value or field_value in exe_name):
                                        return True
                                # Also check application name variations
                                for app_name_var in app_name_variations:
                                    if app_name_var and (app_name_var in field_value or field_value in app_name_var):
                                        return True
        
        return False
    
    def populate_table(self, apps):
        """Populate the table with application data (batched for better performance)."""
        if not apps:
            self.table.setRowCount(0)
            return
        
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        
        try:
            # Process in batches of 150
            batch_size = 150
            total_rows = len(apps)
            self.table.setRowCount(total_rows)
            
            # Highlight color for rows that are running and/or in persistence
            highlight_color = QColor(255, 200, 100)  # Orange/amber color for highlighting
            
            for batch_start in range(0, total_rows, batch_size):
                batch_end = min(batch_start + batch_size, total_rows)
                batch = apps[batch_start:batch_end]
                
                # Populate all rows in this batch at once (with updates disabled)
                for i, app in enumerate(batch):
                    row = batch_start + i
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
                        
                        # Check if this application should be highlighted
                        is_running = self._is_app_running(app)
                        is_in_persistence = self._is_app_in_persistence(app)
                        should_highlight = is_running and is_in_persistence
                        
                        # Create items
                        name_item = QTableWidgetItem(name)
                        version_item = QTableWidgetItem(version)
                        publisher_item = QTableWidgetItem(publisher)
                        install_date_item = QTableWidgetItem(install_date)
                        location_item = QTableWidgetItem(install_location)
                        size_item = QTableWidgetItem(str(size_mb))
                        uninstall_item = QTableWidgetItem(uninstall_string)
                        registry_item = QTableWidgetItem(registry_key)
                        
                        # Apply highlighting if needed
                        if should_highlight:
                            for item in [name_item, version_item, publisher_item, install_date_item,
                                        location_item, size_item, uninstall_item, registry_item]:
                                item.setBackground(highlight_color)
                        
                        # Set tooltips for long text
                        if len(install_location) > 50:
                            location_item.setToolTip(install_location)
                        if len(uninstall_string) > 50:
                            uninstall_item.setToolTip(uninstall_string)
                        
                        # Set items in table
                        self.table.setItem(row, 0, name_item)
                        self.table.setItem(row, 1, version_item)
                        self.table.setItem(row, 2, publisher_item)
                        self.table.setItem(row, 3, install_date_item)
                        self.table.setItem(row, 4, location_item)
                        self.table.setItem(row, 5, size_item)
                        self.table.setItem(row, 6, uninstall_item)
                        self.table.setItem(row, 7, registry_item)
                        
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
                
                # Re-enable updates temporarily to show progress after each batch
                self.table.setUpdatesEnabled(True)
                self.table.setUpdatesEnabled(False)
                
                # Show notification for each batch
                if self.notification_callback and batch_end < total_rows:
                    self.notification_callback(f"Application table: {batch_end}/{total_rows} records loaded...")
            
            # Final notification
            if self.notification_callback:
                self.notification_callback(f"Application table updated: {total_rows} records loaded")
            
            # Resize columns only once after all rows are populated
            self.table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            self.table.setUpdatesEnabled(True)
            self.table.setSortingEnabled(was_sorting)
    
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
    
    def populate_binary_table(self, binaries):
        """Populate the binary table with binary data (batched for better performance)."""
        if not hasattr(self, 'binary_table') or self.binary_table is None:
            return
        
        if not binaries:
            self.binary_table.setRowCount(0)
            return
        
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.binary_table.isSortingEnabled()
        self.binary_table.setSortingEnabled(False)
        self.binary_table.setUpdatesEnabled(False)
        
        try:
            # Process in batches of 150
            batch_size = 150
            total_rows = len(binaries)
            self.binary_table.setRowCount(total_rows)
            
            for batch_start in range(0, total_rows, batch_size):
                batch_end = min(batch_start + batch_size, total_rows)
                batch = binaries[batch_start:batch_end]
                
                # Populate this batch
                for i, binary in enumerate(batch):
                    row = batch_start + i
                    try:
                        # Safely convert all values to strings
                        name = str(binary.get('name', 'N/A'))
                        path = str(binary.get('path', 'N/A'))
                        extension = str(binary.get('extension', 'N/A'))
                        size_mb = str(binary.get('size_mb', 'N/A'))
                        modified = str(binary.get('modified', 'N/A'))
                        created = str(binary.get('created', 'N/A'))
                        user_dir = str(binary.get('user_directory', 'N/A'))
                        sha256 = str(binary.get('sha256', 'N/A'))
                        
                        self.binary_table.setItem(row, 0, QTableWidgetItem(name))
                        
                        path_item = QTableWidgetItem(path)
                        if len(path) > 50:
                            path_item.setToolTip(path)
                        self.binary_table.setItem(row, 1, path_item)
                        
                        self.binary_table.setItem(row, 2, QTableWidgetItem(extension))
                        self.binary_table.setItem(row, 3, QTableWidgetItem(str(size_mb)))
                        self.binary_table.setItem(row, 4, QTableWidgetItem(modified))
                        self.binary_table.setItem(row, 5, QTableWidgetItem(created))
                        self.binary_table.setItem(row, 6, QTableWidgetItem(user_dir))
                        
                        sha256_item = QTableWidgetItem(sha256)
                        if len(sha256) > 50:
                            sha256_item.setToolTip(sha256)
                        self.binary_table.setItem(row, 7, sha256_item)
                        
                        # Handle exports column
                        exports = binary.get('exports', [])
                        export_count = len(exports)
                        if export_count > 0:
                            # Show count and first few exports
                            if export_count <= 3:
                                exports_text = f"{export_count}: {', '.join(exports)}"
                            else:
                                exports_text = f"{export_count}: {', '.join(exports[:3])}..."
                            exports_item = QTableWidgetItem(exports_text)
                            # Set tooltip with all exports
                            all_exports = ', '.join(exports)
                            exports_item.setToolTip(all_exports)
                            self.binary_table.setItem(row, 8, exports_item)
                        else:
                            self.binary_table.setItem(row, 8, QTableWidgetItem('N/A'))
                        
                    except Exception as e:
                        # Still add the row with error info
                        self.binary_table.setItem(row, 0, QTableWidgetItem(binary.get('name', f'Binary {row}')))
                        self.binary_table.setItem(row, 1, QTableWidgetItem('Error'))
                        self.binary_table.setItem(row, 2, QTableWidgetItem('N/A'))
                        self.binary_table.setItem(row, 3, QTableWidgetItem('N/A'))
                        self.binary_table.setItem(row, 4, QTableWidgetItem('N/A'))
                        self.binary_table.setItem(row, 5, QTableWidgetItem('N/A'))
                        self.binary_table.setItem(row, 6, QTableWidgetItem('N/A'))
                        self.binary_table.setItem(row, 7, QTableWidgetItem(f'Error: {str(e)}'))
                        self.binary_table.setItem(row, 8, QTableWidgetItem('N/A'))
                
                # Re-enable updates temporarily to show progress
                self.binary_table.setUpdatesEnabled(True)
                self.binary_table.setUpdatesEnabled(False)
                
                # Show notification for each batch
                if self.notification_callback and batch_end < total_rows:
                    self.notification_callback(f"Binary table: {batch_end}/{total_rows} records loaded...")
            
            # Final notification
            if self.notification_callback:
                self.notification_callback(f"Binary table updated: {total_rows} records loaded")
            
            # Auto-resize columns only once after all rows are populated
            self.binary_table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            self.binary_table.setUpdatesEnabled(True)
            self.binary_table.setSortingEnabled(was_sorting)
    
    def filter_binaries(self, text):
        """Filter binaries based on search text."""
        if not self.binary_data:
            return
        
        if not text:
            self.filtered_binary_data = self.binary_data
            self.populate_binary_table(self.binary_data)
            return
        
        # Filter by text
        filtered = []
        search_lower = text.lower()
        for binary in self.binary_data:
            if (search_lower in binary.get('name', '').lower() or
                search_lower in binary.get('path', '').lower() or
                search_lower in binary.get('extension', '').lower() or
                search_lower in binary.get('user_directory', '').lower()):
                filtered.append(binary)
        
        self.filtered_binary_data = filtered
        self.populate_binary_table(filtered)
    
    def export_data(self):
        """Export application and binary data to a file."""
        from PySide6.QtWidgets import QFileDialog
        import json
        
        export_data = {
            'applications': self.app_data or [],
            'binaries': self.binary_data or []
        }
        
        if not export_data['applications'] and not export_data['binaries']:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Application Data", "applications.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
    
    def show_binary_context_menu(self, position):
        """Show context menu on right-click in binary table."""
        # Get the row at the click position
        row = self.binary_table.rowAt(position.y())
        if row < 0:
            return
        
        # Get the binary data for this row (use filtered data if available)
        binary_data_to_use = self.filtered_binary_data if self.filtered_binary_data is not None else self.binary_data
        if not binary_data_to_use or row >= len(binary_data_to_use):
            return
        
        binary = binary_data_to_use[row]
        extension = binary.get('extension', '').lower()
        file_path = binary.get('path', '')
        
        # Create context menu
        context_menu = QMenu(self)
        
        # Add "Open Location in Explorer" action
        open_location_action = context_menu.addAction("Open Location in Explorer")
        open_location_action.triggered.connect(lambda checked, path=file_path: self.open_location_in_explorer(path))
        
        # Only show "Show Export Functions" for DLL files
        if extension == '.dll':
            context_menu.addSeparator()  # Add separator before DLL-specific actions
            show_exports_action = context_menu.addAction("Show Export Functions")
            show_exports_action.triggered.connect(lambda checked, b=binary: self.show_export_functions(b))
        
        # Show context menu at cursor position
        global_position = self.binary_table.viewport().mapToGlobal(position)
        context_menu.exec(global_position)
    
    def open_location_in_explorer(self, file_path):
        """Open Windows Explorer and highlight the selected file."""
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(
                self,
                "File Not Found",
                f"The file does not exist:\n{file_path}"
            )
            return
        
        try:
            # Use Windows Explorer to select the file
            # The /select, parameter tells Explorer to select the file
            subprocess.Popen(['explorer', '/select,', os.path.normpath(file_path)])
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open Windows Explorer:\n{str(e)}"
            )
    
    def show_export_functions(self, binary):
        """Show a dialog with export functions for a DLL file."""
        exports = binary.get('exports', [])
        dll_name = binary.get('name', 'Unknown DLL')
        dll_path = binary.get('path', 'N/A')
        
        # Create dialog
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Export Functions - {dll_name}")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(dialog)
        
        # Header with DLL info
        header_label = QLabel(f"<b>DLL:</b> {dll_name}<br><b>Path:</b> {dll_path}<br><b>Total Exports:</b> {len(exports)}")
        header_label.setWordWrap(True)
        layout.addWidget(header_label)
        
        # Table for export functions
        if exports:
            table = QTableWidget()
            table.setColumnCount(2)
            table.setHorizontalHeaderLabels(["#", "Function Name"])
            table.setRowCount(len(exports))
            table.setSortingEnabled(True)
            table.setAlternatingRowColors(True)
            table.setSelectionBehavior(QTableWidget.SelectRows)
            
            for idx, export_name in enumerate(exports):
                table.setItem(idx, 0, QTableWidgetItem(str(idx + 1)))
                table.setItem(idx, 1, QTableWidgetItem(export_name))
            
            table.resizeColumnsToContents()
            layout.addWidget(table)
        else:
            no_exports_label = QLabel("No export functions found in this DLL.")
            no_exports_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(no_exports_label)
        
        # Close button
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        button_box.accepted.connect(dialog.accept)
        layout.addWidget(button_box)
        
        dialog.exec()



