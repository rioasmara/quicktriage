"""
File view widget for displaying file system information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QGroupBox,
    QGridLayout, QSplitter, QScrollArea, QCheckBox, QDateTimeEdit
)
from PySide6.QtCore import Qt, QTimer, QDateTime
from PySide6.QtGui import QCursor
from datetime import datetime, timedelta
from functools import partial
import os
from collections import Counter


class FileView(QWidget):
    """Widget for displaying file system information."""
    
    def __init__(self):
        super().__init__()
        self.file_data = None
        self.filtered_data = None
        self.current_filter_days = None  # Track current date filter
        self.custom_start_date = None  # Track custom start date/time
        self.custom_end_date = None  # Track custom end date/time
        self.notification_callback = None  # Callback for notifications
        # Batching for incremental updates
        self.incremental_batch = []  # Queue for batched incremental updates
        self.batch_size = 150  # Number of records to batch before adding to grid
        self.batch_timer = QTimer(self)
        self.batch_timer.setSingleShot(True)
        self.batch_timer.timeout.connect(self._flush_incremental_batch)
        # Track active statistic filter
        self.active_stat_filter = None
        # Track selected extensions for filtering
        self.selected_extensions = set()
        self.extension_checkboxes = {}  # Map extension to checkbox widget
        self._updating_extensions = False  # Flag to prevent recursive updates
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        
        # Control bar
        control_layout = QHBoxLayout()
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(8)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search files...")
        self.search_box.setMinimumWidth(200)
        self.search_box.textChanged.connect(self.filter_files)
        
        # Date filter buttons
        date_filter_label = QLabel("Created:")
        date_filter_label.setStyleSheet("font-weight: 600;")
        self.filter_10_days_btn = QPushButton("Last 10 Days")
        self.filter_10_days_btn.setCheckable(True)
        self.filter_10_days_btn.setMinimumWidth(100)
        self.filter_10_days_btn.clicked.connect(lambda: self.filter_by_date(10))
        
        self.filter_30_days_btn = QPushButton("Last 30 Days")
        self.filter_30_days_btn.setCheckable(True)
        self.filter_30_days_btn.setMinimumWidth(100)
        self.filter_30_days_btn.clicked.connect(lambda: self.filter_by_date(30))
        
        self.filter_60_days_btn = QPushButton("Last 60 Days")
        self.filter_60_days_btn.setCheckable(True)
        self.filter_60_days_btn.setMinimumWidth(100)
        self.filter_60_days_btn.clicked.connect(lambda: self.filter_by_date(60))
        
        # Custom date/time range filter
        custom_date_label = QLabel("Custom Range:")
        custom_date_label.setStyleSheet("font-weight: 600;")
        
        self.start_datetime = QDateTimeEdit()
        self.start_datetime.setCalendarPopup(True)
        self.start_datetime.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.start_datetime.setDateTime(QDateTime.currentDateTime().addDays(-30))
        self.start_datetime.setMinimumWidth(220)
        self.start_datetime.setMaximumWidth(220)
        self.start_datetime.setMinimumHeight(28)
        # Enable time editing - click on time portion or use arrow keys/mouse wheel
        self.start_datetime.setButtonSymbols(QDateTimeEdit.ButtonSymbols.UpDownArrows)
        self.start_datetime.setToolTip("Click on date/time sections to edit. Use arrow keys or mouse wheel to change values.")
        
        self.end_datetime = QDateTimeEdit()
        self.end_datetime.setCalendarPopup(True)
        self.end_datetime.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.end_datetime.setDateTime(QDateTime.currentDateTime())
        self.end_datetime.setMinimumWidth(220)
        self.end_datetime.setMaximumWidth(220)
        self.end_datetime.setMinimumHeight(28)
        # Enable time editing - click on time portion or use arrow keys/mouse wheel
        self.end_datetime.setButtonSymbols(QDateTimeEdit.ButtonSymbols.UpDownArrows)
        self.end_datetime.setToolTip("Click on date/time sections to edit. Use arrow keys or mouse wheel to change values.")
        
        self.apply_custom_date_btn = QPushButton("Apply Range")
        self.apply_custom_date_btn.setMinimumWidth(100)
        self.apply_custom_date_btn.clicked.connect(self.filter_by_custom_date_range)
        
        self.clear_filter_btn = QPushButton("Clear Filter")
        self.clear_filter_btn.setMinimumWidth(90)
        self.clear_filter_btn.clicked.connect(self.clear_date_filter)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.setMinimumWidth(80)
        self.export_btn.clicked.connect(self.export_data)
        
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)
        control_layout.addSpacing(12)
        control_layout.addWidget(date_filter_label)
        control_layout.addWidget(self.filter_10_days_btn)
        control_layout.addWidget(self.filter_30_days_btn)
        control_layout.addWidget(self.filter_60_days_btn)
        control_layout.addSpacing(12)
        control_layout.addWidget(custom_date_label)
        control_layout.addWidget(QLabel("From:"))
        control_layout.addWidget(self.start_datetime)
        control_layout.addWidget(QLabel("To:"))
        control_layout.addWidget(self.end_datetime)
        control_layout.addWidget(self.apply_custom_date_btn)
        control_layout.addWidget(self.clear_filter_btn)
        control_layout.addStretch()
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Create splitter for statistics and table
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Statistics panel
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        stats_layout.setContentsMargins(6, 6, 6, 6)
        stats_layout.setSpacing(6)
        
        stats_group = QGroupBox("Compromise Triage Statistics")
        stats_group_layout = QGridLayout()
        stats_group_layout.setSpacing(10)
        stats_group_layout.setColumnStretch(0, 1)
        stats_group_layout.setColumnStretch(1, 1)
        
        # Statistics labels - organized in two columns for better visibility
        # Make them clickable by using QPushButton styled as labels
        self.stats_total_files = self._create_clickable_stat("Total Files: 0", "total")
        self.stats_filtered_files = self._create_clickable_stat("Filtered Files: 0", "filtered")
        self.stats_suspicious_ext = self._create_clickable_stat("Suspicious Extensions: 0", "suspicious_ext")
        self.stats_temp_files = self._create_clickable_stat("Temp Directory Files: 0", "temp")
        self.stats_startup_files = self._create_clickable_stat("Startup Directory Files: 0", "startup")
        self.stats_large_files = self._create_clickable_stat("Large Files (>10MB): 0", "large")
        self.stats_recent_modified = self._create_clickable_stat("Modified Last 7 Days: 0", "recent_modified")
        self.stats_recent_created = self._create_clickable_stat("Created Last 7 Days: 0", "recent_created")
        self.stats_duplicate_hashes = self._create_clickable_stat("Duplicate Hashes: 0", "duplicate_hashes")
        self.stats_exe_files = self._create_clickable_stat("Executable Files (.exe): 0", "exe")
        self.stats_dll_files = self._create_clickable_stat("DLL Files (.dll): 0", "dll")
        self.stats_script_files = self._create_clickable_stat("Script Files (.bat/.ps1/.vbs): 0", "script")
        
        # Add statistics to grid - better organized layout
        row = 0
        stats_group_layout.addWidget(self.stats_total_files, row, 0)
        stats_group_layout.addWidget(self.stats_filtered_files, row, 1)
        row += 1
        stats_group_layout.addWidget(self.stats_suspicious_ext, row, 0)
        stats_group_layout.addWidget(self.stats_temp_files, row, 1)
        row += 1
        stats_group_layout.addWidget(self.stats_startup_files, row, 0)
        stats_group_layout.addWidget(self.stats_large_files, row, 1)
        row += 1
        stats_group_layout.addWidget(self.stats_recent_modified, row, 0)
        stats_group_layout.addWidget(self.stats_recent_created, row, 1)
        row += 1
        stats_group_layout.addWidget(self.stats_duplicate_hashes, row, 0)
        stats_group_layout.addWidget(self.stats_exe_files, row, 1)
        row += 1
        stats_group_layout.addWidget(self.stats_dll_files, row, 0)
        stats_group_layout.addWidget(self.stats_script_files, row, 1)
        
        stats_group.setLayout(stats_group_layout)
        stats_layout.addWidget(stats_group)
        
        # File extensions statistics group
        extensions_group = QGroupBox("File Extensions Discovered")
        extensions_layout = QVBoxLayout()
        extensions_layout.setContentsMargins(6, 6, 6, 6)
        extensions_layout.setSpacing(4)
        
        # Scroll area for extensions (in case there are many)
        extensions_scroll = QScrollArea()
        extensions_scroll.setWidgetResizable(True)
        extensions_scroll.setMaximumHeight(200)
        extensions_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        self.extensions_widget = QWidget()
        self.extensions_layout = QVBoxLayout(self.extensions_widget)
        self.extensions_layout.setContentsMargins(4, 4, 4, 4)
        self.extensions_layout.setSpacing(2)
        
        self.extensions_label = QLabel("No files collected yet")
        self.extensions_layout.addWidget(self.extensions_label)
        self.extensions_layout.addStretch()
        
        extensions_scroll.setWidget(self.extensions_widget)
        extensions_layout.addWidget(extensions_scroll)
        
        extensions_group.setLayout(extensions_layout)
        stats_layout.addWidget(extensions_group)
        
        stats_layout.addStretch()
        
        # Set better width constraints for statistics panel
        stats_widget.setMinimumWidth(380)
        stats_widget.setMaximumWidth(450)
        
        # Table
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)
        
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
        
        # Set row height for better readability when editing
        self.table.verticalHeader().setDefaultSectionSize(52)
        
        table_layout.addWidget(self.table)
        
        # Add widgets to splitter
        splitter.addWidget(stats_widget)
        splitter.addWidget(table_widget)
        splitter.setStretchFactor(0, 0)  # Statistics panel doesn't stretch
        splitter.setStretchFactor(1, 1)  # Table stretches to fill space
        splitter.setSizes([400, 1000])  # Initial sizes - better proportions
        
        layout.addWidget(splitter)
    
    def _create_clickable_stat(self, text, filter_key):
        """Create a clickable statistic button styled as a label."""
        btn = QPushButton(text)
        btn.setFlat(True)
        btn.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding: 4px;
                border: none;
                background-color: transparent;
                color: #cfe9ff;
            }
            QPushButton:hover {
                background-color: #1b2d43;
                border: 1px solid #29b6d3;
                border-radius: 4px;
            }
            QPushButton:pressed {
                background-color: #21405a;
            }
        """)
        btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn.setToolTip(f"Click to filter by: {text}")
        btn.clicked.connect(lambda: self._on_stat_clicked(filter_key))
        return btn
    
    def _on_stat_clicked(self, filter_key):
        """Handle statistic click to filter the table."""
        if not self.file_data:
            return
        
        # Clear previous stat filter if clicking the same one
        if self.active_stat_filter == filter_key:
            self.active_stat_filter = None
            self._apply_stat_filter()
            return
        
        self.active_stat_filter = filter_key
        self._apply_stat_filter()
    
    def _apply_stat_filter(self):
        """Apply the active statistic filter to the table."""
        if not self.file_data:
            return
        
        # Start with date-filtered data if applicable
        base_data = self._apply_date_filter(self.file_data)
        
        # Apply statistic filter
        if self.active_stat_filter:
            filtered = self._filter_by_stat(base_data, self.active_stat_filter)
        else:
            filtered = base_data
        
        # Apply extension filter if any extensions are selected
        if self.selected_extensions:
            filtered = self._filter_by_extensions(filtered)
        
        # Apply search filter if any
        search_text = self.search_box.text().lower()
        if search_text:
            filtered = [
                f for f in filtered
                if search_text in f['name'].lower() or
                search_text in f['path'].lower() or
                search_text in f.get('sha256', '').lower()
            ]
        
        self.filtered_data = filtered
        self._update_display()
    
    def _filter_by_stat(self, files, filter_key):
        """Filter files based on statistic filter key."""
        if filter_key == "total" or filter_key == "filtered":
            return files  # Show all
        elif filter_key == "suspicious_ext":
            suspicious_extensions = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', 
                                    '.scr', '.com', '.pif', '.hta', '.msi', '.msp', '.appx', '.appxbundle'}
            return [f for f in files 
                   if os.path.splitext(f.get('name', ''))[1].lower() in suspicious_extensions]
        elif filter_key == "temp":
            temp_dirs = [
                os.path.expandvars('%TEMP%').lower(),
                os.path.expandvars('%TMP%').lower(),
                os.path.join(os.path.expandvars('%SystemRoot%'), 'Temp').lower(),
                os.path.expandvars('%LOCALAPPDATA%\\Temp').lower()
            ]
            return [f for f in files 
                   if any(f.get('path', '').lower().startswith(td) for td in temp_dirs)]
        elif filter_key == "startup":
            startup_dirs = [
                os.path.join(os.path.expandvars('%ProgramData%'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup').lower(),
                os.path.join(os.path.expandvars('%USERPROFILE%'), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup').lower()
            ]
            return [f for f in files 
                   if any(sd in f.get('path', '').lower() for sd in startup_dirs)]
        elif filter_key == "large":
            large_file_threshold = 10 * 1024 * 1024  # 10MB
            return [f for f in files 
                   if f.get('size', 0) > large_file_threshold]
        elif filter_key == "recent_modified":
            seven_days_ago = datetime.now() - timedelta(days=7)
            filtered = []
            for f in files:
                try:
                    modified_date = datetime.fromisoformat(f['modified'].replace('Z', '+00:00'))
                    if modified_date.tzinfo is not None:
                        modified_date = modified_date.replace(tzinfo=None)
                    if modified_date >= seven_days_ago:
                        filtered.append(f)
                except (ValueError, AttributeError):
                    pass
            return filtered
        elif filter_key == "recent_created":
            seven_days_ago = datetime.now() - timedelta(days=7)
            filtered = []
            for f in files:
                try:
                    created_date = datetime.fromisoformat(f['created'].replace('Z', '+00:00'))
                    if created_date.tzinfo is not None:
                        created_date = created_date.replace(tzinfo=None)
                    if created_date >= seven_days_ago:
                        filtered.append(f)
                except (ValueError, AttributeError):
                    pass
            return filtered
        elif filter_key == "duplicate_hashes":
            hash_counts = {}
            for f in files:
                sha256 = f.get('sha256', 'N/A')
                if sha256 and sha256 != 'N/A':
                    hash_counts[sha256] = hash_counts.get(sha256, 0) + 1
            duplicate_hashes = {h for h, count in hash_counts.items() if count > 1}
            return [f for f in files 
                   if f.get('sha256', 'N/A') in duplicate_hashes]
        elif filter_key == "exe":
            return [f for f in files 
                   if os.path.splitext(f.get('name', ''))[1].lower() == '.exe']
        elif filter_key == "dll":
            return [f for f in files 
                   if os.path.splitext(f.get('name', ''))[1].lower() == '.dll']
        elif filter_key == "script":
            script_extensions = {'.bat', '.cmd', '.ps1', '.vbs', '.js'}
            return [f for f in files 
                   if os.path.splitext(f.get('name', ''))[1].lower() in script_extensions]
        else:
            return files
    
    def update_data(self, data):
        """Update the view with new file data."""
        if not data or 'files' not in data:
            return
        
        # Check if this is a full update (replaces all data) or incremental
        is_full_update = data.get('is_full_update', False)
        
        if is_full_update:
            # Full update - replace all data
            self.file_data = data['files']
            self.filtered_data = self.file_data.copy() if self.file_data else None
            # Defer heavy work to make UI responsive
            QTimer.singleShot(0, lambda: self._update_display())
        # Otherwise, incremental updates are handled via add_file_incremental
    
    def populate_table(self, files):
        """Populate the table with file data (batched for better performance)."""
        if not files:
            self.table.setRowCount(0)
            return
        
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        
        try:
            # Process in batches of 150
            batch_size = 150
            total_rows = len(files)
            self.table.setRowCount(total_rows)
            
            for batch_start in range(0, total_rows, batch_size):
                batch_end = min(batch_start + batch_size, total_rows)
                batch = files[batch_start:batch_end]
                
                # Populate this batch
                for i, file_info in enumerate(batch):
                    row = batch_start + i
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
                
                # Re-enable updates temporarily to show progress
                self.table.setUpdatesEnabled(True)
                self.table.setUpdatesEnabled(False)
                
                # Show notification for each batch
                if self.notification_callback and batch_end < total_rows:
                    self.notification_callback(f"File table: {batch_end}/{total_rows} records loaded...")
            
            # Final notification
            if self.notification_callback:
                self.notification_callback(f"File table updated: {total_rows} records loaded")
            
            # Resize columns only once after all rows are populated
            self.table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            self.table.setUpdatesEnabled(True)
            self.table.setSortingEnabled(was_sorting)
    
    def clear_data(self):
        """Clear the table and data before starting new collection."""
        self.file_data = []
        self.filtered_data = []
        self.incremental_batch.clear()
        self.table.setRowCount(0)
        self.update_statistics([])
    
    def add_file_incremental(self, file_info):
        """Add a single file entry incrementally to the table (batched)."""
        # Add to batch queue
        self.incremental_batch.append(file_info)
        
        # Only flush when batch reaches 150 records
        if len(self.incremental_batch) >= self.batch_size:
            self._flush_incremental_batch()
    
    def _flush_incremental_batch(self):
        """Flush the batched incremental updates to the table."""
        if not self.incremental_batch:
            return
        
        # Get all items in batch
        batch = self.incremental_batch[:]
        self.incremental_batch.clear()
        
        # Initialize data lists if needed
        if self.file_data is None:
            self.file_data = []
        if self.filtered_data is None:
            self.filtered_data = []
        
        # Add to data lists
        for file_info in batch:
            self.file_data.append(file_info)
            # Add to filtered_data if it passes current filters
            if self._should_show_file(file_info):
                self.filtered_data.append(file_info)
        
        # Add new items to table in batch
        if batch:
            # Filter items that should be visible based on current filters
            visible_items = [f for f in batch if self._should_show_file(f)]
            
            if visible_items:
                # Disable sorting and updates for better performance
                was_sorting = self.table.isSortingEnabled()
                self.table.setSortingEnabled(False)
                self.table.setUpdatesEnabled(False)
                
                try:
                    # Get current row count
                    current_row_count = self.table.rowCount()
                    
                    # Add all rows at once by setting the new row count
                    new_row_count = current_row_count + len(visible_items)
                    self.table.setRowCount(new_row_count)
                    
                    # Populate all rows at once
                    for i, file_info in enumerate(visible_items):
                        row = current_row_count + i
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
                finally:
                    # Re-enable updates and sorting
                    self.table.setUpdatesEnabled(True)
                    self.table.setSortingEnabled(was_sorting)
            
            # Update statistics
            self.update_statistics(self.filtered_data if self.filtered_data else [])
            
            # Show notification only when we actually added records (and it's a full batch or final batch)
            if self.notification_callback and len(batch) > 0:
                # Only show notification for batches of 150 (or final batch)
                if len(batch) >= 150 or len(self.incremental_batch) == 0:
                    total = len(self.file_data) if self.file_data else 0
                    self.notification_callback(f"File table updated: +{len(batch)} records (Total: {total})")
    
    def _should_show_file(self, file_info):
        """Check if a file should be shown based on current filters."""
        # Check date filter (preset days or custom range)
        if self.custom_start_date is not None and self.custom_end_date is not None:
            try:
                created_date = datetime.fromisoformat(file_info['created'].replace('Z', '+00:00'))
                if created_date.tzinfo is not None:
                    created_date = created_date.replace(tzinfo=None)
                if not (self.custom_start_date <= created_date <= self.custom_end_date):
                    return False
            except (ValueError, AttributeError):
                pass  # If date parsing fails, include the file
        elif self.current_filter_days is not None:
            try:
                cutoff_date = datetime.now() - timedelta(days=self.current_filter_days)
                created_date = datetime.fromisoformat(file_info['created'].replace('Z', '+00:00'))
                if created_date.tzinfo is not None:
                    created_date = created_date.replace(tzinfo=None)
                if created_date < cutoff_date:
                    return False
            except (ValueError, AttributeError):
                pass  # If date parsing fails, include the file
        
        # Check search filter
        search_text = self.search_box.text().lower()
        if search_text:
            if (search_text not in file_info['name'].lower() and
                search_text not in file_info['path'].lower() and
                search_text not in file_info.get('sha256', '').lower()):
                return False
        
        return True
    
    def _update_display(self):
        """Update both table and statistics."""
        if not self.filtered_data:
            self.populate_table([])
            self.update_statistics([])
            return
        
        self.populate_table(self.filtered_data)
        self.update_statistics(self.filtered_data)
    
    def _apply_date_filter(self, files):
        """Apply date filter (preset days or custom range) to files."""
        if not files:
            return files
        
        # Check for custom date range first
        if self.custom_start_date is not None and self.custom_end_date is not None:
            filtered = []
            for f in files:
                try:
                    created_date = datetime.fromisoformat(f['created'].replace('Z', '+00:00'))
                    if created_date.tzinfo is not None:
                        created_date = created_date.replace(tzinfo=None)
                    if self.custom_start_date <= created_date <= self.custom_end_date:
                        filtered.append(f)
                except (ValueError, AttributeError):
                    filtered.append(f)
            return filtered
        
        # Check for preset days filter
        if self.current_filter_days is not None:
            cutoff_date = datetime.now() - timedelta(days=self.current_filter_days)
            filtered = []
            for f in files:
                try:
                    created_date = datetime.fromisoformat(f['created'].replace('Z', '+00:00'))
                    if created_date.tzinfo is not None:
                        created_date = created_date.replace(tzinfo=None)
                    if created_date >= cutoff_date:
                        filtered.append(f)
                except (ValueError, AttributeError):
                    filtered.append(f)
            return filtered
        
        # No date filter
        return files
    
    def filter_by_date(self, days):
        """Filter files created within the last N days."""
        if not self.file_data:
            return
        
        # Clear custom date range when using preset buttons
        self.custom_start_date = None
        self.custom_end_date = None
        
        # Uncheck other filter buttons
        self.filter_10_days_btn.setChecked(days == 10)
        self.filter_30_days_btn.setChecked(days == 30)
        self.filter_60_days_btn.setChecked(days == 60)
        
        self.current_filter_days = days
        cutoff_date = datetime.now() - timedelta(days=days)
        
        filtered = []
        for f in self.file_data:
            try:
                created_date = datetime.fromisoformat(f['created'].replace('Z', '+00:00'))
                # Handle timezone-aware datetime
                if created_date.tzinfo is not None:
                    created_date = created_date.replace(tzinfo=None)
                
                if created_date >= cutoff_date:
                    filtered.append(f)
            except (ValueError, AttributeError):
                # If date parsing fails, include the file (better to show than hide)
                filtered.append(f)
        
        # Apply statistic filter if active
        if self.active_stat_filter:
            filtered = self._filter_by_stat(filtered, self.active_stat_filter)
        
        # Apply extension filter if any extensions are selected
        if self.selected_extensions:
            filtered = self._filter_by_extensions(filtered)
        
        # Apply search filter if any
        search_text = self.search_box.text().lower()
        if search_text:
            filtered = [
                f for f in filtered
                if search_text in f['name'].lower() or
                search_text in f['path'].lower() or
                search_text in f.get('sha256', '').lower()
            ]
        
        self.filtered_data = filtered
        self._update_display()
    
    def filter_by_custom_date_range(self):
        """Filter files created within a custom date/time range."""
        if not self.file_data:
            return
        
        # Clear preset date filter buttons
        self.current_filter_days = None
        self.filter_10_days_btn.setChecked(False)
        self.filter_30_days_btn.setChecked(False)
        self.filter_60_days_btn.setChecked(False)
        
        # Get date/time from widgets
        start_qdatetime = self.start_datetime.dateTime()
        end_qdatetime = self.end_datetime.dateTime()
        
        # Convert QDateTime to Python datetime
        self.custom_start_date = start_qdatetime.toPython()
        self.custom_end_date = end_qdatetime.toPython()
        
        # Validate date range
        if self.custom_start_date > self.custom_end_date:
            # Swap if start is after end
            self.custom_start_date, self.custom_end_date = self.custom_end_date, self.custom_start_date
            # Swap the widget values too
            self.start_datetime.setDateTime(end_qdatetime)
            self.end_datetime.setDateTime(start_qdatetime)
        
        # Apply date filter using helper method
        filtered = self._apply_date_filter(self.file_data)
        
        # Apply statistic filter if active
        if self.active_stat_filter:
            filtered = self._filter_by_stat(filtered, self.active_stat_filter)
        
        # Apply extension filter if any extensions are selected
        if self.selected_extensions:
            filtered = self._filter_by_extensions(filtered)
        
        # Apply search filter if any
        search_text = self.search_box.text().lower()
        if search_text:
            filtered = [
                f for f in filtered
                if search_text in f['name'].lower() or
                search_text in f['path'].lower() or
                search_text in f.get('sha256', '').lower()
            ]
        
        self.filtered_data = filtered
        self._update_display()
    
    def clear_date_filter(self):
        """Clear the date filter."""
        self.filter_10_days_btn.setChecked(False)
        self.filter_30_days_btn.setChecked(False)
        self.filter_60_days_btn.setChecked(False)
        self.current_filter_days = None
        self.custom_start_date = None
        self.custom_end_date = None
        self.active_stat_filter = None  # Also clear stat filter
        # Clear extension selections
        self.selected_extensions.clear()
        for checkbox in self.extension_checkboxes.values():
            checkbox.setChecked(False)
        self.filtered_data = self.file_data.copy() if self.file_data else None
        self._update_display()
    
    def filter_files(self, text):
        """Filter files based on search text."""
        if not self.file_data:
            return
        
        # Apply date filter to get base data
        base_data = self._apply_date_filter(self.file_data)
        
        # Apply statistic filter if active
        if self.active_stat_filter:
            base_data = self._filter_by_stat(base_data, self.active_stat_filter)
        
        # Apply extension filter if any extensions are selected
        if self.selected_extensions:
            base_data = self._filter_by_extensions(base_data)
        
        if not text:
            # No search text, use base data (which may be date-filtered, stat-filtered, and extension-filtered)
            self.filtered_data = base_data
        else:
            # Apply search filter to base data
            filtered = [
                f for f in base_data
            if text.lower() in f['name'].lower() or
            text.lower() in f['path'].lower() or
            text.lower() in f.get('sha256', '').lower()
        ]
            self.filtered_data = filtered
        
        self._update_display()
    
    def update_statistics(self, files):
        """Update statistics panel with compromise triage metrics."""
        if not files:
            self.stats_total_files.setText("Total Files: 0")
            self.stats_total_files.setToolTip("Click to filter by: Total Files: 0")
            self.stats_filtered_files.setText("Filtered Files: 0")
            self.stats_filtered_files.setToolTip("Click to filter by: Filtered Files: 0")
            self.stats_suspicious_ext.setText("Suspicious Extensions: 0")
            self.stats_suspicious_ext.setToolTip("Click to filter by: Suspicious Extensions: 0")
            self.stats_temp_files.setText("Temp Directory Files: 0")
            self.stats_temp_files.setToolTip("Click to filter by: Temp Directory Files: 0")
            self.stats_startup_files.setText("Startup Directory Files: 0")
            self.stats_startup_files.setToolTip("Click to filter by: Startup Directory Files: 0")
            self.stats_large_files.setText("Large Files (>10MB): 0")
            self.stats_large_files.setToolTip("Click to filter by: Large Files (>10MB): 0")
            self.stats_recent_modified.setText("Modified Last 7 Days: 0")
            self.stats_recent_modified.setToolTip("Click to filter by: Modified Last 7 Days: 0")
            self.stats_recent_created.setText("Created Last 7 Days: 0")
            self.stats_recent_created.setToolTip("Click to filter by: Created Last 7 Days: 0")
            self.stats_duplicate_hashes.setText("Duplicate Hashes: 0")
            self.stats_duplicate_hashes.setToolTip("Click to filter by: Duplicate Hashes: 0")
            self.stats_exe_files.setText("Executable Files (.exe): 0")
            self.stats_exe_files.setToolTip("Click to filter by: Executable Files (.exe): 0")
            self.stats_dll_files.setText("DLL Files (.dll): 0")
            self.stats_dll_files.setToolTip("Click to filter by: DLL Files (.dll): 0")
            self.stats_script_files.setText("Script Files (.bat/.ps1/.vbs): 0")
            self.stats_script_files.setToolTip("Click to filter by: Script Files (.bat/.ps1/.vbs): 0")
            # Update extensions - always use ALL files, not filtered
            # This ensures all extensions are always visible for selection
            all_files = self.file_data if self.file_data else []
            self._update_extensions_statistics(all_files)
            return
        
        total_files = len(self.file_data) if self.file_data else 0
        filtered_count = len(files)
        
        # Suspicious extensions
        suspicious_extensions = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', 
                                '.scr', '.com', '.pif', '.hta', '.msi', '.msp', '.appx', '.appxbundle'}
        
        suspicious_ext_count = sum(1 for f in files 
                                   if os.path.splitext(f.get('name', ''))[1].lower() in suspicious_extensions)
        
        # Temp directory files
        temp_dirs = [
            os.path.expandvars('%TEMP%').lower(),
            os.path.expandvars('%TMP%').lower(),
            os.path.join(os.path.expandvars('%SystemRoot%'), 'Temp').lower(),
            os.path.expandvars('%LOCALAPPDATA%\\Temp').lower()
        ]
        temp_count = sum(1 for f in files 
                        if any(f.get('path', '').lower().startswith(td) for td in temp_dirs))
        
        # Startup directory files
        startup_dirs = [
            os.path.join(os.path.expandvars('%ProgramData%'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup').lower(),
            os.path.join(os.path.expandvars('%USERPROFILE%'), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup').lower()
        ]
        startup_count = sum(1 for f in files 
                           if any(sd in f.get('path', '').lower() for sd in startup_dirs))
        
        # Large files (>10MB)
        large_file_threshold = 10 * 1024 * 1024  # 10MB
        large_files_count = sum(1 for f in files 
                               if f.get('size', 0) > large_file_threshold)
        
        # Recent modifications (last 7 days)
        seven_days_ago = datetime.now() - timedelta(days=7)
        recent_modified = 0
        recent_created = 0
        for f in files:
            try:
                modified_date = datetime.fromisoformat(f['modified'].replace('Z', '+00:00'))
                if modified_date.tzinfo is not None:
                    modified_date = modified_date.replace(tzinfo=None)
                if modified_date >= seven_days_ago:
                    recent_modified += 1
            except (ValueError, AttributeError):
                pass
            
            try:
                created_date = datetime.fromisoformat(f['created'].replace('Z', '+00:00'))
                if created_date.tzinfo is not None:
                    created_date = created_date.replace(tzinfo=None)
                if created_date >= seven_days_ago:
                    recent_created += 1
            except (ValueError, AttributeError):
                pass
        
        # Duplicate hashes
        hash_counts = {}
        for f in files:
            sha256 = f.get('sha256', 'N/A')
            if sha256 and sha256 != 'N/A':
                hash_counts[sha256] = hash_counts.get(sha256, 0) + 1
        duplicate_hashes = sum(1 for count in hash_counts.values() if count > 1)
        
        # Executable files
        exe_count = sum(1 for f in files 
                       if os.path.splitext(f.get('name', ''))[1].lower() == '.exe')
        
        # DLL files
        dll_count = sum(1 for f in files 
                       if os.path.splitext(f.get('name', ''))[1].lower() == '.dll')
        
        # Script files
        script_extensions = {'.bat', '.cmd', '.ps1', '.vbs', '.js'}
        script_count = sum(1 for f in files 
                          if os.path.splitext(f.get('name', ''))[1].lower() in script_extensions)
        
        # Update labels and tooltips
        total_text = f"Total Files: {total_files:,}"
        self.stats_total_files.setText(total_text)
        self.stats_total_files.setToolTip(f"Click to filter by: {total_text}")
        
        filtered_text = f"Filtered Files: {filtered_count:,}"
        self.stats_filtered_files.setText(filtered_text)
        self.stats_filtered_files.setToolTip(f"Click to filter by: {filtered_text}")
        
        suspicious_text = f"Suspicious Extensions: {suspicious_ext_count:,}"
        self.stats_suspicious_ext.setText(suspicious_text)
        self.stats_suspicious_ext.setToolTip(f"Click to filter by: {suspicious_text}")
        
        temp_text = f"Temp Directory Files: {temp_count:,}"
        self.stats_temp_files.setText(temp_text)
        self.stats_temp_files.setToolTip(f"Click to filter by: {temp_text}")
        
        startup_text = f"Startup Directory Files: {startup_count:,}"
        self.stats_startup_files.setText(startup_text)
        self.stats_startup_files.setToolTip(f"Click to filter by: {startup_text}")
        
        large_text = f"Large Files (>10MB): {large_files_count:,}"
        self.stats_large_files.setText(large_text)
        self.stats_large_files.setToolTip(f"Click to filter by: {large_text}")
        
        recent_mod_text = f"Modified Last 7 Days: {recent_modified:,}"
        self.stats_recent_modified.setText(recent_mod_text)
        self.stats_recent_modified.setToolTip(f"Click to filter by: {recent_mod_text}")
        
        recent_created_text = f"Created Last 7 Days: {recent_created:,}"
        self.stats_recent_created.setText(recent_created_text)
        self.stats_recent_created.setToolTip(f"Click to filter by: {recent_created_text}")
        
        duplicate_text = f"Duplicate Hashes: {duplicate_hashes:,}"
        self.stats_duplicate_hashes.setText(duplicate_text)
        self.stats_duplicate_hashes.setToolTip(f"Click to filter by: {duplicate_text}")
        
        exe_text = f"Executable Files (.exe): {exe_count:,}"
        self.stats_exe_files.setText(exe_text)
        self.stats_exe_files.setToolTip(f"Click to filter by: {exe_text}")
        
        dll_text = f"DLL Files (.dll): {dll_count:,}"
        self.stats_dll_files.setText(dll_text)
        self.stats_dll_files.setToolTip(f"Click to filter by: {dll_text}")
        
        script_text = f"Script Files (.bat/.ps1/.vbs): {script_count:,}"
        self.stats_script_files.setText(script_text)
        self.stats_script_files.setToolTip(f"Click to filter by: {script_text}")
        
        # Update file extensions statistics - always use ALL files, not filtered
        # This ensures all extensions are always visible for selection
        # Only update if not currently updating (to prevent recursion)
        if not self._updating_extensions:
            all_files = self.file_data if self.file_data else []
            self._update_extensions_statistics(all_files)
    
    def _update_statistics_only(self, files):
        """Update statistics without updating extensions (to avoid recursion)."""
        # This is a copy of update_statistics but skips extension update
        if not files:
            self.stats_total_files.setText("Total Files: 0")
            self.stats_total_files.setToolTip("Click to filter by: Total Files: 0")
            self.stats_filtered_files.setText("Filtered Files: 0")
            self.stats_filtered_files.setToolTip("Click to filter by: Filtered Files: 0")
            self.stats_suspicious_ext.setText("Suspicious Extensions: 0")
            self.stats_suspicious_ext.setToolTip("Click to filter by: Suspicious Extensions: 0")
            self.stats_temp_files.setText("Temp Directory Files: 0")
            self.stats_temp_files.setToolTip("Click to filter by: Temp Directory Files: 0")
            self.stats_startup_files.setText("Startup Directory Files: 0")
            self.stats_startup_files.setToolTip("Click to filter by: Startup Directory Files: 0")
            self.stats_large_files.setText("Large Files (>10MB): 0")
            self.stats_large_files.setToolTip("Click to filter by: Large Files (>10MB): 0")
            self.stats_recent_modified.setText("Modified Last 7 Days: 0")
            self.stats_recent_modified.setToolTip("Click to filter by: Modified Last 7 Days: 0")
            self.stats_recent_created.setText("Created Last 7 Days: 0")
            self.stats_recent_created.setToolTip("Click to filter by: Created Last 7 Days: 0")
            self.stats_duplicate_hashes.setText("Duplicate Hashes: 0")
            self.stats_duplicate_hashes.setToolTip("Click to filter by: Duplicate Hashes: 0")
            self.stats_exe_files.setText("Executable Files (.exe): 0")
            self.stats_exe_files.setToolTip("Click to filter by: Executable Files (.exe): 0")
            self.stats_dll_files.setText("DLL Files (.dll): 0")
            self.stats_dll_files.setToolTip("Click to filter by: DLL Files (.dll): 0")
            self.stats_script_files.setText("Script Files (.bat/.ps1/.vbs): 0")
            self.stats_script_files.setToolTip("Click to filter by: Script Files (.bat/.ps1/.vbs): 0")
            return
        
        total_files = len(self.file_data) if self.file_data else 0
        filtered_count = len(files)
        
        # Suspicious extensions
        suspicious_extensions = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', 
                                '.scr', '.com', '.pif', '.hta', '.msi', '.msp', '.appx', '.appxbundle'}
        
        suspicious_ext_count = sum(1 for f in files 
                                   if os.path.splitext(f.get('name', ''))[1].lower() in suspicious_extensions)
        
        # Temp directory files
        temp_dirs = [
            os.path.expandvars('%TEMP%').lower(),
            os.path.expandvars('%TMP%').lower(),
            os.path.join(os.path.expandvars('%SystemRoot%'), 'Temp').lower(),
            os.path.expandvars('%LOCALAPPDATA%\\Temp').lower()
        ]
        temp_count = sum(1 for f in files 
                        if any(f.get('path', '').lower().startswith(td) for td in temp_dirs))
        
        # Startup directory files
        startup_dirs = [
            os.path.join(os.path.expandvars('%ProgramData%'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup').lower(),
            os.path.join(os.path.expandvars('%USERPROFILE%'), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup').lower()
        ]
        startup_count = sum(1 for f in files 
                           if any(sd in f.get('path', '').lower() for sd in startup_dirs))
        
        # Large files (>10MB)
        large_file_threshold = 10 * 1024 * 1024  # 10MB
        large_files_count = sum(1 for f in files 
                               if f.get('size', 0) > large_file_threshold)
        
        # Recent modifications (last 7 days)
        seven_days_ago = datetime.now() - timedelta(days=7)
        recent_modified = 0
        recent_created = 0
        for f in files:
            try:
                modified_date = datetime.fromisoformat(f['modified'].replace('Z', '+00:00'))
                if modified_date.tzinfo is not None:
                    modified_date = modified_date.replace(tzinfo=None)
                if modified_date >= seven_days_ago:
                    recent_modified += 1
            except (ValueError, AttributeError):
                pass
            
            try:
                created_date = datetime.fromisoformat(f['created'].replace('Z', '+00:00'))
                if created_date.tzinfo is not None:
                    created_date = created_date.replace(tzinfo=None)
                if created_date >= seven_days_ago:
                    recent_created += 1
            except (ValueError, AttributeError):
                pass
        
        # Duplicate hashes
        hash_counts = {}
        for f in files:
            sha256 = f.get('sha256', 'N/A')
            if sha256 and sha256 != 'N/A':
                hash_counts[sha256] = hash_counts.get(sha256, 0) + 1
        duplicate_hashes = sum(1 for count in hash_counts.values() if count > 1)
        
        # Executable files
        exe_count = sum(1 for f in files 
                       if os.path.splitext(f.get('name', ''))[1].lower() == '.exe')
        
        # DLL files
        dll_count = sum(1 for f in files 
                       if os.path.splitext(f.get('name', ''))[1].lower() == '.dll')
        
        # Script files
        script_extensions = {'.bat', '.cmd', '.ps1', '.vbs', '.js'}
        script_count = sum(1 for f in files 
                          if os.path.splitext(f.get('name', ''))[1].lower() in script_extensions)
        
        # Update labels and tooltips
        total_text = f"Total Files: {total_files:,}"
        self.stats_total_files.setText(total_text)
        self.stats_total_files.setToolTip(f"Click to filter by: {total_text}")
        
        filtered_text = f"Filtered Files: {filtered_count:,}"
        self.stats_filtered_files.setText(filtered_text)
        self.stats_filtered_files.setToolTip(f"Click to filter by: {filtered_text}")
        
        suspicious_text = f"Suspicious Extensions: {suspicious_ext_count:,}"
        self.stats_suspicious_ext.setText(suspicious_text)
        self.stats_suspicious_ext.setToolTip(f"Click to filter by: {suspicious_text}")
        
        temp_text = f"Temp Directory Files: {temp_count:,}"
        self.stats_temp_files.setText(temp_text)
        self.stats_temp_files.setToolTip(f"Click to filter by: {temp_text}")
        
        startup_text = f"Startup Directory Files: {startup_count:,}"
        self.stats_startup_files.setText(startup_text)
        self.stats_startup_files.setToolTip(f"Click to filter by: {startup_text}")
        
        large_text = f"Large Files (>10MB): {large_files_count:,}"
        self.stats_large_files.setText(large_text)
        self.stats_large_files.setToolTip(f"Click to filter by: {large_text}")
        
        recent_mod_text = f"Modified Last 7 Days: {recent_modified:,}"
        self.stats_recent_modified.setText(recent_mod_text)
        self.stats_recent_modified.setToolTip(f"Click to filter by: {recent_mod_text}")
        
        recent_created_text = f"Created Last 7 Days: {recent_created:,}"
        self.stats_recent_created.setText(recent_created_text)
        self.stats_recent_created.setToolTip(f"Click to filter by: {recent_created_text}")
        
        duplicate_text = f"Duplicate Hashes: {duplicate_hashes:,}"
        self.stats_duplicate_hashes.setText(duplicate_text)
        self.stats_duplicate_hashes.setToolTip(f"Click to filter by: {duplicate_text}")
        
        exe_text = f"Executable Files (.exe): {exe_count:,}"
        self.stats_exe_files.setText(exe_text)
        self.stats_exe_files.setToolTip(f"Click to filter by: {exe_text}")
        
        dll_text = f"DLL Files (.dll): {dll_count:,}"
        self.stats_dll_files.setText(dll_text)
        self.stats_dll_files.setToolTip(f"Click to filter by: {dll_text}")
        
        script_text = f"Script Files (.bat/.ps1/.vbs): {script_count:,}"
        self.stats_script_files.setText(script_text)
        self.stats_script_files.setToolTip(f"Click to filter by: {script_text}")
        # Skip extension update to avoid recursion
    
    def _update_extensions_statistics(self, files):
        """Update file extensions statistics display."""
        # Set flag to prevent recursive updates
        self._updating_extensions = True
        
        try:
            # Store current selections before clearing
            preserved_selections = self.selected_extensions.copy()
            
            # Disconnect signals and clear existing extension widgets
            for ext, checkbox in list(self.extension_checkboxes.items()):
                try:
                    if checkbox:
                        checkbox.toggled.disconnect()
                        checkbox.setParent(None)
                except:
                    pass
            
            # Clear existing extension widgets from layout
            for i in reversed(range(self.extensions_layout.count())):
                item = self.extensions_layout.itemAt(i)
                if item:
                    widget = item.widget()
                    if widget:
                        try:
                            widget.setParent(None)
                        except:
                            pass
            
            # Clear extension checkboxes dictionary
            self.extension_checkboxes.clear()
            
            if not files:
                self.extensions_label = QLabel("No files collected yet")
                self.extensions_layout.addWidget(self.extensions_label)
                self.extensions_layout.addStretch()
                self._updating_extensions = False
                return
            
            # Count file extensions
            extension_counter = Counter()
            for f in files:
                ext = os.path.splitext(f.get('name', ''))[1].lower()
                if not ext:
                    ext = '(no extension)'
                extension_counter[ext] += 1
            
            # Sort by count (descending)
            sorted_extensions = sorted(extension_counter.items(), key=lambda x: x[1], reverse=True)
            
            if not sorted_extensions:
                self.extensions_label = QLabel("No extensions found")
                self.extensions_layout.addWidget(self.extensions_label)
                self.extensions_layout.addStretch()
                self._updating_extensions = False
                return
            
            # Create checkbox extension items with bullet points
            for ext, count in sorted_extensions:
                ext_display = ext if ext != '(no extension)' else '(no extension)'
                ext_checkbox = self._create_extension_checkbox(ext_display, count, ext)
                
                # Block signals while setting up checkbox
                ext_checkbox.blockSignals(True)
                
                # Restore previous selection if it existed
                if ext in preserved_selections:
                    ext_checkbox.setChecked(True)
                    # Make sure it's in selected_extensions
                    self.selected_extensions.add(ext)
                else:
                    ext_checkbox.setChecked(False)
                    # Make sure it's not in selected_extensions
                    self.selected_extensions.discard(ext)
                
                ext_checkbox.blockSignals(False)
                
                self.extensions_layout.addWidget(ext_checkbox)
                self.extension_checkboxes[ext] = ext_checkbox
            
            self.extensions_layout.addStretch()
        finally:
            # Always reset the flag
            self._updating_extensions = False
    
    def _create_extension_checkbox(self, ext_display, count, extension):
        """Create a checkbox for extension selection with bullet point style."""
        checkbox = QCheckBox(f"• {ext_display}: {count:,}")
        checkbox.setStyleSheet("""
            QCheckBox {
                color: #cfe9ff;
                font-size: 9pt;
                spacing: 4px;
            }
            QCheckBox::indicator {
                width: 14px;
                height: 14px;
                border-radius: 3px;
                border: 1px solid #29b6d3;
                background-color: #0b141f;
            }
            QCheckBox::indicator:hover {
                border: 1px solid #55c7df;
            }
            QCheckBox::indicator:checked {
                background-color: qradialgradient(cx:0.5, cy:0.5, radius:0.6,
                                  fx:0.5, fy:0.5,
                                  stop:0 #4caf50,
                                  stop:1 #2e7d32);
                border: 1px solid #66bb6a;
            }
            QCheckBox:hover {
                color: #e5f8ff;
            }
            QCheckBox:checked {
                color: #a5d6a7;
            }
        """)
        checkbox.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        checkbox.setToolTip(f"Select to filter by extension: {extension}")
        # Use toggled signal instead of stateChanged - it's simpler and more reliable
        # Store extension in checkbox property for easier access
        checkbox.setProperty("extension", extension)
        checkbox.toggled.connect(self._on_extension_checkbox_toggled)
        return checkbox
    
    def _on_extension_checkbox_toggled(self, checked):
        """Handle extension checkbox toggle to filter the table."""
        # Prevent recursive updates
        if self._updating_extensions:
            return
        
        try:
            if not self.file_data:
                return
            
            # Get extension from checkbox property
            sender = self.sender()
            if not sender:
                return
            
            extension = sender.property("extension")
            if not extension:
                return
            
            # Verify checkbox exists in our dictionary
            checkbox = self.extension_checkboxes.get(extension)
            if not checkbox or checkbox != sender:
                return
            
            # Update selected extensions set
            if checked:
                self.selected_extensions.add(extension)
            else:
                self.selected_extensions.discard(extension)
            
            # Apply extension filter (defer to avoid blocking UI)
            QTimer.singleShot(0, self._apply_extension_filter)
        except Exception as e:
            # Error handling: log error
            import sys
            import traceback
            print(f"Error in extension checkbox handler: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
    
    def _filter_by_extensions(self, files):
        """Filter files by selected extensions."""
        if not self.selected_extensions:
            return files
        
        filtered = []
        for f in files:
            ext = os.path.splitext(f.get('name', ''))[1].lower()
            if not ext:
                ext = '(no extension)'
            if ext in self.selected_extensions:
                filtered.append(f)
        return filtered
    
    def _apply_extension_filter(self):
        """Apply extension filter based on selected checkboxes."""
        # Prevent recursive updates
        if self._updating_extensions:
            return
        
        try:
            if not self.file_data:
                return
            
            # Start with date-filtered data if applicable
            base_data = self._apply_date_filter(self.file_data)
            
            # Apply statistic filter if active
            if self.active_stat_filter:
                try:
                    base_data = self._filter_by_stat(base_data, self.active_stat_filter)
                except Exception as e:
                    import sys
                    print(f"Error applying stat filter: {e}", file=sys.stderr)
            
            # Apply extension filter if any extensions are selected
            if self.selected_extensions:
                try:
                    base_data = self._filter_by_extensions(base_data)
                except Exception as e:
                    import sys
                    print(f"Error applying extension filter: {e}", file=sys.stderr)
            
            # Apply search filter if any
            try:
                search_text = self.search_box.text().lower() if self.search_box else ""
                if search_text:
                    filtered = [
                        f for f in base_data
                        if search_text in f.get('name', '').lower() or
                        search_text in f.get('path', '').lower() or
                        search_text in f.get('sha256', '').lower()
                    ]
                    base_data = filtered
            except Exception as e:
                import sys
                print(f"Error applying search filter: {e}", file=sys.stderr)
            
            self.filtered_data = base_data
            # Update display - but prevent extension update recursion
            if not self.filtered_data:
                self.populate_table([])
                # Update statistics but skip extension update
                self._update_statistics_only(self.filtered_data)
            else:
                self.populate_table(self.filtered_data)
                # Update statistics but skip extension update to avoid recursion
                self._update_statistics_only(self.filtered_data)
        except Exception as e:
            import sys
            import traceback
            print(f"Error in _apply_extension_filter: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
    
    def export_data(self):
        """Export file data to a file."""
        if not self.file_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        import json
        
        # Export filtered data if available, otherwise all data
        data_to_export = self.filtered_data if self.filtered_data is not None else self.file_data
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export File Data", "files.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(data_to_export, f, indent=2)

