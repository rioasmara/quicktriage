"""
DLL view widget for displaying DLL load information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QMenu,
    QRadioButton, QButtonGroup, QFrame, QStyledItemDelegate
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QBrush, QPainter


class TableHighlightDelegate(QStyledItemDelegate):
    """Custom delegate to paint backgrounds that won't be overridden by stylesheet."""
    
    def __init__(self, table_view):
        super().__init__()
        self.table_view = table_view
    
    def paint(self, painter, option, index):
        """Paint the item with custom background if it has one."""
        # Get row and column
        row = index.row()
        col = index.column()
        
        # Check if this cell has a highlight color stored in the item's data
        item = self.table_view.item(row, col)
        if item:
            # Check if item has background/foreground set
            bg_brush = item.background()
            fg_brush = item.foreground()
            
            # If background is not default (has a color), paint it
            if bg_brush.style() != 0:  # Not NoBrush
                bg_color = bg_brush.color()
                if bg_color.isValid() and bg_color != QColor(0, 0, 0, 0):  # Not transparent
                    # Paint background
                    painter.fillRect(option.rect, bg_color)
                    
                    # Set foreground color if specified
                    if fg_brush.style() != 0:  # Not NoBrush
                        fg_color = fg_brush.color()
                        if fg_color.isValid():
                            option.palette.setColor(option.palette.ColorRole.Text, fg_color)
        
        # Let default delegate handle text rendering
        super().paint(painter, option, index)


import threading
from datetime import datetime
import subprocess
import os


class DLLView(QWidget):
    """Widget for displaying DLL load information."""
    
    def __init__(self):
        super().__init__()
        self.dll_data = []
        self.dll_data_lock = threading.Lock()  # Thread-safe access to DLL data
        self.filtered_dlls = []  # Currently filtered/displayed DLLs
        self.current_filter = "all"  # Current radio button filter: "all", "trusted", "untrusted", "uncommon", "injected"
        # Batching for incremental updates
        self.incremental_batch = []  # Queue for batched incremental updates
        self.batch_size = 150  # Number of records to batch before adding to grid
        self.batch_timer = QTimer(self)
        self.batch_timer.setSingleShot(True)
        self.batch_timer.timeout.connect(self._flush_incremental_batch)
        self.notification_callback = None  # Callback for notifications
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        
        # Color legend
        legend = self._create_legend()
        layout.addWidget(legend)
        
        # Control bar
        control_layout = QHBoxLayout()
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(4)
        
        self.refresh_btn = QPushButton("Refresh")
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_data)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search DLLs...")
        self.search_box.textChanged.connect(self.apply_filters)
        
        # Statistics label
        self.stats_label = QLabel("Total: 0 | Trusted: 0 | Untrusted: 0 | Uncommon Paths: 0 | Injected: 0")
        
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)
        control_layout.addStretch()
        control_layout.addWidget(self.stats_label)
        control_layout.addWidget(self.refresh_btn)
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Radio button filter section
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter:")
        
        # Create radio buttons
        self.filter_all = QRadioButton("All")
        self.filter_trusted = QRadioButton("Trusted")
        self.filter_untrusted = QRadioButton("Untrusted")
        self.filter_uncommon = QRadioButton("Uncommon Paths")
        self.filter_injected = QRadioButton("Injected")
        
        # Set default selection
        self.filter_all.setChecked(True)
        
        # Create button group to ensure only one is selected
        self.filter_group = QButtonGroup(self)
        self.filter_group.addButton(self.filter_all, 0)
        self.filter_group.addButton(self.filter_trusted, 1)
        self.filter_group.addButton(self.filter_untrusted, 2)
        self.filter_group.addButton(self.filter_uncommon, 3)
        self.filter_group.addButton(self.filter_injected, 4)
        
        # Connect radio buttons to filter method
        self.filter_all.toggled.connect(lambda checked: checked and self.on_filter_changed("all"))
        self.filter_trusted.toggled.connect(lambda checked: checked and self.on_filter_changed("trusted"))
        self.filter_untrusted.toggled.connect(lambda checked: checked and self.on_filter_changed("untrusted"))
        self.filter_uncommon.toggled.connect(lambda checked: checked and self.on_filter_changed("uncommon"))
        self.filter_injected.toggled.connect(lambda checked: checked and self.on_filter_changed("injected"))
        
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_all)
        filter_layout.addWidget(self.filter_trusted)
        filter_layout.addWidget(self.filter_untrusted)
        filter_layout.addWidget(self.filter_uncommon)
        filter_layout.addWidget(self.filter_injected)
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels([
            "PID", "Process Name", "DLL Name", "DLL Path",
            "Trusted", "Signature Status", "Signer", "Injection Status", "Created"
        ])
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        # Don't auto-resize columns initially - let user resize manually to see full paths
        self.table.horizontalHeader().setStretchLastSection(False)
        # Performance optimizations
        self.table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)  # Smoother scrolling
        
        # Set row height for better readability when editing
        self.table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(self.table)
    
    def clear_data(self):
        """Clear all DLL data from the table (called when starting new collection)."""
        with self.dll_data_lock:
            self.dll_data = []
        self.incremental_batch.clear()
        self.batch_timer.stop()
        self.table.setRowCount(0)
        self.stats_label.setText("Total: 0 | Trusted: 0 | Untrusted: 0 | Uncommon Paths: 0 | Injected: 0")
    
    def update_data(self, data):
        """Update the table with new DLL data (can be full or incremental)."""
        if not data or 'dlls' not in data:
            return
        
        # Thread-safe update
        with self.dll_data_lock:
            # If this is a full update (replacing all data), clear existing
            if data.get('is_full_update', False):
                self.dll_data = data['dlls'].copy()
            else:
                # Incremental update - append new DLLs
                new_dlls = data['dlls']
                # Avoid duplicates by checking if DLL already exists
                existing_keys = {(d['pid'], d['dll_path']) for d in self.dll_data}
                for dll in new_dlls:
                    key = (dll['pid'], dll['dll_path'])
                    if key not in existing_keys:
                        self.dll_data.append(dll)
                        existing_keys.add(key)
        
        # Defer heavy work to make UI responsive
        def update_view():
            # Apply current filters
            self.apply_filters()
            
            # Update statistics
            with self.dll_data_lock:
                total = len(self.dll_data)
                trusted = sum(1 for d in self.dll_data if d.get('is_trusted', False))
                untrusted = total - trusted
                uncommon_count = sum(1 for d in self.dll_data if not d.get('is_common_path', True))
                injected_count = sum(1 for d in self.dll_data if d.get('is_injected', False))
            self.stats_label.setText(f"Total: {total} | Trusted: {trusted} | Untrusted: {untrusted} | Uncommon Paths: {uncommon_count} | Injected: {injected_count}")
        
        QTimer.singleShot(0, update_view)
    
    def add_dll_incremental(self, dll_info):
        """Add a single DLL entry incrementally to the table (batched)."""
        # Add to batch queue
        self.incremental_batch.append(dll_info)
        
        # Only flush when batch reaches 50 records
        if len(self.incremental_batch) >= self.batch_size:
            self._flush_incremental_batch()
    
    def _flush_incremental_batch(self):
        """Flush the batched incremental updates to the table."""
        if not self.incremental_batch:
            return
        
        # Get all items in batch
        batch = self.incremental_batch[:]
        self.incremental_batch.clear()
        
        # Thread-safe add to data
        with self.dll_data_lock:
            existing_keys = {(d['pid'], d['dll_path']) for d in self.dll_data}
            new_items = []
            
            for dll_info in batch:
                # Check if DLL already exists
                key = (dll_info['pid'], dll_info['dll_path'])
                if key in existing_keys:
                    continue  # Already exists, skip
                
                self.dll_data.append(dll_info)
                existing_keys.add(key)
                new_items.append(dll_info)
            
            total = len(self.dll_data)
            trusted = sum(1 for d in self.dll_data if d.get('is_trusted', False))
            untrusted = total - trusted
            uncommon_count = sum(1 for d in self.dll_data if not d.get('is_common_path', True))
            injected_count = sum(1 for d in self.dll_data if d.get('is_injected', False))
        
        # Add new items to table in batch
        if new_items:
            # Filter items that should be visible based on current filters
            visible_items = [dll_info for dll_info in new_items if self._should_show_dll(dll_info)]
            
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
                    for i, dll_info in enumerate(visible_items):
                        row = current_row_count + i
                        self._populate_row(row, dll_info)
                finally:
                    # Re-enable updates and sorting
                    self.table.setUpdatesEnabled(True)
                    self.table.setSortingEnabled(was_sorting)
            
            # Update statistics
            self.stats_label.setText(f"Total: {total} | Trusted: {trusted} | Untrusted: {untrusted} | Uncommon Paths: {uncommon_count} | Injected: {injected_count}")
            
            # Show notification only when we actually added records (and it's a full batch or final batch)
            if self.notification_callback and len(new_items) > 0:
                # Only show notification for batches of 150 (or final batch)
                if len(batch) >= 150 or len(self.incremental_batch) == 0:
                    self.notification_callback(f"DLL table updated: +{len(new_items)} records (Total: {total})")
    
    def populate_table(self, dlls):
        """Populate the table with DLL data (batched for better performance)."""
        if not dlls:
            self.table.setRowCount(0)
            return
        
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        
        try:
            # Process in batches of 150
            batch_size = 150
            total_rows = len(dlls)
            self.table.setRowCount(total_rows)
            
            for batch_start in range(0, total_rows, batch_size):
                batch_end = min(batch_start + batch_size, total_rows)
                batch = dlls[batch_start:batch_end]
                
                # Populate this batch
                for i, dll in enumerate(batch):
                    row = batch_start + i
                    self._populate_row(row, dll)
                
                # Re-enable updates temporarily to show progress
                self.table.setUpdatesEnabled(True)
                self.table.setUpdatesEnabled(False)
                
                # Show notification for each batch
                if self.notification_callback and batch_end < total_rows:
                    self.notification_callback(f"DLL table: {batch_end}/{total_rows} records loaded...")
            
            # Final notification
            if self.notification_callback:
                self.notification_callback(f"DLL table updated: {total_rows} records loaded")
            
            # Auto-resize columns only once after all rows are populated
            if total_rows > 0:
                self.table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            self.table.setUpdatesEnabled(True)
            self.table.setSortingEnabled(was_sorting)
    
    def _populate_row(self, row, dll):
        """Populate a single row with DLL data."""
        # Enhanced color for highlighting uncommon paths - darker orange/yellow for better contrast
        uncommon_path_color = QColor(220, 180, 50)  # Darker yellow/orange for better contrast
        uncommon_path_fg = QColor(0, 0, 0)  # Black text on yellow background
        
        # Color for injected DLLs - red/pink background
        injected_color = QColor(200, 80, 100)  # Red/pink for injected DLLs
        injected_fg = QColor(255, 255, 255)  # White text on red background
        
        is_uncommon_path = not dll.get('is_common_path', True)
        is_injected = dll.get('is_injected', False)
        
        # Priority: Injected > Uncommon Path
        highlight_color = injected_color if is_injected else (uncommon_path_color if is_uncommon_path else None)
        highlight_fg = injected_fg if is_injected else (uncommon_path_fg if is_uncommon_path else None)
        
        # Helper function to set item with highlighting
        def set_item_with_highlight(col, item):
            if highlight_color:
                item.setBackground(QBrush(highlight_color))
            if highlight_fg:
                item.setForeground(QBrush(highlight_fg))
            self.table.setItem(row, col, item)
        
        # PID
        pid_item = QTableWidgetItem(str(dll['pid']))
        set_item_with_highlight(0, pid_item)
        
        # Process Name
        process_item = QTableWidgetItem(dll['process_name'])
        set_item_with_highlight(1, process_item)
        
        # DLL Name
        dll_name_item = QTableWidgetItem(dll['dll_name'])
        set_item_with_highlight(2, dll_name_item)
        
        # DLL Path - don't truncate, show full path
        path_item = QTableWidgetItem(dll['dll_path'])
        path_item.setToolTip(dll['dll_path'])  # Always show tooltip with full path
        set_item_with_highlight(3, path_item)
        
        # Trusted Status
        trusted_item = QTableWidgetItem("Yes" if dll['is_trusted'] else "No")
        if not highlight_color:  # Only set foreground if not highlighted
            if not dll['is_trusted']:
                trusted_item.setForeground(QBrush(QColor(220, 100, 100)))  # Darker red for better contrast
            else:
                trusted_item.setForeground(QBrush(QColor(50, 180, 50)))  # Darker green for better contrast
        set_item_with_highlight(4, trusted_item)
        
        # Signature Status
        status_item = QTableWidgetItem(dll['signature_status'])
        if not highlight_color and dll['signature_status'] != 'Valid':
            status_item.setForeground(QBrush(QColor(220, 100, 100)))  # Darker red for better contrast
        set_item_with_highlight(5, status_item)
        
        # Signer - don't truncate, show full signer info
        signer_item = QTableWidgetItem(dll['signer'])
        signer_item.setToolTip(dll['signer'])  # Always show tooltip with full signer
        set_item_with_highlight(6, signer_item)
        
        # Injection Status
        injection_reason = dll.get('injection_reason', 'Normal')
        injection_item = QTableWidgetItem(injection_reason)
        injection_item.setToolTip(injection_reason)  # Show full reason in tooltip
        if is_injected:
            # Make injected status stand out even more
            injection_item.setForeground(QBrush(QColor(255, 200, 200)))  # Light red text
        set_item_with_highlight(7, injection_item)
        
        # Creation Time
        creation_time = dll.get('creation_time', 'N/A')
        # Format the timestamp to be more readable (remove microseconds if present)
        if creation_time != 'N/A' and 'T' in creation_time:
            try:
                # Format: YYYY-MM-DD HH:MM:SS
                dt = datetime.fromisoformat(creation_time.replace('Z', '+00:00'))
                creation_time = dt.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, AttributeError):
                pass  # Keep original format if parsing fails
        
        created_item = QTableWidgetItem(creation_time)
        set_item_with_highlight(8, created_item)
    
    def on_filter_changed(self, filter_type):
        """Handle radio button filter change."""
        self.current_filter = filter_type
        self.apply_filters()
    
    def _should_show_dll(self, dll):
        """Check if a DLL should be shown based on current filters."""
        # Apply radio button filter
        if self.current_filter == "trusted":
            if not dll.get('is_trusted', False):
                return False
        elif self.current_filter == "untrusted":
            if dll.get('is_trusted', False):
                return False
        elif self.current_filter == "uncommon":
            if dll.get('is_common_path', True):
                return False
        elif self.current_filter == "injected":
            if not dll.get('is_injected', False):
                return False
        
        # Apply search text filter
        search_text = self.search_box.text().lower()
        if search_text:
            injection_reason = dll.get('injection_reason', 'Normal').lower()
            if not (search_text in dll['dll_name'].lower() or
                    search_text in dll['dll_path'].lower() or
                    search_text in dll['process_name'].lower() or
                    search_text in str(dll['pid']) or
                    search_text in dll['signature_status'].lower() or
                    search_text in dll['signer'].lower() or
                    search_text in injection_reason or
                    search_text in str(dll.get('creation_time', '')).lower()):
                return False
        
        return True
    
    def apply_filters(self):
        """Apply both search text and radio button filters."""
        with self.dll_data_lock:
            if not self.dll_data:
                self.table.setRowCount(0)
                return
        
        with self.dll_data_lock:
            filtered = [d for d in self.dll_data if self._should_show_dll(d)]
        
        self.filtered_dlls = filtered
        self.populate_table(filtered)
    
    def filter_dlls(self, text):
        """Filter DLLs based on search text (legacy method, now calls apply_filters)."""
        self.apply_filters()
    
    def export_data(self):
        """Export DLL data to a file."""
        from PySide6.QtWidgets import QFileDialog
        import json
        
        # Thread-safe access to DLL data
        with self.dll_data_lock:
            if not self.dll_data:
                return
            data_to_export = self.dll_data.copy()
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export DLL Data", "dlls.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(data_to_export, f, indent=2)
    
    def show_context_menu(self, position):
        """Show context menu on right-click."""
        # Get the row at the click position
        row = self.table.rowAt(position.y())
        if row < 0:
            return
        
        # Get DLL path from the selected row
        dll_path_item = self.table.item(row, 3)  # Column 3 is DLL Path
        if not dll_path_item:
            return
        
        dll_path = dll_path_item.text()
        
        # Create context menu
        context_menu = QMenu(self)
        
        # Add "Show in Folder" action
        show_in_folder_action = context_menu.addAction("Show in Folder")
        show_in_folder_action.triggered.connect(lambda: self.open_in_explorer(dll_path))
        
        # Show context menu at cursor position (map viewport coordinates to global)
        global_position = self.table.viewport().mapToGlobal(position)
        context_menu.exec(global_position)
    
    def open_in_explorer(self, file_path):
        """Open Windows Explorer and highlight the selected file."""
        if not file_path or not os.path.exists(file_path):
            from PySide6.QtWidgets import QMessageBox
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
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open Windows Explorer:\n{str(e)}"
            )
    
    def _create_legend(self):
        """Create a color legend widget."""
        legend_frame = QFrame()
        legend_frame.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Plain)
        legend_frame.setStyleSheet(
            "QFrame {"
            " background-color: #121f2d;"
            " padding: 8px 10px;"
            " border: 1px solid #29b6d3;"
            " border-radius: 6px;"
            "}"
        )
        legend_frame.setMinimumHeight(48)
        legend_frame.setMaximumHeight(56)
        legend_layout = QHBoxLayout(legend_frame)
        legend_layout.setSpacing(6)
        legend_layout.setContentsMargins(6, 4, 6, 4)
        
        # Orange-yellow background with black text - Uncommon paths (darker yellow/orange for better contrast)
        orange_box = QLabel()
        orange_box.setFixedSize(14, 14)
        orange_box.setStyleSheet(
            "background-color: #dcb432;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(orange_box)
        orange_label = QLabel("Yellow: Uncommon paths")
        orange_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(orange_label)
        
        # Red/pink background with white text - Injected DLLs
        injected_box = QLabel()
        injected_box.setFixedSize(14, 14)
        injected_box.setStyleSheet(
            "background-color: #c85064;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(injected_box)
        injected_label = QLabel("Red: Injected DLLs")
        injected_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(injected_label)
        
        # Red text - Untrusted/Invalid signature
        red_text_label = QLabel("Red Text")
        red_text_label.setStyleSheet(
            "QLabel { color: #ff7a7a; font-weight: 600; font-size: 9pt; background-color: transparent; }"
        )
        legend_layout.addWidget(red_text_label)
        red_label = QLabel(": Untrusted/Invalid")
        red_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(red_label)
        
        # Green text - Trusted
        green_text_label = QLabel("Green Text")
        green_text_label.setStyleSheet(
            "QLabel { color: #58f29c; font-weight: 600; font-size: 9pt; background-color: transparent; }"
        )
        legend_layout.addWidget(green_text_label)
        green_label = QLabel(": Trusted")
        green_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(green_label)
        
        legend_layout.addStretch()
        return legend_frame

