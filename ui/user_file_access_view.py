"""
User file access view widget for displaying file access events by user.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QComboBox
)
from PySide6.QtCore import Qt, QTimer
from datetime import datetime, timedelta


class UserFileAccessView(QWidget):
    """Widget for displaying file access events by user."""
    
    def __init__(self):
        super().__init__()
        self.file_access_data = None
        self.mft_data = None
        self.filtered_data = None
        self.show_mft = True  # Toggle to show MFT data
        self.init_ui()
        # Initialize with empty data to show UI elements
        self.update_data({'file_accesses': [], 'users': []})
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        
        # Control bar
        control_layout = QHBoxLayout()
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(8)
        
        # User filter dropdown
        self.user_filter = QComboBox()
        self.user_filter.setPlaceholderText("Select User")
        self.user_filter.addItem("All Users")
        self.user_filter.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self.user_filter.setMinimumWidth(200)
        view = self.user_filter.view()
        view.setMinimumWidth(300)
        self.user_filter.currentTextChanged.connect(self.on_user_filter_changed)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search files...")
        self.search_box.setMinimumWidth(200)
        self.search_box.textChanged.connect(self.filter_data)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.setMinimumWidth(80)
        self.export_btn.clicked.connect(self.export_data)
        
        control_layout.addWidget(QLabel("Filter User:"))
        control_layout.addWidget(self.user_filter)
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)
        control_layout.addStretch()
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Info label
        self.info_label = QLabel("Showing file access events and MFT data from the last 7 days. Select a user from the dropdown to filter.")
        self.info_label.setStyleSheet("color: #9fd1f5; font-size: 9pt; padding: 4px;")
        layout.addWidget(self.info_label)
        
        # Error label
        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #ff6f00; font-size: 9pt; padding: 4px; background-color: rgba(255, 111, 0, 0.1); border: 1px solid #ff6f00; border-radius: 4px;")
        self.error_label.setWordWrap(True)
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)
        
        # Table - expanded to include MFT data
        self.table = QTableWidget()
        self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels([
            "Time", "User", "Domain", "File Path", "Access Rights", "Process", "Process ID",
            "MFT Record", "Last Access", "Last Write", "Owner"
        ])
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self.table.resizeColumnsToContents()
        self.table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(self.table)
    
    def update_data(self, data):
        """Update the view with new file access data."""
        error_messages = []
        
        # Check if this is MFT data or file access data
        if 'mft_entries' in data:
            # This is MFT data
            self.mft_data = data.copy() if isinstance(data, dict) else data
            
            # Check for errors in MFT data
            if 'error' in data:
                error_messages.append(f"MFT Collection Error: {data['error']}")
        else:
            # This is file access event data
            # Ensure data has proper structure even if empty or None
            if not data:
                data = {'file_accesses': [], 'users': []}
            else:
                # Ensure required keys exist
                if 'file_accesses' not in data:
                    data['file_accesses'] = []
                if 'users' not in data:
                    data['users'] = []
            
            # Check for errors in file access data
            if 'error' in data:
                error_messages.append(f"File Access Collection Error: {data['error']}")
            
            # Store the data
            self.file_access_data = data.copy() if isinstance(data, dict) else data
            
            # Filter to last 7 days
            seven_days_ago = datetime.now() - timedelta(days=7)
            filtered_accesses = []
            for access in self.file_access_data.get('file_accesses', []):
                try:
                    access_time = datetime.fromisoformat(access['time'].replace('Z', '+00:00'))
                    if access_time.tzinfo is not None:
                        access_time = access_time.replace(tzinfo=None)
                    if access_time >= seven_days_ago:
                        filtered_accesses.append(access)
                except (ValueError, AttributeError, KeyError):
                    # If we can't parse the time, include it anyway (better to show than hide)
                    filtered_accesses.append(access)
            
            # Update the stored data with filtered accesses
            self.file_access_data['file_accesses'] = filtered_accesses
        
        # Display errors if any
        if error_messages:
            self.error_label.setText("\n".join(error_messages))
            self.error_label.setVisible(True)
        else:
            # Check if we have any data at all
            has_file_access = self.file_access_data and len(self.file_access_data.get('file_accesses', [])) > 0
            has_mft = self.mft_data and len(self.mft_data.get('mft_entries', [])) > 0
            
            if not has_file_access and not has_mft:
                # No data and no errors - might be normal (no events in last 7 days)
                self.error_label.setText("No file access events or MFT entries found in the last 7 days. This may be normal if:\n- Object Access auditing is not enabled (for event log)\n- No files were accessed in the monitored directories (for MFT)\n- The application is not running as Administrator")
                self.error_label.setVisible(True)
            else:
                self.error_label.setVisible(False)
        
        # Defer heavy work to make UI responsive
        def update_view():
            self.populate_user_filter()
            self.filter_data(self.search_box.text())
        
        QTimer.singleShot(0, update_view)
    
    def update_mft_data(self, mft_data):
        """Update MFT data separately."""
        if not mft_data:
            mft_data = {'mft_entries': [], 'users': []}
        self.update_data(mft_data)
    
    def populate_user_filter(self):
        """Populate the user filter dropdown from both file access and MFT data."""
        self.user_filter.blockSignals(True)
        self.user_filter.clear()
        self.user_filter.addItem("All Users")
        
        user_counts = {}
        
        # Get users from file access events
        if self.file_access_data:
            accesses = self.file_access_data.get('file_accesses', [])
            for access in accesses:
                username = access.get('username', 'Unknown')
                if username and username != 'Unknown':
                    user_counts[username] = user_counts.get(username, 0) + 1
        
        # Get users from MFT data
        if self.mft_data:
            mft_entries = self.mft_data.get('mft_entries', [])
            for entry in mft_entries:
                owner = entry.get('owner')
                if owner:
                    user_counts[owner] = user_counts.get(owner, 0) + 1
        
        # Sort users by count (descending)
        if user_counts:
            users_sorted = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)
            
            # Add users to dropdown with count
            for username, count in users_sorted:
                self.user_filter.addItem(f"{username} ({count})", username)
        
        self.user_filter.blockSignals(False)
    
    def on_user_filter_changed(self, text):
        """Handle user filter dropdown selection to filter table."""
        self.filter_data(self.search_box.text())
    
    def filter_data(self, search_text=""):
        """Filter table based on selected user and search text, combining file access and MFT data."""
        # Get selected user
        current_text = self.user_filter.currentText()
        if current_text == "All Users" or not current_text:
            selected_user = None
        else:
            selected_user = self.user_filter.currentData()
            if not selected_user:
                # Fallback: try to extract from text
                if " (" in current_text:
                    selected_user = current_text.split(" (")[0]
                else:
                    selected_user = current_text
        
        # Combine file access events and MFT entries
        combined_data = []
        
        # Add file access events
        if self.file_access_data:
            accesses = self.file_access_data.get('file_accesses', [])
            for access in accesses:
                # Filter by user
                if selected_user and access.get('username') != selected_user:
                    continue
                
                # Filter by search text
                search_lower = search_text.lower()
                if search_lower:
                    if not (search_lower in access.get('object_name', '').lower() or
                           search_lower in access.get('username', '').lower() or
                           search_lower in access.get('process_name', '').lower() or
                           search_lower in access.get('access_list', '').lower()):
                        continue
                
                combined_data.append({
                    'type': 'event',
                    'time': access.get('time_display', access.get('time', 'N/A')),
                    'user': access.get('username', 'N/A'),
                    'domain': access.get('domain', 'N/A'),
                    'file_path': access.get('object_name', 'N/A'),
                    'access_rights': access.get('access_list', 'N/A'),
                    'process': access.get('process_name', 'N/A'),
                    'process_id': access.get('process_id', 'N/A'),
                    'mft_record': None,
                    'last_access': None,
                    'last_write': None,
                    'owner': None
                })
        
        # Add MFT entries
        if self.mft_data:
            mft_entries = self.mft_data.get('mft_entries', [])
            for entry in mft_entries:
                # Filter by user (owner)
                if selected_user and entry.get('owner') != selected_user:
                    continue
                
                # Filter by search text
                search_lower = search_text.lower()
                if search_lower:
                    if not (search_lower in entry.get('file_path', '').lower() or
                           search_lower in entry.get('file_name', '').lower() or
                           search_lower in entry.get('owner', '').lower()):
                        continue
                
                combined_data.append({
                    'type': 'mft',
                    'time': entry.get('last_access_time', 'N/A'),
                    'user': entry.get('owner', 'N/A'),
                    'domain': entry.get('domain', 'N/A'),
                    'file_path': entry.get('file_path', 'N/A'),
                    'access_rights': 'N/A',
                    'process': 'N/A',
                    'process_id': 'N/A',
                    'mft_record': entry.get('mft_record_number', 'N/A'),
                    'last_access': entry.get('last_access_time', 'N/A'),
                    'last_write': entry.get('last_write_time', 'N/A'),
                    'owner': entry.get('owner', 'N/A')
                })
        
        self.filtered_data = combined_data
        self.populate_table(combined_data)
        
        # Update info label
        event_count = len([d for d in combined_data if d.get('type') == 'event'])
        mft_count = len([d for d in combined_data if d.get('type') == 'mft'])
        
        if selected_user:
            self.info_label.setText(
                f"Showing {len(combined_data)} items ({event_count} events, {mft_count} MFT entries) for user '{selected_user}' from the last 7 days."
            )
        else:
            self.info_label.setText(
                f"Showing {len(combined_data)} items ({event_count} events, {mft_count} MFT entries) from the last 7 days. Select a user from the dropdown to filter."
            )
    
    def populate_table(self, combined_data):
        """Populate the table with combined file access and MFT data."""
        if not combined_data:
            self.table.setRowCount(0)
            return
        
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        
        try:
            self.table.setRowCount(len(combined_data))
            
            for row, item in enumerate(combined_data):
                # Time
                time_str = item.get('time', 'N/A')
                if time_str and time_str != 'N/A':
                    # Format ISO datetime if needed
                    try:
                        if 'T' in time_str:
                            dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                            if dt.tzinfo:
                                dt = dt.replace(tzinfo=None)
                            time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        pass
                self.table.setItem(row, 0, QTableWidgetItem(time_str))
                
                # User
                username = item.get('user', 'N/A')
                self.table.setItem(row, 1, QTableWidgetItem(username))
                
                # Domain
                domain = item.get('domain', 'N/A')
                self.table.setItem(row, 2, QTableWidgetItem(domain))
                
                # File Path
                file_path = item.get('file_path', 'N/A')
                file_path_item = QTableWidgetItem(file_path)
                if len(file_path) > 100:
                    file_path_item.setToolTip(file_path)
                self.table.setItem(row, 3, file_path_item)
                
                # Access Rights
                access_rights = item.get('access_rights', 'N/A')
                access_item = QTableWidgetItem(access_rights)
                if len(access_rights) > 100:
                    access_item.setToolTip(access_rights)
                self.table.setItem(row, 4, access_item)
                
                # Process
                process = item.get('process', 'N/A')
                self.table.setItem(row, 5, QTableWidgetItem(process))
                
                # Process ID
                process_id = item.get('process_id', 'N/A')
                self.table.setItem(row, 6, QTableWidgetItem(str(process_id)))
                
                # MFT Record
                mft_record = item.get('mft_record', 'N/A')
                self.table.setItem(row, 7, QTableWidgetItem(str(mft_record) if mft_record else 'N/A'))
                
                # Last Access
                last_access = item.get('last_access', 'N/A')
                if last_access and last_access != 'N/A':
                    try:
                        if 'T' in last_access:
                            dt = datetime.fromisoformat(last_access.replace('Z', '+00:00'))
                            if dt.tzinfo:
                                dt = dt.replace(tzinfo=None)
                            last_access = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        pass
                self.table.setItem(row, 8, QTableWidgetItem(last_access))
                
                # Last Write
                last_write = item.get('last_write', 'N/A')
                if last_write and last_write != 'N/A':
                    try:
                        if 'T' in last_write:
                            dt = datetime.fromisoformat(last_write.replace('Z', '+00:00'))
                            if dt.tzinfo:
                                dt = dt.replace(tzinfo=None)
                            last_write = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        pass
                self.table.setItem(row, 9, QTableWidgetItem(last_write))
                
                # Owner
                owner = item.get('owner', 'N/A')
                self.table.setItem(row, 10, QTableWidgetItem(owner))
            
            # Resize columns only once after all rows are populated
            self.table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            self.table.setUpdatesEnabled(True)
            self.table.setSortingEnabled(was_sorting)
    
    def export_data(self):
        """Export file access and MFT data to a file."""
        if not self.file_access_data and not self.mft_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export File Access & MFT Data", "file_access_mft.json", "JSON Files (*.json)"
        )
        
        if filename:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'file_access_events': self.file_access_data.get('file_accesses', []) if self.file_access_data else [],
                'mft_entries': self.mft_data.get('mft_entries', []) if self.mft_data else [],
                'combined_data': self.filtered_data if self.filtered_data is not None else [],
                'total_events': len(self.file_access_data.get('file_accesses', [])) if self.file_access_data else 0,
                'total_mft_entries': len(self.mft_data.get('mft_entries', [])) if self.mft_data else 0
            }
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)

