"""
Service view widget for displaying service information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QMessageBox,
    QRadioButton, QButtonGroup
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QBrush
import os


class ServiceView(QWidget):
    """Widget for displaying service information."""
    
    # Common LOLBINs (Living Off The Land Binaries)
    LOLBINS = {
        'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wmic.exe', 'reg.exe',
        'certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'rundll32.exe',
        'msbuild.exe', 'csc.exe', 'cscript.exe', 'wscript.exe',
        'msiexec.exe', 'schtasks.exe', 'sc.exe', 'net.exe', 'netstat.exe',
        'tasklist.exe', 'whoami.exe', 'systeminfo.exe', 'ipconfig.exe',
        'arp.exe', 'nslookup.exe', 'ping.exe', 'tracert.exe', 'route.exe',
        'at.exe', 'attrib.exe', 'copy.exe', 'xcopy.exe', 'robocopy.exe',
        'wevtutil.exe', 'bcdedit.exe', 'diskpart.exe', 'vssadmin.exe',
        'wbinfo.exe', 'dsquery.exe', 'dsget.exe', 'netdom.exe',
        'nltest.exe', 'quser.exe', 'qprocess.exe', 'qwinsta.exe',
        'rclone.exe', 'curl.exe', 'wget.exe', 'findstr.exe', 'find.exe',
        'forfiles.exe', 'ftp.exe', 'telnet.exe', 'tftp.exe', 'ncat.exe',
        'nc.exe', 'netcat.exe', 'python.exe', 'pythonw.exe', 'perl.exe',
        'ruby.exe', 'java.exe', 'javaw.exe', 'node.exe', 'php.exe',
        'ssh.exe', 'scp.exe', 'sftp.exe', 'plink.exe', 'pscp.exe',
        'psftp.exe', 'rsh.exe', 'rcp.exe', 'rexec.exe', 'rlogin.exe',
        'rsync.exe', 'svchost.exe', 'dllhost.exe', 'regsvr32.exe',
        'odbcconf.exe', 'cmstp.exe', 'msxsl.exe', 'winrm.exe', 'winrs.exe'
    }
    
    def __init__(self):
        super().__init__()
        self.service_data = None
        self.error_label = None
        self.notification_callback = None  # Callback for notifications
        self.pending_services = []  # Services waiting to be populated
        self.batch_timer = QTimer(self)
        self.batch_timer.setSingleShot(True)
        self.batch_timer.timeout.connect(self._process_next_batch)
        self.batch_size = 50  # Process 50 items at a time for better responsiveness
        self.current_batch_index = 0
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
        self.search_box.setPlaceholderText("Search services...")
        self.search_box.textChanged.connect(self.filter_services)
        
        # Status filter radio buttons
        self.status_group = QButtonGroup(self)
        self.status_all_radio = QRadioButton("All")
        self.status_running_radio = QRadioButton("Running")
        self.status_stopped_radio = QRadioButton("Stopped")
        
        self.status_all_radio.setChecked(True)  # Default to "All"
        
        self.status_group.addButton(self.status_all_radio, 0)
        self.status_group.addButton(self.status_running_radio, 1)
        self.status_group.addButton(self.status_stopped_radio, 2)
        
        # Connect radio buttons to filter
        self.status_all_radio.toggled.connect(self.filter_services)
        self.status_running_radio.toggled.connect(self.filter_services)
        self.status_stopped_radio.toggled.connect(self.filter_services)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_data)
        
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)
        control_layout.addWidget(QLabel("Status:"))
        control_layout.addWidget(self.status_all_radio)
        control_layout.addWidget(self.status_running_radio)
        control_layout.addWidget(self.status_stopped_radio)
        control_layout.addStretch()
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Error label (hidden by default)
        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet("color: rgb(255, 100, 100); padding: 8px; background-color: #1A0000; border: 2px solid #FF0000; border-radius: 0px; font-weight: 500;")
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Service Name", "Display Name", "Status", "LOLBIN", "Start Type",
            "Binary Path", "Description"
        ])
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        # Performance optimizations
        self.table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)  # Smoother scrolling
        self.table.resizeColumnsToContents()
        
        # Set row height for better readability when editing
        self.table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(self.table)
    
    def update_data(self, data):
        """Update the view with new service data."""
        if not data:
            self.error_label.setText("No data received.")
            self.error_label.setVisible(True)
            self.service_data = []
            QTimer.singleShot(0, lambda: self.populate_table([]))
            return
        
        if 'services' not in data:
            error_msg = data.get('error', 'Unknown error: services key missing')
            self.error_label.setText(f"Error: {error_msg}")
            self.error_label.setVisible(True)
            self.service_data = []
            QTimer.singleShot(0, lambda: self.populate_table([]))
            # Also show a message box for visibility
            QMessageBox.warning(self, "Service Collection Error", error_msg)
            return
        
        # Check for errors in data
        if 'error' in data:
            error_msg = data['error']
            self.error_label.setText(f"Warning: {error_msg}")
            self.error_label.setVisible(True)
            # Still show services if we have any
        else:
            self.error_label.setVisible(False)
        
        services_list = data['services'] or []
        self.service_data = services_list
        # Defer heavy work to make UI responsive
        QTimer.singleShot(0, lambda: self.populate_table(services_list))
        
        # If no services and no error, show a message
        if not self.service_data and 'error' not in data:
            self.error_label.setText("No services found.")
            self.error_label.setVisible(True)
    
    def populate_table(self, services):
        """Populate the table with service data (chunked for better UI responsiveness)."""
        if not services:
            self.table.setRowCount(0)
            return
        
        # Stop any existing batch processing
        self.batch_timer.stop()
        
        # Store services and reset batch index
        self.pending_services = services
        self.current_batch_index = 0
        
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        
        # Set total row count upfront
        total_rows = len(services)
        self.table.setRowCount(total_rows)
        
        # Store sorting state for later restoration
        self._was_sorting = was_sorting
        
        # Start processing first batch
        self._process_next_batch()
    
    def _process_next_batch(self):
        """Process the next batch of services with proper yielding to event loop."""
        if not self.pending_services or self.current_batch_index >= len(self.pending_services):
            # All done, re-enable updates and sorting
            total_rows = len(self.pending_services) if self.pending_services else 0
            self.table.setUpdatesEnabled(True)
            self.table.setSortingEnabled(self._was_sorting)
            self.table.resizeColumnsToContents()
            
            # Final notification
            if self.notification_callback and total_rows > 0:
                self.notification_callback(f"Service table updated: {total_rows} records loaded")
            
            # Clear pending services
            self.pending_services = []
            return
        
        # Get next batch
        batch_start = self.current_batch_index
        batch_end = min(batch_start + self.batch_size, len(self.pending_services))
        batch = self.pending_services[batch_start:batch_end]
        
        # Populate this batch
        for i, service in enumerate(batch):
            row = batch_start + i
            try:
                # Safely convert all values to strings
                name = str(service.get('name', 'N/A'))
                display_name = str(service.get('display_name', 'N/A'))
                status = str(service.get('status', 'N/A'))
                start_type = str(service.get('start_type', 'N/A'))
                binary_path = str(service.get('binary_path', 'N/A'))
                description = str(service.get('description', 'N/A'))
                
                self.table.setItem(row, 0, QTableWidgetItem(name))
                self.table.setItem(row, 1, QTableWidgetItem(display_name))
                self.table.setItem(row, 2, QTableWidgetItem(status))
                
                # Check if executable name is a LOLBIN and add to LOLBIN column
                is_lolbin = False
                if binary_path and binary_path != 'N/A':
                    # Extract executable name from binary path
                    # Handle paths that might be quoted or have arguments
                    executable_name = binary_path.split()[0].strip('"\'')
                    executable_name = os.path.basename(executable_name).lower()
                    
                    if executable_name in self.LOLBINS:
                        is_lolbin = True
                
                # Add LOLBIN column (after Status)
                lolbin_item = QTableWidgetItem("Yes" if is_lolbin else "No")
                if is_lolbin:
                    lolbin_item.setForeground(QBrush(QColor(100, 160, 220)))  # Blue text for LOLBIN
                self.table.setItem(row, 3, lolbin_item)
                
                self.table.setItem(row, 4, QTableWidgetItem(start_type))
                
                path_item = QTableWidgetItem(binary_path)
                if len(binary_path) > 50:
                    path_item.setToolTip(binary_path)
                self.table.setItem(row, 5, path_item)
                
                desc_item = QTableWidgetItem(description)
                if len(description) > 50:
                    desc_item.setToolTip(description)
                self.table.setItem(row, 6, desc_item)
            except Exception as e:
                # Still add the row with error info
                self.table.setItem(row, 0, QTableWidgetItem(service.get('name', f'Service {row}')))
                self.table.setItem(row, 1, QTableWidgetItem('Error'))
                self.table.setItem(row, 2, QTableWidgetItem('N/A'))
                self.table.setItem(row, 3, QTableWidgetItem('N/A'))  # LOLBIN column
                self.table.setItem(row, 4, QTableWidgetItem('N/A'))
                self.table.setItem(row, 5, QTableWidgetItem(f'Error: {str(e)}'))
                self.table.setItem(row, 6, QTableWidgetItem('N/A'))
        
        # Update batch index
        self.current_batch_index = batch_end
        
        # Re-enable updates temporarily to show progress
        self.table.setUpdatesEnabled(True)
        self.table.setUpdatesEnabled(False)
        
        # Show notification for this batch
        if self.notification_callback and batch_end < len(self.pending_services):
            self.notification_callback(f"Service table: {batch_end}/{len(self.pending_services)} records loaded...")
        
        # Schedule next batch with a small delay to yield to event loop
        if batch_end < len(self.pending_services):
            self.batch_timer.start(10)  # Process next batch after 10ms
        else:
            # All done, re-enable updates and sorting
            self.table.setUpdatesEnabled(True)
            self.table.setSortingEnabled(self._was_sorting)
            self.table.resizeColumnsToContents()
            
            # Final notification
            if self.notification_callback:
                self.notification_callback(f"Service table updated: {len(self.pending_services)} records loaded")
            
            # Clear pending services
            self.pending_services = []
    
    def filter_services(self, text=None):
        """Filter services based on search text and status."""
        if not self.service_data:
            return
        
        # Get search text (if called from textChanged, text is the search string)
        # If called from radio button, text is the checked state (True/False)
        if text is None or isinstance(text, bool):
            search_text = self.search_box.text()
        else:
            search_text = text
        
        # Get selected status filter
        selected_status = None
        if self.status_running_radio.isChecked():
            selected_status = 'Running'
        elif self.status_stopped_radio.isChecked():
            selected_status = 'Stopped'
        # If "All" is selected, selected_status remains None
        
        # Filter by text and status
        filtered = []
        for s in self.service_data:
            # Text filter
            text_match = (
                not search_text or
                search_text.lower() in s['name'].lower() or
                search_text.lower() in s['display_name'].lower()
            )
            
            # Status filter
            status_match = (
                selected_status is None or
                s.get('status', '') == selected_status
            )
            
            if text_match and status_match:
                filtered.append(s)
        
        self.populate_table(filtered)
    
    def export_data(self):
        """Export service data to a file."""
        if not self.service_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Service Data", "services.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.service_data, f, indent=2)
    

