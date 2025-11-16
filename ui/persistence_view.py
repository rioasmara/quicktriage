"""
Persistence view widget for displaying persistence mechanism information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QTabWidget,
    QTextEdit, QGroupBox, QTreeWidget, QTreeWidgetItem, QFrame,
    QStyledItemDelegate
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


import json
import os
from datetime import datetime, timedelta


class PersistenceView(QWidget):
    """Widget for displaying persistence mechanism information."""
    
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
        self.persistence_data = None
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
        self.search_box.setPlaceholderText("Search persistence mechanisms...")
        self.search_box.textChanged.connect(self.filter_data)
        
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)
        control_layout.addStretch()
        control_layout.addWidget(self.refresh_btn)
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Tab widget for different persistence types
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Create tab pages
        self.create_registry_run_tab()
        self.create_registry_logon_tab()
        self.create_registry_ifeo_tab()
        self.create_registry_appinit_tab()
        self.create_startup_folders_tab()
        self.create_scheduled_tasks_tab()
        self.create_wmi_subscriptions_tab()
        self.create_services_tab()
        self.create_summary_tab()
    
    def create_registry_run_tab(self):
        """Create tab for registry run keys."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Registry Hive", "Key Path", "Value Name", "Value"])
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setWordWrap(True)
        # Set consistent row height (same as process tree)
        table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(QLabel("<b>Registry Run Keys</b>"))
        layout.addWidget(QLabel("These keys execute programs at startup/login"))
        layout.addWidget(table)
        
        self.registry_run_table = table
        self.tabs.addTab(widget, "Registry Run Keys")
    
    def create_registry_logon_tab(self):
        """Create tab for registry logon keys."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Registry Hive", "Key Path", "Value Name", "Value"])
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setWordWrap(True)
        # Set consistent row height (same as process tree)
        table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(QLabel("<b>Registry Logon Keys</b>"))
        layout.addWidget(QLabel("Winlogon configuration keys"))
        layout.addWidget(table)
        
        self.registry_logon_table = table
        self.tabs.addTab(widget, "Logon Keys")
    
    def create_registry_ifeo_tab(self):
        """Create tab for Image File Execution Options."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Registry Hive", "Key Path", "Value Name", "Value"])
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setWordWrap(True)
        # Set consistent row height (same as process tree)
        table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(QLabel("<b>Image File Execution Options (IFEO)</b>"))
        layout.addWidget(QLabel("Used for debugger hijacking - MITRE T1546.012"))
        layout.addWidget(table)
        
        self.registry_ifeo_table = table
        self.tabs.addTab(widget, "IFEO")
    
    def create_registry_appinit_tab(self):
        """Create tab for AppInit DLLs."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Registry Hive", "Key Path", "Value Name", "Value"])
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setWordWrap(True)
        # Set consistent row height (same as process tree)
        table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(QLabel("<b>AppInit DLLs</b>"))
        layout.addWidget(QLabel("DLLs loaded into every process - MITRE T1546.010"))
        layout.addWidget(table)
        
        self.registry_appinit_table = table
        self.tabs.addTab(widget, "AppInit DLLs")
    
    def create_startup_folders_tab(self):
        """Create tab for startup folders."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels(["Folder", "Type", "File Name", "Target/Path", "Size (bytes)", "Created", "Modified"])
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setWordWrap(True)
        # Set consistent row height (same as process tree)
        table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(QLabel("<b>Startup Folders</b>"))
        layout.addWidget(QLabel("Executables and shortcuts in startup directories - MITRE T1547.001"))
        layout.addWidget(table)
        
        self.startup_folders_table = table
        self.tabs.addTab(widget, "Startup Folders")
    
    def create_scheduled_tasks_tab(self):
        """Create tab for scheduled tasks."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Task Name", "Path", "Size (bytes)", "Modified"])
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setWordWrap(True)
        # Set consistent row height (same as process tree)
        table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(QLabel("<b>Scheduled Tasks</b>"))
        layout.addWidget(QLabel("Windows Task Scheduler tasks - MITRE T1053.005"))
        layout.addWidget(table)
        
        self.scheduled_tasks_table = table
        self.tabs.addTab(widget, "Scheduled Tasks")
    
    def create_wmi_subscriptions_tab(self):
        """Create tab for WMI event subscriptions."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Registry Hive", "Key Path", "Value Name", "Value"])
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setWordWrap(True)
        # Set consistent row height (same as process tree)
        table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(QLabel("<b>WMI Event Subscriptions</b>"))
        layout.addWidget(QLabel("WMI event filters and consumers - MITRE T1546.003"))
        layout.addWidget(table)
        
        self.wmi_subscriptions_table = table
        self.tabs.addTab(widget, "WMI Subscriptions")
    
    def create_services_tab(self):
        """Create tab for suspicious services."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Service Name", "Image Path"])
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setWordWrap(True)
        # Set consistent row height (same as process tree)
        table.verticalHeader().setDefaultSectionSize(52)
        
        layout.addWidget(QLabel("<b>Suspicious Service Paths</b>"))
        layout.addWidget(QLabel("Services with ImagePath in suspicious locations"))
        layout.addWidget(table)
        
        self.services_table = table
        self.tabs.addTab(widget, "Services")
    
    def create_summary_tab(self):
        """Create summary tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFontFamily("Courier")
        
        layout.addWidget(QLabel("<b>Summary</b>"))
        layout.addWidget(text_edit)
        
        self.summary_text = text_edit
        self.tabs.addTab(widget, "Summary")
    
    def update_data(self, data):
        """Update the view with new persistence data."""
        if not data:
            return
        
        self.persistence_data = data
        
        if 'mechanisms' not in data:
            return
        
        mechanisms = data['mechanisms']
        
        # Defer all heavy work to make UI responsive
        def update_all_tables():
            # Update registry run keys
            if 'registry_run_keys' in mechanisms:
                self.populate_registry_table(self.registry_run_table, mechanisms['registry_run_keys'])
            
            # Update registry logon keys
            if 'registry_logon_keys' in mechanisms:
                self.populate_registry_table(self.registry_logon_table, mechanisms['registry_logon_keys'])
            
            # Update IFEO
            if 'registry_image_hijack' in mechanisms:
                self.populate_registry_table(self.registry_ifeo_table, mechanisms['registry_image_hijack'])
            
            # Update AppInit
            if 'registry_appinit' in mechanisms:
                self.populate_registry_table(self.registry_appinit_table, mechanisms['registry_appinit'])
            
            # Update startup folders
            if 'startup_folders' in mechanisms:
                self.populate_startup_folders_table(mechanisms['startup_folders'])
            
            # Update scheduled tasks
            if 'scheduled_tasks' in mechanisms:
                self.populate_scheduled_tasks_table(mechanisms['scheduled_tasks'])
            
            # Update WMI subscriptions
            if 'wmi_subscriptions' in mechanisms:
                self.populate_registry_table(self.wmi_subscriptions_table, mechanisms['wmi_subscriptions'])
            
            # Update services
            if 'services' in mechanisms and 'suspicious_service_paths' in mechanisms['services']:
                self.populate_services_table(mechanisms['services']['suspicious_service_paths'])
            
            # Update summary
            self.update_summary(data)
        
        QTimer.singleShot(0, update_all_tables)
    
    def populate_registry_table(self, table, registry_data):
        """Populate a registry table with data."""
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = table.isSortingEnabled()
        table.setSortingEnabled(False)
        table.setUpdatesEnabled(False)
        
        try:
            rows = []
            
            for entry in registry_data:
                if 'error' in entry:
                    continue
                    
                hkey = entry.get('hkey', 'N/A')
                key_path = entry.get('key', 'N/A')
                
                if 'values' in entry:
                    for value in entry['values']:
                        rows.append({
                            'hkey': hkey,
                            'key_path': key_path,
                            'name': value.get('name', ''),
                            'value': value.get('value', '')
                        })
            
            table.setRowCount(len(rows))
            
            for row_idx, row_data in enumerate(rows):
                table.setItem(row_idx, 0, QTableWidgetItem(row_data['hkey']))
                table.setItem(row_idx, 1, QTableWidgetItem(row_data['key_path']))
                table.setItem(row_idx, 2, QTableWidgetItem(row_data['name']))
                table.setItem(row_idx, 3, QTableWidgetItem(row_data['value']))
                
                # Determine highlighting priority:
                # 1. Debugger value (highest priority - indicates hijacking) - red/orange
                # 2. LOLBIN in value (lower priority) - blue
                value_str = str(row_data['value'])
                value_name_str = str(row_data['name'])
                
                background_color = None
                foreground_color = None
                
                # Check if this is a Debugger value (IFEO hijacking indicator)
                if value_name_str and 'debugger' in value_name_str.lower():
                    # Debugger value indicates hijacking - highlight in red/orange
                    background_color = QColor(220, 100, 50)  # Orange-red for hijacking
                    foreground_color = QColor(255, 255, 255)  # White text
                elif value_str and value_str != 'N/A' and value_str not in ['(empty - no IFEO entries configured)', '(subkey exists but no values found)']:
                    # Check if value contains a LOLBIN
                    # Extract executable name from value (handle quoted paths and arguments)
                    executable_name = value_str.split()[0].strip('"\'')
                    executable_name = os.path.basename(executable_name).lower()
                    
                    if executable_name in self.LOLBINS:
                        background_color = QColor(80, 140, 200)  # Darker blue for better contrast
                        foreground_color = QColor(255, 255, 255)  # White text for readability
                
                # Apply highlighting if set
                if background_color:
                    for col in range(4):
                        item = table.item(row_idx, col)
                        if item:
                            item.setBackground(QBrush(background_color))
                            if foreground_color:
                                item.setForeground(QBrush(foreground_color))
            
            # Resize columns only once after all rows are populated
            table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            table.setUpdatesEnabled(True)
            table.setSortingEnabled(was_sorting)
    
    def populate_startup_folders_table(self, folders_data):
        """Populate startup folders table."""
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.startup_folders_table.isSortingEnabled()
        self.startup_folders_table.setSortingEnabled(False)
        self.startup_folders_table.setUpdatesEnabled(False)
        
        try:
            rows = []
            
            for folder_entry in folders_data:
                folder = folder_entry.get('folder', 'N/A')
                
                # Handle folder errors (folder doesn't exist, permission denied, etc.)
                if 'error' in folder_entry:
                    rows.append({
                        'folder': folder,
                        'type': 'Error',
                        'name': '',
                        'target_path': folder_entry.get('error', 'Unknown error'),
                        'size': 0,
                        'created': '',
                        'modified': ''
                    })
                    continue
                
                # Handle empty folders
                if 'files' not in folder_entry or not folder_entry['files']:
                    rows.append({
                        'folder': folder,
                        'type': 'Empty',
                        'name': '(No files found)',
                        'target_path': '',
                        'size': 0,
                        'created': '',
                        'modified': ''
                    })
                    continue
                
                # Process files in folder
                for file in folder_entry['files']:
                    file_type = file.get('type', 'file')
                    file_name = file.get('name', '')
                    
                    # For shortcuts, show target; for files, show path
                    if file_type == 'shortcut':
                        target_path = file.get('target', 'Unable to resolve shortcut')
                        # Include arguments if present
                        arguments = file.get('arguments', '')
                        if arguments:
                            target_path = f"{target_path} {arguments}"
                    else:
                        target_path = file.get('path', '')
                    
                    # Handle file errors
                    if 'error' in file:
                        target_path = file.get('error', 'Unknown error')
                    
                    rows.append({
                        'folder': folder,
                        'type': file_type.capitalize(),
                        'name': file_name,
                        'target_path': target_path,
                        'size': file.get('size', 0),
                        'created': file.get('created', ''),
                        'modified': file.get('modified', '')
                    })
            
            self.startup_folders_table.setRowCount(len(rows))
            
            for row_idx, row_data in enumerate(rows):
                self.startup_folders_table.setItem(row_idx, 0, QTableWidgetItem(row_data['folder']))
                self.startup_folders_table.setItem(row_idx, 1, QTableWidgetItem(row_data['type']))
                self.startup_folders_table.setItem(row_idx, 2, QTableWidgetItem(row_data['name']))
                self.startup_folders_table.setItem(row_idx, 3, QTableWidgetItem(row_data['target_path']))
                self.startup_folders_table.setItem(row_idx, 4, QTableWidgetItem(str(row_data['size'])))
                self.startup_folders_table.setItem(row_idx, 5, QTableWidgetItem(row_data['created']))
                self.startup_folders_table.setItem(row_idx, 6, QTableWidgetItem(row_data['modified']))
                
                # Check if target/path contains a LOLBIN and highlight in blue
                target_path_str = str(row_data['target_path'])
                if target_path_str and target_path_str != 'N/A' and target_path_str not in ['', 'Unable to resolve shortcut', 'Unable to resolve shortcut target']:
                    # Extract executable name from target path (handle quoted paths and arguments)
                    executable_name = target_path_str.split()[0].strip('"\'')
                    executable_name = os.path.basename(executable_name).lower()
                    
                    if executable_name in self.LOLBINS:
                        lolbin_color = QColor(80, 140, 200)  # Darker blue for better contrast
                        fg_color = QColor(255, 255, 255)  # White text for readability
                        for col in range(7):
                            item = self.startup_folders_table.item(row_idx, col)
                            if item:
                                item.setBackground(QBrush(lolbin_color))
                                item.setForeground(QBrush(fg_color))
                
                # Highlight shortcuts in a different color (light yellow)
                if row_data['type'].lower() == 'shortcut':
                    shortcut_color = QColor(255, 255, 200)  # Light yellow
                    for col in range(7):
                        item = self.startup_folders_table.item(row_idx, col)
                        if item:
                            # Only apply if not already highlighted as LOLBIN
                            bg_brush = item.background()
                            if bg_brush.style() != 0:  # Has a background
                                bg_color = bg_brush.color()
                                if bg_color != QColor(80, 140, 200):  # Not LOLBIN blue
                                    item.setBackground(QBrush(shortcut_color))
                            else:
                                # No background set, apply shortcut color
                                item.setBackground(QBrush(shortcut_color))
            
            # Resize columns only once after all rows are populated
            self.startup_folders_table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            self.startup_folders_table.setUpdatesEnabled(True)
            self.startup_folders_table.setSortingEnabled(was_sorting)
    
    def populate_scheduled_tasks_table(self, tasks_data):
        """Populate scheduled tasks table."""
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.scheduled_tasks_table.isSortingEnabled()
        self.scheduled_tasks_table.setSortingEnabled(False)
        self.scheduled_tasks_table.setUpdatesEnabled(False)
        
        try:
            rows = []
            
            # Calculate the date 30 days ago
            thirty_days_ago = datetime.now() - timedelta(days=30)
            
            for task in tasks_data:
                if 'error' in task:
                    continue
                
                rows.append({
                    'name': task.get('name', ''),
                    'path': task.get('path', ''),
                    'size': task.get('size', 0),
                    'modified': task.get('modified', '')
                })
            
            self.scheduled_tasks_table.setRowCount(len(rows))
            
            for row_idx, row_data in enumerate(rows):
                self.scheduled_tasks_table.setItem(row_idx, 0, QTableWidgetItem(row_data['name']))
                self.scheduled_tasks_table.setItem(row_idx, 1, QTableWidgetItem(row_data['path']))
                self.scheduled_tasks_table.setItem(row_idx, 2, QTableWidgetItem(str(row_data['size'])))
                self.scheduled_tasks_table.setItem(row_idx, 3, QTableWidgetItem(row_data['modified']))
                
                # Check if task was modified in the last 30 days
                is_recently_modified = False
                modified_str = row_data.get('modified', '')
                if modified_str:
                    try:
                        # Parse ISO format datetime (handles both with and without timezone)
                        modified_str_clean = modified_str.replace('Z', '+00:00')
                        modified_date = datetime.fromisoformat(modified_str_clean)
                        # Remove timezone info for comparison if present
                        if modified_date.tzinfo:
                            modified_date = modified_date.replace(tzinfo=None)
                        is_recently_modified = modified_date > thirty_days_ago
                    except (ValueError, AttributeError, TypeError):
                        # If ISO parsing fails, try parsing as-is (already handled timezone)
                        try:
                            modified_date = datetime.fromisoformat(modified_str)
                            if modified_date.tzinfo:
                                modified_date = modified_date.replace(tzinfo=None)
                            is_recently_modified = modified_date > thirty_days_ago
                        except (ValueError, AttributeError, TypeError):
                            # If all parsing fails, skip highlighting
                            pass
                
                # Determine background color based on priority:
                # 1. Recently modified (orange) - highest priority
                # 2. LOLBIN (blue) - lower priority
                background_color = None
                foreground_color = None
                
                if is_recently_modified:
                    background_color = QColor(220, 150, 50)  # Darker orange for better contrast
                    foreground_color = QColor(0, 0, 0)  # Black text on orange background
                else:
                    # Check if path contains a LOLBIN and highlight in blue
                    path_str = str(row_data['path'])
                    if path_str and path_str != 'N/A':
                        # Extract executable name from path (handle quoted paths and arguments)
                        executable_name = path_str.split()[0].strip('"\'')
                        executable_name = os.path.basename(executable_name).lower()
                        
                        if executable_name in self.LOLBINS:
                            background_color = QColor(80, 140, 200)  # Darker blue for better contrast
                            foreground_color = QColor(255, 255, 255)  # White text for readability
                
                # Apply background color if set
                if background_color:
                    for col in range(4):
                        item = self.scheduled_tasks_table.item(row_idx, col)
                        if item:
                            item.setBackground(QBrush(background_color))
                            if foreground_color:
                                item.setForeground(QBrush(foreground_color))
            
            # Resize columns only once after all rows are populated
            self.scheduled_tasks_table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            self.scheduled_tasks_table.setUpdatesEnabled(True)
            self.scheduled_tasks_table.setSortingEnabled(was_sorting)
    
    def populate_services_table(self, services_data):
        """Populate services table."""
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.services_table.isSortingEnabled()
        self.services_table.setSortingEnabled(False)
        self.services_table.setUpdatesEnabled(False)
        
        try:
            self.services_table.setRowCount(len(services_data))
            
            for row_idx, service in enumerate(services_data):
                self.services_table.setItem(row_idx, 0, QTableWidgetItem(service.get('service', '')))
                self.services_table.setItem(row_idx, 1, QTableWidgetItem(service.get('image_path', '')))
                
                # Check if image path contains a LOLBIN and highlight in light blue
                image_path = service.get('image_path', '')
                if image_path and image_path != 'N/A':
                    # Extract executable name from image path (handle quoted paths and arguments)
                    executable_name = image_path.split()[0].strip('"\'')
                    executable_name = os.path.basename(executable_name).lower()
                    
                    if executable_name in self.LOLBINS:
                        lolbin_color = QColor(200, 230, 255)  # Light blue
                        for col in range(2):
                            item = self.services_table.item(row_idx, col)
                            if item:
                                item.setBackground(lolbin_color)
            
            # Resize columns only once after all rows are populated
            self.services_table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            self.services_table.setUpdatesEnabled(True)
            self.services_table.setSortingEnabled(was_sorting)
    
    def update_summary(self, data):
        """Update summary text."""
        summary_lines = []
        
        summary_lines.append("PERSISTENCE MECHANISMS ANALYSIS SUMMARY")
        summary_lines.append("=" * 60)
        summary_lines.append("")
        
        if 'platform' in data:
            summary_lines.append(f"Platform: {data['platform']}")
        if 'timestamp' in data:
            summary_lines.append(f"Timestamp: {data['timestamp']}")
        summary_lines.append("")
        
        if 'mechanisms' in data:
            mechanisms = data['mechanisms']
            
            # Count entries
            registry_run_count = self.count_registry_entries(mechanisms.get('registry_run_keys', []))
            registry_logon_count = self.count_registry_entries(mechanisms.get('registry_logon_keys', []))
            ifeo_count = self.count_registry_entries(mechanisms.get('registry_image_hijack', []))
            appinit_count = self.count_registry_entries(mechanisms.get('registry_appinit', []))
            startup_files = sum(len(entry.get('files', [])) for entry in mechanisms.get('startup_folders', []))
            tasks_count = len([t for t in mechanisms.get('scheduled_tasks', []) if 'error' not in t])
            wmi_count = self.count_registry_entries(mechanisms.get('wmi_subscriptions', []))
            suspicious_services = len(mechanisms.get('services', {}).get('suspicious_service_paths', []))
            
            summary_lines.append("DETECTED MECHANISMS:")
            summary_lines.append("-" * 60)
            summary_lines.append(f"Registry Run Keys: {registry_run_count} entries")
            summary_lines.append(f"Registry Logon Keys: {registry_logon_count} entries")
            summary_lines.append(f"Image File Execution Options: {ifeo_count} entries")
            summary_lines.append(f"AppInit DLLs: {appinit_count} entries")
            summary_lines.append(f"Startup Folder Files: {startup_files} files")
            summary_lines.append(f"Scheduled Tasks: {tasks_count} tasks")
            summary_lines.append(f"WMI Subscriptions: {wmi_count} entries")
            summary_lines.append(f"Suspicious Service Paths: {suspicious_services} services")
            summary_lines.append("")
            
            if suspicious_services > 0:
                summary_lines.append("⚠️ WARNING: Suspicious service paths detected!")
                summary_lines.append("")
        
        self.summary_text.setPlainText("\n".join(summary_lines))
    
    def count_registry_entries(self, registry_data):
        """Count total registry values."""
        count = 0
        for entry in registry_data:
            if 'values' in entry:
                count += len(entry['values'])
        return count
    
    def filter_data(self, text):
        """Filter data based on search text."""
        # This is a simple implementation - could be enhanced
        # For now, just highlight matching rows
        pass
    
    def export_data(self):
        """Export persistence data to a file."""
        if not self.persistence_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Persistence Data", "persistence.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.persistence_data, f, indent=2)
    
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
        
        # Orange-Red - Debugger/Hijacking (highest priority)
        orange_red_box = QLabel()
        orange_red_box.setFixedSize(14, 14)
        orange_red_box.setStyleSheet(
            "background-color: #dc6432;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(orange_red_box)
        orange_red_label = QLabel("Orange-Red: Debugger/Hijacking")
        orange_red_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(orange_red_label)
        
        # Orange - Recently modified (darker orange for better contrast)
        orange_box = QLabel()
        orange_box.setFixedSize(14, 14)
        orange_box.setStyleSheet(
            "background-color: #dc9632;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(orange_box)
        orange_label = QLabel("Orange: Recently modified (30 days)")
        orange_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(orange_label)
        
        # Blue - LOLBIN (darker blue for better contrast)
        blue_box = QLabel()
        blue_box.setFixedSize(14, 14)
        blue_box.setStyleSheet(
            "background-color: #508cc8;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(blue_box)
        blue_label = QLabel("Blue: LOLBIN")
        blue_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(blue_label)
        
        # Yellow - Shortcut (light yellow)
        yellow_box = QLabel()
        yellow_box.setFixedSize(14, 14)
        yellow_box.setStyleSheet(
            "background-color: #ffffc8;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(yellow_box)
        yellow_label = QLabel("Yellow: Shortcut")
        yellow_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(yellow_label)
        
        legend_layout.addStretch()
        return legend_frame


