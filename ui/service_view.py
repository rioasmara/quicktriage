"""
Service view widget for displaying service information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QMessageBox,
    QRadioButton, QButtonGroup, QFrame
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
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
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Color legend
        legend = self._create_legend()
        layout.addWidget(legend)
        
        # Control bar
        control_layout = QHBoxLayout()
        
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
        self.error_label.setStyleSheet("color: red; padding: 5px;")
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Service Name", "Display Name", "Status", "Start Type",
            "Binary Path", "Description"
        ])
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.resizeColumnsToContents()
        
        layout.addWidget(self.table)
    
    def update_data(self, data):
        """Update the view with new service data."""
        import sys
        print(f"[ServiceView] update_data called with data type: {type(data)}", file=sys.stderr)
        
        if not data:
            print(f"[ServiceView] No data received", file=sys.stderr)
            self.error_label.setText("No data received.")
            self.error_label.setVisible(True)
            self.service_data = []
            self.populate_table([])
            return
        
        print(f"[ServiceView] Data keys: {list(data.keys())}", file=sys.stderr)
        print(f"[ServiceView] Has 'services' key: {'services' in data}", file=sys.stderr)
        
        if 'services' not in data:
            error_msg = data.get('error', 'Unknown error: services key missing')
            print(f"[ServiceView] ERROR: {error_msg}", file=sys.stderr)
            self.error_label.setText(f"Error: {error_msg}")
            self.error_label.setVisible(True)
            self.service_data = []
            self.populate_table([])
            # Also show a message box for visibility
            QMessageBox.warning(self, "Service Collection Error", error_msg)
            return
        
        # Check for errors in data
        if 'error' in data:
            error_msg = data['error']
            print(f"[ServiceView] WARNING: {error_msg}", file=sys.stderr)
            self.error_label.setText(f"Warning: {error_msg}")
            self.error_label.setVisible(True)
            # Still show services if we have any
        else:
            self.error_label.setVisible(False)
        
        services_list = data['services'] or []
        print(f"[ServiceView] Services list length: {len(services_list)}", file=sys.stderr)
        self.service_data = services_list
        self.populate_table(services_list)
        
        # If no services and no error, show a message
        if not self.service_data and 'error' not in data:
            print(f"[ServiceView] No services found", file=sys.stderr)
            self.error_label.setText("No services found.")
            self.error_label.setVisible(True)
        else:
            print(f"[ServiceView] Successfully updated table with {len(self.service_data)} services", file=sys.stderr)
    
    def populate_table(self, services):
        """Populate the table with service data."""
        import sys
        print(f"[ServiceView] populate_table called with {len(services)} services", file=sys.stderr)
        self.table.setRowCount(len(services))
        
        for row, service in enumerate(services):
            try:
                if row < 5:  # Debug first 5
                    print(f"[ServiceView] Adding service {row}: {service.get('name', 'N/A')}", file=sys.stderr)
                
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
                self.table.setItem(row, 3, QTableWidgetItem(start_type))
                
                path_item = QTableWidgetItem(binary_path)
                if len(binary_path) > 50:
                    path_item.setToolTip(binary_path)
                self.table.setItem(row, 4, path_item)
                
                desc_item = QTableWidgetItem(description)
                if len(description) > 50:
                    desc_item.setToolTip(description)
                self.table.setItem(row, 5, desc_item)
                
                # Check if executable name is a LOLBIN and highlight in blue
                if binary_path and binary_path != 'N/A':
                    # Extract executable name from binary path
                    # Handle paths that might be quoted or have arguments
                    executable_name = binary_path.split()[0].strip('"\'')
                    executable_name = os.path.basename(executable_name).lower()
                    
                    if executable_name in self.LOLBINS:
                        # Darker blue for running LOLBIN services, light blue for others
                        if status == 'Running':
                            lolbin_color = QColor(150, 180, 255)  # Darker blue
                        else:
                            lolbin_color = QColor(200, 230, 255)  # Light blue
                        
                        for col in range(6):
                            item = self.table.item(row, col)
                            if item:
                                item.setBackground(lolbin_color)
            except Exception as e:
                print(f"[ServiceView] ERROR processing service {row}: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc(file=sys.stderr)
                # Still add the row with error info
                self.table.setItem(row, 0, QTableWidgetItem(service.get('name', f'Service {row}')))
                self.table.setItem(row, 1, QTableWidgetItem('Error'))
                self.table.setItem(row, 2, QTableWidgetItem('N/A'))
                self.table.setItem(row, 3, QTableWidgetItem('N/A'))
                self.table.setItem(row, 4, QTableWidgetItem(f'Error: {str(e)}'))
                self.table.setItem(row, 5, QTableWidgetItem('N/A'))
        
        self.table.resizeColumnsToContents()
    
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
    
    def _create_legend(self):
        """Create a color legend widget."""
        legend_frame = QFrame()
        legend_frame.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Raised)
        legend_frame.setStyleSheet("QFrame { background-color: #f0f0f0; padding: 2px; }")
        legend_frame.setMaximumHeight(30)
        legend_layout = QHBoxLayout(legend_frame)
        legend_layout.setSpacing(5)
        legend_layout.setContentsMargins(3, 2, 3, 2)
        
        legend_label = QLabel("<b>Legend:</b>")
        legend_label.setStyleSheet("font-size: 9pt;")
        legend_layout.addWidget(legend_label)
        
        # Darker blue - Running LOLBIN service
        dark_blue_box = QLabel()
        dark_blue_box.setFixedSize(12, 12)
        dark_blue_box.setStyleSheet(f"background-color: rgb(150, 180, 255); border: 1px solid black;")
        legend_layout.addWidget(dark_blue_box)
        dark_blue_label = QLabel("Dark Blue: Running LOLBIN")
        dark_blue_label.setStyleSheet("font-size: 9pt;")
        legend_layout.addWidget(dark_blue_label)
        
        # Light blue - Stopped LOLBIN service
        light_blue_box = QLabel()
        light_blue_box.setFixedSize(12, 12)
        light_blue_box.setStyleSheet(f"background-color: rgb(200, 230, 255); border: 1px solid black;")
        legend_layout.addWidget(light_blue_box)
        light_blue_label = QLabel("Light Blue: Stopped LOLBIN")
        light_blue_label.setStyleSheet("font-size: 9pt;")
        legend_layout.addWidget(light_blue_label)
        
        legend_layout.addStretch()
        return legend_frame

