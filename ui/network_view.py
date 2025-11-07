"""
Network view widget for displaying network connection information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QGroupBox, QGridLayout, QFrame
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor


class NetworkView(QWidget):
    """Widget for displaying network connection information."""
    
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
        self.network_data = None
        self.process_data = None  # Store process data to map PID to create_time
        # Track rows that should blink (LOLBIN + ESTABLISHED)
        self.blinking_rows = {}  # {row: connection_data}
        self.blink_state = False  # Current blink state (on/off)
        self.blink_timer = QTimer(self)
        self.blink_timer.timeout.connect(self._toggle_blink)
        self.blink_timer.start(500)  # Blink every 500ms
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        
        # Color legend
        legend = self._create_legend()
        layout.addWidget(legend)
        
        # Statistics group
        stats_group = QGroupBox("Network Statistics")
        stats_layout = QGridLayout()
        stats_layout.setContentsMargins(4, 4, 4, 4)
        stats_layout.setSpacing(4)
        
        self.stats_labels = {
            'bytes_sent': QLabel("Bytes Sent: N/A"),
            'bytes_recv': QLabel("Bytes Received: N/A"),
            'packets_sent': QLabel("Packets Sent: N/A"),
            'packets_recv': QLabel("Packets Received: N/A"),
        }
        
        row = 0
        for label in self.stats_labels.values():
            stats_layout.addWidget(label, row // 2, row % 2)
            row += 1
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Control bar
        control_layout = QHBoxLayout()
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(4)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search connections...")
        self.search_box.textChanged.connect(self.filter_connections)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_data)
        
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)
        control_layout.addStretch()
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "PID", "Process Name", "Local Address", "Remote Address",
            "Status", "Family", "Process Created"
        ])
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.resizeColumnsToContents()
        
        # Enable tooltips and connect to itemEntered signal for hover tooltips
        self.table.setMouseTracking(True)
        self.table.itemEntered.connect(self._on_item_hovered)
        
        layout.addWidget(self.table)
    
    def update_data(self, data):
        """Update the view with new network data."""
        if not data:
            return
        
        self.network_data = data
        
        # Update statistics
        if 'statistics' in data:
            stats = data['statistics']
            self.stats_labels['bytes_sent'].setText(f"Bytes Sent: {stats.get('bytes_sent', 0):,}")
            self.stats_labels['bytes_recv'].setText(f"Bytes Received: {stats.get('bytes_recv', 0):,}")
            self.stats_labels['packets_sent'].setText(f"Packets Sent: {stats.get('packets_sent', 0):,}")
            self.stats_labels['packets_recv'].setText(f"Packets Received: {stats.get('packets_recv', 0):,}")
        
        # Update connections table
        if 'connections' in data:
            self.populate_table(data['connections'])
    
    def update_process_data(self, process_data):
        """Update process data for correlating PID to create_time."""
        self.process_data = process_data
        # Refresh the table if network data is already loaded
        if self.network_data and 'connections' in self.network_data:
            self.populate_table(self.network_data['connections'])
    
    def _is_localhost(self, address):
        """Check if an address is localhost (127.0.0.1 or localhost)."""
        if not address or address == 'N/A':
            return False
        
        # Extract IP from "IP:PORT" format
        if ':' in address:
            ip = address.split(':')[0].strip()
        else:
            ip = address.strip()
        
        # Check if it's localhost
        return ip.lower() in ('127.0.0.1', 'localhost', '::1', '0.0.0.0')
    
    def populate_table(self, connections):
        """Populate the table with connection data."""
        # Clear blinking rows before repopulating
        self.blinking_rows.clear()
        self.blink_state = False
        
        self.table.setRowCount(len(connections))
        
        # Build PID to create_time mapping if process data is available
        pid_to_create_time = {}
        if self.process_data and 'processes' in self.process_data:
            for proc in self.process_data['processes']:
                pid_to_create_time[proc['pid']] = proc.get('create_time', 'N/A')
        
        for row, conn in enumerate(connections):
            self.table.setItem(row, 0, QTableWidgetItem(str(conn['pid'])))
            self.table.setItem(row, 1, QTableWidgetItem(conn['process_name']))
            self.table.setItem(row, 2, QTableWidgetItem(conn['local_address']))
            self.table.setItem(row, 3, QTableWidgetItem(conn['remote_address']))
            self.table.setItem(row, 4, QTableWidgetItem(conn['status']))
            self.table.setItem(row, 5, QTableWidgetItem(conn['family']))
            
            # Get process creation time from process data
            pid = conn.get('pid')
            create_time = pid_to_create_time.get(pid, 'N/A') if pid != 'N/A' and pid is not None else 'N/A'
            self.table.setItem(row, 6, QTableWidgetItem(create_time))
            
            # Check if remote address is localhost
            remote_addr = conn.get('remote_address', '')
            is_localhost = self._is_localhost(remote_addr)
            
            # Skip highlighting if remote address is localhost
            if is_localhost:
                continue
            
            # Apply color coding based on network status and LOLBIN
            # Priority: ESTABLISHED + LOLBIN (blinking red) > ESTABLISHED (red) > LISTEN (yellow) > LOLBIN (light blue)
            process_name_lower = conn.get('process_name', '').lower()
            is_lolbin = process_name_lower in self.LOLBINS
            status = conn.get('status', '').upper()
            
            if status == 'ESTABLISHED' and is_lolbin:
                # Blinking red for LOLBINs with established connections (highest priority)
                self.blinking_rows[row] = conn
                # Start with red background
                color = QColor(255, 150, 150)
                for col in range(7):
                    self.table.item(row, col).setBackground(color)
            elif status == 'ESTABLISHED':
                # Red for established connections
                color = QColor(255, 200, 200)
                for col in range(7):
                    self.table.item(row, col).setBackground(color)
            elif status == 'LISTEN':
                # Yellow for listening processes
                color = QColor(255, 255, 200)
                for col in range(7):
                    self.table.item(row, col).setBackground(color)
            elif is_lolbin:
                # Light blue for LOLBINs (when no network status)
                color = QColor(200, 230, 255)
                for col in range(7):
                    self.table.item(row, col).setBackground(color)
        
        self.table.resizeColumnsToContents()
    
    def _toggle_blink(self):
        """Toggle the blinking state for rows that should blink."""
        if not self.blinking_rows:
            return
        
        self.blink_state = not self.blink_state
        
        # Bright red when on, darker red when off
        if self.blink_state:
            color = QColor(255, 100, 100)  # Bright red
        else:
            color = QColor(255, 200, 200)  # Lighter red
        
        # Update all blinking rows
        for row in self.blinking_rows.keys():
            if row < self.table.rowCount():  # Check if row still exists
                for col in range(7):
                    item = self.table.item(row, col)
                    if item:  # Check if item exists
                        item.setBackground(color)
    
    def filter_connections(self, text):
        """Filter connections based on search text."""
        if not self.network_data or 'connections' not in self.network_data:
            return
        
        if not text.strip():
            # Show all connections if filter is empty
            self.populate_table(self.network_data['connections'])
            return
        
        filtered = [
            c for c in self.network_data['connections']
            if text.lower() in c['local_address'].lower() or
            text.lower() in c['remote_address'].lower() or
            text.lower() in c['process_name'].lower() or
            text.lower() in str(c['pid']) or
            text.lower() in c.get('status', '').lower()
        ]
        
        self.populate_table(filtered)
    
    def export_data(self):
        """Export network data to a file."""
        if not self.network_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Network Data", "network.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.network_data, f, indent=2)
    
    def _on_item_hovered(self, item):
        """Handle mouse hover over a table item to show process details tooltip."""
        if not item:
            return
        
        row = item.row()
        if row < 0 or row >= self.table.rowCount():
            return
        
        # Get PID from the first column (column 0)
        pid_item = self.table.item(row, 0)
        if not pid_item:
            return
        
        try:
            pid = int(pid_item.text())
        except (ValueError, TypeError):
            return
        
        # Get process details (parent and children)
        tooltip_text = self._get_process_details_tooltip(pid)
        
        # Set tooltip on all items in the row with rich text enabled
        for col in range(self.table.columnCount()):
            cell_item = self.table.item(row, col)
            if cell_item:
                cell_item.setToolTip(tooltip_text)
    
    def _escape_html(self, text):
        """Escape HTML special characters."""
        if not text:
            return ""
        text = str(text)
        # Replace & first to avoid double-escaping
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        text = text.replace('"', "&quot;")
        text = text.replace("'", "&#39;")
        return text
    
    def _get_process_details_tooltip(self, pid):
        """Get formatted tooltip text with parent and child process information."""
        if not self.process_data or 'processes' not in self.process_data:
            return f"<p style='white-space: pre-wrap;'>PID: {pid}<br/>No process data available</p>"
        
        # Find the current process
        current_process = None
        for proc in self.process_data['processes']:
            if proc.get('pid') == pid:
                current_process = proc
                break
        
        if not current_process:
            return f"<p style='white-space: pre-wrap;'>PID: {pid}<br/>Process not found in collected data</p>"
        
        # Build tooltip text with proper HTML formatting
        html_parts = []
        html_parts.append("<div style='font-family: monospace; white-space: pre-wrap; max-width: 500px;'>")
        
        # Process Details
        html_parts.append("<b style='font-size: 11pt;'>Process Details</b><br/>")
        html_parts.append(f"PID: {pid}<br/>")
        process_name = self._escape_html(current_process.get('name', 'N/A'))
        html_parts.append(f"Name: {process_name}<br/>")
        html_parts.append("<br/>")
        
        # Find parent process
        ppid = current_process.get('ppid')
        if ppid:
            parent_process = None
            for proc in self.process_data['processes']:
                if proc.get('pid') == ppid:
                    parent_process = proc
                    break
            
            if parent_process:
                html_parts.append("<b>Parent Process:</b><br/>")
                html_parts.append(f"&nbsp;&nbsp;PID: {ppid}<br/>")
                parent_name = self._escape_html(parent_process.get('name', 'N/A'))
                html_parts.append(f"&nbsp;&nbsp;Name: {parent_name}<br/>")
                exe_path = parent_process.get('exe', 'N/A')
                exe_path = self._escape_html(exe_path)
                # Truncate long paths for better display
                if len(exe_path) > 70:
                    exe_path = exe_path[:67] + "..."
                html_parts.append(f"&nbsp;&nbsp;Path: {exe_path}<br/>")
            else:
                html_parts.append("<b>Parent Process:</b><br/>")
                html_parts.append(f"&nbsp;&nbsp;PID: {ppid} (not found in collected data)<br/>")
        else:
            html_parts.append("<b>Parent Process:</b> None (root process)<br/>")
        
        html_parts.append("<br/>")
        
        # Find child processes
        child_processes = []
        for proc in self.process_data['processes']:
            if proc.get('ppid') == pid:
                child_processes.append(proc)
        
        if child_processes:
            html_parts.append(f"<b>Child Processes ({len(child_processes)}):</b><br/>")
            # Show up to 10 child processes to avoid tooltip being too large
            for i, child in enumerate(child_processes[:10]):
                child_name = self._escape_html(child.get('name', 'N/A'))
                child_pid = child.get('pid', 'N/A')
                html_parts.append(f"&nbsp;&nbsp;{i+1}. PID: {child_pid} - {child_name}<br/>")
            if len(child_processes) > 10:
                html_parts.append(f"&nbsp;&nbsp;... and {len(child_processes) - 10} more<br/>")
        else:
            html_parts.append("<b>Child Processes:</b> None<br/>")
        
        html_parts.append("</div>")
        
        return "".join(html_parts)
    
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
        
        # Blinking red - LOLBIN with ESTABLISHED
        red_box = QLabel()
        red_box.setFixedSize(14, 14)
        red_box.setStyleSheet(
            "background-color: #ff6464;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(red_box)
        red_label = QLabel("Blink Red: LOLBIN+ESTABLISHED")
        red_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(red_label)
        
        # Red - ESTABLISHED
        red_box2 = QLabel()
        red_box2.setFixedSize(14, 14)
        red_box2.setStyleSheet(
            "background-color: #ff8585;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(red_box2)
        red_label2 = QLabel("Red: ESTABLISHED")
        red_label2.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(red_label2)
        
        # Yellow - LISTEN
        yellow_box = QLabel()
        yellow_box.setFixedSize(14, 14)
        yellow_box.setStyleSheet(
            "background-color: #f6d96f;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(yellow_box)
        yellow_label = QLabel("Yellow: LISTEN")
        yellow_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(yellow_label)
        
        # Light blue - LOLBIN
        blue_box = QLabel()
        blue_box.setFixedSize(14, 14)
        blue_box.setStyleSheet(
            "background-color: #5fc4ff;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(blue_box)
        blue_label = QLabel("Light Blue: LOLBIN")
        blue_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(blue_label)
        
        legend_layout.addStretch()
        return legend_frame


