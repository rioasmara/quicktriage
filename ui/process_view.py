"""
Process view widget for displaying process information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QFrame
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor


class ProcessView(QWidget):
    """Widget for displaying process information."""
    
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
        self.process_data = None
        self.network_data = None
        # Track items that should blink (LOLBIN + ESTABLISHED)
        self.blinking_items = {}  # {pid: QTreeWidgetItem}
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
        
        # Control bar
        control_layout = QHBoxLayout()
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(4)
        
        self.refresh_btn = QPushButton("Refresh")
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_data)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search processes...")
        self.search_box.textChanged.connect(self.filter_processes)
        
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)
        control_layout.addStretch()
        control_layout.addWidget(self.refresh_btn)
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Tree
        self.tree = QTreeWidget()
        self.tree.setColumnCount(8)
        self.tree.setHeaderLabels([
            "PID", "Name", "Username", "CPU %", "Memory (MB)",
            "Status", "Created", "Command Line"
        ])
        self.tree.setSortingEnabled(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionBehavior(QTreeWidget.SelectRows)
        self.tree.resizeColumnToContents(0)
        
        layout.addWidget(self.tree)
    
    def update_data(self, data):
        """Update the tree with new process data."""
        if not data or 'processes' not in data:
            return
        
        processes = data['processes']
        if not isinstance(processes, list):
            return
        
        self.process_data = processes
        self.populate_tree(self.process_data)
    
    def update_network_data(self, network_data):
        """Update network data for correlation with processes."""
        self.network_data = network_data
        # Refresh the tree if process data is already loaded
        if self.process_data:
            self.populate_tree(self.process_data)
    
    def populate_tree(self, processes):
        """Populate the tree with process data organized by parent-child relationships."""
        # Stop blinking before clearing
        self.blinking_items.clear()
        self.blink_state = False
        self.tree.clear()
        
        if not processes:
            return
        
        # Build network status mapping from network data
        network_status_map = self._build_network_status_map()
        
        # Create a mapping of PID to process
        process_map = {p['pid']: p for p in processes}
        
        # Create a mapping of PPID to list of child processes
        children_map = {}
        for process in processes:
            ppid = process['ppid']
            if ppid is None:
                ppid = 0
            if ppid not in children_map:
                children_map[ppid] = []
            children_map[ppid].append(process)
        
        # Track which processes have been added to the tree
        added_pids = set()
        
        # Find root processes (processes with PPID not in the process list, PPID of 0, or None)
        root_processes = []
        for process in processes:
            ppid = process['ppid']
            if ppid is None or ppid == 0 or ppid not in process_map:
                root_processes.append(process)
        
        # Build tree items recursively
        def create_tree_item(process):
            """Create a tree item for a process and its children."""
            pid = process['pid']
            if pid in added_pids:
                # Skip if already added (avoid duplicates)
                return None
            
            added_pids.add(pid)
            item = QTreeWidgetItem()
            item.setText(0, str(process['pid']))
            item.setText(1, process['name'])
            item.setText(2, process['username'])
            item.setText(3, f"{process['cpu_percent']:.2f}")
            item.setText(4, f"{process['memory_mb']:.2f}")
            item.setText(5, process['status'])
            item.setText(6, process.get('create_time', 'N/A'))
            
            cmdline = process['cmdline'] if process['cmdline'] else ''
            item.setText(7, cmdline)
            
            # Apply color coding based on network status and LOLBIN
            # Priority: ESTABLISHED + LOLBIN (blinking red) > ESTABLISHED (red) > LISTEN (yellow) > LOLBIN (light blue)
            process_name_lower = process['name'].lower()
            is_lolbin = process_name_lower in self.LOLBINS
            
            if network_status_map:
                pid_status = network_status_map.get(pid)
                if pid_status == 'established' and is_lolbin:
                    # Blinking red for LOLBINs with established connections (highest priority)
                    self.blinking_items[pid] = item
                    # Start with red background
                    item.setBackground(0, QColor(255, 150, 150))
                    for col in range(1, 8):
                        item.setBackground(col, QColor(255, 150, 150))
                elif pid_status == 'established':
                    # Red for established connections
                    item.setBackground(0, QColor(255, 200, 200))
                    for col in range(1, 8):
                        item.setBackground(col, QColor(255, 200, 200))
                elif pid_status == 'listening':
                    # Yellow for listening processes
                    item.setBackground(0, QColor(255, 255, 200))
                    for col in range(1, 8):
                        item.setBackground(col, QColor(255, 255, 200))
                elif is_lolbin:
                    # Light blue for LOLBINs (when no network status)
                    item.setBackground(0, QColor(200, 230, 255))
                    for col in range(1, 8):
                        item.setBackground(col, QColor(200, 230, 255))
            elif is_lolbin:
                # Light blue for LOLBINs (when no network data available)
                item.setBackground(0, QColor(200, 230, 255))
                for col in range(1, 8):
                    item.setBackground(col, QColor(200, 230, 255))
            
            # Add child processes
            if pid in children_map:
                for child in children_map[pid]:
                    child_item = create_tree_item(child)
                    if child_item:
                        item.addChild(child_item)
            
            return item
        
        # Add root processes to tree
        for process in root_processes:
            root_item = create_tree_item(process)
            if root_item:
                self.tree.addTopLevelItem(root_item)
        
        # Also add any orphaned processes (processes not in the tree yet)
        for process in processes:
            if process['pid'] not in added_pids:
                root_item = create_tree_item(process)
                if root_item:
                    self.tree.addTopLevelItem(root_item)
        
        # Expand all items by default so nothing is hidden
        self.tree.expandAll()
        
        # Resize columns
        for i in range(8):
            self.tree.resizeColumnToContents(i)
    
    def _toggle_blink(self):
        """Toggle the blinking state for items that should blink."""
        if not self.blinking_items:
            return
        
        self.blink_state = not self.blink_state
        
        # Bright red when on, darker red when off
        if self.blink_state:
            color = QColor(255, 100, 100)  # Bright red
        else:
            color = QColor(255, 200, 200)  # Lighter red
        
        # Update all blinking items
        for item in self.blinking_items.values():
            if item:  # Check if item still exists
                for col in range(8):
                    item.setBackground(col, color)
    
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
    
    def _build_network_status_map(self):
        """Build a mapping of PID to network status (listening or established)."""
        status_map = {}
        
        if not self.network_data or 'connections' not in self.network_data:
            return status_map
        
        connections = self.network_data['connections']
        
        for conn in connections:
            pid = conn.get('pid')
            if pid == 'N/A' or pid is None:
                continue
            
            status = conn.get('status', '').upper()
            
            # Skip highlighting if remote address is localhost
            remote_addr = conn.get('remote_address', '')
            if status == 'ESTABLISHED' and self._is_localhost(remote_addr):
                continue
            
            # If process has an established connection, mark it as established (highest priority)
            if status == 'ESTABLISHED':
                status_map[pid] = 'established'
            # If process is listening and not already marked as established, mark as listening
            elif status == 'LISTEN' and pid not in status_map:
                status_map[pid] = 'listening'
        
        return status_map
    
    def filter_processes(self, text):
        """Filter processes based on search text."""
        if not self.process_data:
            return
        
        if not text.strip():
            # Show all processes if filter is empty
            self.populate_tree(self.process_data)
            return
        
        # Find matching processes
        matching_pids = set()
        process_map = {p['pid']: p for p in self.process_data}
        
        # First pass: find directly matching processes
        for p in self.process_data:
            if (text.lower() in p['name'].lower() or
                text.lower() in str(p['pid']) or
                text.lower() in p['cmdline'].lower()):
                matching_pids.add(p['pid'])
        
        # Second pass: include parents of matching processes to maintain tree structure
        additional_pids = set()
        for pid in matching_pids:
            process = process_map[pid]
            ppid = process['ppid']
            # Walk up the parent chain
            while ppid != 0 and ppid in process_map:
                if ppid not in matching_pids:
                    additional_pids.add(ppid)
                parent = process_map[ppid]
                ppid = parent['ppid']
        
        matching_pids.update(additional_pids)
        
        # Filter to only matching processes
        filtered = [p for p in self.process_data if p['pid'] in matching_pids]
        
        self.populate_tree(filtered)
    
    def export_data(self):
        """Export process data to a file."""
        if not self.process_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Process Data", "processes.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.process_data, f, indent=2)
    
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


