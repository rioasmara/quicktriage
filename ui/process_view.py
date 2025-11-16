"""
Process view widget for displaying process information.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QFrame,
    QStyledItemDelegate, QStyleOptionViewItem, QMenu, QDialog,
    QTextEdit, QDialogButtonBox, QApplication
)
from PySide6.QtCore import Qt, QTimer, QRect, QPoint, QEvent
from PySide6.QtGui import QColor, QBrush, QPainter, QAction, QPen, QMouseEvent
import base64


class Base64DecodeDialog(QDialog):
    """Dialog for displaying decoded base64 text."""
    
    def __init__(self, decoded_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Base64 Decoded Result")
        self.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(self)
        
        # Label
        label = QLabel("Decoded Base64:")
        layout.addWidget(label)
        
        # Text area
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setPlainText(decoded_text)
        layout.addWidget(self.text_area)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        button_box.accepted.connect(self.accept)
        layout.addWidget(button_box)


class HighlightDelegate(QStyledItemDelegate):
    """Custom delegate to paint backgrounds that won't be overridden by stylesheet."""
    
    def __init__(self, process_view):
        super().__init__()
        self.process_view = process_view
        # Cache for faster lookups - map (row, parent_row) to tree item
        self._item_cache = {}
        self._cache_dirty = True
    
    def _get_tree_item(self, index):
        """Get the QTreeWidgetItem from the index, using cache for performance."""
        if self._cache_dirty:
            self._rebuild_cache()
        
        parent = index.parent()
        row = index.row()
        parent_row = parent.row() if parent.isValid() else -1
        cache_key = (row, parent_row)
        
        if cache_key in self._item_cache:
            return self._item_cache[cache_key]
        
        # Fallback: find item directly
        tree_widget = self.process_view.tree
        tree_item = None
        
        if parent.isValid():
            parent_row = parent.row()
            if parent_row < tree_widget.topLevelItemCount():
                parent_item = tree_widget.topLevelItem(parent_row)
                if parent_item and row < parent_item.childCount():
                    tree_item = parent_item.child(row)
        else:
            if row < tree_widget.topLevelItemCount():
                tree_item = tree_widget.topLevelItem(row)
        
        if tree_item:
            self._item_cache[cache_key] = tree_item
        
        return tree_item
    
    def _rebuild_cache(self):
        """Rebuild the cache of tree items."""
        self._item_cache.clear()
        tree_widget = self.process_view.tree
        
        # Cache top-level items
        for row in range(tree_widget.topLevelItemCount()):
            item = tree_widget.topLevelItem(row)
            if item:
                self._item_cache[(row, -1)] = item
                # Cache children
                for child_row in range(item.childCount()):
                    child = item.child(child_row)
                    if child:
                        self._item_cache[(child_row, row)] = child
        
        self._cache_dirty = False
    
    def invalidate_cache(self):
        """Invalidate the cache - call this when the tree is repopulated."""
        self._cache_dirty = True
        self._item_cache.clear()
    
    def paint(self, painter, option, index):
        """Paint the item with custom background if it has one."""
        # Draw visible branch indicators for column 0
        if index.column() == 0:
            tree_item = self._get_tree_item(index)
            if tree_item and tree_item.childCount() > 0:
                # Draw visible arrow indicator
                self._draw_branch_indicator(painter, option, tree_item)
        
        # Get highlight colors from item data (much faster than dictionary lookup)
        # Use column 0 data role to store highlight info
        if index.column() == 0:
            highlight_type = index.data(Qt.ItemDataRole.UserRole)
            if highlight_type:
                # Get colors from item data roles (stored as QVariant)
                bg_color_data = index.data(Qt.ItemDataRole.UserRole + 1)  # Background color
                fg_color_data = index.data(Qt.ItemDataRole.UserRole + 2)  # Foreground color
                
                if bg_color_data:
                    bg_color = bg_color_data if isinstance(bg_color_data, QColor) else QColor(bg_color_data)
                    painter.fillRect(option.rect, bg_color)
                    
                    if fg_color_data:
                        fg_color = fg_color_data if isinstance(fg_color_data, QColor) else QColor(fg_color_data)
                        option.palette.setColor(option.palette.ColorRole.Text, fg_color)
                    
                    super().paint(painter, option, index)
                    return
        
        # For other columns, check if parent item (column 0) has highlight
        if index.column() != 0:
            # Get the item for column 0 of the same row
            parent_index = index.sibling(index.row(), 0)
            if parent_index.isValid():
                highlight_type = parent_index.data(Qt.ItemDataRole.UserRole)
                if highlight_type:
                    bg_color_data = parent_index.data(Qt.ItemDataRole.UserRole + 1)
                    fg_color_data = parent_index.data(Qt.ItemDataRole.UserRole + 2)
                    
                    if bg_color_data:
                        bg_color = bg_color_data if isinstance(bg_color_data, QColor) else QColor(bg_color_data)
                        painter.fillRect(option.rect, bg_color)
                        
                        if fg_color_data:
                            fg_color = fg_color_data if isinstance(fg_color_data, QColor) else QColor(fg_color_data)
                            option.palette.setColor(option.palette.ColorRole.Text, fg_color)
                        
                        super().paint(painter, option, index)
                        return
        
        # Default painting for non-highlighted items
        super().paint(painter, option, index)
    
    def _draw_branch_indicator(self, painter, option, item):
        """Draw a visible branch indicator (arrow) for expandable items."""
        if not item or item.childCount() == 0:
            return
        
        # Get the tree widget to check if item is expanded
        tree_widget = self.process_view.tree
        is_expanded = item.isExpanded()
        
        # Calculate arrow position - draw it in the branch area (to the left of the item)
        arrow_size = 8
        indent = tree_widget.indentation()
        
        # In Qt, the branch area is always to the immediate left of the item
        # option.rect.left() already accounts for the item's indentation level
        # The branch area for this item is from (option.rect.left() - indent) to option.rect.left()
        # Center the arrow in this branch area
        branch_area_left = option.rect.left() - indent
        arrow_x = branch_area_left + indent // 2 - arrow_size // 2
        arrow_y = option.rect.center().y()
        
        # Make sure arrow doesn't go off-screen to the left (safety check)
        if arrow_x < 0:
            arrow_x = max(2, option.rect.left() - indent + 2)
        
        # Use a visible color (light blue/cyan from theme)
        arrow_color = QColor(41, 182, 211)  # #29b6d3 - theme accent color
        
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(arrow_color, 1.5))
        painter.setBrush(QBrush(arrow_color))
        
        # Draw arrow (triangle)
        if is_expanded:
            # Draw down arrow (▼)
            points = [
                QPoint(arrow_x, arrow_y - arrow_size // 2),
                QPoint(arrow_x + arrow_size, arrow_y - arrow_size // 2),
                QPoint(arrow_x + arrow_size // 2, arrow_y + arrow_size // 2)
            ]
        else:
            # Draw right arrow (▶)
            points = [
                QPoint(arrow_x, arrow_y - arrow_size // 2),
                QPoint(arrow_x + arrow_size // 2, arrow_y),
                QPoint(arrow_x, arrow_y + arrow_size // 2)
            ]
        
        painter.drawPolygon(points)
        painter.restore()


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
        # Store original command line text to prevent accidental edits
        self.original_command_texts = {}  # {item: original_text}
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
        self.tree.setAlternatingRowColors(False)  # Disable to allow custom backgrounds
        self.tree.setSelectionBehavior(QTreeWidget.SelectRows)
        self.tree.setTextElideMode(Qt.TextElideMode.ElideNone)  # Allow full text display
        self.tree.resizeColumnToContents(0)
        
        # Enable context menu
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_context_menu)
        
        # Prevent accidental edits to command column
        self.tree.itemChanged.connect(self._prevent_command_edit)
        
        # Set custom delegate to paint backgrounds
        self.tree.setItemDelegate(HighlightDelegate(self))
        
        # Install event filter to handle arrow clicks
        self.tree.viewport().installEventFilter(self)
        
        layout.addWidget(self.tree)
    
    def update_data(self, data):
        """Update the tree with new process data."""
        if not data or 'processes' not in data:
            return
        
        processes = data['processes']
        if not isinstance(processes, list):
            return
        
        self.process_data = processes
        # Defer heavy work to make UI responsive
        # Use QTimer.singleShot to defer work after current event processing
        QTimer.singleShot(0, lambda: self.populate_tree(self.process_data))
    
    def update_network_data(self, network_data):
        """Update network data for correlation with processes."""
        self.network_data = network_data
        # Refresh the tree if process data is already loaded - defer heavy work
        if self.process_data:
            QTimer.singleShot(0, lambda: self.populate_tree(self.process_data))
    
    def populate_tree(self, processes):
        """Populate the tree with process data organized by parent-child relationships."""
        # Stop blinking before clearing
        self.blinking_items.clear()
        self.original_command_texts.clear()
        self.blink_state = False
        self.tree.clear()
        
        # Invalidate the delegate cache when tree is cleared
        delegate = self.tree.itemDelegate()
        if isinstance(delegate, HighlightDelegate):
            delegate.invalidate_cache()
        
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
            # Ensure PID is an integer for consistent comparison
            try:
                pid = int(pid)
            except (ValueError, TypeError):
                pass
            
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
            # Store original command text to prevent accidental edits
            self.original_command_texts[item] = cmdline
            # Make command column editable to allow text selection
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
            
            # Apply color coding based on network status, LOLBIN, and public IP
            # Priority: Public IP + LOLBIN (blinking red) > Public IP (red) > ESTABLISHED + LOLBIN (blinking red) > 
            #          ESTABLISHED (red) > LISTEN (yellow) > LOLBIN (light blue)
            process_name_lower = process['name'].lower()
            is_lolbin = process_name_lower in self.LOLBINS
            
            # Get network status for this PID
            pid_status = network_status_map.get(pid) if network_status_map else None
            
            # Apply highlighting based on priority
            # Store highlight colors in item data roles (much faster than dictionaries)
            # Using darker backgrounds with white text for better readability
            if pid_status == 'public_ip' and is_lolbin:
                # Blinking red for LOLBINs with public IP connections (highest priority)
                self.blinking_items[pid] = item
                bg_color = QColor(200, 50, 50)  # Darker red for better contrast
                fg_color = QColor(255, 255, 255)  # White text for readability
                # Store in item data roles (delegate will read from here)
                item.setData(0, Qt.ItemDataRole.UserRole, "blink-red")
                item.setData(0, Qt.ItemDataRole.UserRole + 1, bg_color)  # Background color
                item.setData(0, Qt.ItemDataRole.UserRole + 2, fg_color)  # Foreground color
            elif pid_status == 'public_ip':
                # Red for public IP connections
                bg_color = QColor(220, 100, 100)  # Medium red for better contrast
                fg_color = QColor(255, 255, 255)  # White text for readability
                item.setData(0, Qt.ItemDataRole.UserRole, "red")
                item.setData(0, Qt.ItemDataRole.UserRole + 1, bg_color)
                item.setData(0, Qt.ItemDataRole.UserRole + 2, fg_color)
            elif pid_status == 'established' and is_lolbin:
                # Blinking red for LOLBINs with established connections
                self.blinking_items[pid] = item
                bg_color = QColor(200, 50, 50)  # Darker red for better contrast
                fg_color = QColor(255, 255, 255)  # White text for readability
                # Store in item data roles (delegate will read from here)
                item.setData(0, Qt.ItemDataRole.UserRole, "blink-red")
                item.setData(0, Qt.ItemDataRole.UserRole + 1, bg_color)  # Background color
                item.setData(0, Qt.ItemDataRole.UserRole + 2, fg_color)  # Foreground color
            elif pid_status == 'established':
                # Red for established connections
                bg_color = QColor(220, 100, 100)  # Medium red for better contrast
                fg_color = QColor(255, 255, 255)  # White text for readability
                item.setData(0, Qt.ItemDataRole.UserRole, "red")
                item.setData(0, Qt.ItemDataRole.UserRole + 1, bg_color)
                item.setData(0, Qt.ItemDataRole.UserRole + 2, fg_color)
            elif pid_status == 'listening':
                # Yellow for listening processes
                bg_color = QColor(220, 180, 50)  # Darker yellow/orange for better contrast
                fg_color = QColor(0, 0, 0)  # Black text on yellow background
                item.setData(0, Qt.ItemDataRole.UserRole, "yellow")
                item.setData(0, Qt.ItemDataRole.UserRole + 1, bg_color)
                item.setData(0, Qt.ItemDataRole.UserRole + 2, fg_color)
            elif is_lolbin:
                # Light blue for LOLBINs (when no network status)
                bg_color = QColor(80, 140, 200)  # Darker blue for better contrast
                fg_color = QColor(255, 255, 255)  # White text for readability
                item.setData(0, Qt.ItemDataRole.UserRole, "blue")
                item.setData(0, Qt.ItemDataRole.UserRole + 1, bg_color)
                item.setData(0, Qt.ItemDataRole.UserRole + 2, fg_color)
            
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
        
        # Bright red when on, darker red when off - using darker colors for better contrast
        if self.blink_state:
            bg_color = QColor(220, 30, 30)  # Bright red with good contrast
        else:
            bg_color = QColor(180, 60, 60)  # Darker red
        
        # Update all blinking items - only update item data roles (delegate will handle painting)
        for item in self.blinking_items.values():
            if item:  # Check if item still exists
                # Get foreground color from item data
                fg_color = item.data(0, Qt.ItemDataRole.UserRole + 2)
                if not fg_color:
                    fg_color = QColor(255, 255, 255)  # Default white
                
                # Update item data roles (delegate will read from here)
                item.setData(0, Qt.ItemDataRole.UserRole + 1, bg_color)  # Background color
                item.setData(0, Qt.ItemDataRole.UserRole + 2, fg_color)  # Foreground color
        
        # Trigger single repaint after updating all items (much more efficient)
        if self.blinking_items:
            self.tree.viewport().update()
    
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
    
    def _is_public_ip(self, address):
        """Check if an address is a public IP (not private/localhost)."""
        if not address or address == 'N/A':
            return False
        
        # Extract IP from "IP:PORT" format
        if ':' in address:
            ip = address.split(':')[0].strip()
        else:
            ip = address.strip()
        
        # Check if it's localhost first
        if self._is_localhost(address):
            return False
        
        # IPv6 check
        if ':' in ip:
            # IPv6 link-local addresses (fe80::/10)
            if ip.startswith('fe80:') or ip.startswith('fe80::'):
                return False
            # IPv6 unique local addresses (fc00::/7) - fc00::/7 and fd00::/8
            if ip.startswith('fc') or ip.startswith('fd'):
                return False
            # IPv6 localhost/loopback
            if ip == '::1' or ip.lower() == 'localhost' or ip == '0:0:0:0:0:0:0:1':
                return False
            # IPv6 unspecified address
            if ip == '::' or ip == '0:0:0:0:0:0:0:0':
                return False
            # If it's a valid IPv6 and not private, it's public
            return True
        
        # IPv4 check
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            # Convert to integers
            octets = [int(part) for part in parts]
            
            # Private IP ranges:
            # 10.0.0.0/8
            if octets[0] == 10:
                return False
            # 172.16.0.0/12
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return False
            # 192.168.0.0/16
            if octets[0] == 192 and octets[1] == 168:
                return False
            # 169.254.0.0/16 (link-local)
            if octets[0] == 169 and octets[1] == 254:
                return False
            # 127.0.0.0/8 (localhost)
            if octets[0] == 127:
                return False
            # 0.0.0.0 (unspecified)
            if all(o == 0 for o in octets):
                return False
            
            # If it's a valid IPv4 and not in private ranges, it's public
            return True
        except (ValueError, IndexError):
            return False
    
    def _build_network_status_map(self):
        """Build a mapping of PID to network status (listening, established, or public_ip)."""
        status_map = {}
        
        if not self.network_data:
            return status_map
        
        if 'connections' not in self.network_data:
            return status_map
        
        connections = self.network_data['connections']
        if not connections:
            return status_map
        
        for conn in connections:
            pid = conn.get('pid')
            # Skip if PID is 'N/A', None, or cannot be converted to int
            if pid == 'N/A' or pid is None:
                continue
            
            # Convert PID to integer for consistent comparison
            try:
                pid = int(pid)
            except (ValueError, TypeError):
                continue
            
            status = conn.get('status', '')
            if not status or status == 'N/A':
                continue
            
            status = status.upper()
            
            # Skip highlighting if remote address is localhost
            remote_addr = conn.get('remote_address', '')
            if status == 'ESTABLISHED' and self._is_localhost(remote_addr):
                continue
            
            # Check if it's a public IP connection
            is_public_ip = self._is_public_ip(remote_addr)
            
            # Priority: public_ip > established > listening
            # If process has an established connection to public IP, mark it as public_ip (highest priority)
            if status == 'ESTABLISHED' and is_public_ip:
                status_map[pid] = 'public_ip'
            # If process has an established connection and not already marked as public_ip, mark it as established
            elif status == 'ESTABLISHED' and pid not in status_map:
                status_map[pid] = 'established'
            # If process is listening and not already marked, mark as listening
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
        
        # Blinking red - LOLBIN with ESTABLISHED (darker red for better contrast)
        red_box = QLabel()
        red_box.setFixedSize(14, 14)
        red_box.setStyleSheet(
            "background-color: #c83232;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(red_box)
        red_label = QLabel("Blink Red: LOLBIN+ESTABLISHED")
        red_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(red_label)
        
        # Red - ESTABLISHED (medium red for better contrast)
        red_box2 = QLabel()
        red_box2.setFixedSize(14, 14)
        red_box2.setStyleSheet(
            "background-color: #dc6464;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(red_box2)
        red_label2 = QLabel("Red: ESTABLISHED")
        red_label2.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(red_label2)
        
        # Yellow - LISTEN (darker yellow/orange for better contrast)
        yellow_box = QLabel()
        yellow_box.setFixedSize(14, 14)
        yellow_box.setStyleSheet(
            "background-color: #dcb432;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(yellow_box)
        yellow_label = QLabel("Yellow: LISTEN")
        yellow_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(yellow_label)
        
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
        
        legend_layout.addStretch()
        return legend_frame
    
    def _prevent_command_edit(self, item, column):
        """Prevent accidental edits to the command column by reverting changes."""
        if column == 7:  # Command column
            if item in self.original_command_texts:
                original_text = self.original_command_texts[item]
                # Block signals to prevent infinite loop
                self.tree.blockSignals(True)
                item.setText(7, original_text)
                self.tree.blockSignals(False)
    
    def _show_context_menu(self, position):
        """Show context menu on right-click."""
        item = self.tree.itemAt(position)
        if not item:
            return
        
        # Get the column where the click occurred
        column = self.tree.columnAt(position.x())
        
        # Only show decode option for command column (column 7)
        if column != 7:
            return
        
        # Get text from the command column
        cell_text = item.text(7)
        if not cell_text:
            return
        
        # Try to get selected text from clipboard first (user might have copied selected text)
        # Otherwise, use the full cell text
        clipboard = QApplication.clipboard()
        clipboard_text = clipboard.text()
        
        # Use clipboard text if it's a subset of the cell text, otherwise use cell text
        if clipboard_text and clipboard_text in cell_text:
            text_to_decode = clipboard_text
        else:
            text_to_decode = cell_text
        
        # Create context menu
        menu = QMenu(self)
        
        # Add decode base64 action
        decode_action = QAction("Decode base64", self)
        decode_action.triggered.connect(lambda: self._decode_base64(text_to_decode))
        menu.addAction(decode_action)
        
        # Show menu at cursor position
        menu.exec(self.tree.mapToGlobal(position))
    
    def _decode_base64(self, text):
        """Decode base64 text and show in dialog."""
        try:
            # Try to decode the selected text
            decoded_bytes = base64.b64decode(text, validate=True)
            # Try to decode as UTF-8 first
            try:
                decoded_text = decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # If UTF-8 fails, try latin-1
                try:
                    decoded_text = decoded_bytes.decode('latin-1')
                except UnicodeDecodeError:
                    # If both fail, show as hex
                    decoded_text = decoded_bytes.hex()
        except Exception as e:
            # If decoding fails, show error message
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self,
                "Decode Error",
                f"Failed to decode base64:\n{str(e)}"
            )
            return
        
        # Show decoded text in dialog
        dialog = Base64DecodeDialog(decoded_text, self)
        dialog.exec()
    
    def eventFilter(self, obj, event):
        """Handle mouse clicks on arrow indicators to expand/collapse items."""
        if obj == self.tree.viewport() and event.type() == QEvent.Type.MouseButtonPress:
            if isinstance(event, QMouseEvent) and event.button() == Qt.MouseButton.LeftButton:
                # Get the item at the click position
                item = self.tree.itemAt(event.pos())
                if item and item.childCount() > 0:
                    # Calculate arrow area - arrows are drawn in the branch area (left of items)
                    arrow_size = 6
                    indent = self.tree.indentation()
                    
                    # Get the visual rect for the item
                    visual_rect = self.tree.visualItemRect(item)
                    
                    # Calculate the depth of this item
                    depth = 0
                    parent = item.parent()
                    while parent:
                        depth += 1
                        parent = parent.parent()
                    
                    # Calculate the branch area (left of the item)
                    # The branch area starts at the left edge minus the indentation
                    branch_area_left = visual_rect.left() - indent * (depth + 1)
                    branch_area_right = visual_rect.left()
                    
                    # Arrow is drawn at the left edge of the item (with small offset)
                    arrow_area_left = visual_rect.left() + 2
                    arrow_area_right = arrow_area_left + arrow_size + 4  # Add padding for easier clicking
                    
                    # Check if click is in the arrow area or branch area
                    click_x = event.pos().x()
                    if (branch_area_left <= click_x <= branch_area_right) or \
                       (arrow_area_left <= click_x <= arrow_area_right):
                        # Toggle expand/collapse
                        item.setExpanded(not item.isExpanded())
                        return True  # Event handled
        
        # Let the default event handling proceed
        return super().eventFilter(obj, event)
