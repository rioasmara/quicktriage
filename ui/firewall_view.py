"""
Firewall view widget for displaying Windows Firewall rules.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QComboBox,
    QCheckBox, QFrame, QStyledItemDelegate
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


class FirewallView(QWidget):
    """Widget for displaying Windows Firewall rules."""
    
    def __init__(self):
        super().__init__()
        self.firewall_data = None
        self.network_data = None
        self.matched_rules = set()  # Store indices of rules that match active connections
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
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search rules...")
        self.search_box.textChanged.connect(self.filter_rules)
        
        # Profile filter
        control_layout.addWidget(QLabel("Profile:"))
        self.profile_filter = QComboBox()
        self.profile_filter.addItems(["All", "Domain", "Private", "Public"])
        self.profile_filter.currentTextChanged.connect(self.filter_rules)
        control_layout.addWidget(self.profile_filter)
        
        # Direction filter
        control_layout.addWidget(QLabel("Direction:"))
        self.direction_filter = QComboBox()
        self.direction_filter.addItems(["All", "Inbound", "Outbound"])
        self.direction_filter.currentTextChanged.connect(self.filter_rules)
        control_layout.addWidget(self.direction_filter)
        
        # Action filter
        control_layout.addWidget(QLabel("Action:"))
        self.action_filter = QComboBox()
        self.action_filter.addItems(["All", "Allow", "Block"])
        self.action_filter.currentTextChanged.connect(self.filter_rules)
        control_layout.addWidget(self.action_filter)
        
        # Enabled filter
        self.enabled_only_checkbox = QCheckBox("Enabled Only")
        self.enabled_only_checkbox.toggled.connect(self.filter_rules)
        control_layout.addWidget(self.enabled_only_checkbox)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_data)
        
        control_layout.addStretch()
        control_layout.addWidget(self.export_btn)
        
        layout.addLayout(control_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(13)
        self.table.setHorizontalHeaderLabels([
            "Name", "Profile", "Direction", "Enabled", "Action", "Protocol",
            "Local Ports", "Remote Ports", "Local Addresses", "Remote Addresses",
            "Application", "Service", "Description"
        ])
        # Set custom delegate to paint backgrounds
        self.table.setItemDelegate(TableHighlightDelegate(self.table))
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        # Performance optimizations
        self.table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)  # Smoother scrolling
        self.table.resizeColumnsToContents()
        
        layout.addWidget(self.table)
    
    def update_network_data(self, data):
        """Update network connection data for correlation."""
        self.network_data = data
        self._correlate_network_with_firewall()
        # Re-populate table to show highlights
        if self.firewall_data:
            self.filter_rules()
    
    def _correlate_network_with_firewall(self):
        """Correlate network connections with firewall rules."""
        if not self.firewall_data or not self.network_data:
            self.matched_rules = set()
            return
        
        connections = self.network_data.get('connections', []) or []
        if not connections:
            self.matched_rules = set()
            return
        
        self.matched_rules = set()
        
        # For each connection, find matching firewall rules
        for conn_idx, conn in enumerate(connections):
            if conn.get('status') == 'NONE' or conn.get('status') == 'CLOSED':
                continue
            
            local_addr = conn.get('local_address', 'N/A')
            remote_addr = conn.get('remote_address', 'N/A')
            
            # Parse addresses
            local_ip, local_port = self._parse_address(local_addr)
            remote_ip, remote_port = self._parse_address(remote_addr)
            
            if local_ip == 'N/A' or local_port == 'N/A':
                continue
            
            # Determine connection type based on status
            conn_status = conn.get('status', '').upper()
            is_listening = (conn_status == 'LISTEN')
            is_established = (conn_status == 'ESTABLISHED')
            
            # Check each firewall rule
            for idx, rule in enumerate(self.firewall_data):
                # Rule must be enabled and allow
                if not rule.get('enabled', False) or rule.get('action', '') != 'Allow':
                    continue
                
                rule_direction = rule.get('direction', '')
                
                # Match protocol
                rule_protocol = rule.get('protocol', '').upper()
                if rule_protocol not in ('TCP', 'UDP', 'ANY', 'N/A', ''):
                    continue
                
                # Match based on connection type
                if is_listening:
                    # Listening connections match Inbound rules
                    if rule_direction != 'Inbound':
                        continue
                    # Match local port
                    rule_local_ports = rule.get('local_ports', 'N/A')
                    if not self._port_matches(local_port, rule_local_ports):
                        continue
                    # Match local address if specified
                    rule_local_addr = rule.get('local_addresses', 'N/A')
                    if rule_local_addr != 'N/A' and rule_local_addr:
                        if not self._address_matches(local_ip, rule_local_addr):
                            continue
                elif is_established and remote_ip != 'N/A':
                    # Established connections: try both directions
                    # For outbound established: match Outbound rules with remote port
                    if rule_direction == 'Outbound':
                        rule_remote_ports = rule.get('remote_ports', 'N/A')
                        if self._port_matches(remote_port, rule_remote_ports):
                            rule_remote_addr = rule.get('remote_addresses', 'N/A')
                            if rule_remote_addr == 'N/A' or not rule_remote_addr or self._address_matches(remote_ip, rule_remote_addr):
                                self.matched_rules.add(idx)
                                continue
                    # For inbound established: match Inbound rules with local port
                    elif rule_direction == 'Inbound':
                        rule_local_ports = rule.get('local_ports', 'N/A')
                        if self._port_matches(local_port, rule_local_ports):
                            rule_local_addr = rule.get('local_addresses', 'N/A')
                            if rule_local_addr == 'N/A' or not rule_local_addr or self._address_matches(local_ip, rule_local_addr):
                                self.matched_rules.add(idx)
                                continue
                    continue
                else:
                    # Other states: try outbound rules
                    if rule_direction != 'Outbound':
                        continue
                    # Match remote port if available
                    if remote_port != 'N/A':
                        rule_remote_ports = rule.get('remote_ports', 'N/A')
                        if not self._port_matches(remote_port, rule_remote_ports):
                            continue
                        rule_remote_addr = rule.get('remote_addresses', 'N/A')
                        if rule_remote_addr != 'N/A' and rule_remote_addr:
                            if not self._address_matches(remote_ip, rule_remote_addr):
                                continue
                    else:
                        # No remote port, match local port
                        rule_local_ports = rule.get('local_ports', 'N/A')
                        if not self._port_matches(local_port, rule_local_ports):
                            continue
                
                # This rule matches the connection
                self.matched_rules.add(idx)
    
    def _parse_address(self, address_str):
        """Parse an address string like '192.168.1.1:8080' into IP and port."""
        if address_str == 'N/A' or not address_str:
            return 'N/A', 'N/A'
        
        try:
            if ':' in address_str:
                ip, port = address_str.rsplit(':', 1)
                return ip.strip(), port.strip()
            else:
                return address_str.strip(), 'N/A'
        except:
            return 'N/A', 'N/A'
    
    def _port_matches(self, port, rule_ports):
        """Check if a port matches a firewall rule port specification."""
        if rule_ports == 'N/A' or not rule_ports or rule_ports == '*':
            return True  # Wildcard matches all
        
        try:
            port_int = int(port)
        except:
            return False
        
        # Rule ports can be: single port, range (e.g., "80-90"), or comma-separated list
        port_ranges = str(rule_ports).split(',')
        for port_range in port_ranges:
            port_range = port_range.strip()
            if '-' in port_range:
                # Range
                try:
                    start, end = port_range.split('-', 1)
                    if int(start.strip()) <= port_int <= int(end.strip()):
                        return True
                except:
                    continue
            else:
                # Single port
                try:
                    if int(port_range) == port_int:
                        return True
                except:
                    continue
        
        return False
    
    def _address_matches(self, ip, rule_addresses):
        """Check if an IP matches a firewall rule address specification."""
        if rule_addresses == 'N/A' or not rule_addresses or rule_addresses == '*':
            return True  # Wildcard matches all
        
        rule_addresses = str(rule_addresses).upper()
        
        # Common patterns: Any, LocalSubnet, DNS, DHCP, WINS, DefaultGateway
        if rule_addresses in ('ANY', '*', 'LOCALSUBNET'):
            return True
        
        # Check if IP is in the rule addresses (comma-separated or range)
        address_list = [addr.strip() for addr in rule_addresses.split(',')]
        for addr in address_list:
            if addr == ip or addr == '*' or addr == 'ANY':
                return True
            # Check for CIDR notation (e.g., 192.168.1.0/24)
            if '/' in addr:
                if self._ip_in_cidr(ip, addr):
                    return True
            # Check for range (e.g., 192.168.1.1-192.168.1.255)
            if '-' in addr:
                if self._ip_in_range(ip, addr):
                    return True
        
        return False
    
    def _ip_in_cidr(self, ip, cidr):
        """Check if IP is in CIDR range."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except:
            return False
    
    def _ip_in_range(self, ip, ip_range):
        """Check if IP is in range."""
        try:
            start, end = ip_range.split('-', 1)
            import ipaddress
            return ipaddress.ip_address(start.strip()) <= ipaddress.ip_address(ip) <= ipaddress.ip_address(end.strip())
        except:
            return False
    
    def update_data(self, data):
        """Update the view with new firewall data."""
        if not data:
            self.firewall_data = []
            QTimer.singleShot(0, lambda: self.populate_table([]))
            return
        
        # Check for errors
        if 'error' in data:
            # Show error message
            error_msg = data.get('error', 'Unknown error')
        
        rules_list = data.get('rules', []) or []
        self.firewall_data = rules_list
        
        # Re-correlate with network data if available
        if self.network_data:
            self._correlate_network_with_firewall()
        
        # Populate table with all rules first, then apply filters if any are set
        if rules_list:
            # Check if any filters are active
            search_text = self.search_box.text().lower()
            profile_filter = self.profile_filter.currentText()
            direction_filter = self.direction_filter.currentText()
            action_filter = self.action_filter.currentText()
            enabled_only = self.enabled_only_checkbox.isChecked()
            
            # If any filters are active, apply them; otherwise show all
            # Defer heavy work to make UI responsive
            if search_text or profile_filter != "All" or direction_filter != "All" or action_filter != "All" or enabled_only:
                QTimer.singleShot(0, lambda: self.filter_rules())
            else:
                QTimer.singleShot(0, lambda: self.populate_table(rules_list))
        else:
            QTimer.singleShot(0, lambda: self.populate_table([]))
    
    def populate_table(self, rules):
        """Populate the table with firewall rules."""
        # Disable sorting and updates for better performance during bulk operations
        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        
        try:
            self.table.setRowCount(len(rules))
            
            # Create a mapping from rule index in firewall_data to row index in filtered rules
            # This is needed because matched_rules uses indices from firewall_data
            rule_idx_to_row = {}
            if self.firewall_data:
                for row, rule in enumerate(rules):
                    try:
                        # Find the index of this rule in the original firewall_data
                        rule_idx = self.firewall_data.index(rule)
                        rule_idx_to_row[rule_idx] = row
                    except ValueError:
                        # Rule not found in original data (shouldn't happen)
                        pass
            
            for row, rule in enumerate(rules):
                try:
                    # Safely convert all values to strings
                    name = str(rule.get('name', 'N/A'))
                    profile = str(rule.get('profile', 'N/A'))
                    direction = str(rule.get('direction', 'N/A'))
                    enabled = rule.get('enabled', False)
                    action = str(rule.get('action', 'N/A'))
                    protocol = str(rule.get('protocol', 'N/A'))
                    local_ports = str(rule.get('local_ports', 'N/A'))
                    remote_ports = str(rule.get('remote_ports', 'N/A'))
                    local_addresses = str(rule.get('local_addresses', 'N/A'))
                    remote_addresses = str(rule.get('remote_addresses', 'N/A'))
                    application_name = str(rule.get('application_name', 'N/A'))
                    service_name = str(rule.get('service_name', 'N/A'))
                    description = str(rule.get('description', 'N/A'))
                    
                    # Set items
                    self.table.setItem(row, 0, QTableWidgetItem(name))
                    self.table.setItem(row, 1, QTableWidgetItem(profile))
                    self.table.setItem(row, 2, QTableWidgetItem(direction))
                    
                    # Enabled status with color coding - darker colors for better contrast
                    enabled_item = QTableWidgetItem("Yes" if enabled else "No")
                    if enabled:
                        enabled_item.setBackground(QBrush(QColor(50, 180, 50)))  # Darker green for better contrast
                        enabled_item.setForeground(QBrush(QColor(255, 255, 255)))  # White text
                    else:
                        enabled_item.setBackground(QBrush(QColor(220, 100, 100)))  # Darker red for better contrast
                        enabled_item.setForeground(QBrush(QColor(255, 255, 255)))  # White text
                    self.table.setItem(row, 3, enabled_item)
                    
                    # Action with color coding - darker colors for better contrast
                    action_item = QTableWidgetItem(action)
                    if action == "Allow":
                        action_item.setBackground(QBrush(QColor(50, 180, 50)))  # Darker green for better contrast
                        action_item.setForeground(QBrush(QColor(255, 255, 255)))  # White text
                    elif action == "Block":
                        action_item.setBackground(QBrush(QColor(220, 100, 100)))  # Darker red for better contrast
                        action_item.setForeground(QBrush(QColor(255, 255, 255)))  # White text
                    self.table.setItem(row, 4, action_item)
                    
                    self.table.setItem(row, 5, QTableWidgetItem(protocol))
                    self.table.setItem(row, 6, QTableWidgetItem(local_ports))
                    self.table.setItem(row, 7, QTableWidgetItem(remote_ports))
                    
                    # Addresses with tooltips for long values
                    local_addr_item = QTableWidgetItem(local_addresses)
                    if len(local_addresses) > 30:
                        local_addr_item.setToolTip(local_addresses)
                    self.table.setItem(row, 8, local_addr_item)
                    
                    remote_addr_item = QTableWidgetItem(remote_addresses)
                    if len(remote_addresses) > 30:
                        remote_addr_item.setToolTip(remote_addresses)
                    self.table.setItem(row, 9, remote_addr_item)
                    
                    # Application name with tooltip
                    app_item = QTableWidgetItem(application_name)
                    if len(application_name) > 50:
                        app_item.setToolTip(application_name)
                    self.table.setItem(row, 10, app_item)
                    
                    self.table.setItem(row, 11, QTableWidgetItem(service_name))
                    
                    # Description with tooltip
                    desc_item = QTableWidgetItem(description)
                    if len(description) > 50:
                        desc_item.setToolTip(description)
                    self.table.setItem(row, 12, desc_item)
                    
                    # Highlight rules that match active network connections
                    try:
                        # Find the index of this rule in the original firewall_data
                        rule_idx = self.firewall_data.index(rule)
                        if rule_idx in self.matched_rules:
                            # Highlight the entire row with darker yellow/orange background for better contrast
                            highlight_color = QColor(220, 180, 50)  # Darker yellow/orange for better contrast
                            fg_color = QColor(0, 0, 0)  # Black text on yellow background
                            for col in range(13):
                                item = self.table.item(row, col)
                                if item:
                                    # Override with yellow highlight for matched rules
                                    item.setBackground(QBrush(highlight_color))
                                    item.setForeground(QBrush(fg_color))
                                    # Add tooltip indicating match
                                    current_tooltip = item.toolTip()
                                    match_text = "✓ Matches active network connection"
                                    if current_tooltip:
                                        item.setToolTip(f"{current_tooltip}\n\n{match_text}")
                                    else:
                                        item.setToolTip(match_text)
                    except ValueError:
                        # Rule not found in firewall_data (shouldn't happen)
                        pass
                    except Exception as e:
                        pass
                    
                except Exception as e:
                    # Still add the row with error info
                    self.table.setItem(row, 0, QTableWidgetItem(rule.get('name', f'Rule {row}')))
                    self.table.setItem(row, 1, QTableWidgetItem('Error'))
                    self.table.setItem(row, 2, QTableWidgetItem('N/A'))
                    self.table.setItem(row, 3, QTableWidgetItem('N/A'))
                    self.table.setItem(row, 4, QTableWidgetItem('N/A'))
                    self.table.setItem(row, 5, QTableWidgetItem('N/A'))
                    self.table.setItem(row, 6, QTableWidgetItem('N/A'))
                    self.table.setItem(row, 7, QTableWidgetItem('N/A'))
                    self.table.setItem(row, 8, QTableWidgetItem('N/A'))
                    self.table.setItem(row, 9, QTableWidgetItem('N/A'))
                    self.table.setItem(row, 10, QTableWidgetItem('N/A'))
                    self.table.setItem(row, 11, QTableWidgetItem('N/A'))
                    self.table.setItem(row, 12, QTableWidgetItem(f'Error: {str(e)}'))
            
            # Resize columns only once after all rows are populated
            self.table.resizeColumnsToContents()
        finally:
            # Re-enable updates and sorting
            self.table.setUpdatesEnabled(True)
            self.table.setSortingEnabled(was_sorting)
    
    def filter_rules(self):
        """Filter rules based on search text and filters."""
        if not self.firewall_data:
            return
        
        # Get filter values
        search_text = self.search_box.text().lower()
        profile_filter = self.profile_filter.currentText()
        direction_filter = self.direction_filter.currentText()
        action_filter = self.action_filter.currentText()
        enabled_only = self.enabled_only_checkbox.isChecked()
        
        # Filter rules
        filtered = []
        for rule in self.firewall_data:
            # Text search
            text_match = (
                not search_text or
                search_text in rule.get('name', '').lower() or
                search_text in rule.get('description', '').lower() or
                search_text in rule.get('application_name', '').lower()
            )
            
            # Profile filter
            profile_match = (
                profile_filter == "All" or
                rule.get('profile', '') == profile_filter
            )
            
            # Direction filter
            direction_match = (
                direction_filter == "All" or
                rule.get('direction', '') == direction_filter
            )
            
            # Action filter
            action_match = (
                action_filter == "All" or
                rule.get('action', '') == action_filter
            )
            
            # Enabled filter
            enabled_match = (
                not enabled_only or
                rule.get('enabled', False)
            )
            
            if text_match and profile_match and direction_match and action_match and enabled_match:
                filtered.append(rule)
        
        self.populate_table(filtered)
    
    def export_data(self):
        """Export firewall data to a file."""
        if not self.firewall_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Firewall Data", "firewall_rules.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.firewall_data, f, indent=2)
    
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
        
        # Yellow - Matches active network connection (darker yellow/orange for better contrast)
        yellow_box = QLabel()
        yellow_box.setFixedSize(14, 14)
        yellow_box.setStyleSheet(
            "background-color: #dcb432;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(yellow_box)
        yellow_label = QLabel("Yellow: Matches network connection")
        yellow_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(yellow_label)
        
        # Green - Enabled/Allow (darker green for better contrast)
        green_box = QLabel()
        green_box.setFixedSize(14, 14)
        green_box.setStyleSheet(
            "background-color: #32b432;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(green_box)
        green_label = QLabel("Green: Enabled/Allow")
        green_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(green_label)
        
        # Red - Disabled/Block (darker red for better contrast)
        red_box = QLabel()
        red_box.setFixedSize(14, 14)
        red_box.setStyleSheet(
            "background-color: #dc6464;"
            " border: 1px solid #29b6d3;"
            " border-radius: 3px;"
        )
        legend_layout.addWidget(red_box)
        red_label = QLabel("Red: Disabled/Block")
        red_label.setStyleSheet(
            "QLabel { font-size: 9pt; color: #e6faff; background-color: transparent; }"
        )
        legend_layout.addWidget(red_label)
        
        legend_layout.addStretch()
        return legend_frame

