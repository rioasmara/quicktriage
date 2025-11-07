"""
Login view widget for displaying user login events and timeline chart.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout,
    QPushButton, QHBoxLayout, QLineEdit, QLabel, QGridLayout, QFrame, QComboBox, QScrollArea
)
from PySide6.QtCore import Qt
from datetime import datetime, timedelta
import numpy as np
import matplotlib
matplotlib.use('QtAgg')  # Use Qt backend for matplotlib
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.dates as mdates
try:
    import mplcursors
    MPLCURSORS_AVAILABLE = True
except ImportError:
    MPLCURSORS_AVAILABLE = False


class LoginView(QWidget):
    """Widget for displaying login events with timeline chart."""
    
    def __init__(self):
        super().__init__()
        self.login_data = None
        self.init_ui()
        # Initialize with empty data to show UI elements
        self.update_data({'logins': [], 'users': []})
    
    def init_ui(self):
        """Initialize the user interface."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(4)
        
        # Control bar (fixed at top)
        control_layout = QHBoxLayout()
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(4)
        
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_data)
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search events...")
        self.search_box.textChanged.connect(self.filter_data)
        
        # User filter dropdown
        self.user_filter = QComboBox()
        self.user_filter.setPlaceholderText("All Users")
        self.user_filter.addItem("All Users")
        # Configure to show full text without truncation
        self.user_filter.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self.user_filter.setMinimumWidth(200)  # Set minimum width to prevent truncation
        # Make the view show full text in dropdown
        view = self.user_filter.view()
        view.setMinimumWidth(300)  # Ensure dropdown list shows full text
        self.user_filter.currentTextChanged.connect(self.on_user_filter_changed)
        
        control_layout.addWidget(QLabel("Filter User:"))
        control_layout.addWidget(self.user_filter)
        control_layout.addWidget(QLabel("Search:"))
        control_layout.addWidget(self.search_box)
        control_layout.addStretch()
        control_layout.addWidget(self.export_btn)
        
        main_layout.addLayout(control_layout)
        
        # Create scroll area for scrollable content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        # Create content widget for scrollable area
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(4, 4, 4, 4)
        content_layout.setSpacing(4)
        
        # Statistics panel above the chart
        stats_frame = QFrame()
        stats_frame.setObjectName("stats_panel")
        stats_frame.setFrameStyle(QFrame.StyledPanel)
        stats_frame.setStyleSheet(
            "QFrame#stats_panel {"
            " background: qlineargradient(x1:0, y1:0, x2:1, y2:1,"
            " stop:0 #0d1724, stop:1 #12263a);"
            " border: 1px solid #29b6d3;"
            " border-radius: 10px;"
            " padding: 14px;"
            "}"
            "QFrame#stats_panel QLabel[role='heading'] {"
            " color: #7be9ff;"
            " font-size: 12pt;"
            " font-weight: 700;"
            " letter-spacing: 0.5px;"
            "}"
            "QFrame#stats_panel QLabel[role='subheading'] {"
            " color: #8fbad6;"
            " font-size: 9pt;"
            " padding-bottom: 4px;"
            "}"
            "QFrame#stats_panel QFrame[role='statCard'] {"
            " background-color: rgba(15, 28, 41, 0.9);"
            " border: 1px solid rgba(41, 182, 211, 0.25);"
            " border-radius: 8px;"
            " padding: 8px 10px;"
            "}"
            "QFrame#stats_panel QFrame[role='statCard']:hover {"
            " border: 1px solid #29b6d3;"
            " background-color: rgba(21, 40, 60, 0.95);"
            "}"
            "QFrame#stats_panel QLabel[role='statTitle'] {"
            " color: #9fd1f5;"
            " font-size: 8.5pt;"
            " font-weight: 600;"
            " letter-spacing: 0.4px;"
            "}"
            "QFrame#stats_panel QLabel[role='statValue'] {"
            " color: #f1faff;"
            " font-size: 18pt;"
            " font-weight: 600;"
            "}"
            "QFrame#stats_panel QLabel[role='statValue'][variant='primary'] {"
            " color: #7be9ff;"
            " font-size: 20pt;"
            "}"
            "QFrame#stats_panel QLabel[role='statValue'][variant='alert'] {"
            " color: #ff9f6e;"
            "}"
            "QFrame#stats_panel QLabel[role='statHint'] {"
            " color: #6f8195;"
            " font-size: 8pt;"
            "}"
        )
        stats_layout = QGridLayout(stats_frame)
        stats_layout.setHorizontalSpacing(14)
        stats_layout.setVerticalSpacing(12)
        stats_layout.setContentsMargins(4, 0, 4, 4)

        # Title and subtitle
        self.stats_title = QLabel("Authentication Snapshot")
        self.stats_title.setProperty("role", "heading")
        stats_layout.addWidget(self.stats_title, 0, 0, 1, 3)

        self.stats_subtitle = QLabel("Flight deck telemetry for recent logons")
        self.stats_subtitle.setProperty("role", "subheading")
        stats_layout.addWidget(self.stats_subtitle, 1, 0, 1, 3)

        # Create metric cards
        self.stat_values = {}
        self._metric_variants = {}
        metric_specs = [
            ("total_logins", "Total Logins", "Success events recorded", "primary"),
            ("failed_logins", "Failed Attempts", "Alerts for event 4625", "default"),
            ("avg_duration", "Avg Session", "Median observed session length", "primary"),
            ("earliest_login", "Earliest Login", "First successful access", "default"),
            ("latest_login", "Latest Login", "Most recent session", "default"),
            ("day_logins", "Daytime Logins", "06:00 - 18:00 activity", "default"),
            ("night_logins", "Nighttime Logins", "18:00 - 06:00 activity", "default"),
            ("unique_ips", "Unique Source IPs", "Distinct client addresses", "default"),
            ("unique_workstations", "Unique Workstations", "Originating hostnames", "default"),
            ("most_active_hour", "Peak Hour", "Highest density in past data", "default"),
        ]

        row = 2
        col = 0
        columns = 3
        for key, title, hint, variant in metric_specs:
            card_frame, value_label = self._create_stat_card(title, hint, variant)
            stats_layout.addWidget(card_frame, row, col)
            self.stat_values[key] = value_label
            self._metric_variants[key] = variant if variant else "default"
            col += 1
            if col >= columns:
                col = 0
                row += 1

        # ensure layout consumes remaining space nicely
        stats_layout.setRowStretch(row, 1)
        
        content_layout.addWidget(stats_frame)
        
        # Timeline chart (full width)
        self.figure = Figure(figsize=(12, 6))
        self.canvas = FigureCanvas(self.figure)
        self.axes = self.figure.add_subplot(111)
        self.canvas.setMinimumHeight(400)
        content_layout.addWidget(self.canvas)
        
        # Histogram chart (full width with proper sizing)
        self.histogram_figure = Figure(figsize=(12, 6))
        self.histogram_canvas = FigureCanvas(self.histogram_figure)
        self.histogram_axes = self.histogram_figure.add_subplot(111)
        self.histogram_canvas.setMinimumHeight(400)
        content_layout.addWidget(self.histogram_canvas)
        
        # Add stretch at the end
        content_layout.addStretch()
        
        # Set content widget to scroll area
        scroll_area.setWidget(content_widget)
        
        # Add scroll area to main layout
        main_layout.addWidget(scroll_area)

    def _create_stat_card(self, title, hint, variant):
        """Create a stylized statistics card with title, value placeholder, and hint."""
        card_frame = QFrame()
        card_frame.setProperty("role", "statCard")

        card_layout = QVBoxLayout(card_frame)
        card_layout.setContentsMargins(10, 8, 10, 10)
        card_layout.setSpacing(2)

        title_label = QLabel(title.upper())
        title_label.setProperty("role", "statTitle")
        title_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        card_layout.addWidget(title_label)

        value_label = QLabel("—")
        value_label.setProperty("role", "statValue")
        value_label.setProperty("variant", variant if variant else "default")
        value_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        card_layout.addWidget(value_label)

        if hint:
            hint_label = QLabel(hint)
            hint_label.setProperty("role", "statHint")
            hint_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            card_layout.addWidget(hint_label)

        card_layout.addStretch()
        card_frame.setToolTip(f"{title} — {hint}" if hint else title)
        return card_frame, value_label

    def _set_stat_value(self, key, value, variant=None):
        """Update a statistic card's value label and styling."""
        label = self.stat_values.get(key)
        if not label:
            return
        default_variant = self._metric_variants.get(key, "default")
        effective_variant = variant if variant is not None else default_variant
        label.setText(value)
        label.setProperty("variant", effective_variant)
        # Refresh style to apply new variant immediately
        label.style().unpolish(label)
        label.style().polish(label)
    
    def update_data(self, data):
        """Update the view with new login data."""
        # Ensure data has proper structure even if empty or None
        if not data:
            data = {'logins': [], 'users': []}
        else:
            # Ensure required keys exist
            if 'logins' not in data:
                data['logins'] = []
            if 'users' not in data:
                data['users'] = []
        
        # Store the data (ensure we store a copy to avoid modifying the original)
        self.login_data = data.copy() if isinstance(data, dict) else data
        
        # Always update the view, even with empty data
        self.populate_user_filter(self.login_data)
        self.update_timeline_chart(self.login_data)
        self.update_histogram_chart(self.login_data)
        self.update_statistics(self.login_data, username=None)  # Show overall statistics
    
    def populate_user_filter(self, data):
        """Populate the user filter dropdown."""
        self.user_filter.blockSignals(True)  # Prevent triggering filter while updating
        self.user_filter.clear()
        self.user_filter.addItem("All Users")
        
        if 'users' in data and data['users']:
            # Get unique users from logins (only successful logons)
            logins = data.get('logins', [])
            user_counts = {}
            for login in logins:
                if login.get('event_id') == 4624:  # Successful logon
                    username = login.get('username', 'Unknown')
                    if username:
                        user_counts[username] = user_counts.get(username, 0) + 1
            
            # Sort users by login count (descending)
            users_sorted = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)
            
            # Add users to dropdown with count
            for username, count in users_sorted:
                self.user_filter.addItem(f"{username} ({count})", username)
        
        self.user_filter.blockSignals(False)
    
    def update_timeline_chart(self, data, username=None):
        """Update the timeline chart with login events.
        
        Args:
            data: Login data dictionary
            username: Optional username to filter chart for specific user.
        """
        self.axes.clear()
        
        # Check for error in data
        if isinstance(data, dict) and 'error' in data:
            error_msg = data.get('error', 'Unknown error')
            # Truncate long error messages for display
            if len(error_msg) > 100:
                error_msg = error_msg[:97] + "..."
            self.axes.text(0.5, 0.5, f'Error: {error_msg}', 
                          ha='center', va='center', transform=self.axes.transAxes,
                          fontsize=10, color='red', wrap=True)
            self.canvas.draw()
            return
        
        logins = data.get('logins', [])
        
        # Filter by username if specified
        if username:
            logins = [login for login in logins if login.get('username') == username]
        
        if not logins:
            self.axes.text(0.5, 0.5, 'No login events found', 
                          ha='center', va='center', transform=self.axes.transAxes)
            self.canvas.draw()
            return
        
        # Group logins by user with full login data for tooltips
        user_events = {}
        # Store login data indexed by point for tooltips
        self.login_data_by_point = {}  # (x, y) -> login_data
        
        for login in logins:
            login_username = login.get('username', 'Unknown')
            if not login_username:
                continue
            
            try:
                event_time = datetime.fromisoformat(login['time'].replace('Z', '+00:00'))
            except:
                try:
                    event_time = datetime.strptime(login['time_display'], '%Y-%m-%d %H:%M:%S')
                except:
                    continue
            
            if login_username not in user_events:
                user_events[login_username] = []
            user_events[login_username].append((event_time, login))
        
        if not user_events:
            self.axes.text(0.5, 0.5, 'No valid login events found', 
                          ha='center', va='center', transform=self.axes.transAxes)
            self.canvas.draw()
            return
        
        # Define color mapping for different event types
        event_colors = {
            4624: 'green',      # Successful logon
            4625: 'red',        # Failed logon
            4648: 'orange',     # Explicit credentials logon
            4672: 'purple',     # Special privileges logon
            4634: 'blue',       # Account logged off
            4647: 'cyan',       # User initiated logoff
        }
        
        # Event type labels for legend
        event_labels = {
            4624: 'Successful Logon',
            4625: 'Failed Logon',
            4648: 'Explicit Credentials',
            4672: 'Special Privileges',
            4634: 'Account Logged Off',
            4647: 'User Logoff',
        }
        
        # Plot timeline for each user with color-coded event types
        y_positions = {}
        y_pos = 0
        all_scatter_points = []  # Store all scatter plots for tooltips
        legend_handles = {}  # Track legend handles for each event type
        
        for user, time_login_pairs in sorted(user_events.items()):
            if user not in y_positions:
                y_positions[user] = y_pos
                y_pos += 1
            
            y = y_positions[user]
            
            # Group points by event type for color coding
            events_by_type = {}
            for time, login_data in time_login_pairs:
                event_id = login_data.get('event_id', 4624)  # Default to successful logon
                if event_id not in events_by_type:
                    events_by_type[event_id] = []
                events_by_type[event_id].append((time, login_data))
            
            # Plot points for each event type with appropriate color
            for event_id, event_pairs in events_by_type.items():
                times = [pair[0] for pair in event_pairs]
                login_data_list = [pair[1] for pair in event_pairs]
                
                # Convert times to matplotlib dates
                mpl_times = mdates.date2num(times)
                
                # Get color for this event type
                color = event_colors.get(event_id, 'gray')
                
                # Plot points with event-specific color
                scatter = self.axes.scatter(mpl_times, [y] * len(times), 
                                           c=color, alpha=0.7, s=50, picker=True)
                
                # Store login data for tooltips
                if not hasattr(scatter, 'login_data'):
                    scatter.login_data = []
                for i, (mpl_time, login_data) in enumerate(zip(mpl_times, login_data_list)):
                    # Store login data with index for easy lookup
                    scatter.login_data.append(login_data)
                    # Also store by coordinates for fallback
                    self.login_data_by_point[(mpl_time, y)] = login_data
                
                all_scatter_points.append(scatter)
                
                # Store legend handle (only once per event type)
                if event_id not in legend_handles:
                    from matplotlib.lines import Line2D
                    legend_handles[event_id] = Line2D([0], [0], marker='o', color='w', 
                                                     markerfacecolor=color, markersize=8,
                                                     label=event_labels.get(event_id, f'Event {event_id}'))
        
        # Formatting
        self.axes.set_xlabel('Date/Time')
        self.axes.set_ylabel('Users')
        title = f'User Login Timeline' + (f' - {username}' if username else '')
        self.axes.set_title(title)
        self.axes.grid(True, alpha=0.3)
        
        # Set y-axis labels to usernames
        self.axes.set_yticks(list(range(len(y_positions))))
        self.axes.set_yticklabels(list(y_positions.keys()))
        
        # Add legend for event types
        if legend_handles:
            self.axes.legend(handles=list(legend_handles.values()), 
                           loc='upper right', fontsize=8, framealpha=0.9)
        
        # Format x-axis dates
        self.axes.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
        self.axes.xaxis.set_major_locator(mdates.AutoDateLocator())
        self.figure.autofmt_xdate()
        
        # Rotate x-axis labels
        plt = self.figure
        plt.tight_layout()
        
        # Add tooltips using mplcursors if available
        if MPLCURSORS_AVAILABLE:
            # Clear any existing cursor to prevent tooltip persistence
            if hasattr(self, 'cursor'):
                try:
                    self.cursor.remove()
                except:
                    pass
            
            # Create cursor for all scatter plots with hover mode
            # Use version-agnostic parameters
            try:
                # Try with hover mode (newer versions)
                self.cursor = mplcursors.cursor(all_scatter_points, hover=True, multiple=False)
            except (TypeError, ValueError):
                # Fallback for older versions
                try:
                    self.cursor = mplcursors.cursor(all_scatter_points, hover=True)
                except (TypeError, ValueError):
                    # Even older versions - just use basic cursor
                    self.cursor = mplcursors.cursor(all_scatter_points)
            
            # Track current annotation to ensure it's removed
            current_annotation = [None]
            
            @self.cursor.connect("add")
            def on_add(sel):
                # Get the point coordinates
                x, y = sel.target[0], sel.target[1]
                
                # Find which scatter plot this belongs to by checking artist
                login_data = None
                artist = sel.artist
                
                # Find the scatter plot in our list
                scatter_idx = -1
                for i, scatter in enumerate(all_scatter_points):
                    if scatter == artist:
                        scatter_idx = i
                        break
                
                # Get the point index from the selection
                if scatter_idx >= 0 and hasattr(sel, 'index'):
                    idx = sel.index
                    scatter = all_scatter_points[scatter_idx]
                    if hasattr(scatter, 'login_data') and idx < len(scatter.login_data):
                        login_data = scatter.login_data[idx]
                
                # Fallback: try to find by coordinates
                if not login_data:
                    # Find closest point
                    for (px, py), data in self.login_data_by_point.items():
                        if abs(px - x) < 0.001 and abs(py - y) < 0.1:
                            login_data = data
                            break
                
                if login_data:
                    # Format tooltip with detailed information
                    time_str = login_data.get('time_display', login_data.get('time', 'N/A'))
                    username = login_data.get('username', 'N/A')
                    domain = login_data.get('domain', 'N/A')
                    event_type = login_data.get('event_type', 'N/A')
                    source_ip = login_data.get('source_ip', 'N/A')
                    workstation = login_data.get('workstation', 'N/A')
                    
                    tooltip = f"Time: {time_str}\n"
                    tooltip += f"User: {username}\n"
                    tooltip += f"Domain: {domain}\n"
                    tooltip += f"Event: {event_type}\n"
                    if source_ip and source_ip not in ['-', 'N/A', '']:
                        tooltip += f"IP: {source_ip}\n"
                    if workstation and workstation not in ['-', 'N/A', '']:
                        tooltip += f"Workstation: {workstation}"
                    
                    sel.annotation.set_text(tooltip)
                    sel.annotation.set(bbox=dict(boxstyle="round,pad=0.5", facecolor="yellow", alpha=0.8))
                    current_annotation[0] = sel.annotation
                else:
                    # Fallback: just show the datetime
                    dt = mdates.num2date(x)
                    sel.annotation.set_text(f"{dt.strftime('%Y-%m-%d %H:%M:%S')}")
                    current_annotation[0] = sel.annotation
            
            @self.cursor.connect("remove")
            def on_remove(sel):
                # Explicitly remove annotation when mouse leaves
                if sel.annotation:
                    try:
                        sel.annotation.remove()
                    except:
                        pass
                    # Note: sel.annotation is read-only, cannot set to None
                current_annotation[0] = None
        else:
            # Fallback: use matplotlib's built-in annotation on hover
            current_tooltip = [None]
            
            def on_hover(event):
                if event.inaxes == self.axes:
                    for scatter in all_scatter_points:
                        if hasattr(scatter, 'contains'):
                            contains, ind = scatter.contains(event)
                            if contains and hasattr(scatter, 'login_data'):
                                idx = ind['ind'][0]
                                if idx < len(scatter.login_data):
                                    login_data = scatter.login_data[idx]
                                    time_str = login_data.get('time_display', login_data.get('time', 'N/A'))
                                    # Show simple tooltip
                                    tooltip_text = f"Time: {time_str}"
                                    if current_tooltip[0] != tooltip_text:
                                        self.canvas.setToolTip(tooltip_text)
                                        current_tooltip[0] = tooltip_text
                                    return
                
                # Remove tooltip when mouse leaves
                if current_tooltip[0]:
                    self.canvas.setToolTip("")
                    current_tooltip[0] = None
            
            self.canvas.mpl_connect('motion_notify_event', on_hover)
        
        self.canvas.draw()
    
    def update_histogram_chart(self, data, username=None):
        """Update histogram chart showing login frequency distribution by hour.
        
        Args:
            data: Login data dictionary
            username: Optional username to filter chart for specific user.
        """
        # Clear all existing elements
        self.histogram_axes.clear()
        
        # Check for error in data
        if isinstance(data, dict) and 'error' in data:
            error_msg = data.get('error', 'Unknown error')
            # Truncate long error messages for display
            if len(error_msg) > 100:
                error_msg = error_msg[:97] + "..."
            self.histogram_axes.text(0.5, 0.5, f'Error: {error_msg}', 
                                    ha='center', va='center', transform=self.histogram_axes.transAxes,
                                    fontsize=10, color='red', wrap=True)
            self.histogram_canvas.draw()
            return
        
        logins = data.get('logins', [])
        
        # Filter by username if specified
        if username:
            logins = [login for login in logins if login.get('username') == username]
        
        if not logins:
            self.histogram_axes.text(0.5, 0.5, 'No login events found', 
                                    ha='center', va='center', transform=self.histogram_axes.transAxes)
            self.histogram_canvas.draw()
            return
        
        # Count logins by hour (0-23)
        hour_counts = [0] * 24
        
        # Separate successful and failed logins for different colors
        successful_hour_counts = [0] * 24
        failed_hour_counts = [0] * 24
        
        for login in logins:
            try:
                # Parse time
                try:
                    event_time = datetime.fromisoformat(login['time'].replace('Z', '+00:00'))
                except:
                    try:
                        event_time = datetime.strptime(login['time_display'], '%Y-%m-%d %H:%M:%S')
                    except:
                        continue
                
                event_id = login.get('event_id')
                hour = event_time.hour
                
                if event_id == 4624:  # Successful logon
                    successful_hour_counts[hour] += 1
                    hour_counts[hour] += 1
                elif event_id == 4625:  # Failed logon
                    failed_hour_counts[hour] += 1
                    hour_counts[hour] += 1
            
            except Exception:
                continue
        
        # Create histogram
        hours = list(range(24))
        hour_labels = [f'{h:02d}:00' for h in range(24)]
        
        # Create stacked bar chart for successful and failed logins
        width = 0.8
        x_pos = np.arange(24)
        
        # Plot bars
        bars1 = self.histogram_axes.bar(x_pos, successful_hour_counts, width, 
                                        label='Successful Logins', color='green', alpha=0.7)
        bars2 = self.histogram_axes.bar(x_pos, failed_hour_counts, width, 
                                        bottom=successful_hour_counts,
                                        label='Failed Logins', color='red', alpha=0.7)
        
        # Set x-axis labels
        self.histogram_axes.set_xticks(x_pos)
        self.histogram_axes.set_xticklabels(hour_labels, rotation=45, ha='right')
        
        # Labels and title
        self.histogram_axes.set_xlabel('Hour of Day')
        self.histogram_axes.set_ylabel('Number of Logins')
        title = 'Login Activity Distribution by Hour' + (f' - {username}' if username else '')
        self.histogram_axes.set_title(title)
        
        # Add grid for better readability
        self.histogram_axes.grid(True, alpha=0.3, axis='y')
        
        # Add legend
        self.histogram_axes.legend(loc='upper right')
        
        # Add value labels on top of bars
        max_value = max(hour_counts) if hour_counts else 0
        if max_value > 0:
            for i, (success, failed) in enumerate(zip(successful_hour_counts, failed_hour_counts)):
                total = success + failed
                if total > 0:
                    # Position label at top of bar
                    y_pos = total
                    self.histogram_axes.text(i, y_pos + max_value * 0.02, str(total),
                                           ha='center', va='bottom', fontsize=8, fontweight='bold')
        
        self.histogram_figure.tight_layout()
        self.histogram_canvas.draw()
    
    def update_statistics(self, data, username=None):
        """Update forensic statistics panel.
        
        Args:
            data: Login data dictionary
            username: Optional username to filter statistics for specific user.
                     If None, shows overall statistics.
        """
        # Check for error in data
        if isinstance(data, dict) and 'error' in data:
            error_msg = data.get('error', 'Unknown error')
            self.stats_title.setText("Authentication Snapshot")
            self.stats_subtitle.setText(f"Data error: {error_msg}")
            for key in self.stat_values.keys():
                self._set_stat_value(key, "—")
            return
        
        logins = data.get('logins', [])
        
        # Filter by username if specified
        if username:
            logins = [login for login in logins if login.get('username') == username]
            title_text = f"Authentication Snapshot - {username}" if username else "Authentication Snapshot"
            subtitle_text = "Focused metrics for the selected account" if logins else "No login telemetry for this account"
        else:
            title_text = "Authentication Snapshot"
            subtitle_text = "Flight deck telemetry for recent logons"
        
        self.stats_title.setText(title_text)
        self.stats_subtitle.setText(subtitle_text)
        
        if not logins:
            self._set_stat_value("total_logins", "0", "primary")
            self._set_stat_value("failed_logins", "0", "default")
            self._set_stat_value("avg_duration", "—", "default")
            self._set_stat_value("earliest_login", "—")
            self._set_stat_value("latest_login", "—")
            self._set_stat_value("day_logins", "0")
            self._set_stat_value("night_logins", "0")
            self._set_stat_value("unique_ips", "0")
            self._set_stat_value("unique_workstations", "0")
            self._set_stat_value("most_active_hour", "—")
            return
        
        # Parse login times
        login_times = []
        logon_events = []  # Event 4624 (successful logon)
        logoff_events = []  # Events 4634, 4647 (logoff)
        failed_logins = 0  # Event 4625 (failed logon)
        
        # Track unique IPs and workstations
        unique_ips = set()
        unique_workstations = set()
        hour_counts = {}  # Track activity by hour
        
        day_count = 0
        night_count = 0
        
        for login in logins:
            try:
                # Parse time
                try:
                    event_time = datetime.fromisoformat(login['time'].replace('Z', '+00:00'))
                except:
                    try:
                        event_time = datetime.strptime(login['time_display'], '%Y-%m-%d %H:%M:%S')
                    except:
                        continue
                
                event_id = login.get('event_id')
                login_username = login.get('username')
                
                # Count only actual logon events (not logoffs) for total count
                if event_id == 4624:  # Successful logon
                    login_times.append(event_time)
                    logon_events.append({
                        'time': event_time,
                        'username': login_username,
                        'event': login
                    })
                    
                    # Count day vs night (6 AM - 6 PM = day, 6 PM - 6 AM = night)
                    hour = event_time.hour
                    hour_counts[hour] = hour_counts.get(hour, 0) + 1
                    if 6 <= hour < 18:
                        day_count += 1
                    else:
                        night_count += 1
                    
                    # Track unique IPs and workstations
                    source_ip = login.get('source_ip')
                    if source_ip and source_ip not in ['-', 'N/A', '']:
                        unique_ips.add(source_ip)
                    
                    workstation = login.get('workstation')
                    if workstation and workstation not in ['-', 'N/A', '']:
                        unique_workstations.add(workstation)
                
                elif event_id == 4625:  # Failed logon
                    failed_logins += 1
                    
                    # Track unique IPs for failed attempts too
                    source_ip = login.get('source_ip')
                    if source_ip and source_ip not in ['-', 'N/A', '']:
                        unique_ips.add(source_ip)
                
                elif event_id in [4634, 4647]:  # Logoff events
                    logoff_events.append({
                        'time': event_time,
                        'username': login_username,
                        'event': login
                    })
            
            except Exception:
                continue
        
        # Update total logins
        total_logins = len(login_times)
        self._set_stat_value("total_logins", str(total_logins), "primary")
        
        # Find earliest and latest login
        if login_times:
            earliest = min(login_times)
            latest = max(login_times)
            self._set_stat_value("earliest_login", earliest.strftime('%Y-%m-%d %H:%M:%S'))
            self._set_stat_value("latest_login", latest.strftime('%Y-%m-%d %H:%M:%S'))
        else:
            self._set_stat_value("earliest_login", "—")
            self._set_stat_value("latest_login", "—")
        
        # Calculate average session duration
        # Pair logon events with subsequent logoff events for the same user
        durations = []
        logoff_events_sorted = sorted(logoff_events, key=lambda x: x['time'])
        
        for logon in sorted(logon_events, key=lambda x: x['time']):
            logon_time = logon['time']
            logon_username = logon['username']
            
            # Find the next logoff for this user after the logon
            for logoff in logoff_events_sorted:
                if (logoff['username'] == logon_username and 
                    logoff['time'] > logon_time):
                    duration = logoff['time'] - logon_time
                    # Only count reasonable durations (less than 30 days)
                    if duration.total_seconds() > 0 and duration.days < 30:
                        durations.append(duration)
                    break
        
        if durations:
            avg_seconds = sum(d.total_seconds() for d in durations) / len(durations)
            avg_duration = timedelta(seconds=avg_seconds)
            
            # Format duration nicely
            hours = int(avg_duration.total_seconds() // 3600)
            minutes = int((avg_duration.total_seconds() % 3600) // 60)
            if hours > 0:
                duration_str = f"{hours}h {minutes}m"
            else:
                duration_str = f"{minutes}m"
            
            self._set_stat_value("avg_duration", duration_str, "primary")
        else:
            self._set_stat_value("avg_duration", "—", "default")
        
        # Update day/night counts
        self._set_stat_value("day_logins", str(day_count))
        self._set_stat_value("night_logins", str(night_count))
        
        # Update failed login attempts
        failed_variant = "alert" if failed_logins else "default"
        self._set_stat_value("failed_logins", str(failed_logins), failed_variant)
        
        # Update unique IPs and workstations
        self._set_stat_value("unique_ips", str(len(unique_ips)))
        self._set_stat_value("unique_workstations", str(len(unique_workstations)))
        
        # Calculate most active hour
        if hour_counts:
            most_active_hour = max(hour_counts.items(), key=lambda x: x[1])
            hour_num = most_active_hour[0]
            count = most_active_hour[1]
            hour_str = f"{hour_num:02d}:00 ({count} logins)"
            self._set_stat_value("most_active_hour", hour_str)
        else:
            self._set_stat_value("most_active_hour", "—")

        # Update subtitle with context
        success_count = total_logins
        self.stats_subtitle.setText(
            f"{success_count} successful logins / {failed_logins} failed / {len(unique_ips)} unique IPs"
        )
    
    def on_user_filter_changed(self, text):
        """Handle user filter dropdown selection to filter chart, statistics, and events."""
        if not self.login_data:
            return
        
        # Get username from dropdown (extract from "username (count)" format or use "All Users")
        if text == "All Users" or not text:
            username = None
        else:
            # Extract username from "username (count)" format
            username = self.user_filter.currentData()
            if not username:
                # Fallback: try to extract from text
                if " (" in text:
                    username = text.split(" (")[0]
                else:
                    username = text
        
        # Update chart, statistics, and histogram based on selected user
        self.update_timeline_chart(self.login_data, username=username)
        self.update_histogram_chart(self.login_data, username=username)
        self.update_statistics(self.login_data, username=username)
        
        # No need to filter events table anymore - it's removed
    
    def filter_data(self, text):
        """Filter chart based on search text, respecting user filter."""
        if not self.login_data:
            return
        
        # Get current user filter
        current_text = self.user_filter.currentText()
        if current_text == "All Users" or not current_text:
            username = None
        else:
            username = self.user_filter.currentData()
            if not username:
                if " (" in current_text:
                    username = current_text.split(" (")[0]
                else:
                    username = current_text
        
        # Filter logins based on search text and user filter
        filtered_logins = self.login_data['logins']
        
        if username:
            filtered_logins = [
                login for login in filtered_logins
                if login.get('username') == username
            ]
        
        search_text = text.lower()
        if search_text:
            filtered_logins = [
                login for login in filtered_logins
                if search_text in login.get('username', '').lower() or
                search_text in login.get('domain', '').lower()
            ]
        
        # Update chart with filtered data
        filtered_data = self.login_data.copy()
        filtered_data['logins'] = filtered_logins
        self.update_timeline_chart(filtered_data, username=username)
        self.update_histogram_chart(filtered_data, username=username)
    
    def export_data(self):
        """Export login data to a file."""
        if not self.login_data:
            return
        
        from PySide6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Login Data", "logins.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.login_data, f, indent=2)


