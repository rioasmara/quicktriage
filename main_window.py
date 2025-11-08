"""
Main window for the Host Triage Analysis Tool.
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget, QPushButton,
    QHBoxLayout, QStatusBar, QMessageBox, QProgressBar
)
from PySide6.QtCore import Qt, QThread, Signal, QMutex, QMutexLocker, QTimer
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor
from collectors.process_collector import ProcessCollector
from collectors.network_collector import NetworkCollector
from collectors.service_collector import ServiceCollector
from collectors.file_collector import FileCollector
from collectors.system_collector import SystemCollector
from collectors.persistence_collector import PersistenceCollector
from collectors.dll_collector import DLLCollector
from collectors.login_collector import LoginCollector
from collectors.app_collector import AppCollector
from collectors.binary_collector import BinaryCollector
from collectors.firewall_collector import FirewallCollector
from ui.process_view import ProcessView
from ui.network_view import NetworkView
from ui.service_view import ServiceView
from ui.file_view import FileView
from ui.system_view import SystemView
from ui.persistence_view import PersistenceView
from ui.dll_view import DLLView
from ui.login_view import LoginView
from ui.app_view import AppView
from ui.firewall_view import FirewallView
from ui.hayabusa_view import HayabusaView


class CollectionThread(QThread):
    """Thread for collecting data without blocking the UI."""
    finished = Signal(object, str)  # data, collector_name
    error = Signal(str, str)  # error_message, collector_name
    incremental_update = Signal(object, str)  # incremental_data, collector_name
    
    def __init__(self, collector, collector_name):
        super().__init__()
        self.collector = collector
        self.collector_name = collector_name
    
    def run(self):
        try:
            # For DLL collector, set up incremental callback
            if self.collector_name == "dlls" and hasattr(self.collector, 'incremental_callback'):
                # Create a callback that emits incremental updates
                def dll_incremental_callback(dll_info):
                    self.incremental_update.emit(dll_info, self.collector_name)
                self.collector.incremental_callback = dll_incremental_callback
            
            # For binaries collector, set up incremental callback
            elif self.collector_name == "binaries" and hasattr(self.collector, 'incremental_callback'):
                # Create a callback that emits incremental updates
                def binary_incremental_callback(binary_info):
                    self.incremental_update.emit(binary_info, self.collector_name)
                self.collector.incremental_callback = binary_incremental_callback
            
            import sys
            print(f"[CollectionThread] {self.collector_name} thread starting collection...", file=sys.stderr)
            data = self.collector.collect()
            print(f"[CollectionThread] {self.collector_name} collection completed: data type={type(data)}", file=sys.stderr)
            
            # Ensure data is not None and is a dictionary
            if data is None:
                print(f"[CollectionThread] {self.collector_name} WARNING: collector returned None!", file=sys.stderr)
                data = {}
            
            # Check if collector returned an error (some collectors return error in dict)
            if isinstance(data, dict) and 'error' in data:
                # Still emit finished but with error info
                # The view should handle this gracefully
                pass
            
            # Ensure data has required structure for each collector
            if self.collector_name == "logins":
                if not isinstance(data, dict):
                    data = {}
                if 'logins' not in data:
                    data['logins'] = []
                if 'users' not in data:
                    data['users'] = []
            
            self.finished.emit(data, self.collector_name)
        except Exception as e:
            # Log the error for debugging
            import traceback
            error_details = f"{str(e)}\n{traceback.format_exc()}"
            self.error.emit(error_details, self.collector_name)


class MainWindow(QMainWindow):
    """Main window of the triage analysis application."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Host Triage Analysis Tool")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize collectors
        self.collectors = {
            "processes": ProcessCollector(),
            "network": NetworkCollector(),
            "services": ServiceCollector(),
            "files": FileCollector(),
            "system": SystemCollector(),
            "persistence": PersistenceCollector(),
            "dlls": DLLCollector(),
            "logins": LoginCollector(),
            "applications": AppCollector(),
            "binaries": BinaryCollector(),
            "firewall": FirewallCollector()
        }
        
        # Collection threads
        self.collection_threads = {}
        
        # Thread-safe progress tracking
        self.progress_mutex = QMutex()
        self.completed_count = 0
        self.total_collectors = len(self.collectors)
        
        # Store collected data for correlation
        self.collected_data = {}
        
        # Mapping from collector names to tab indices
        self.collector_to_tab = {
            "processes": 0,
            "network": 1,
            "services": 2,
            "files": 3,
            "system": 4,
            "persistence": 5,
            "dlls": 6,
            "logins": 7,
            "applications": 8,
            "binaries": 8,  # Same tab as applications
            "firewall": 9
        }
        
        # Reverse mapping: tab index -> list of collector names that map to it
        self.tab_to_collectors = {}
        for collector_name, tab_index in self.collector_to_tab.items():
            if tab_index not in self.tab_to_collectors:
                self.tab_to_collectors[tab_index] = []
            self.tab_to_collectors[tab_index].append(collector_name)
        
        # Track which collectors have finished
        self.finished_collectors = set()
        
        # Create green icon for completed tabs
        self.green_icon = self.create_green_icon()
        
        # Create red icons for blinking (bright and dark)
        self.red_icon_bright = self.create_red_icon(True)
        self.red_icon_dark = self.create_red_icon(False)
        
        # Blinking timer for red icons on tabs (slower frequency for better performance)
        self.blink_timer = QTimer()
        self.blink_timer.timeout.connect(self.blink_red_tabs)
        self.is_red_bright = True
        
        # Track which tabs are still processing
        self.processing_tabs = set()
        
        # Batching for incremental updates (DLL and binary)
        self.dll_update_queue = []
        self.binary_update_queue = []
        self.dll_batch_timer = QTimer()
        self.dll_batch_timer.setSingleShot(True)
        self.dll_batch_timer.timeout.connect(self._process_dll_batch)
        self.binary_batch_timer = QTimer()
        self.binary_batch_timer.setSingleShot(True)
        self.binary_batch_timer.timeout.connect(self._process_binary_batch)
        self.batch_delay_ms = 100  # Batch updates every 100ms for better performance
        
        self.init_ui()
    
    def _cleanup_existing_threads(self):
        """Clean up any existing running threads before starting new collection."""
        for name, thread in list(self.collection_threads.items()):
            if thread.isRunning():
                # Wait for thread to finish (with timeout)
                if not thread.wait(1000):  # Wait up to 1 second
                    # If thread is still running, terminate it
                    thread.terminate()
                    thread.wait(500)  # Wait for termination
                # Disconnect signals to prevent memory leaks
                try:
                    thread.finished.disconnect()
                    thread.error.disconnect()
                    if hasattr(thread, 'incremental_update'):
                        thread.incremental_update.disconnect()
                except:
                    pass
        self.collection_threads.clear()
    
    def _create_collector_instance(self, name, template_collector):
        """Create a new collector instance for a thread to ensure independence.
        
        Args:
            name: Collector name (e.g., 'processes', 'logins')
            template_collector: The original collector instance to use as template
            
        Returns:
            New collector instance (or template if copying is not needed)
        """
        # For thread safety, create a new instance of each collector
        # This ensures each thread has completely independent state
        if name == "processes":
            return ProcessCollector()
        elif name == "network":
            return NetworkCollector()
        elif name == "services":
            return ServiceCollector()
        elif name == "files":
            return FileCollector()
        elif name == "system":
            return SystemCollector()
        elif name == "persistence":
            return PersistenceCollector()
        elif name == "dlls":
            return DLLCollector()
        elif name == "logins":
            return LoginCollector()
        elif name == "applications":
            return AppCollector()
        elif name == "binaries":
            return BinaryCollector()
        elif name == "firewall":
            return FirewallCollector()
        else:
            # Fallback: return template (shouldn't happen)
            return template_collector
    
    def _cleanup_finished_threads(self):
        """Clean up threads that have finished executing."""
        for name, thread in list(self.collection_threads.items()):
            if not thread.isRunning():
                # Thread has finished, disconnect signals to prevent memory leaks
                try:
                    thread.finished.disconnect()
                    thread.error.disconnect()
                    if hasattr(thread, 'incremental_update'):
                        thread.incremental_update.disconnect()
                except:
                    pass
                # Thread will be cleaned up by Python's garbage collector
                # but we remove it from our tracking dict
                del self.collection_threads[name]
    
    def init_ui(self):
        """Initialize the user interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        
        # Tab widget for different views
        self.tabs = QTabWidget()
        
        # Create views
        self.process_view = ProcessView()
        self.network_view = NetworkView()
        self.service_view = ServiceView()
        self.file_view = FileView()
        self.system_view = SystemView()
        self.persistence_view = PersistenceView()
        self.dll_view = DLLView()
        self.login_view = LoginView()
        self.app_view = AppView()
        self.firewall_view = FirewallView()
        self.hayabusa_view = HayabusaView()
        
        # Add tabs
        self.tabs.addTab(self.process_view, "Processes")
        self.tabs.addTab(self.network_view, "Network")
        self.tabs.addTab(self.service_view, "Services")
        self.tabs.addTab(self.file_view, "Files")
        self.tabs.addTab(self.system_view, "System Info")
        self.tabs.addTab(self.persistence_view, "Persistence")
        self.tabs.addTab(self.dll_view, "DLLs")
        self.tabs.addTab(self.login_view, "Logins")
        self.tabs.addTab(self.app_view, "Applications")
        self.tabs.addTab(self.firewall_view, "Firewall")
        self.tabs.addTab(self.hayabusa_view, "Hayabusa")
        
        # Connect tab change signal to defer heavy work
        self.tabs.currentChanged.connect(self.on_tab_changed)
        
        # Store pending updates for each view
        self.pending_updates = {}
        
        layout.addWidget(self.tabs)
        
        # Status bar with collect button and progress bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        
        # Add collect button to status bar
        self.collect_all_btn = QPushButton("Collect All Data")
        self.collect_all_btn.clicked.connect(self.collect_all_data)
        self.statusBar.addPermanentWidget(self.collect_all_btn)
        
        # Progress bar in status bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        self.statusBar.addPermanentWidget(self.progress_bar)
        
        self.statusBar.showMessage("Ready")
    
    def on_tab_changed(self, index):
        """Handle tab change - defer heavy work to make switching instant."""
        # Process any pending updates for the newly visible tab
        # Use QTimer.singleShot to defer work after tab switch completes
        QTimer.singleShot(0, lambda: self._process_pending_updates(index))
    
    def _process_pending_updates(self, tab_index):
        """Process any pending updates for a specific tab."""
        # Map tab index to view
        views = [
            self.process_view,
            self.network_view,
            self.service_view,
            self.file_view,
            self.system_view,
            self.persistence_view,
            self.dll_view,
            self.login_view,
            self.app_view,
            self.firewall_view,
            self.hayabusa_view
        ]
        
        if 0 <= tab_index < len(views):
            view = views[tab_index]
            # Check if there are pending updates for this view
            if hasattr(view, 'process_pending_updates'):
                view.process_pending_updates()
    
    def _update_view_data(self, collector_name, data):
        """Update view data - deferred to avoid blocking UI."""
        if collector_name == "processes":
            self.process_view.update_data(data)
            # If network data is already collected, pass it for correlation
            if "network" in self.collected_data:
                self.process_view.update_network_data(self.collected_data["network"])
            # Also pass process data to network view for create_time correlation
            if "network" in self.collected_data:
                self.network_view.update_process_data(data)
        elif collector_name == "services":
            self.service_view.update_data(data)
        elif collector_name == "files":
            self.file_view.update_data(data)
        elif collector_name == "system":
            self.system_view.update_data(data)
        elif collector_name == "persistence":
            self.persistence_view.update_data(data)
        elif collector_name == "dlls":
            # Mark as full update to replace any incremental data
            data['is_full_update'] = True
            self.dll_view.update_data(data)
        elif collector_name == "logins":
            import sys
            print(f"[MainWindow] Login collection finished: received data type={type(data)}", file=sys.stderr)
            if isinstance(data, dict):
                print(f"[MainWindow] Login data: logins={len(data.get('logins', []))}, users={len(data.get('users', []))}, has_error={'error' in data}", file=sys.stderr)
                if 'error' in data:
                    print(f"[MainWindow] Login collection error: {data.get('error')}", file=sys.stderr)
            # Ensure login data has proper structure
            if not isinstance(data, dict):
                data = {'logins': [], 'users': []}
            else:
                if 'logins' not in data:
                    data['logins'] = []
                if 'users' not in data:
                    data['users'] = []
            print(f"[MainWindow] Updating login view with {len(data.get('logins', []))} logins", file=sys.stderr)
            self.login_view.update_data(data)
        elif collector_name == "applications":
            self.app_view.update_data(data)
        elif collector_name == "binaries":
            self.app_view.update_binary_data(data)
        elif collector_name == "firewall":
            self.firewall_view.update_data(data)
            # If network data is already collected, pass it for correlation
            if "network" in self.collected_data:
                self.firewall_view.update_network_data(self.collected_data["network"])
        elif collector_name == "network":
            self.network_view.update_data(data)
            # If firewall data is already collected, pass network data to firewall view
            if "firewall" in self.collected_data:
                self.firewall_view.update_network_data(data)
            # If process data is already collected, update process view with network data
            if "processes" in self.collected_data:
                self.process_view.update_network_data(data)
                # Also pass process data to network view for create_time correlation
                self.network_view.update_process_data(self.collected_data["processes"])
    
    def create_green_icon(self):
        """Create a small green circle icon for tab headers."""
        pixmap = QPixmap(16, 16)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QColor(0, 200, 0))  # Green color
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(2, 2, 12, 12)  # Draw a small circle
        painter.end()
        return QIcon(pixmap)
    
    def create_red_icon(self, bright=True):
        """Create a small red circle icon for tab headers (bright or dark for blinking)."""
        pixmap = QPixmap(16, 16)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if bright:
            painter.setBrush(QColor(255, 0, 0))  # Bright red
        else:
            painter.setBrush(QColor(128, 0, 0))  # Dark red
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(2, 2, 12, 12)  # Draw a small circle
        painter.end()
        return QIcon(pixmap)
    
    def blink_red_tabs(self):
        """Toggle red icons on tabs that are still processing."""
        self.is_red_bright = not self.is_red_bright
        current_icon = self.red_icon_bright if self.is_red_bright else self.red_icon_dark
        
        # Update all tabs that are still processing
        for tab_index in self.processing_tabs:
            self.tabs.setTabIcon(tab_index, current_icon)
    
    def collect_all_data(self):
        """Collect data from all collectors in parallel using multiple threads."""
        # Prevent multiple simultaneous collection runs
        if self.collect_all_btn.isEnabled() == False:
            # Check if threads are still running
            running_threads = [t for t in self.collection_threads.values() if t.isRunning()]
            if running_threads:
                return  # Collection already in progress
        
        self.collect_all_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, self.total_collectors)
        self.progress_bar.setValue(0)
        self.statusBar.showMessage("Collecting data from all collectors in parallel...")
        
        # Wait for any existing threads to finish or terminate them
        self._cleanup_existing_threads()
        
        # Reset finished collectors tracking
        self.finished_collectors.clear()
        
        # Initialize all tabs as processing and set red blinking icons
        collector_tab_indices = set(self.collector_to_tab.values())
        self.processing_tabs = set(collector_tab_indices)
        self.is_red_bright = True
        for tab_index in range(self.tabs.count()):
            if tab_index in collector_tab_indices:
                self.tabs.setTabIcon(tab_index, self.red_icon_bright)
            else:
                self.tabs.setTabIcon(tab_index, QIcon())
        
        # Start blinking timer (slower frequency for better performance)
        self.blink_timer.start(1000)  # Blink every 1000ms (1 second)
        
        # Reset thread-safe counter
        with QMutexLocker(self.progress_mutex):
            self.completed_count = 0
        
        # Clear DLL view before starting new collection (for incremental updates)
        self.dll_view.clear_data()
        
        # Clear binary table before starting new collection (for incremental updates)
        self.app_view.clear_binary_data()
        
        # Clear and stop batch timers
        self.dll_update_queue.clear()
        self.binary_update_queue.clear()
        self.dll_batch_timer.stop()
        self.binary_batch_timer.stop()
        
        # Clear previous thread references
        self.collection_threads.clear()
        
        # Start all collection threads in parallel - each gets its own collector instance
        for name, collector_template in self.collectors.items():
            # Create a new collector instance for each thread to ensure independence
            # This ensures each thread has its own collector state
            collector_instance = self._create_collector_instance(name, collector_template)
            
            # Create and start thread for this collector
            thread = CollectionThread(collector_instance, name)
            thread.finished.connect(self.on_collection_finished)
            thread.error.connect(self.on_collection_error)
            # Connect incremental updates for DLL collector
            if name == "dlls":
                thread.incremental_update.connect(self.on_dll_incremental_update)
            # Connect incremental updates for binaries collector
            elif name == "binaries":
                thread.incremental_update.connect(self.on_binary_incremental_update)
            self.collection_threads[name] = thread
            thread.start()  # All threads start immediately and run in parallel
    
    def on_collection_finished(self, data, collector_name):
        """Handle successful data collection (called from worker thread)."""
        # Thread-safe progress update
        with QMutexLocker(self.progress_mutex):
            self.completed_count += 1
            current_count = self.completed_count
        
        # Update progress bar (this is thread-safe, Qt handles cross-thread calls)
        self.progress_bar.setValue(current_count)
        
        # Store collected data
        self.collected_data[collector_name] = data
        
        # Defer all view updates to make UI instantly responsive
        # Use QTimer.singleShot to defer work after current event processing
        # This ensures tab switching is instant and smooth
        QTimer.singleShot(0, lambda: self._update_view_data(collector_name, data))
        
        # Mark this collector as finished
        self.finished_collectors.add(collector_name)
        
        # Check if all collectors for this tab have finished
        if collector_name in self.collector_to_tab:
            tab_index = self.collector_to_tab[collector_name]
            # Get all collectors that map to this tab
            collectors_for_tab = self.tab_to_collectors.get(tab_index, [])
            # Check if all collectors for this tab have finished
            all_finished = all(c in self.finished_collectors for c in collectors_for_tab)
            
            if all_finished:
                # All collectors for this tab are done, set green icon
                self.tabs.setTabIcon(tab_index, self.green_icon)
                # Remove from processing tabs set
                self.processing_tabs.discard(tab_index)
            # If not all finished, keep the tab in processing_tabs (red blinking will continue)
        
        # Check if all collections are done (thread-safe check)
        with QMutexLocker(self.progress_mutex):
            all_done = (self.completed_count >= self.total_collectors)
        
        if all_done:
            # Process any remaining batched updates before finishing
            if self.dll_update_queue:
                self._process_dll_batch()
            if self.binary_update_queue:
                self._process_binary_batch()
            
            self.progress_bar.setVisible(False)
            self.collect_all_btn.setEnabled(True)
            self.statusBar.showMessage("Data collection complete")
            # Stop blinking timer
            self.blink_timer.stop()
            self.processing_tabs.clear()
            # Clean up finished threads (optional - can be done later)
            self._cleanup_finished_threads()
    
    def on_dll_incremental_update(self, dll_info, collector_name):
        """Handle incremental DLL updates (called from worker thread) - batched for performance."""
        # Queue the update instead of applying immediately
        if collector_name == "dlls":
            self.dll_update_queue.append(dll_info)
            # Start/restart batch timer if not already running
            if not self.dll_batch_timer.isActive():
                self.dll_batch_timer.start(self.batch_delay_ms)
    
    def _process_dll_batch(self):
        """Process batched DLL updates for better performance."""
        if not self.dll_update_queue:
            return
        
        # Get all queued updates
        batch = self.dll_update_queue[:]
        self.dll_update_queue.clear()
        
        # Apply all updates at once (view handles batching internally)
        for dll_info in batch:
            self.dll_view.add_dll_incremental(dll_info)
        
        # If there are more queued updates, schedule another batch
        if self.dll_update_queue:
            self.dll_batch_timer.start(self.batch_delay_ms)
    
    def on_binary_incremental_update(self, binary_info, collector_name):
        """Handle incremental binary updates (called from worker thread) - batched for performance."""
        # Queue the update instead of applying immediately
        if collector_name == "binaries":
            self.binary_update_queue.append(binary_info)
            # Start/restart batch timer if not already running
            if not self.binary_batch_timer.isActive():
                self.binary_batch_timer.start(self.batch_delay_ms)
    
    def _process_binary_batch(self):
        """Process batched binary updates for better performance."""
        if not self.binary_update_queue:
            return
        
        # Get all queued updates
        batch = self.binary_update_queue[:]
        self.binary_update_queue.clear()
        
        # Apply all updates at once (view handles batching internally)
        for binary_info in batch:
            self.app_view.add_binary_incremental(binary_info)
        
        # If there are more queued updates, schedule another batch
        if self.binary_update_queue:
            self.binary_batch_timer.start(self.batch_delay_ms)
    
    def on_collection_error(self, error_message, collector_name):
        """Handle collection errors (called from worker thread)."""
        # Thread-safe progress update
        with QMutexLocker(self.progress_mutex):
            self.completed_count += 1
            current_count = self.completed_count
        
        # Update progress bar (this is thread-safe, Qt handles cross-thread calls)
        self.progress_bar.setValue(current_count)
        
        QMessageBox.warning(
            self,
            "Collection Error",
            f"Error collecting {collector_name} data:\n{error_message}"
        )
        
        # For login collector, update view with empty data structure
        if collector_name == "logins":
            error_data = {
                'timestamp': None,
                'error': error_message,
                'logins': [],
                'users': []
            }
            self.login_view.update_data(error_data)
        
        # Mark this collector as finished (even if there was an error)
        self.finished_collectors.add(collector_name)
        
        # Check if all collectors for this tab have finished
        if collector_name in self.collector_to_tab:
            tab_index = self.collector_to_tab[collector_name]
            # Get all collectors that map to this tab
            collectors_for_tab = self.tab_to_collectors.get(tab_index, [])
            # Check if all collectors for this tab have finished
            all_finished = all(c in self.finished_collectors for c in collectors_for_tab)
            
            if all_finished:
                # All collectors for this tab are done, set green icon
                self.tabs.setTabIcon(tab_index, self.green_icon)
                # Remove from processing tabs set
                self.processing_tabs.discard(tab_index)
            # If not all finished, keep the tab in processing_tabs (red blinking will continue)
        
        # Check if all collections are done (thread-safe check)
        with QMutexLocker(self.progress_mutex):
            all_done = (self.completed_count >= self.total_collectors)
        
        if all_done:
            # Process any remaining batched updates before finishing
            if self.dll_update_queue:
                self._process_dll_batch()
            if self.binary_update_queue:
                self._process_binary_batch()
            
            self.progress_bar.setVisible(False)
            self.collect_all_btn.setEnabled(True)
            self.statusBar.showMessage("Data collection complete (with errors)")
            # Stop blinking timer
            self.blink_timer.stop()
            self.processing_tabs.clear()
            # Clean up finished threads (optional - can be done later)
            self._cleanup_finished_threads()

