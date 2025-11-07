# Host Triage Analysis Tool

A Python-based application using the latest Qt framework (PySide6) for conducting triage analysis on Windows systems. This tool is designed exclusively for Windows operating systems and helps security analysts and system administrators gather and analyze critical system information quickly.

## Features

### Core Analysis Modules

- **Process Analysis**: View all running processes with CPU, memory usage, command-line arguments, and process creation times. Correlate processes with network connections.

- **Network Connections**: Monitor active network connections (TCP/UDP) with their associated processes, local/remote addresses, ports, and connection states. Correlate with firewall rules.

- **Windows Services**: List all Windows services with their status, start type, binary paths, display names, and descriptions. Enumerate services from the Service Control Manager.

- **File System Analysis**: Scan important Windows directories for file information including:
  - Startup folders (user and system)
  - Temp directories
  - System directories
  - File metadata (size, timestamps, attributes)

- **System Information**: Comprehensive Windows system hardware and software details including:
  - CPU information and architecture
  - Memory statistics
  - Disk information
  - Operating system version and build
  - Network interfaces
  - Boot time and uptime

### Security & Threat Detection

- **Persistence Mechanisms**: Enumerate Windows persistence mechanisms including:
  - Registry Run keys (Run, RunOnce, RunOnceEx, RunServices)
  - Registry logon keys (Winlogon Shell, Userinit, Notify)
  - Registry policies (Explorer Run)
  - Image File Execution Options (IFEO) hijacks
  - AppInit DLLs
  - COM object hijacks
  - Startup folders (user and system)
  - Scheduled tasks
  - Windows services
  - WMI event subscriptions

- **DLL Analysis**: Collect loaded DLL information from all running processes with:
  - DLL path and process association
  - Digital signature verification
  - Identification of unsigned or suspicious DLLs
  - Detection of DLLs loaded from uncommon locations
  - Incremental real-time updates during collection

- **Login Events**: Collect Windows Security Event Log login events including:
  - Successful logons (Event ID 4624)
  - Failed logon attempts (Event ID 4625)
  - Explicit credential logons (Event ID 4648)
  - Special privilege assignments (Event ID 4672)
  - Logoff events (Event IDs 4647, 4634)
  - User account enumeration

- **Firewall Rules**: Collect Windows Firewall rules from all profiles:
  - Domain profile rules
  - Private profile rules
  - Public profile rules
  - Inbound and outbound rules
  - Rule actions (Allow/Block)
  - Port and protocol information
  - Correlation with active network connections

- **Binary Analysis**: Analyze binary files with:
  - PE file parsing
  - Digital signature verification
  - Import/export information
  - Section analysis
  - Metadata extraction

- **Applications**: Collect installed applications information including:
  - Installed software inventory
  - Application metadata
  - Installation paths
  - Version information

### Advanced Features

- **Hayabusa Event Log Analysis**: Integrated Windows Event Log (EVTX) scanning using Hayabusa-style YAML detection rules:
  - Load and compile Hayabusa/Yamato YAML rules
  - Scan single EVTX files or entire directories
  - Real-time match detection and reporting
  - Rule filtering by status and severity level
  - Pause/resume/stop scan controls
  - Multi-threaded scanning for performance
  - Match statistics and rule-based grouping
  - Export scan results

### User Interface Features

- **Modern Flight Deck Theme**: Dark-themed UI inspired by modern aircraft cockpits with:
  - High-contrast color scheme for visibility
  - Intuitive tab-based navigation
  - Real-time collection progress indicators
  - Visual status indicators (green/red icons) for collection completion
  - Responsive and professional design

- **Data Collection**:
  - Parallel multi-threaded data collection from all modules
  - Real-time progress tracking
  - Incremental updates for long-running collections (DLLs, binaries)
  - Error handling and graceful degradation

- **Data Export**: Export collected data to JSON format from any module

- **Search and Filter**: Built-in search functionality in each tab to quickly filter and find specific data

- **Data Correlation**: Automatic correlation between related data:
  - Processes ↔ Network connections
  - Network connections ↔ Firewall rules
  - Processes ↔ DLLs

## Requirements

- **Windows Operating System** (Windows 7 or later)
- Python 3.8 or higher
- **Required Python packages** (install via `pip install -r requirements.txt`):
  - `PySide6>=6.7.0` - Qt 6 framework for Python (GUI)
  - `psutil>=5.9.0` - System and process utilities
  - `matplotlib>=3.7.0` - Data visualization (for charts/graphs)
  - `pywin32>=306` - Windows API access (services, registry, event logs)
  - `mplcursors>=0.5.0` - Interactive matplotlib cursors
  - `pefile>=2023.2.7` - PE file parsing (binary analysis)
  - `PyYAML>=6.0` - YAML parsing (Hayabusa rules)
  - `python-evtx>=0.7.4` - Windows EVTX log parsing

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

**Note**: 
- `pywin32` is required for Windows service enumeration, registry access, and event log reading. The application will show errors if `pywin32` is not installed when using these features.
- Some features may require administrator privileges for full functionality (e.g., reading Security event log, accessing certain registry keys).

## Usage

Run the application:

```bash
python main.py
```

### Using the Application

1. **Collect Data**: Click the "Collect All Data" button to gather information from all collectors in parallel. The progress bar shows collection status, and tab icons indicate completion (green) or in-progress (red blinking).

2. **View Data**: Navigate through the tabs to view different types of collected data:
   - **Processes**: Running processes with detailed information, CPU/memory usage, command-line arguments
   - **Network**: Active network connections (TCP/UDP) with process correlation
   - **Services**: System services status, start types, and binary paths
   - **Files**: File system information from key directories (startup folders, temp, system)
   - **System Info**: System hardware and configuration details
   - **Persistence**: Windows persistence mechanisms (registry keys, scheduled tasks, startup folders)
   - **DLLs**: Loaded DLL information with digital signature verification
   - **Logins**: Windows Security Event Log login events (successful/failed logons)
   - **Applications**: Installed applications and binary analysis
   - **Firewall**: Windows Firewall rules from all profiles with network correlation
   - **Hayabusa**: Windows Event Log (EVTX) scanning using Hayabusa-style YAML rules

3. **Search/Filter**: Use the search boxes in each tab to filter data quickly

4. **Export**: Click the "Export" button in any tab to save data as JSON

5. **Hayabusa Event Log Analysis**:
   - Load Hayabusa/Yamato YAML rules from the `hayabusa/builtin/` directory or custom locations
   - Select rules by status and severity level
   - Choose EVTX files or directories to scan
   - Start, pause, resume, or stop scans
   - View matches in real-time with rule-based grouping
   - Export scan results

## Architecture

The application follows a modular architecture with separation of concerns:

- **`main.py`**: Application entry point with Windows OS check and Flight Deck theme stylesheet
- **`main_window.py`**: Main window and UI orchestration with multi-threaded data collection
- **`hayabusa_engine.py`**: Lightweight Hayabusa-style rule processing engine for EVTX log analysis
- **`collectors/`**: Windows-specific data collection modules
  - `base_collector.py`: Base class for all collectors
  - `process_collector.py`: Windows process information collection
  - `network_collector.py`: Network connections (TCP/UDP) collection
  - `service_collector.py`: Windows Service Control Manager enumeration
  - `file_collector.py`: Windows file system scanning (startup folders, temp directories, system directories)
  - `system_collector.py`: Windows system information (hardware, OS, network interfaces)
  - `persistence_collector.py`: Windows persistence mechanism enumeration (registry keys, scheduled tasks, startup folders, services, WMI)
  - `dll_collector.py`: Loaded DLL information with digital signature verification
  - `login_collector.py`: Windows Security Event Log login events collection
  - `app_collector.py`: Installed applications information
  - `binary_collector.py`: Binary file analysis (PE parsing, signatures)
  - `firewall_collector.py`: Windows Firewall rules collection (all profiles)
- **`ui/`**: User interface components
  - `process_view.py`: Process data display with network correlation
  - `network_view.py`: Network data display with process correlation
  - `service_view.py`: Service data display
  - `file_view.py`: File data display
  - `system_view.py`: System information display
  - `persistence_view.py`: Persistence mechanisms display
  - `dll_view.py`: DLL information display with incremental updates
  - `login_view.py`: Login events display
  - `app_view.py`: Applications and binary analysis display
  - `firewall_view.py`: Firewall rules display with network correlation
  - `hayabusa_view.py`: Hayabusa event log analysis interface
- **`hayabusa/`**: Hayabusa-style YAML detection rules
  - `builtin/`: Built-in detection rules organized by category
  - `sysmon/`: Sysmon-specific detection rules

## Platform Support

- **Windows Only**: This tool is designed exclusively for Windows operating systems
  - Requires Windows 7 or later
  - Some operations require administrator privileges for full functionality
  - The tool will not run on Linux or macOS

## Security Notes

- Some operations require elevated privileges
- The application may trigger antivirus software due to system inspection capabilities
- Run with appropriate permissions based on your security policies

## License

This tool is provided as-is for security analysis and system administration purposes.

## Contributing

Feel free to submit issues or pull requests to improve this tool.

