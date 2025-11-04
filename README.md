# Host Triage Analysis Tool

A Python-based application using the latest Qt framework (PySide6) for conducting triage analysis on Windows systems. This tool is designed exclusively for Windows operating systems and helps security analysts and system administrators gather and analyze critical system information quickly.

## Features

- **Process Analysis**: View all running processes with CPU, memory usage, and command-line arguments
- **Network Connections**: Monitor active network connections and their associated processes
- **Windows Services**: List all Windows services and their status, start type, and binary paths
- **File System Analysis**: Scan important Windows directories for file information (Startup folders, Temp directories, System directories)
- **System Information**: Comprehensive Windows system hardware and software details
- **Persistence Mechanisms**: Enumerate Windows persistence mechanisms including registry run keys, scheduled tasks, startup folders, and more

## Requirements

- **Windows Operating System** (Windows 7 or later)
- Python 3.8 or higher
- PySide6 (Qt 6 for Python)
- psutil (for system information collection)
- pywin32 (required for Windows service enumeration and registry access)

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Install pywin32 for full Windows functionality:

```bash
pip install pywin32
```

**Note**: pywin32 is required for Windows service enumeration and registry access. The application will show errors if pywin32 is not installed when using these features.

## Usage

Run the application:

```bash
python main.py
```

### Using the Application

1. **Collect Data**: Click the "Collect All Data" button to gather information from all collectors
2. **View Data**: Navigate through the tabs to view different types of collected data:
   - **Processes**: Running processes with detailed information
   - **Network**: Active network connections
   - **Services**: System services status
   - **Files**: File system information from key directories
   - **System Info**: System hardware and configuration details
3. **Search/Filter**: Use the search boxes in each tab to filter data
4. **Export**: Click the "Export" button in any tab to save data as JSON

## Architecture

The application follows a modular architecture:

- **`main.py`**: Application entry point (includes Windows OS check)
- **`main_window.py`**: Main window and UI orchestration
- **`collectors/`**: Windows-specific data collection modules
  - `process_collector.py`: Windows process information
  - `network_collector.py`: Network connections
  - `service_collector.py`: Windows Service Control Manager enumeration
  - `file_collector.py`: Windows file system scanning (focused on startup folders, temp directories, system directories)
  - `system_collector.py`: Windows system information
  - `persistence_collector.py`: Windows persistence mechanism enumeration (registry keys, scheduled tasks, startup folders)
- **`ui/`**: User interface components
  - `process_view.py`: Process data display
  - `network_view.py`: Network data display
  - `service_view.py`: Service data display
  - `file_view.py`: File data display
  - `system_view.py`: System information display

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

