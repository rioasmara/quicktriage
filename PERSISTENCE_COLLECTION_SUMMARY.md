# Persistence Mechanisms Collection - Summary

## Overview

This collection includes comprehensive information and tools for detecting persistence mechanisms commonly used by malware and adversaries.

## Files Created

### 1. `collectors/persistence_collector.py`
A Python module that automatically detects and collects persistence mechanisms from Windows, Linux, and macOS systems.

**Features:**
- Windows registry key analysis (Run keys, Winlogon, IFEO, AppInit, etc.)
- Windows scheduled tasks detection
- Windows startup folder monitoring
- Linux cron job detection
- Linux systemd service analysis
- Linux shell startup file analysis
- macOS Launch Agent/Launch Daemon detection
- Cross-platform persistence detection

### 2. `persistence_mechanisms_reference.md`
Comprehensive documentation of persistence mechanisms with:
- MITRE ATT&CK mapping for each technique
- Detailed descriptions
- Common locations and paths
- Detection recommendations
- References to tools and resources

**Covers:**
- **Windows**: 17+ persistence mechanisms
- **Linux**: 10+ persistence mechanisms  
- **macOS**: 6+ persistence mechanisms
- **Cross-platform**: Memory persistence, web shells, etc.

### 3. `persistence_collector_example.py`
Example script demonstrating how to use the PersistenceCollector module.

**Usage:**
```bash
python persistence_collector_example.py
```

## Quick Start

### Using the Persistence Collector

```python
from collectors.persistence_collector import PersistenceCollector

# Initialize collector
collector = PersistenceCollector()

# Collect persistence data
data = collector.collect()

# Access mechanisms
mechanisms = data['mechanisms']

# Check specific mechanism types
if 'registry_run_keys' in mechanisms:
    run_keys = mechanisms['registry_run_keys']
    # Analyze run keys...
```

### Command Line Example

Run the example script:
```bash
python persistence_collector_example.py
```

This will:
1. Collect all persistence mechanisms
2. Display detected mechanisms
3. Save results to `persistence_analysis.json`

## Windows Persistence Mechanisms Detected

| Mechanism | MITRE ATT&CK | Collector Module |
|-----------|--------------|------------------|
| Registry Run Keys | T1547.001 | ✓ |
| Startup Folders | T1547.001 | ✓ |
| Scheduled Tasks | T1053.005 | ✓ |
| Windows Services | T1543.003 | ✓ |
| Winlogon Helper DLL | T1547.004 | ✓ |
| Image File Execution Options | T1546.012 | ✓ |
| AppInit DLLs | T1546.010 | ✓ |
| COM Hijacking | T1546.015 | ✓ |
| WMI Event Subscriptions | T1546.003 | ✓ |

## Linux Persistence Mechanisms Detected

| Mechanism | MITRE ATT&CK | Collector Module |
|-----------|--------------|------------------|
| Cron Jobs | T1053.003 | ✓ |
| Systemd Services | T1543.002 | ✓ |
| Init.d Scripts | T1037.004 | ✓ |
| Shell Startup Files | T1546.004 | ✓ |
| Autostart Directories | - | ✓ |

## macOS Persistence Mechanisms Detected

| Mechanism | MITRE ATT&CK | Collector Module |
|-----------|--------------|------------------|
| Launch Agents/Daemons | T1543.001 | ✓ |
| Cron Jobs | T1053.003 | ✓ |
| Shell Startup Files | T1546.004 | ✓ |

## Integration with Host Triage Analysis Tool

To integrate the persistence collector into the main application:

1. Add to `main_window.py`:
```python
from collectors.persistence_collector import PersistenceCollector
from ui.persistence_view import PersistenceView  # (create this view)

# In __init__:
self.collectors["persistence"] = PersistenceCollector()

# In init_ui:
self.persistence_view = PersistenceView()
self.tabs.addTab(self.persistence_view, "Persistence")
```

2. Create `ui/persistence_view.py` similar to other view modules

## Analysis Recommendations

### For Windows Analysis:
1. Focus on registry run keys first (most common)
2. Check scheduled tasks for hidden tasks (names starting with `$`)
3. Review services in suspicious locations (`%TEMP%`, `%APPDATA%`)
4. Examine WMI event subscriptions for unusual filters
5. Check IFEO registry entries for debugger hijacking

### For Linux Analysis:
1. Review all crontab files for suspicious commands
2. Check systemd services in user directories
3. Examine shell startup files for obfuscated code (base64, eval, etc.)
4. Review init.d scripts and rc.local
5. Check autostart directories for malicious `.desktop` files

### For macOS Analysis:
1. Review Launch Agents in user directories
2. Check Launch Daemons for system-level persistence
3. Examine shell startup files
4. Review periodic scripts

## Detection Patterns to Look For

### Suspicious Indicators:
- Executables in temporary directories
- Executables in user profile directories with suspicious names
- Base64-encoded payloads in startup files
- Obfuscated commands (eval, exec, etc.)
- Hidden scheduled tasks
- Services with suspicious ImagePath locations
- Registry entries with suspicious paths
- DLLs in unusual locations

### Common Malware Patterns:
- Files with legitimate-sounding names in suspicious locations
- Scheduled tasks masquerading as system tasks
- Registry entries pointing to `%TEMP%` or `%APPDATA%`
- Base64 or encoded commands in shell scripts
- DLLs with misspelled legitimate names (DLL side-loading)

## Future Enhancements

Potential additions:
- Memory-only persistence detection
- Process injection detection
- Browser extension analysis
- File association hijacking detection
- Shortcut modification detection
- SSH authorized keys analysis
- PAM configuration analysis

## References

- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **Sysinternals Autoruns**: For Windows persistence analysis
- **Atomic Red Team**: For testing persistence mechanisms
- **Documentation**: See `persistence_mechanisms_reference.md` for detailed information

## License

This collection is provided for security analysis and defensive purposes only.








