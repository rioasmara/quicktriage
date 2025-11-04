# Persistence Mechanisms Reference

A comprehensive collection of persistence mechanisms commonly used by malware and adversaries.

## Windows Persistence Mechanisms

### 1. Registry Run Keys
**MITRE ATT&CK**: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**Common Registry Keys:**
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`

**Description**: Programs executed automatically at user logon or system startup.

**Detection**: Monitor registry modifications to these keys.

### 2. Startup Folders
**MITRE ATT&CK**: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**Paths:**
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp`

**Description**: Executables and shortcuts placed in startup folders execute automatically at login.

**Detection**: Monitor file creation in startup directories.

### 3. Scheduled Tasks
**MITRE ATT&CK**: T1053.005 - Scheduled Task/Job: Scheduled Task

**Location**: `%WINDIR%\System32\Tasks`

**Description**: Windows Task Scheduler can execute programs at specific times or events.

**Common Techniques:**
- Hidden tasks (tasks with names starting with `$`)
- Tasks masquerading as legitimate system tasks
- Tasks with high privileges

**Detection**: Examine task XML files in System32\Tasks, check task properties via `schtasks`.

### 4. Windows Services
**MITRE ATT&CK**: T1543.003 - Create or Modify System Process: Windows Service

**Registry Location**: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`

**Description**: Services run in the background and can be set to start automatically.

**Common Techniques:**
- Service DLL hijacking
- Services with suspicious ImagePath locations
- Services with weak permissions

**Detection**: Analyze service registry entries, check ImagePath values for suspicious locations.

### 5. Winlogon Helper DLL
**MITRE ATT&CK**: T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL

**Registry Keys:**
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`

**Description**: Modifies Winlogon process to load malicious DLLs during user authentication.

**Detection**: Monitor Winlogon registry keys, baseline normal values.

### 6. Image File Execution Options (IFEO)
**MITRE ATT&CK**: T1546.012 - Event Triggered Execution: Image File Execution Options Injection

**Registry Locations:**
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>`

**Description**: Debugger hijacking - redirects execution of a legitimate program to a malicious debugger.

**Common Technique**: Set `Debugger` value to malicious executable.

**Detection**: Monitor IFEO registry keys for unexpected entries.

### 7. AppInit DLLs
**MITRE ATT&CK**: T1546.010 - Event Triggered Execution: AppInit DLLs

**Registry Keys:**
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`

**Description**: DLLs listed here are loaded into every process that loads User32.dll.

**Detection**: Monitor AppInit_DLLs registry key for modifications.

### 8. Component Object Model (COM) Hijacking
**MITRE ATT&CK**: T1546.015 - Event Triggered Execution: Component Object Model Hijacking

**Registry Locations:**
- `HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\<CLSID>\InprocServer32`
- `HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\<CLSID>\InprocServer32`

**Description**: Hijacks COM objects by modifying registry entries to point to malicious DLLs.

**Detection**: Baseline COM object registry entries, monitor for modifications.

### 9. WMI Event Subscriptions
**MITRE ATT&CK**: T1546.003 - Event Triggered Execution: WMI Event Subscription

**Registry Location**: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem\EventSub`

**Description**: Creates WMI event filters and consumers that execute code when specific events occur.

**Common Events:**
- Process creation
- System startup
- User logon

**Detection**: Query WMI event subscriptions: `Get-WmiObject -Namespace root\Subscription -Class __EventFilter`

### 10. Browser Extensions
**MITRE ATT&CK**: T1176 - Browser Extensions

**Chrome/Edge**: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions`
**Firefox**: `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\extensions`

**Description**: Malicious browser extensions can persist and execute code.

**Detection**: Review installed browser extensions.

### 11. File Association Hijacking
**MITRE ATT&CK**: T1546.001 - Event Triggered Execution: Change Default File Association

**Description**: Modifies file associations to execute malicious code when specific file types are opened.

**Common Targets**: `.bat`, `.cmd`, `.exe`, `.scr`, `.com`

**Detection**: Monitor file association registry keys.

### 12. Shortcut Modification
**MITRE ATT&CK**: T1547.009 - Boot or Logon Autostart Execution: Shortcut Modification

**Description**: Modifies shortcuts (`.lnk` files) to execute malicious code.

**Common Locations**: Desktop shortcuts, start menu shortcuts

**Detection**: Analyze `.lnk` file contents for suspicious targets or arguments.

### 13. DLL Side-loading
**MITRE ATT&CK**: T1574.002 - Hijack Execution Flow: DLL Side-Loading

**Description**: Places malicious DLL in the same directory as a legitimate executable that will load it.

**Detection**: Identify DLLs with mismatched signatures or in unusual locations.

### 14. Scheduled Task via COM
**MITRE ATT&CK**: T1053.005 - Scheduled Task/Job: Scheduled Task

**Description**: Creates scheduled tasks programmatically via COM interfaces.

**Detection**: Monitor scheduled task creation events.

### 15. Accessibility Features
**MITRE ATT&CK**: T1546.008 - Event Triggered Execution: Accessibility Features

**Registry Keys:**
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe`

**Description**: Replaces accessibility tools (Sticky Keys, On-Screen Keyboard, Utility Manager) with malicious executables.

**Detection**: Monitor IFEO registry entries for accessibility tools.

### 16. PowerShell Profile
**MITRE ATT&CK**: T1546.013 - Event Triggered Execution: PowerShell Profile

**Paths:**
- `$PROFILE` (user-specific)
- `$PSHOME\Profile.ps1` (system-wide)

**Description**: PowerShell profiles execute automatically when PowerShell starts.

**Detection**: Review PowerShell profile files for malicious code.

### 17. Startup Items (macOS-like on Windows)
**Description**: Various other startup mechanisms including:
- Group Policy logon scripts
- Netsh helper DLLs
- BITS jobs
- Windows Management Instrumentation (WMI) subscriptions

## Linux Persistence Mechanisms

### 1. Cron Jobs
**MITRE ATT&CK**: T1053.003 - Scheduled Task/Job: Cron

**Common Locations:**
- `/etc/cron.d/`
- `/etc/cron.daily/`
- `/etc/cron.hourly/`
- `/etc/cron.monthly/`
- `/etc/cron.weekly/`
- `/var/spool/cron/crontabs/` (user crontabs)
- `~/.crontab` (user crontab)

**Description**: Scheduled tasks that execute commands at specified intervals.

**Detection**: Review all crontab files, check for jobs executing from `/tmp` or other suspicious locations.

### 2. Systemd Services
**MITRE ATT&CK**: T1543.002 - Create or Modify System Process: Systemd Service

**Common Locations:**
- `/etc/systemd/system/` (system services)
- `/usr/lib/systemd/system/` (package-installed services)
- `~/.config/systemd/user/` (user services)

**Description**: Systemd service units that can start automatically.

**Detection**: Review systemd service files, check for services in unusual locations or with suspicious ExecStart paths.

### 3. Init.d Scripts
**MITRE ATT&CK**: T1037.004 - Boot or Logon Initialization Scripts: RC Scripts

**Common Locations:**
- `/etc/init.d/` (traditional init scripts)
- `/etc/rc.local` (system-wide initialization script)

**Description**: Legacy init scripts that execute during system boot.

**Detection**: Review init.d scripts and rc.local for modifications.

### 4. Shell Startup Files
**MITRE ATT&CK**: T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification

**Common Files:**
- `~/.bashrc`
- `~/.bash_profile`
- `~/.profile`
- `~/.zshrc`
- `~/.zshenv`
- `/etc/bash.bashrc` (system-wide)
- `/etc/profile` (system-wide)
- `/etc/profile.d/` (directory)

**Description**: Shell configuration files that execute commands when a shell starts.

**Detection**: Review shell startup files for malicious code or suspicious commands (curl, wget, base64, eval).

### 5. Autostart Directories
**Paths:**
- `~/.config/autostart/` (user-specific)
- `/etc/xdg/autostart/` (system-wide)

**Description**: Desktop environment autostart files (`.desktop` files).

**Detection**: Review autostart `.desktop` files.

### 6. SSH Authorized Keys
**MITRE ATT&CK**: T1098.004 - Account Manipulation: SSH Authorized Keys

**File**: `~/.ssh/authorized_keys`

**Description**: Adds public keys to authorized_keys file for passwordless SSH access.

**Detection**: Review authorized_keys files, monitor for unexpected additions.

### 7. Kernel Modules
**MITRE ATT&CK**: T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions

**Common Locations:**
- `/lib/modules/`
- `/etc/modules` (modules to load at boot)

**Description**: Loadable kernel modules (LKMs) can persist and execute at kernel level.

**Detection**: Review loaded kernel modules: `lsmod`, check `/etc/modules`.

### 8. PAM Configuration
**MITRE ATT&CK**: T1556.003 - Modify Authentication Process: Pluggable Authentication Modules

**Common Files:**
- `/etc/pam.d/`

**Description**: Modifies PAM configuration to execute code during authentication.

**Detection**: Review PAM configuration files for unauthorized modifications.

### 9. Systemd Timers
**MITRE ATT&CK**: T1053.006 - Scheduled Task/Job: Systemd Timers

**Locations:**
- `/etc/systemd/system/` (`.timer` files)
- `~/.config/systemd/user/` (user timers)

**Description**: Systemd timer units for scheduled execution.

**Detection**: Review systemd timer files.

### 10. Network Configuration Scripts
**Common Locations:**
- `/etc/network/if-up.d/`
- `/etc/NetworkManager/dispatcher.d/`

**Description**: Scripts that execute when network interfaces come up.

**Detection**: Review network configuration scripts.

## macOS Persistence Mechanisms

### 1. Launch Agents and Launch Daemons
**MITRE ATT&CK**: T1543.001 - Create or Modify System Process: Launch Agent

**Common Locations:**
- `~/Library/LaunchAgents/` (user Launch Agents)
- `/Library/LaunchAgents/` (system-wide Launch Agents)
- `/Library/LaunchDaemons/` (system Launch Daemons)
- `/System/Library/LaunchAgents/` (Apple-provided Launch Agents)
- `/System/Library/LaunchDaemons/` (Apple-provided Launch Daemons)

**Description**: Property list (`.plist`) files that define processes to be executed.

**Detection**: Review LaunchAgent and LaunchDaemon plist files, check for suspicious ProgramArguments or RunAtLoad.

### 2. Login Items
**Description**: Applications set to launch at login.

**Detection**: Check System Preferences > Users & Groups > Login Items, or use `defaults read com.apple.loginwindow`.

### 3. Cron Jobs
**MITRE ATT&CK**: T1053.003 - Scheduled Task/Job: Cron

**Locations**: Same as Linux cron directories.

**Detection**: Review crontab files.

### 4. Shell Startup Files
**MITRE ATT&CK**: T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification

**Files**: Same as Linux shell startup files.

**Detection**: Review shell configuration files.

### 5. Kernel Extensions
**MITRE ATT&CK**: T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions

**Description**: Kernel extensions (.kext files) that load at boot.

**Detection**: Review loaded kernel extensions: `kextstat`, check `/Library/Extensions` and `/System/Library/Extensions`.

### 6. Periodic Scripts
**Locations:**
- `/etc/periodic/daily/`
- `/etc/periodic/weekly/`
- `/etc/periodic/monthly/`

**Description**: Scripts that execute on a periodic schedule.

**Detection**: Review periodic script directories.

## Cross-Platform Persistence Mechanisms

### 1. File Timestomping
**MITRE ATT&CK**: T1070.006 - Indicator Removal on Host: Timestomping

**Description**: Modifies file timestamps to hide modifications or make files appear legitimate.

**Detection**: Compare file modification times with baseline, look for inconsistencies.

### 2. Process Injection
**MITRE ATT&CK**: T1055 - Process Injection

**Description**: Injects malicious code into legitimate processes to maintain persistence.

**Common Techniques:**
- DLL injection
- Thread hijacking
- Process hollowing
- Reflective DLL loading

**Detection**: Analyze process memory, monitor for unusual process behavior.

### 3. Memory-Only Persistence
**Description**: Malware that persists only in memory without writing to disk.

**Detection**: Memory analysis, monitor for suspicious processes.

### 4. Web Shells
**MITRE ATT&CK**: T1505.003 - Server Software Component: Web Shell

**Description**: Backdoors placed on web servers for remote access.

**Common Locations:**
- Web root directories
- Temporary directories
- Obscure file names

**Detection**: Review web server directories, analyze file contents for web shell signatures.

## Detection and Analysis Recommendations

1. **Baseline Normal State**: Establish baseline of legitimate persistence mechanisms
2. **Regular Monitoring**: Continuously monitor persistence locations for changes
3. **File Integrity Monitoring**: Monitor changes to critical files and registry keys
4. **Process Monitoring**: Monitor process creation and parent-child relationships
5. **Network Monitoring**: Monitor for connections from persistence mechanisms
6. **Behavioral Analysis**: Look for unusual execution patterns or timing
7. **Digital Signatures**: Verify digital signatures of executables and DLLs
8. **Log Analysis**: Review system logs for persistence-related events

## Tools for Analysis

- **Windows**: Autoruns (Sysinternals), PowerSploit, Registry analysis tools
- **Linux**: chkrootkit, rkhunter, systemd-analyze, auditd
- **macOS**: LaunchControl, log analysis tools
- **Cross-Platform**: Volatility (memory forensics), Wireshark (network analysis)

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- Red Canary's Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- Sysinternals Suite: https://docs.microsoft.com/en-us/sysinternals/




