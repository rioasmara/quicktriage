"""
Persistence mechanism collector for malware/adversary analysis.
Windows-specific persistence mechanism enumeration.
Collects information about various Windows persistence mechanisms used by attackers.
"""

import os
from datetime import datetime
from collectors.base_collector import BaseCollector

try:
    import winreg
except ImportError:
    winreg = None


class PersistenceCollector(BaseCollector):
    """Collects Windows persistence mechanism information for triage analysis."""
    
    # Windows persistence locations and mechanisms
    PERSISTENCE_MECHANISMS = {
            'registry_run_keys': [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
            ],
            'registry_logon_keys': [
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"),
            ],
            'registry_policies': [
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            ],
            'registry_ie_keys': [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Internet Explorer\Main"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Internet Explorer\Main"),
            ],
            'registry_image_hijack': [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
            ],
            'registry_appinit': [
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"),
            ],
            'registry_com_hijack': [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\CLSID"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\CLSID"),
            ],
            'startup_folders': [
                os.path.join(os.environ.get('APPDATA', ''), r"Microsoft\Windows\Start Menu\Programs\Startup"),
                os.path.join(os.environ.get('PROGRAMDATA', ''), r"Microsoft\Windows\Start Menu\Programs\StartUp"),
            ],
            'scheduled_tasks_paths': [
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), r'System32\Tasks'),
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), r'Tasks'),  # Legacy location
            ],
            'services_registry': [
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
            ],
            'wmi_event_subscriptions': [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Wbem\EventSub"),
            ],
    }
    
    def __init__(self):
        """Initialize persistence collector."""
        super().__init__()
    
    def collect(self):
        """Collect Windows persistence mechanism information."""
        persistence_data = {
            'timestamp': datetime.now().isoformat(),
            'platform': 'Windows',
            'mechanisms': {}
        }
        
        persistence_data['mechanisms'].update(self._collect_windows_persistence())
        
        return persistence_data
    
    def _collect_windows_persistence(self):
        """Collect Windows-specific persistence mechanisms."""
        mechanisms = {}
        
        if winreg is None:
            return {'error': 'winreg module not available'}
        
        # Registry Run Keys
        mechanisms['registry_run_keys'] = self._read_registry_keys(
            self.PERSISTENCE_MECHANISMS['registry_run_keys']
        )
        
        # Registry Logon Keys
        mechanisms['registry_logon_keys'] = self._read_registry_keys(
            self.PERSISTENCE_MECHANISMS['registry_logon_keys']
        )
        
        # Registry Policy Keys
        mechanisms['registry_policies'] = self._read_registry_keys(
            self.PERSISTENCE_MECHANISMS['registry_policies']
        )
        
        # Registry Image File Execution Options (IFEO)
        mechanisms['registry_image_hijack'] = self._read_registry_keys(
            self.PERSISTENCE_MECHANISMS['registry_image_hijack']
        )
        
        # Registry AppInit DLLs
        mechanisms['registry_appinit'] = self._read_registry_keys(
            self.PERSISTENCE_MECHANISMS['registry_appinit']
        )
        
        # Startup Folders
        mechanisms['startup_folders'] = self._check_startup_folders(
            self.PERSISTENCE_MECHANISMS['startup_folders']
        )
        
        # Scheduled Tasks (check multiple locations)
        mechanisms['scheduled_tasks'] = self._check_scheduled_tasks(
            self.PERSISTENCE_MECHANISMS['scheduled_tasks_paths']
        )
        
        # WMI Event Subscriptions
        mechanisms['wmi_subscriptions'] = self._read_registry_keys(
            self.PERSISTENCE_MECHANISMS['wmi_event_subscriptions']
        )
        
        # Services (basic check)
        mechanisms['services'] = self._check_windows_services()
        
        return mechanisms
    
    def _read_registry_keys(self, registry_paths):
        """Read values from Windows registry keys."""
        results = []
        
        if winreg is None:
            return results
        
        for hkey, subkey_path in registry_paths:
            try:
                key = winreg.OpenKey(hkey, subkey_path)
                items = []
                
                i = 0
                while True:
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        items.append({
                            'name': name,
                            'value': str(value),
                            'type': str(reg_type),
                            'hkey': self._get_hkey_name(hkey),
                            'path': subkey_path
                        })
                        i += 1
                    except OSError:
                        break
                
                winreg.CloseKey(key)
                
                if items:
                    results.append({
                        'key': subkey_path,
                        'hkey': self._get_hkey_name(hkey),
                        'values': items
                    })
            except (FileNotFoundError, PermissionError, OSError) as e:
                results.append({
                    'key': subkey_path,
                    'hkey': self._get_hkey_name(hkey),
                    'error': str(e)
                })
        
        return results
    
    def _get_hkey_name(self, hkey):
        """Get string name of registry hive."""
        hkey_map = {
            winreg.HKEY_CURRENT_USER: 'HKEY_CURRENT_USER',
            winreg.HKEY_LOCAL_MACHINE: 'HKEY_LOCAL_MACHINE',
            winreg.HKEY_CLASSES_ROOT: 'HKEY_CLASSES_ROOT',
        }
        return hkey_map.get(hkey, 'UNKNOWN')
    
    def _check_startup_folders(self, folders):
        """Check startup folders for executables."""
        results = []
        
        for folder in folders:
            if not folder or not os.path.exists(folder):
                continue
            
            try:
                files = []
                for item in os.listdir(folder):
                    item_path = os.path.join(folder, item)
                    if os.path.isfile(item_path):
                        stat = os.stat(item_path)
                        files.append({
                            'name': item,
                            'path': item_path,
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'extension': os.path.splitext(item)[1].lower()
                        })
                
                if files:
                    results.append({
                        'folder': folder,
                        'files': files
                    })
            except (PermissionError, OSError) as e:
                results.append({
                    'folder': folder,
                    'error': str(e)
                })
        
        return results
    
    def _check_scheduled_tasks(self, tasks_paths):
        """Check Windows scheduled tasks from multiple locations."""
        results = []
        seen_tasks = set()  # Track tasks by path to avoid duplicates
        
        # Handle both single path (backward compatibility) and list of paths
        if isinstance(tasks_paths, str):
            tasks_paths = [tasks_paths]
        
        def enumerate_tasks_recursive(directory, base_path):
            """Recursively enumerate scheduled tasks in directory structure."""
            try:
                for item in os.listdir(directory):
                    item_path = os.path.join(directory, item)
                    
                    if os.path.isfile(item_path):
                        # Scheduled tasks are stored as files without extensions
                        # They are XML files but stored without .xml extension
                        # Skip duplicates
                        if item_path.lower() in seen_tasks:
                            continue
                        seen_tasks.add(item_path.lower())
                        
                        stat = os.stat(item_path)
                        # Construct the task name with path structure
                        relative_path = os.path.relpath(item_path, base_path)
                        task_name = relative_path.replace(os.sep, '\\')
                        
                        results.append({
                            'name': task_name,
                            'path': item_path,
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                        })
                    elif os.path.isdir(item_path):
                        # Recursively check subdirectories
                        enumerate_tasks_recursive(item_path, base_path)
            except (PermissionError, OSError) as e:
                # Store error but continue with other directories
                if not results or (results and 'error' not in results[-1]):
                    results.append({'error': f'Error accessing {directory}: {str(e)}'})
        
        # Check all provided paths
        for tasks_path in tasks_paths:
            if not tasks_path or not os.path.exists(tasks_path):
                continue
            
            try:
                enumerate_tasks_recursive(tasks_path, tasks_path)
            except (PermissionError, OSError) as e:
                results.append({'error': f'Error accessing {tasks_path}: {str(e)}'})
        
        # Also try to enumerate tasks using Task Scheduler COM API
        try:
            com_tasks = self._check_scheduled_tasks_com()
            for task in com_tasks:
                task_path = task.get('path', '')
                # Check if this task path is already in our results
                if task_path:
                    task_path_lower = task_path.lower()
                    # Check both the path and the task name to avoid duplicates
                    task_name_lower = task.get('name', '').lower()
                    is_duplicate = False
                    
                    # Check if we've seen this file path
                    if task_path_lower in seen_tasks:
                        is_duplicate = True
                    # Also check if task name matches any existing task
                    for existing_task in results:
                        if 'name' in existing_task and existing_task['name'].lower() == task_name_lower:
                            is_duplicate = True
                            break
                    
                    if not is_duplicate:
                        seen_tasks.add(task_path_lower)
                        results.append(task)
        except Exception as e:
            # COM API not available or failed, continue with file system enumeration
            pass
        
        return results
    
    def _check_scheduled_tasks_com(self):
        """Check Windows scheduled tasks using Task Scheduler COM API."""
        results = []
        
        try:
            import win32com.client
            scheduler = win32com.client.Dispatch('Schedule.Service')
            scheduler.Connect()
            
            def enumerate_tasks_recursive(folder, folder_path='\\'):
                """Recursively enumerate tasks from Task Scheduler Library."""
                try:
                    # Get all tasks in current folder
                    try:
                        tasks = folder.GetTasks(0)
                        for task in tasks:
                            try:
                                task_path = task.Path
                                task_name = task.Name
                                
                                # Construct full task path with folder structure
                                # Normalize folder path (remove leading/trailing backslashes, then add properly)
                                normalized_folder_path = folder_path.strip('\\')
                                if normalized_folder_path:
                                    full_task_path = normalized_folder_path + '\\' + task_name
                                else:
                                    full_task_path = task_name
                                
                                # Get task file path if available
                                # Task files are stored in System32\Tasks with folder structure
                                file_path = None
                                try:
                                    # Construct file path from task path
                                    task_path_relative = full_task_path.replace('\\', os.sep)
                                    file_path = os.path.join(
                                        os.environ.get('WINDIR', 'C:\\Windows'),
                                        'System32\\Tasks',
                                        task_path_relative
                                    )
                                    if not os.path.exists(file_path):
                                        # Try alternative path construction
                                        file_path = None
                                except:
                                    pass
                                
                                # Get task info
                                task_info = {
                                    'name': full_task_path,
                                    'path': file_path or f'Task Scheduler Library: {full_task_path}',
                                    'size': 0,
                                    'modified': datetime.now().isoformat()  # Default if file not found
                                }
                                
                                # If we found the file, get its actual modification time and size
                                if file_path and os.path.exists(file_path):
                                    try:
                                        stat = os.stat(file_path)
                                        task_info['size'] = stat.st_size
                                        task_info['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
                                        task_info['path'] = file_path  # Use actual file path
                                    except:
                                        pass
                                
                                results.append(task_info)
                            except Exception as e:
                                # Skip tasks that can't be accessed, but continue with other tasks
                                continue
                    except Exception as e:
                        # If we can't get tasks from this folder, continue to subfolders
                        pass
                    
                    # Get all subfolders and enumerate recursively
                    # This ensures we traverse ALL folders and subfolders in the Task Scheduler Library
                    try:
                        folders = folder.GetFolders(0)
                        for subfolder in folders:
                            try:
                                subfolder_name = subfolder.Name
                                # Build the path for the subfolder
                                normalized_folder_path = folder_path.strip('\\')
                                if normalized_folder_path:
                                    subfolder_path = normalized_folder_path + '\\' + subfolder_name + '\\'
                                else:
                                    subfolder_path = subfolder_name + '\\'
                                
                                # Recursively enumerate all tasks in this subfolder and its children
                                enumerate_tasks_recursive(subfolder, subfolder_path)
                            except Exception as e:
                                # If we can't access a subfolder, continue with other subfolders
                                continue
                    except Exception as e:
                        # If we can't get folders, this folder has no subfolders, continue
                        pass
                except Exception as e:
                    # If folder access completely fails, continue with other folders
                    pass
            
            # Start from root folder
            root_folder = scheduler.GetFolder('\\')
            enumerate_tasks_recursive(root_folder, '\\')
            
        except ImportError:
            # pywin32 not available
            pass
        except Exception as e:
            # COM API failed, silently continue
            pass
        
        return results
    
    def _check_windows_services(self):
        """Check Windows services for suspicious entries."""
        # This is a basic check - full service enumeration should use ServiceCollector
        return {
            'note': 'Full service enumeration available via ServiceCollector',
            'suspicious_service_paths': self._get_suspicious_service_paths()
        }
    
    def _get_suspicious_service_paths(self):
        """Check for services in suspicious locations."""
        suspicious_paths = []
        
        if winreg is None:
            return suspicious_paths
        
        try:
            key_path = r"SYSTEM\CurrentControlSet\Services"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            
            i = 0
            while i < 100:  # Limit to prevent excessive enumeration
                try:
                    service_name = winreg.EnumKey(key, i)
                    service_key_path = f"{key_path}\\{service_name}"
                    service_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, service_key_path)
                    
                    try:
                        image_path, _ = winreg.QueryValueEx(service_key, "ImagePath")
                        if image_path:
                            # Check for suspicious locations
                            suspicious_locations = [
                                r'%TEMP%',
                                r'%APPDATA%',
                                r'Users\Public',
                                r'C:\ProgramData',
                            ]
                            
                            path_lower = image_path.lower()
                            if any(loc.lower() in path_lower for loc in suspicious_locations):
                                suspicious_paths.append({
                                    'service': service_name,
                                    'image_path': image_path
                                })
                    except FileNotFoundError:
                        pass
                    
                    winreg.CloseKey(service_key)
                    i += 1
                except OSError:
                    break
            
            winreg.CloseKey(key)
        except (PermissionError, OSError):
            pass
        
        return suspicious_paths


# Comprehensive documentation of Windows persistence mechanisms
PERSISTENCE_MECHANISMS_DOC = {
        'registry_run_keys': {
            'description': 'Registry keys that execute programs at startup/login',
            'common_keys': [
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            ],
            'adversary_tactics': [
                'T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
            ]
        },
        'registry_logon_keys': {
            'description': 'Registry keys that control Windows logon process',
            'common_keys': [
                'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell',
                'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit',
            ],
            'adversary_tactics': [
                'T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL'
            ]
        },
        'scheduled_tasks': {
            'description': 'Windows Task Scheduler tasks',
            'adversary_tactics': [
                'T1053.005 - Scheduled Task/Job: Scheduled Task'
            ]
        },
        'services': {
            'description': 'Windows Services',
            'adversary_tactics': [
                'T1543.003 - Create or Modify System Process: Windows Service'
            ]
        },
        'startup_folders': {
            'description': 'Startup folders that execute programs at login',
            'paths': [
                '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
                '%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp',
            ],
            'adversary_tactics': [
                'T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
            ]
        },
        'wmi_event_subscriptions': {
            'description': 'WMI Event Subscriptions for persistence',
            'adversary_tactics': [
                'T1546.003 - Event Triggered Execution: WMI Event Subscription'
            ]
        },
        'image_file_execution_options': {
            'description': 'Image File Execution Options (IFEO) for DLL injection',
            'adversary_tactics': [
                'T1546.012 - Event Triggered Execution: Image File Execution Options Injection'
            ]
        },
        'appinit_dlls': {
            'description': 'AppInit_DLLs registry key for DLL injection',
            'adversary_tactics': [
                'T1546.010 - Event Triggered Execution: AppInit DLLs'
            ]
        },
        'com_hijacking': {
            'description': 'Component Object Model (COM) hijacking',
            'adversary_tactics': [
                'T1546.015 - Event Triggered Execution: Component Object Model Hijacking'
            ]
        },
    }

