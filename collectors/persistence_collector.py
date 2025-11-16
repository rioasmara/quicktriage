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
                # These are actually values/subkeys in the Winlogon key, handled by _read_logon_keys()
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
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
        
        # Registry Logon Keys (special handling required - Shell and Userinit are values, Notify is a subkey)
        mechanisms['registry_logon_keys'] = self._read_logon_keys()
        
        # Registry Policy Keys
        mechanisms['registry_policies'] = self._read_registry_keys(
            self.PERSISTENCE_MECHANISMS['registry_policies']
        )
        
        # Registry Image File Execution Options (IFEO) - special handling required (contains subkeys)
        mechanisms['registry_image_hijack'] = self._read_ifeo_keys(
            self.PERSISTENCE_MECHANISMS['registry_image_hijack']
        )
        
        # Registry AppInit DLLs (special handling required)
        mechanisms['registry_appinit'] = self._read_appinit_dlls(
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
        
        # WMI Event Subscriptions (special handling required - contains subkeys)
        mechanisms['wmi_subscriptions'] = self._read_wmi_subscriptions(
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
    
    def _read_appinit_dlls(self, registry_paths):
        """Read AppInit_DLLs registry values (special handling required)."""
        results = []
        
        if winreg is None:
            return results
        
        for hkey, subkey_path in registry_paths:
            try:
                key = winreg.OpenKey(hkey, subkey_path)
                items = []
                
                # First, check if LoadAppInit_DLLs is enabled (DWORD value)
                load_appinit_enabled = False
                try:
                    load_appinit_value, _ = winreg.QueryValueEx(key, "LoadAppInit_DLLs")
                    load_appinit_enabled = (load_appinit_value == 1)
                except (FileNotFoundError, OSError):
                    # LoadAppInit_DLLs doesn't exist or can't be read
                    pass
                
                # Read the AppInit_DLLs value (can be REG_SZ or REG_MULTI_SZ)
                try:
                    appinit_value, reg_type = winreg.QueryValueEx(key, "AppInit_DLLs")
                    
                    # Handle different registry types
                    if reg_type == winreg.REG_MULTI_SZ:
                        # REG_MULTI_SZ is a list of strings
                        dll_list = appinit_value if isinstance(appinit_value, list) else [appinit_value]
                        dll_paths = [dll.strip() for dll in dll_list if dll.strip()]
                    elif reg_type == winreg.REG_SZ:
                        # REG_SZ is a single string, may contain multiple DLLs separated by spaces or commas
                        dll_string = str(appinit_value).strip()
                        if dll_string:
                            # Split by comma or space
                            dll_paths = [dll.strip() for dll in dll_string.replace(',', ' ').split() if dll.strip()]
                        else:
                            dll_paths = []
                    else:
                        # Unknown type, try to convert to string
                        dll_string = str(appinit_value).strip()
                        dll_paths = [dll.strip() for dll in dll_string.replace(',', ' ').split() if dll.strip()] if dll_string else []
                    
                    # Add LoadAppInit_DLLs status
                    items.append({
                        'name': 'LoadAppInit_DLLs',
                        'value': '1 (Enabled)' if load_appinit_enabled else '0 (Disabled)',
                        'type': 'REG_DWORD',
                        'hkey': self._get_hkey_name(hkey),
                        'path': subkey_path,
                        'enabled': load_appinit_enabled
                    })
                    
                    # Add AppInit_DLLs value
                    if dll_paths:
                        # Multiple DLLs found
                        for dll_path in dll_paths:
                            items.append({
                                'name': 'AppInit_DLLs',
                                'value': dll_path,
                                'type': str(reg_type),
                                'hkey': self._get_hkey_name(hkey),
                                'path': subkey_path,
                                'enabled': load_appinit_enabled
                            })
                    else:
                        # No DLLs configured (empty value)
                        items.append({
                            'name': 'AppInit_DLLs',
                            'value': '(empty - no DLLs configured)',
                            'type': str(reg_type),
                            'hkey': self._get_hkey_name(hkey),
                            'path': subkey_path,
                            'enabled': load_appinit_enabled
                        })
                        
                except (FileNotFoundError, OSError) as e:
                    # AppInit_DLLs value doesn't exist or can't be read
                    items.append({
                        'name': 'AppInit_DLLs',
                        'value': f'Error: {str(e)}',
                        'type': 'N/A',
                        'hkey': self._get_hkey_name(hkey),
                        'path': subkey_path,
                        'enabled': load_appinit_enabled
                    })
                
                # Also enumerate any other values in this key (for completeness)
                i = 0
                while True:
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        # Skip AppInit_DLLs and LoadAppInit_DLLs as we already handled them
                        if name not in ['AppInit_DLLs', 'LoadAppInit_DLLs']:
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
                else:
                    # Even if no items, report the key was checked
                    results.append({
                        'key': subkey_path,
                        'hkey': self._get_hkey_name(hkey),
                        'values': [{
                            'name': 'Status',
                            'value': 'Key exists but no values found',
                            'type': 'N/A',
                            'hkey': self._get_hkey_name(hkey),
                            'path': subkey_path
                        }]
                    })
                    
            except (FileNotFoundError, PermissionError, OSError) as e:
                results.append({
                    'key': subkey_path,
                    'hkey': self._get_hkey_name(hkey),
                    'error': str(e)
                })
        
        return results
    
    def _read_logon_keys(self):
        """Read Winlogon registry keys (Shell, Userinit, and Notify subkey)."""
        results = []
        
        if winreg is None:
            return results
        
        winlogon_path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        hkey = winreg.HKEY_LOCAL_MACHINE
        
        try:
            key = winreg.OpenKey(hkey, winlogon_path)
            items = []
            
            # Read Shell value (default shell, usually explorer.exe)
            try:
                shell_value, shell_type = winreg.QueryValueEx(key, "Shell")
                items.append({
                    'name': 'Shell',
                    'value': str(shell_value),
                    'type': str(shell_type),
                    'hkey': self._get_hkey_name(hkey),
                    'path': winlogon_path,
                    'description': 'Default shell executed at logon'
                })
            except (FileNotFoundError, OSError) as e:
                # Shell value doesn't exist (unusual but possible)
                items.append({
                    'name': 'Shell',
                    'value': f'Not found (Error: {str(e)})',
                    'type': 'N/A',
                    'hkey': self._get_hkey_name(hkey),
                    'path': winlogon_path,
                    'description': 'Default shell - value not found'
                })
            
            # Read Userinit value (user initialization program)
            try:
                userinit_value, userinit_type = winreg.QueryValueEx(key, "Userinit")
                # Userinit often has a trailing comma, normalize it
                userinit_str = str(userinit_value).rstrip(',')
                items.append({
                    'name': 'Userinit',
                    'value': userinit_str,
                    'type': str(userinit_type),
                    'hkey': self._get_hkey_name(hkey),
                    'path': winlogon_path,
                    'description': 'User initialization program executed at logon'
                })
            except (FileNotFoundError, OSError) as e:
                # Userinit value doesn't exist (unusual but possible)
                items.append({
                    'name': 'Userinit',
                    'value': f'Not found (Error: {str(e)})',
                    'type': 'N/A',
                    'hkey': self._get_hkey_name(hkey),
                    'path': winlogon_path,
                    'description': 'User initialization program - value not found'
                })
            
            # Enumerate Notify subkey (contains DLL notification packages)
            notify_path = winlogon_path + r"\Notify"
            try:
                notify_key = winreg.OpenKey(hkey, notify_path)
                notify_items = []
                
                # Enumerate all subkeys in Notify
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(notify_key, i)
                        subkey_path = notify_path + "\\" + subkey_name
                        
                        # Open each subkey and read its values
                        try:
                            subkey = winreg.OpenKey(notify_key, subkey_name)
                            subkey_values = []
                            
                            j = 0
                            while True:
                                try:
                                    value_name, value_data, value_type = winreg.EnumValue(subkey, j)
                                    subkey_values.append({
                                        'name': value_name,
                                        'value': str(value_data),
                                        'type': str(value_type)
                                    })
                                    j += 1
                                except OSError:
                                    break
                            
                            winreg.CloseKey(subkey)
                            
                            if subkey_values:
                                notify_items.append({
                                    'name': subkey_name,
                                    'path': subkey_path,
                                    'values': subkey_values,
                                    'description': f'Notification package: {subkey_name}'
                                })
                        except (PermissionError, OSError) as e:
                            # Can't read this subkey
                            notify_items.append({
                                'name': subkey_name,
                                'path': subkey_path,
                                'error': f'Cannot access subkey: {str(e)}',
                                'description': f'Notification package: {subkey_name}'
                            })
                        
                        i += 1
                    except OSError:
                        break
                
                winreg.CloseKey(notify_key)
                
                if notify_items:
                    # Add each Notify subkey as a separate entry
                    for notify_item in notify_items:
                        if 'values' in notify_item:
                            for value in notify_item['values']:
                                items.append({
                                    'name': f"Notify\\{notify_item['name']}\\{value['name']}",
                                    'value': value['value'],
                                    'type': value['type'],
                                    'hkey': self._get_hkey_name(hkey),
                                    'path': notify_item['path'],
                                    'description': notify_item.get('description', 'Notification package')
                                })
                        elif 'error' in notify_item:
                            items.append({
                                'name': f"Notify\\{notify_item['name']}",
                                'value': notify_item['error'],
                                'type': 'N/A',
                                'hkey': self._get_hkey_name(hkey),
                                'path': notify_item['path'],
                                'description': notify_item.get('description', 'Notification package')
                            })
                else:
                    # Notify subkey exists but is empty
                    items.append({
                        'name': 'Notify',
                        'value': '(empty - no notification packages configured)',
                        'type': 'Subkey',
                        'hkey': self._get_hkey_name(hkey),
                        'path': notify_path,
                        'description': 'Notification packages subkey - empty'
                    })
            except (FileNotFoundError, PermissionError, OSError) as e:
                # Notify subkey doesn't exist or can't be accessed
                items.append({
                    'name': 'Notify',
                    'value': f'Subkey not found or inaccessible: {str(e)}',
                    'type': 'Subkey',
                    'hkey': self._get_hkey_name(hkey),
                    'path': notify_path,
                    'description': 'Notification packages subkey'
                })
            
            # Also enumerate any other important values in Winlogon key
            # (for completeness, but skip Shell and Userinit as we already handled them)
            i = 0
            important_values = ['Shell', 'Userinit']  # Already handled
            while True:
                try:
                    name, value, reg_type = winreg.EnumValue(key, i)
                    if name not in important_values:
                        # Add other Winlogon values (like AutoAdminLogon, DefaultDomainName, etc.)
                        items.append({
                            'name': name,
                            'value': str(value),
                            'type': str(reg_type),
                            'hkey': self._get_hkey_name(hkey),
                            'path': winlogon_path,
                            'description': f'Winlogon configuration value: {name}'
                        })
                    i += 1
                except OSError:
                    break
            
            winreg.CloseKey(key)
            
            if items:
                results.append({
                    'key': winlogon_path,
                    'hkey': self._get_hkey_name(hkey),
                    'values': items
                })
            else:
                # Even if no items, report the key was checked
                results.append({
                    'key': winlogon_path,
                    'hkey': self._get_hkey_name(hkey),
                    'values': [{
                        'name': 'Status',
                        'value': 'Key exists but no values found',
                        'type': 'N/A',
                        'hkey': self._get_hkey_name(hkey),
                        'path': winlogon_path
                    }]
                })
                
        except (FileNotFoundError, PermissionError, OSError) as e:
            results.append({
                'key': winlogon_path,
                'hkey': self._get_hkey_name(hkey),
                'error': str(e)
            })
        
        return results
    
    def _read_ifeo_keys(self, registry_paths):
        """Read Image File Execution Options (IFEO) registry keys (contains subkeys for each executable)."""
        results = []
        
        if winreg is None:
            return results
        
        for hkey, subkey_path in registry_paths:
            try:
                key = winreg.OpenKey(hkey, subkey_path)
                items = []
                
                # Enumerate all subkeys in IFEO (each subkey is an executable name)
                i = 0
                while True:
                    try:
                        executable_name = winreg.EnumKey(key, i)
                        executable_path = subkey_path + "\\" + executable_name
                        
                        # Open each executable's subkey and read its values
                        try:
                            exec_key = winreg.OpenKey(key, executable_name)
                            exec_values = []
                            
                            # Read all values in this executable's subkey
                            j = 0
                            while True:
                                try:
                                    value_name, value_data, value_type = winreg.EnumValue(exec_key, j)
                                    exec_values.append({
                                        'name': value_name,
                                        'value': str(value_data),
                                        'type': str(value_type)
                                    })
                                    j += 1
                                except OSError:
                                    break
                            
                            winreg.CloseKey(exec_key)
                            
                            # Add each value as a separate entry
                            if exec_values:
                                for value in exec_values:
                                    # Highlight Debugger value as it's the most important for hijacking
                                    is_debugger = (value['name'].lower() == 'debugger')
                                    items.append({
                                        'name': f"{executable_name}\\{value['name']}",
                                        'value': value['value'],
                                        'type': value['type'],
                                        'hkey': self._get_hkey_name(hkey),
                                        'path': executable_path,
                                        'executable': executable_name,
                                        'value_name': value['name'],
                                        'is_debugger': is_debugger,
                                        'description': f'IFEO for {executable_name}: {value["name"]}'
                                    })
                            else:
                                # Subkey exists but has no values (unusual)
                                items.append({
                                    'name': executable_name,
                                    'value': '(subkey exists but no values found)',
                                    'type': 'Subkey',
                                    'hkey': self._get_hkey_name(hkey),
                                    'path': executable_path,
                                    'executable': executable_name,
                                    'description': f'IFEO subkey for {executable_name} (empty)'
                                })
                        except (PermissionError, OSError) as e:
                            # Can't read this subkey
                            items.append({
                                'name': executable_name,
                                'value': f'Cannot access subkey: {str(e)}',
                                'type': 'Subkey',
                                'hkey': self._get_hkey_name(hkey),
                                'path': executable_path,
                                'executable': executable_name,
                                'description': f'IFEO subkey for {executable_name} (inaccessible)'
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
                else:
                    # Even if no subkeys, report the key was checked
                    results.append({
                        'key': subkey_path,
                        'hkey': self._get_hkey_name(hkey),
                        'values': [{
                            'name': 'Status',
                            'value': '(empty - no IFEO entries configured)',
                            'type': 'N/A',
                            'hkey': self._get_hkey_name(hkey),
                            'path': subkey_path,
                            'description': 'IFEO key exists but no executables have IFEO configured'
                        }]
                    })
                    
            except (FileNotFoundError, PermissionError, OSError) as e:
                results.append({
                    'key': subkey_path,
                    'hkey': self._get_hkey_name(hkey),
                    'error': str(e)
                })
        
        return results
    
    def _read_wmi_subscriptions(self, registry_paths):
        """Read WMI Event Subscriptions registry keys (contains subkeys for EventFilter, EventConsumer, FilterToConsumerBinding)."""
        results = []
        
        if winreg is None:
            return results
        
        for hkey, subkey_path in registry_paths:
            try:
                key = winreg.OpenKey(hkey, subkey_path)
                items = []
                
                # WMI EventSub key contains subkeys for different subscription types:
                # - EventFilter: Defines what events to monitor
                # - EventConsumer: Defines what action to take
                # - FilterToConsumerBinding: Binds filters to consumers
                
                # Enumerate all subkeys in EventSub
                i = 0
                while True:
                    try:
                        subscription_type = winreg.EnumKey(key, i)
                        subscription_path = subkey_path + "\\" + subscription_type
                        
                        # Open each subscription type's subkey and enumerate its entries
                        try:
                            type_key = winreg.OpenKey(key, subscription_type)
                            entries_found = False
                            
                            # Enumerate all entries in this subscription type (each entry is a subkey)
                            j = 0
                            while True:
                                try:
                                    entry_name = winreg.EnumKey(type_key, j)
                                    entry_path = subscription_path + "\\" + entry_name
                                    
                                    # Open each entry's subkey and read its values
                                    try:
                                        entry_key = winreg.OpenKey(type_key, entry_name)
                                        entry_values = []
                                        
                                        # Read all values in this entry
                                        k = 0
                                        while True:
                                            try:
                                                value_name, value_data, value_type = winreg.EnumValue(entry_key, k)
                                                entry_values.append({
                                                    'name': value_name,
                                                    'value': str(value_data),
                                                    'type': str(value_type)
                                                })
                                                k += 1
                                            except OSError:
                                                break
                                        
                                        winreg.CloseKey(entry_key)
                                        
                                        # Add each value as a separate entry
                                        if entry_values:
                                            entries_found = True
                                            for value in entry_values:
                                                items.append({
                                                    'name': f"{subscription_type}\\{entry_name}\\{value['name']}",
                                                    'value': value['value'],
                                                    'type': value['type'],
                                                    'hkey': self._get_hkey_name(hkey),
                                                    'path': entry_path,
                                                    'subscription_type': subscription_type,
                                                    'entry_name': entry_name,
                                                    'value_name': value['name'],
                                                    'description': f'WMI {subscription_type}: {entry_name} - {value["name"]}'
                                                })
                                        else:
                                            # Entry exists but has no values (unusual)
                                            entries_found = True
                                            items.append({
                                                'name': f"{subscription_type}\\{entry_name}",
                                                'value': '(entry exists but no values found)',
                                                'type': 'Subkey',
                                                'hkey': self._get_hkey_name(hkey),
                                                'path': entry_path,
                                                'subscription_type': subscription_type,
                                                'entry_name': entry_name,
                                                'description': f'WMI {subscription_type}: {entry_name} (empty)'
                                            })
                                    except (PermissionError, OSError) as e:
                                        # Can't read this entry
                                        entries_found = True
                                        items.append({
                                            'name': f"{subscription_type}\\{entry_name}",
                                            'value': f'Cannot access entry: {str(e)}',
                                            'type': 'Subkey',
                                            'hkey': self._get_hkey_name(hkey),
                                            'path': entry_path,
                                            'subscription_type': subscription_type,
                                            'entry_name': entry_name,
                                            'description': f'WMI {subscription_type}: {entry_name} (inaccessible)'
                                        })
                                    
                                    j += 1
                                except OSError:
                                    break
                            
                            winreg.CloseKey(type_key)
                            
                            if not entries_found:
                                # Subscription type exists but is empty
                                items.append({
                                    'name': subscription_type,
                                    'value': '(empty - no entries configured)',
                                    'type': 'Subkey',
                                    'hkey': self._get_hkey_name(hkey),
                                    'path': subscription_path,
                                    'subscription_type': subscription_type,
                                    'description': f'WMI {subscription_type} (empty)'
                                })
                        except (PermissionError, OSError) as e:
                            # Can't read this subscription type
                            items.append({
                                'name': subscription_type,
                                'value': f'Cannot access subscription type: {str(e)}',
                                'type': 'Subkey',
                                'hkey': self._get_hkey_name(hkey),
                                'path': subscription_path,
                                'subscription_type': subscription_type,
                                'description': f'WMI {subscription_type} (inaccessible)'
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
                else:
                    # Even if no subkeys, report the key was checked
                    results.append({
                        'key': subkey_path,
                        'hkey': self._get_hkey_name(hkey),
                        'values': [{
                            'name': 'Status',
                            'value': '(empty - no WMI event subscriptions configured)',
                            'type': 'N/A',
                            'hkey': self._get_hkey_name(hkey),
                            'path': subkey_path,
                            'description': 'WMI EventSub key exists but no subscriptions configured'
                        }]
                    })
                    
            except (FileNotFoundError, PermissionError, OSError) as e:
                results.append({
                    'key': subkey_path,
                    'hkey': self._get_hkey_name(hkey),
                    'error': str(e)
                })
        
        return results
    
    def _check_startup_folders(self, folders):
        """Check startup folders for executables and shortcuts."""
        results = []
        
        for folder in folders:
            if not folder:
                # Report missing folder path
                results.append({
                    'folder': 'N/A',
                    'error': 'Folder path is empty or not defined'
                })
                continue
            
            # Always report the folder, even if it doesn't exist or is empty
            folder_result = {
                'folder': folder,
                'files': []
            }
            
            if not os.path.exists(folder):
                folder_result['error'] = f'Folder does not exist: {folder}'
                results.append(folder_result)
                continue
            
            try:
                # Check if it's actually a directory
                if not os.path.isdir(folder):
                    folder_result['error'] = f'Path exists but is not a directory: {folder}'
                    results.append(folder_result)
                    continue
                
                files = []
                for item in os.listdir(folder):
                    item_path = os.path.join(folder, item)
                    
                    # Check both files and shortcuts
                    if os.path.isfile(item_path) or item_path.lower().endswith('.lnk'):
                        try:
                            stat = os.stat(item_path)
                            file_info = {
                                'name': item,
                                'path': item_path,
                                'size': stat.st_size,
                                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                'extension': os.path.splitext(item)[1].lower()
                            }
                            
                            # Try to resolve shortcut target if it's a .lnk file
                            if item_path.lower().endswith('.lnk'):
                                file_info['type'] = 'shortcut'
                                try:
                                    # Try to read shortcut target using win32com
                                    import win32com.client
                                    shell = win32com.client.Dispatch("WScript.Shell")
                                    shortcut = shell.CreateShortCut(item_path)
                                    file_info['target'] = shortcut.Targetpath
                                    file_info['arguments'] = shortcut.Arguments
                                    file_info['working_directory'] = shortcut.WorkingDirectory
                                except:
                                    # If win32com is not available or fails, just mark as shortcut
                                    file_info['target'] = 'Unable to resolve shortcut target'
                            else:
                                file_info['type'] = 'file'
                            
                            files.append(file_info)
                        except (OSError, PermissionError) as e:
                            # If we can't stat the file, still add it with error info
                            files.append({
                                'name': item,
                                'path': item_path,
                                'error': f'Cannot access file: {str(e)}',
                                'extension': os.path.splitext(item)[1].lower()
                            })
                
                folder_result['files'] = files
                # Always add result, even if files list is empty (to show folder was checked)
                results.append(folder_result)
                
            except (PermissionError, OSError) as e:
                folder_result['error'] = str(e)
                results.append(folder_result)
        
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

