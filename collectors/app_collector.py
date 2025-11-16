"""
Application collector for triage analysis.
Collects installed applications from Windows registry.
"""

from datetime import datetime
from collectors.base_collector import BaseCollector
import winreg


class AppCollector(BaseCollector):
    """Collects installed application information from Windows registry."""
    
    def collect(self):
        """Collect installed application information."""
        import sys
        print(f"[AppCollector] collect() method called!", file=sys.stderr)
        if sys.stderr is not None:
            sys.stderr.flush()
        
        applications = []
        
        # Registry paths for installed applications
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        
        # Track seen applications to avoid duplicates
        seen_apps = set()
        
        print(f"[AppCollector] Starting registry collection...", file=sys.stderr)
        if sys.stderr is not None:
            sys.stderr.flush()
        
        for hkey, path in registry_paths:
            try:
                applications.extend(self._get_apps_from_registry(hkey, path, seen_apps))
            except Exception as e:
                # Continue with other registry paths if one fails
                print(f"[AppCollector] Error reading registry path {path}: {e}", file=sys.stderr)
                if sys.stderr is not None:
                    sys.stderr.flush()
                continue
        
        print(f"[AppCollector] Registry collection complete. Found {len(applications)} applications", file=sys.stderr)
        if sys.stderr is not None:
            sys.stderr.flush()
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'applications': applications,
            'total_count': len(applications)
        }
        
        print(f"[AppCollector] collect() method returning. Applications: {len(applications)}", file=sys.stderr)
        if sys.stderr is not None:
            sys.stderr.flush()
        
        return result
    
    def _get_apps_from_registry(self, hkey, path, seen_apps):
        """Get applications from a specific registry path."""
        applications = []
        
        try:
            with winreg.OpenKey(hkey, path) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        
                        try:
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                app_data = self._read_app_data(subkey, subkey_name)
                                
                                if app_data:
                                    # Use DisplayName as unique identifier to avoid duplicates
                                    display_name = app_data.get('name', '')
                                    if display_name and display_name not in seen_apps:
                                        seen_apps.add(display_name)
                                        applications.append(app_data)
                        except Exception:
                            # Skip this subkey if we can't read it
                            continue
                    except OSError:
                        # No more keys
                        break
        except Exception:
            # Can't open this registry path, skip it
            pass
        
        return applications
    
    def _read_app_data(self, subkey, subkey_name):
        """Read application data from a registry subkey."""
        app_data = {}
        
        try:
            # Read DisplayName (required field)
            try:
                display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                if not display_name:
                    return None
                app_data['name'] = display_name
            except FileNotFoundError:
                # No DisplayName, skip this entry
                return None
            
            # Read DisplayVersion
            try:
                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                app_data['version'] = version if version and str(version).strip() else 'N/A'
            except FileNotFoundError:
                app_data['version'] = 'N/A'
            
            # Read Publisher
            try:
                publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                app_data['publisher'] = publisher if publisher and str(publisher).strip() else 'N/A'
            except FileNotFoundError:
                app_data['publisher'] = 'N/A'
            
            # Read InstallDate
            try:
                install_date = winreg.QueryValueEx(subkey, "InstallDate")[0]
                if install_date and str(install_date).strip() and len(str(install_date).strip()) == 8:
                    # Format: YYYYMMDD
                    install_date_str = str(install_date).strip()
                    formatted_date = f"{install_date_str[:4]}-{install_date_str[4:6]}-{install_date_str[6:8]}"
                    app_data['install_date'] = formatted_date
                else:
                    app_data['install_date'] = 'N/A'
            except FileNotFoundError:
                app_data['install_date'] = 'N/A'
            
            # Read InstallLocation
            try:
                install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                app_data['install_location'] = install_location if install_location and str(install_location).strip() else 'N/A'
            except FileNotFoundError:
                app_data['install_location'] = 'N/A'
            
            # Read UninstallString
            try:
                uninstall_string = winreg.QueryValueEx(subkey, "UninstallString")[0]
                app_data['uninstall_string'] = uninstall_string if uninstall_string and str(uninstall_string).strip() else 'N/A'
            except FileNotFoundError:
                app_data['uninstall_string'] = 'N/A'
            
            # Read EstimatedSize (in bytes)
            try:
                size_bytes = winreg.QueryValueEx(subkey, "EstimatedSize")[0]
                if size_bytes:
                    size_mb = round(size_bytes / (1024 * 1024), 2)
                    app_data['size_mb'] = size_mb
                else:
                    app_data['size_mb'] = 'N/A'
            except FileNotFoundError:
                app_data['size_mb'] = 'N/A'
            
            # Read Registry Key
            app_data['registry_key'] = subkey_name
            
            return app_data
            
        except Exception as e:
            # If we can't read some fields, return what we have
            return app_data if 'name' in app_data else None

