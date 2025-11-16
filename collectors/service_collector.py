"""
Service collector for triage analysis.
Windows-specific service enumeration using Windows Service Control Manager.
"""

from datetime import datetime
from collectors.base_collector import BaseCollector


class ServiceCollector(BaseCollector):
    """Collects Windows service information from the system."""
    
    def collect(self):
        """Collect Windows service information."""
        services = []
        service_manager = None
        win32service = None
        
        try:
            import win32serviceutil
            import win32service
            import win32con
            
            # Open Service Control Manager with all necessary access rights
            # SC_MANAGER_ENUMERATE_SERVICE and SC_MANAGER_CONNECT are in win32service module
            try:
                service_manager = win32service.OpenSCManager(
                    None, 
                    None, 
                    win32service.SC_MANAGER_ENUMERATE_SERVICE | 
                    win32service.SC_MANAGER_CONNECT
                )
            except Exception as e:
                import traceback
                traceback.print_exc(file=sys.stderr)
                raise
            
            if service_manager is None:
                return {
                    'timestamp': datetime.now().isoformat(),
                    'services': [],
                    'total_count': 0,
                    'error': 'Failed to open Service Control Manager. Ensure you have administrator privileges.'
                }
            
            # Enumerate all services (both active and inactive)
            # EnumServicesStatus returns all services by default
            try:
                status = win32service.EnumServicesStatus(service_manager)
            except Exception as e:
                import traceback
                traceback.print_exc(file=sys.stderr)
                return {
                    'timestamp': datetime.now().isoformat(),
                    'services': [],
                    'total_count': 0,
                    'error': f'Failed to enumerate services: {str(e)}. Ensure you have administrator privileges.'
                }
            
            if not status:
                return {
                    'timestamp': datetime.now().isoformat(),
                    'services': [],
                    'total_count': 0,
                    'error': 'No services found or access denied.'
                }
            
            for short_name, display_name, service_status in status:
                service_handle = None
                try:
                    service_handle = win32service.OpenService(
                        service_manager, 
                        short_name, 
                        win32service.SERVICE_QUERY_CONFIG
                    )
                    service_config = win32service.QueryServiceConfig(service_handle)
                    
                    # Determine service status
                    state = service_status[1]
                    if state == win32service.SERVICE_RUNNING:
                        status_str = 'Running'
                    elif state == win32service.SERVICE_STOPPED:
                        status_str = 'Stopped'
                    elif state == win32service.SERVICE_PAUSED:
                        status_str = 'Paused'
                    elif state == win32service.SERVICE_START_PENDING:
                        status_str = 'Starting'
                    elif state == win32service.SERVICE_STOP_PENDING:
                        status_str = 'Stopping'
                    else:
                        status_str = 'Unknown'
                    
                    # QueryServiceConfig returns: (service_type, start_type, error_control, binary_path,
                    # load_order_group, tag_id, dependencies, service_start_name, display_name)
                    # Index: 0=service_type (int), 1=start_type (int), 2=error_control (int), 3=binary_path (str), etc.
                    binary_path = str(service_config[3]) if len(service_config) > 3 and service_config[3] else 'N/A'
                    start_type_index = service_config[1] if len(service_config) > 1 else 3  # start_type is at index 1
                    description = str(service_config[8]) if len(service_config) > 8 and service_config[8] else 'N/A'
                    
                    service_data = {
                        'name': short_name or 'N/A',
                        'display_name': display_name or short_name or 'N/A',
                        'status': status_str,
                        'start_type': self._get_start_type(start_type_index),
                        'binary_path': binary_path,
                        'description': description
                    }
                    services.append(service_data)
                except Exception as e:
                    # If we can't query config, still add basic info
                    state = service_status[1]
                    if state == win32service.SERVICE_RUNNING:
                        status_str = 'Running'
                    elif state == win32service.SERVICE_STOPPED:
                        status_str = 'Stopped'
                    else:
                        status_str = 'Unknown'
                    
                    service_data = {
                        'name': short_name or 'N/A',
                        'display_name': display_name or short_name or 'N/A',
                        'status': status_str,
                        'start_type': 'N/A',
                        'binary_path': 'N/A',
                        'description': f'Error querying: {str(e)}'
                    }
                    services.append(service_data)
                finally:
                    if service_handle:
                        try:
                            win32service.CloseServiceHandle(service_handle)
                        except:
                            pass
                        
        except ImportError as e:
            # pywin32 is not available - return empty list with note
            import traceback
            traceback.print_exc(file=sys.stderr)
            return {
                'timestamp': datetime.now().isoformat(),
                'services': [],
                'total_count': 0,
                'error': f'pywin32 is required for Windows service enumeration. Import error: {str(e)}. Install with: pip install pywin32'
            }
        except Exception as e:
            # If we can't access services, return what we have with error
            import traceback
            error_detail = traceback.format_exc()
            traceback.print_exc(file=sys.stderr)
            return {
                'timestamp': datetime.now().isoformat(),
                'services': services,
                'total_count': len(services),
                'error': f'Error accessing Windows services: {str(e)}\nDetails: {error_detail}'
            }
        finally:
            if service_manager:
                try:
                    # Try to import win32service in case it wasn't imported earlier
                    try:
                        import win32service
                        win32service.CloseServiceHandle(service_manager)
                    except (ImportError, NameError):
                        pass
                except:
                    pass
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'services': services,
            'total_count': len(services)
        }
        return result
    
    def _get_start_type(self, start_type):
        """Convert Windows service start type to readable string."""
        start_types = {
            0: 'Boot',
            1: 'System',
            2: 'Auto',
            3: 'Manual',
            4: 'Disabled'
        }
        return start_types.get(start_type, 'Unknown')

