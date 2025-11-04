"""
System collector for triage analysis.
"""

import platform
import psutil
import socket
import subprocess
from datetime import datetime
from collectors.base_collector import BaseCollector


class SystemCollector(BaseCollector):
    """Collects general system information."""
    
    def _get_disk_device_id(self):
        """Get disk device ID using WMI."""
        try:
            # Try using WMI via win32com
            import win32com.client
            wmi = win32com.client.GetObject("winmgmts:")
            disk_drives = wmi.InstancesOf("Win32_DiskDrive")
            device_ids = []
            for drive in disk_drives:
                device_id = drive.Properties_("SerialNumber").Value
                if device_id and device_id.strip():
                    device_ids.append(device_id.strip())
            if device_ids:
                return ", ".join(device_ids)
        except ImportError:
            # Fallback to wmic command
            try:
                result = subprocess.run(
                    ['wmic', 'diskdrive', 'get', 'serialnumber'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    lines = [line.strip() for line in result.stdout.strip().split('\n') if line.strip() and 'SerialNumber' not in line]
                    if lines:
                        return ", ".join(lines)
            except:
                pass
        except:
            pass
        return 'N/A'
    
    def _get_computer_hardware_id(self):
        """Get computer hardware ID using WMI."""
        try:
            # Try using WMI via win32com
            import win32com.client
            wmi = win32com.client.GetObject("winmgmts:")
            
            # Try to get motherboard serial number first
            baseboards = wmi.InstancesOf("Win32_BaseBoard")
            for board in baseboards:
                serial = board.Properties_("SerialNumber").Value
                if serial and serial.strip() and serial.strip() != "To be filled by O.E.M.":
                    return serial.strip()
            
            # Fallback to computer system product UUID
            products = wmi.InstancesOf("Win32_ComputerSystemProduct")
            for product in products:
                uuid = product.Properties_("UUID").Value
                if uuid and uuid.strip():
                    return uuid.strip()
        except ImportError:
            # Fallback to wmic command
            try:
                # Try motherboard serial number
                result = subprocess.run(
                    ['wmic', 'baseboard', 'get', 'serialnumber'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    lines = [line.strip() for line in result.stdout.strip().split('\n') if line.strip() and 'SerialNumber' not in line]
                    if lines and lines[0] and lines[0] != "To be filled by O.E.M.":
                        return lines[0]
                
                # Fallback to UUID
                result = subprocess.run(
                    ['wmic', 'csproduct', 'get', 'uuid'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    lines = [line.strip() for line in result.stdout.strip().split('\n') if line.strip() and 'UUID' not in line]
                    if lines:
                        return lines[0]
            except:
                pass
        except:
            pass
        return 'N/A'
    
    def collect(self):
        """Collect system information."""
        # Basic system info
        system_info = {
            'hostname': socket.gethostname(),
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'architecture': platform.architecture()[0],
            'python_version': platform.python_version(),
            'disk_device_id': self._get_disk_device_id(),
            'computer_hardware_id': self._get_computer_hardware_id()
        }
        
        # CPU information
        cpu_info = {
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'cpu_per_core': psutil.cpu_percent(interval=1, percpu=True),
            'cpu_freq': {
                'current': psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A',
                'min': psutil.cpu_freq().min if psutil.cpu_freq() else 'N/A',
                'max': psutil.cpu_freq().max if psutil.cpu_freq() else 'N/A'
            }
        }
        
        # Memory information
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        memory_info = {
            'total_mb': round(mem.total / (1024 * 1024), 2),
            'available_mb': round(mem.available / (1024 * 1024), 2),
            'used_mb': round(mem.used / (1024 * 1024), 2),
            'percent': mem.percent,
            'swap_total_mb': round(swap.total / (1024 * 1024), 2),
            'swap_used_mb': round(swap.used / (1024 * 1024), 2),
            'swap_percent': swap.percent
        }
        
        # Disk information
        disk_info = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total_gb': round(usage.total / (1024 * 1024 * 1024), 2),
                    'used_gb': round(usage.used / (1024 * 1024 * 1024), 2),
                    'free_gb': round(usage.free / (1024 * 1024 * 1024), 2),
                    'percent': usage.percent
                })
            except PermissionError:
                pass
        
        # Boot time
        boot_time = datetime.fromtimestamp(psutil.boot_time()).isoformat()
        
        # Users
        users = []
        try:
            for user in psutil.users():
                users.append({
                    'name': user.name,
                    'terminal': user.terminal or 'N/A',
                    'host': user.host or 'N/A',
                    'started': datetime.fromtimestamp(user.started).isoformat() if user.started else 'N/A'
                })
        except:
            pass
        
        return {
            'timestamp': datetime.now().isoformat(),
            'system': system_info,
            'cpu': cpu_info,
            'memory': memory_info,
            'disk': disk_info,
            'boot_time': boot_time,
            'users': users
        }


