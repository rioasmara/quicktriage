"""
Process collector for triage analysis.
"""

import psutil
from datetime import datetime
from collectors.base_collector import BaseCollector


class ProcessCollector(BaseCollector):
    """Collects process information from the system."""
    
    def collect(self):
        """Collect process information."""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 
                                        'memory_info', 'create_time', 'status', 
                                        'cmdline', 'exe', 'ppid', 'num_threads']):
            try:
                pinfo = proc.info
                
                # Convert create_time to readable format
                create_time = datetime.fromtimestamp(pinfo['create_time']).strftime('%Y-%m-%d %H:%M:%S')
                
                # Get memory info in MB
                memory_mb = pinfo['memory_info'].rss / (1024 * 1024) if pinfo['memory_info'] else 0
                
                # Get command line
                cmdline = ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else ''
                
                process_data = {
                    'pid': pinfo['pid'],
                    'name': pinfo['name'] or 'N/A',
                    'username': pinfo['username'] or 'N/A',
                    'cpu_percent': pinfo['cpu_percent'] or 0.0,
                    'memory_mb': round(memory_mb, 2),
                    'create_time': create_time,
                    'status': pinfo['status'] or 'N/A',
                    'cmdline': cmdline,
                    'exe': pinfo['exe'] or 'N/A',
                    'ppid': pinfo['ppid'],
                    'num_threads': pinfo['num_threads'] or 0
                }
                processes.append(process_data)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return {
            'timestamp': datetime.now().isoformat(),
            'processes': processes,
            'total_count': len(processes)
        }




