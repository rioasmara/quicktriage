"""
Network collector for triage analysis.
"""

import psutil
from datetime import datetime
from collectors.base_collector import BaseCollector


class NetworkCollector(BaseCollector):
    """Collects network connection information from the system."""
    
    def collect(self):
        """Collect network connection information."""
        connections = []
        
        # Get all network connections
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A'
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A'
                    status = conn.status if conn.status else 'N/A'
                    
                    # Get process info if available
                    pid = conn.pid if conn.pid else 'N/A'
                    process_name = 'N/A'
                    if pid != 'N/A':
                        try:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    conn_data = {
                        'pid': pid,
                        'process_name': process_name,
                        'local_address': local_addr,
                        'remote_address': remote_addr,
                        'status': status,
                        'family': 'IPv4' if conn.family == 2 else 'IPv6'
                    }
                    connections.append(conn_data)
                except Exception:
                    pass
        except (psutil.AccessDenied, AttributeError):
            pass
        
        # Get network statistics
        net_stats = psutil.net_io_counters()
        network_stats = {
            'bytes_sent': net_stats.bytes_sent,
            'bytes_recv': net_stats.bytes_recv,
            'packets_sent': net_stats.packets_sent,
            'packets_recv': net_stats.packets_recv,
            'errin': net_stats.errin,
            'errout': net_stats.errout,
            'dropin': net_stats.dropin,
            'dropout': net_stats.dropout
        }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'connections': connections,
            'statistics': network_stats,
            'total_connections': len(connections)
        }













