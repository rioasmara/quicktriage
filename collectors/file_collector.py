"""
File collector for triage analysis.
Windows-specific file system scanning.
"""

import os
import string
import shutil
import hashlib
from datetime import datetime
from collectors.base_collector import BaseCollector


class FileCollector(BaseCollector):
    """Collects Windows file system information for triage analysis."""
    
    def __init__(self, max_files=1000):
        """Initialize file collector.
        
        Args:
            max_files: Maximum number of files to collect (for performance)
        """
        super().__init__()
        self.max_files = max_files
    
    def collect(self):
        """Collect Windows file system information."""
        files = []
        
        # Windows-specific interesting directories to scan
        interesting_dirs = [
            os.path.expandvars('%TEMP%'),
            os.path.expandvars('%APPDATA%'),
            os.path.expandvars('%LOCALAPPDATA%'),
            os.path.join(os.path.expandvars('%SystemRoot%'), 'System32'),
            os.path.join(os.path.expandvars('%SystemRoot%'), 'Temp'),
            os.path.join(os.path.expandvars('%ProgramData%'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(os.path.expandvars('%USERPROFILE%'), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(os.path.expandvars('%SystemRoot%'), 'Tasks'),
            os.path.expandvars('%PUBLIC%'),
        ]
        
        # Collect files from interesting directories
        file_count = 0
        for directory in interesting_dirs:
            if file_count >= self.max_files:
                break
            
            if os.path.exists(directory):
                try:
                    for root, dirs, filenames in os.walk(directory):
                        if file_count >= self.max_files:
                            break
                        
                        for filename in filenames:
                            if file_count >= self.max_files:
                                break
                            
                            file_path = os.path.join(root, filename)
                            try:
                                stat_info = os.stat(file_path)
                                
                                # Calculate SHA256 hash
                                sha256_hash = None
                                try:
                                    with open(file_path, 'rb') as f:
                                        file_hash = hashlib.sha256()
                                        # Read file in chunks to handle large files
                                        while chunk := f.read(8192):
                                            file_hash.update(chunk)
                                        sha256_hash = file_hash.hexdigest()
                                except (OSError, PermissionError, IOError):
                                    # If we can't read the file, set hash to None
                                    sha256_hash = None
                                
                                file_data = {
                                    'path': file_path,
                                    'name': filename,
                                    'size': stat_info.st_size,
                                    'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                                    'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                                    'extension': os.path.splitext(filename)[1].lower(),
                                    'sha256': sha256_hash or 'N/A'
                                }
                                files.append(file_data)
                                file_count += 1
                            except (OSError, PermissionError):
                                pass
                except (OSError, PermissionError):
                    pass
        
        # Get disk usage for all Windows drives
        disk_usage = {}
        for drive in string.ascii_uppercase:
            drive_path = f"{drive}:\\"
            if os.path.exists(drive_path):
                try:
                    total, used, free = shutil.disk_usage(drive_path)
                    disk_usage[drive_path] = {
                        'total': total,
                        'used': used,
                        'free': free,
                        'percent_used': round((used / total) * 100, 2) if total > 0 else 0
                    }
                except (OSError, PermissionError):
                    pass
        
        return {
            'timestamp': datetime.now().isoformat(),
            'files': files[:self.max_files],
            'disk_usage': disk_usage,
            'total_files': len(files)
        }

