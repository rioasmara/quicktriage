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
    
    def __init__(self, max_files=5000, incremental_callback=None):
        """Initialize file collector.
        
        Args:
            max_files: Maximum number of files to collect (default: 5000)
            incremental_callback: Optional callback function(file_info) called for each file as it's processed
        """
        super().__init__()
        self.max_files = max_files
        self.incremental_callback = incremental_callback
    
    def collect(self):
        """Collect Windows file system information."""
        files = []
        
        # Windows-specific interesting directories to scan
        # Focus on malware-prone locations and user activity paths
        user_profile = os.path.expandvars('%USERPROFILE%')
        interesting_dirs = [
            # User activity directories (high priority for malware)
            os.path.join(user_profile, 'Downloads'),
            os.path.join(user_profile, 'Desktop'),
            os.path.join(user_profile, 'Documents'),
            os.path.join(user_profile, 'Pictures'),
            os.path.join(user_profile, 'Videos'),
            
            # Recent files and activity
            os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent'),
            os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent', 'AutomaticDestinations'),
            os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent', 'CustomDestinations'),
            
            # Temp directories (common malware staging areas)
            os.path.expandvars('%TEMP%'),
            os.path.expandvars('%TMP%'),
            os.path.join(user_profile, 'AppData', 'Local', 'Temp'),
            os.path.join(os.path.expandvars('%SystemRoot%'), 'Temp'),
            
            # AppData directories (malware persistence locations)
            os.path.join(user_profile, 'AppData', 'Roaming'),
            os.path.join(user_profile, 'AppData', 'Local'),
            os.path.join(user_profile, 'AppData', 'LocalLow'),
            
            # Startup locations (persistence mechanisms)
            os.path.join(os.path.expandvars('%ProgramData%'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(user_profile, 'AppData', 'Local', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            
            # Scheduled tasks (persistence)
            os.path.join(os.path.expandvars('%SystemRoot%'), 'Tasks'),
            os.path.join(os.path.expandvars('%SystemRoot%'), 'System32', 'Tasks'),
            
            # Public directories (shared access)
            os.path.join(os.path.expandvars('%PUBLIC%'), 'Downloads'),
            os.path.join(os.path.expandvars('%PUBLIC%'), 'Desktop'),
            
            # Browser download locations (common malware entry points)
            os.path.join(user_profile, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Downloads'),
            os.path.join(user_profile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Downloads'),
            os.path.join(user_profile, 'AppData', 'Local', 'Mozilla', 'Firefox', 'Profiles'),
            
            # User profile root (sometimes used by malware)
            user_profile,
        ]
        
        # Collect files from interesting directories
        # Prioritize high-value directories first
        file_count = 0
        
        # Define directory priorities and max depth
        # High priority: shallow scan (depth 1-2)
        # Medium priority: moderate scan (depth 3-4)
        # Low priority: deeper scan (depth 5+)
        high_priority_dirs = [
            os.path.join(user_profile, 'Downloads'),
            os.path.join(user_profile, 'Desktop'),
            os.path.join(user_profile, 'Documents'),
            os.path.join(os.path.expandvars('%TEMP%')),
            os.path.join(os.path.expandvars('%TMP%')),
            os.path.join(user_profile, 'AppData', 'Local', 'Temp'),
            os.path.join(os.path.expandvars('%ProgramData%'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(user_profile, 'AppData', 'Local', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
        ]
        
        def should_scan_dir(root, current_dir, max_depth=5):
            """Determine if we should scan a directory based on depth."""
            # Check if this is a high priority directory (or subdirectory of one)
            root_normalized = os.path.normpath(root).lower()
            for high_priority in high_priority_dirs:
                high_priority_normalized = os.path.normpath(high_priority).lower()
                if root_normalized.startswith(high_priority_normalized):
                    return True  # Always scan high priority dirs and their subdirs
            
            # For other directories, limit depth
            relative_path = os.path.relpath(root, current_dir) if root != current_dir else ''
            depth = relative_path.count(os.sep) if relative_path else 0
            return depth <= max_depth
        
        for directory in interesting_dirs:
            if self.max_files is not None and file_count >= self.max_files:
                break
            
            if os.path.exists(directory):
                try:
                    for root, dirs, filenames in os.walk(directory):
                        if self.max_files is not None and file_count >= self.max_files:
                            break
                        
                        # Skip if directory is too deep (except for high priority)
                        if not should_scan_dir(root, directory):
                            # Remove subdirectories from walk to skip them
                            dirs[:] = []
                            continue
                        
                        for filename in filenames:
                            if self.max_files is not None and file_count >= self.max_files:
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
                                
                                # Call incremental callback if provided for real-time updates
                                if self.incremental_callback:
                                    try:
                                        self.incremental_callback(file_data)
                                    except Exception:
                                        # Don't fail collection if callback fails
                                        pass
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
            'files': files if self.max_files is None else files[:self.max_files],
            'disk_usage': disk_usage,
            'total_files': len(files)
        }

