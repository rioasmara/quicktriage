"""
Binary collector for triage analysis.
Discovers binary files from user directories.
"""

from datetime import datetime
from collectors.base_collector import BaseCollector
import os
import hashlib
import sys

# Try to import pefile for DLL export extraction
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class BinaryCollector(BaseCollector):
    """Discovers binary files from user directories."""
    
    def __init__(self, incremental_callback=None):
        """
        Initialize binary collector.
        
        Args:
            incremental_callback: Optional callback function(binary_info) called for each binary as it's discovered
        """
        super().__init__()
        self.incremental_callback = incremental_callback
    
    def collect(self):
        """Discover binary files from user directories."""
        # Discover binaries from all users' directories
        try:
            binaries = self._discover_binaries_from_users()
        except Exception as e:
            binaries = []
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'binaries': binaries,
            'binary_count': len(binaries)
        }
        
        return result
    
    def _discover_binaries_from_users(self):
        """Discover binary files from all users' directories recursively."""
        binaries = []
        
        # Binary file extensions to search for
        binary_extensions = {'.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.msi', '.sys', '.drv', '.ocx', '.cpl'}
        
        # Get the Users directory path
        # Try to get it from environment variable first
        users_dir = os.environ.get('USERPROFILE', '')
        if users_dir:
            # Get parent directory (Users folder)
            users_dir = os.path.dirname(users_dir)
        
        # If that didn't work, try common paths
        if not users_dir or not os.path.exists(users_dir):
            # Try common Windows paths
            system_drive = os.environ.get('SystemDrive', 'C:')
            users_dir = os.path.normpath(f"{system_drive}\\Users")
        
        # Verify the path exists
        if not os.path.exists(users_dir):
            # Try alternative path
            users_dir = os.path.normpath("C:\\Users")
            if not os.path.exists(users_dir):
                return binaries
        
        # Iterate through all user directories
        try:
            user_folders = os.listdir(users_dir)
            
            for user_folder in user_folders:
                user_path = os.path.join(users_dir, user_folder)
                
                # Skip if not a directory
                if not os.path.isdir(user_path):
                    continue
                
                # Recursively search for binaries in this user's directory
                try:
                    depth = 0
                    
                    # Error handler for os.walk to continue traversal even if some directories can't be accessed
                    def walk_error_handler(error_instance):
                        """Handle errors during directory traversal to continue searching."""
                        # Continue traversal by not raising the exception
                        pass
                    
                    files_checked = 0
                    binaries_found_in_user = 0
                    for root, dirs, filenames in os.walk(user_path, onerror=walk_error_handler):
                        depth += 1
                        
                        # Filter out directories we want to skip to avoid permission issues
                        # Only skip hidden directories (starting with .) on Windows
                        dirs_to_skip = []
                        for d in dirs:
                            # Only skip hidden directories (starting with .) to avoid permission issues
                            if d.startswith('.'):
                                dirs_to_skip.append(d)
                        
                        # Remove skipped directories from dirs list
                        dirs[:] = [d for d in dirs if d not in dirs_to_skip]
                        
                        for filename in filenames:
                            files_checked += 1
                            file_path = os.path.join(root, filename)
                            
                            # Check if file has a binary extension
                            _, ext = os.path.splitext(filename)
                            if ext.lower() in binary_extensions:
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
                                    
                                    # Extract DLL exports if this is a DLL file
                                    exports = []
                                    if ext.lower() == '.dll':
                                        exports = self._extract_dll_exports(file_path)
                                    
                                    binary_data = {
                                        'path': file_path,
                                        'name': filename,
                                        'extension': ext.lower(),
                                        'size': stat_info.st_size,
                                        'size_mb': round(stat_info.st_size / (1024 * 1024), 2),
                                        'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                                        'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                                        'user_directory': user_folder,
                                        'sha256': sha256_hash or 'N/A',
                                        'exports': exports,
                                        'export_count': len(exports)
                                    }
                                    binaries.append(binary_data)
                                    binaries_found_in_user += 1
                                    
                                    # Call incremental callback if provided for real-time updates
                                    if self.incremental_callback:
                                        try:
                                            self.incremental_callback(binary_data)
                                        except Exception:
                                            # Don't fail collection if callback fails
                                            pass
                                except (OSError, PermissionError) as e:
                                    # Skip files we can't access
                                    continue
                    
                except (OSError, PermissionError) as e:
                    # Skip user directories we can't access
                    continue
                except Exception as e:
                    # Catch any other exceptions to prevent the whole search from failing
                    continue
        except (OSError, PermissionError) as e:
            # Can't access Users directory
            pass
        except Exception as e:
            # Catch any other exceptions
            pass
        
        return binaries
    
    def _extract_dll_exports(self, dll_path):
        """
        Extract export functions from a DLL file.
        
        Args:
            dll_path: Path to the DLL file
            
        Returns:
            list: List of exported function names, or empty list if extraction fails
        """
        exports = []
        
        if not PEFILE_AVAILABLE:
            return exports
        
        try:
            # Use fast_load=False to ensure export directory is parsed
            pe = pefile.PE(dll_path, fast_load=False)
            
            # Parse export directory explicitly
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
            
            # Check if PE has export directory
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        try:
                            export_name = exp.name.decode('utf-8', errors='ignore')
                            exports.append(export_name)
                        except (UnicodeDecodeError, AttributeError):
                            # Skip if name can't be decoded
                            continue
            
            pe.close()
        except (pefile.PEFormatError, OSError, PermissionError, IOError, Exception):
            # Silently handle any errors during export extraction
            pass
        
        return exports

