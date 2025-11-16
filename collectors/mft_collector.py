"""
MFT (Master File Table) collector for triage analysis.
Collects file metadata from NTFS MFT entries including timestamps and ownership.
"""

import os
from datetime import datetime, timedelta
from collectors.base_collector import BaseCollector

try:
    import win32file
    import win32security
    import win32api
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


class MFTCollector(BaseCollector):
    """Collects MFT metadata for files accessed in the last 7 days."""
    
    def __init__(self):
        """Initialize MFT collector."""
        super().__init__()
    
    def collect(self):
        """Collect MFT metadata for files accessed in the last 7 days."""
        if not WIN32_AVAILABLE:
            return {
                'timestamp': datetime.now().isoformat(),
                'error': 'win32file/win32security modules not available. Please install pywin32.',
                'mft_entries': [],
                'users': []
            }
        
        # Calculate cutoff date (7 days ago)
        cutoff_date = datetime.now() - timedelta(days=7)
        
        mft_entries = []
        users = set()
        
        try:
            # Get all NTFS drives
            drives = self._get_ntfs_drives()
            
            # Scan interesting directories (same as file collector)
            user_profile = os.path.expandvars('%USERPROFILE%')
            interesting_dirs = [
                # User activity directories
                os.path.join(user_profile, 'Downloads'),
                os.path.join(user_profile, 'Desktop'),
                os.path.join(user_profile, 'Documents'),
                os.path.join(user_profile, 'Pictures'),
                os.path.join(user_profile, 'Videos'),
                
                # Recent files
                os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent'),
                
                # Temp directories
                os.path.expandvars('%TEMP%'),
                os.path.expandvars('%TMP%'),
                os.path.join(user_profile, 'AppData', 'Local', 'Temp'),
                os.path.join(os.path.expandvars('%SystemRoot%'), 'Temp'),
                
                # AppData directories
                os.path.join(user_profile, 'AppData', 'Roaming'),
                os.path.join(user_profile, 'AppData', 'Local'),
                
                # Startup locations
                os.path.join(os.path.expandvars('%ProgramData%'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            ]
            
            # Collect MFT metadata from interesting directories
            scanned_dirs = 0
            for directory in interesting_dirs:
                if os.path.exists(directory):
                    try:
                        self._scan_directory_mft(directory, cutoff_date, mft_entries, users)
                        scanned_dirs += 1
                    except (OSError, PermissionError) as e:
                        # Skip directories we can't access
                        continue
                    except Exception as e:
                        # Other errors - continue with other directories
                        import sys
                        print(f"Error scanning {directory}: {e}", file=sys.stderr)
                        continue
            
            # If no directories were scanned and no entries found, add a helpful message
            if scanned_dirs == 0 and len(mft_entries) == 0:
                return {
                    'timestamp': datetime.now().isoformat(),
                    'error': 'No accessible directories found to scan. Ensure the application has proper permissions.',
                    'mft_entries': [],
                    'users': []
                }
            
        except Exception as e:
            import traceback
            error_str = str(e)
            
            # Check if this is a privilege error
            if '1314' in error_str or 'privilege' in error_str.lower() or 'A required privilege is not held' in error_str:
                error_message = (
                    "Insufficient privileges to read MFT metadata.\n\n"
                    "To collect MFT data, this application must be run as Administrator.\n"
                    "Please right-click the application and select 'Run as administrator'."
                )
            else:
                error_message = f"Error collecting MFT data: {error_str}"
            
            return {
                'timestamp': datetime.now().isoformat(),
                'error': error_message,
                'mft_entries': [],
                'users': []
            }
        
        # Sort by access time (newest first)
        try:
            mft_entries.sort(key=lambda x: x.get('last_access_time', ''), reverse=True)
        except Exception:
            pass
        
        # Convert users set to sorted list
        try:
            users_list = sorted(list(users))
        except Exception:
            users_list = []
        
        return {
            'timestamp': datetime.now().isoformat(),
            'mft_entries': mft_entries,
            'users': users_list,
            'total_entries': len(mft_entries)
        }
    
    def _get_ntfs_drives(self):
        """Get list of NTFS drives."""
        drives = []
        for drive in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            drive_path = f"{drive}:\\"
            if os.path.exists(drive_path):
                try:
                    # Check if NTFS
                    volume_info = win32api.GetVolumeInformation(drive_path)
                    if volume_info[4] == 'NTFS':  # File system name
                        drives.append(drive_path)
                except Exception:
                    continue
        return drives
    
    def _scan_directory_mft(self, directory, cutoff_date, mft_entries, users, max_depth=3, current_depth=0):
        """Scan directory and collect MFT metadata for files."""
        if current_depth > max_depth:
            return
        
        try:
            if not os.path.exists(directory):
                return
            
            for root, dirs, filenames in os.walk(directory):
                if current_depth > max_depth:
                    dirs[:] = []  # Don't recurse deeper
                    continue
                
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    try:
                        mft_data = self._get_mft_metadata(file_path, cutoff_date)
                        if mft_data:
                            mft_entries.append(mft_data)
                            if mft_data.get('owner'):
                                users.add(mft_data['owner'])
                    except (OSError, PermissionError):
                        # Skip files we can't access
                        continue
                    except Exception as e:
                        # Skip files that cause other errors
                        continue
                
                # Limit depth
                if current_depth >= max_depth:
                    dirs[:] = []
                    continue
                
                current_depth += 1
        except (OSError, PermissionError) as e:
            # Directory access denied or doesn't exist
            pass
        except Exception as e:
            # Other errors - log but continue
            import sys
            print(f"MFT collector error scanning {directory}: {e}", file=sys.stderr)
    
    def _get_mft_metadata(self, file_path, cutoff_date):
        """Get MFT metadata for a file."""
        try:
            # Get file handle
            handle = win32file.CreateFile(
                file_path,
                0,  # No access needed for metadata
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            
            try:
                # Get file information by handle
                file_info = win32file.GetFileInformationByHandle(handle)
                
                # Get file times
                file_times = win32file.GetFileTime(handle)
                
                # Get file attributes
                file_attrs = win32file.GetFileAttributes(file_path)
                
                # Get file size
                # file_info structure: (handle, volume_serial, file_index_high, file_index_low, nFileSizeHigh, nFileSizeLow, ...)
                try:
                    nFileSizeHigh = file_info[4]
                    nFileSizeLow = file_info[5]
                    file_size = (nFileSizeHigh << 32) | nFileSizeLow
                except (IndexError, TypeError):
                    try:
                        file_size = os.path.getsize(file_path)
                    except:
                        file_size = 0
                
                # Get file owner
                owner = None
                try:
                    sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
                    owner_sid = sd.GetSecurityDescriptorOwner()
                    owner, domain, type = win32security.LookupAccountSid(None, owner_sid)
                    if domain:
                        owner = f"{domain}\\{owner}"
                except Exception:
                    pass
                
                # Convert Windows file times to Python datetime
                # Windows file times are 100-nanosecond intervals since January 1, 1601
                def filetime_to_datetime(filetime):
                    if filetime is None:
                        return None
                    # Convert to seconds since epoch
                    epoch = datetime(1601, 1, 1)
                    seconds = filetime / 10000000.0
                    return epoch + timedelta(seconds=seconds)
                
                creation_time = filetime_to_datetime(file_times[0])
                last_access_time = filetime_to_datetime(file_times[1])
                last_write_time = filetime_to_datetime(file_times[2])
                
                # Filter by last access time (must be within last 7 days)
                if last_access_time and last_access_time < cutoff_date:
                    return None
                
                # Get MFT record number (from file index)
                mft_record_number = file_info[0]  # dwFileIndexHigh and dwFileIndexLow
                if mft_record_number:
                    # Combine high and low parts
                    mft_record = (mft_record_number[0] << 32) | mft_record_number[1]
                else:
                    mft_record = None
                
                mft_data = {
                    'file_path': file_path,
                    'file_name': os.path.basename(file_path),
                    'mft_record_number': mft_record,
                    'creation_time': creation_time.isoformat() if creation_time else None,
                    'last_access_time': last_access_time.isoformat() if last_access_time else None,
                    'last_write_time': last_write_time.isoformat() if last_write_time else None,
                    'file_size': file_size,
                    'file_attributes': file_attrs,
                    'owner': owner,
                    'domain': None,  # Extracted from owner if available
                }
                
                # Extract domain from owner if it's in DOMAIN\USER format
                if owner and '\\' in owner:
                    parts = owner.split('\\', 1)
                    mft_data['domain'] = parts[0]
                    mft_data['owner'] = parts[1] if len(parts) > 1 else owner
                
                return mft_data
                
            finally:
                win32file.CloseHandle(handle)
        
        except Exception:
            return None

