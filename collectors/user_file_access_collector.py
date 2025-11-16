"""
User file access collector for triage analysis.
Windows-specific Security Event Log collection for file access events by user.
"""

from datetime import datetime, timedelta
from collectors.base_collector import BaseCollector

try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


class UserFileAccessCollector(BaseCollector):
    """Collects Windows Security Event Log file access events."""
    
    # Security event ID for file access
    FILE_ACCESS_EVENT_ID = 4656  # A handle to an object was requested
    
    def __init__(self):
        """Initialize user file access collector."""
        super().__init__()
    
    def collect(self):
        """Collect Windows Security Event Log file access events from the last 7 days."""
        if not WIN32_AVAILABLE:
            return {
                'timestamp': datetime.now().isoformat(),
                'error': 'win32evtlog module not available. Please install pywin32.',
                'file_accesses': [],
                'users': []
            }
        
        # Calculate cutoff date (7 days ago)
        cutoff_date = datetime.now() - timedelta(days=7)
        
        file_accesses = []
        users = set()
        
        try:
            # Open Security event log
            hand = win32evtlog.OpenEventLog(None, "Security")
            
            try:
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                # Read events, filtering to last 7 days
                event_count = 0
                file_access_count = 0
                while True:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    if not events:
                        break
                    
                    event_count += len(events)
                    events_older_than_cutoff = False
                    
                    for event in events:
                        # Check event time - if older than 7 days, skip it
                        try:
                            event_time = event.TimeGenerated
                            if event_time < cutoff_date:
                                # Since we're reading backwards (newest first),
                                # if we encounter an event older than cutoff,
                                # all subsequent events will also be older
                                events_older_than_cutoff = True
                                break
                        except Exception:
                            # If we can't get event time, skip this event
                            continue
                        
                        event_id = event.EventID
                        
                        # Filter for file access events
                        if event_id == self.FILE_ACCESS_EVENT_ID:
                            file_access_count += 1
                            try:
                                # Parse event data
                                access_data = self._parse_file_access_event(event)
                                if access_data:
                                    file_accesses.append(access_data)
                                    
                                    # Track unique users
                                    if access_data.get('username'):
                                        users.add(access_data['username'])
                            except Exception as e:
                                # Skip events that can't be parsed
                                continue
                    
                    # If we encountered events older than cutoff, stop reading
                    if events_older_than_cutoff:
                        break
                
            finally:
                win32evtlog.CloseEventLog(hand)
        
        except Exception as e:
            import traceback
            error_str = str(e)
            error_code = None
            
            # Check if this is a privilege error
            if '1314' in error_str or 'privilege' in error_str.lower() or 'A required privilege is not held' in error_str:
                error_message = (
                    "Insufficient privileges to read Security event log.\n\n"
                    "To collect file access events, this application must be run as Administrator.\n"
                    "Also, Object Access auditing must be enabled in Windows Group Policy.\n"
                    "Please right-click the application and select 'Run as administrator'."
                )
            else:
                error_message = f"Error reading Security event log: {error_str}"
            
            return {
                'timestamp': datetime.now().isoformat(),
                'error': error_message,
                'error_code': error_code,
                'file_accesses': [],
                'users': []
            }
        
        # Sort file accesses by time (newest first)
        try:
            file_accesses.sort(key=lambda x: x.get('time', '') or '', reverse=True)
        except Exception:
            # If sorting fails, just return unsorted
            pass
        
        # Convert users set to sorted list
        try:
            users_list = sorted(list(users))
        except Exception:
            users_list = []
        
        # Ensure we always return a valid structure
        result = {
            'timestamp': datetime.now().isoformat(),
            'file_accesses': file_accesses if file_accesses else [],
            'users': users_list if users_list else [],
            'total_events': len(file_accesses)
        }
        
        return result
    
    def _parse_file_access_event(self, event):
        """Parse a file access event from Windows Event Log."""
        try:
            # Get event time
            event_time = event.TimeGenerated
            time_str = event_time.strftime('%Y-%m-%d %H:%M:%S')
            time_iso = event_time.isoformat()
            
            # Get event message strings (these contain the file and user info)
            strings = event.StringInserts if event.StringInserts else []
            
            access_data = {
                'event_id': self.FILE_ACCESS_EVENT_ID,
                'time': time_iso,
                'time_display': time_str,
                'username': None,
                'domain': None,
                'object_name': None,  # File path
                'object_type': None,
                'access_mask': None,
                'access_list': None,  # Human-readable access rights
                'process_name': None,
                'process_id': None
            }
            
            # Event ID 4656 string format:
            # [0] SubjectUserSid
            # [1] SubjectUserName (username)
            # [2] SubjectDomainName
            # [3] SubjectLogonId
            # [4] ObjectServer
            # [5] ObjectType
            # [6] ObjectName (file path)
            # [7] HandleId
            # [8] ProcessId
            # [9] ProcessName
            # [10] AccessList (comma-separated access rights)
            # [11] AccessMask
            
            if len(strings) >= 12:
                access_data['username'] = strings[1] if strings[1] else None
                access_data['domain'] = strings[2] if strings[2] else None
                access_data['object_name'] = strings[6] if len(strings) > 6 and strings[6] else None
                access_data['object_type'] = strings[5] if len(strings) > 5 and strings[5] else None
                access_data['process_id'] = strings[8] if len(strings) > 8 and strings[8] else None
                access_data['process_name'] = strings[9] if len(strings) > 9 and strings[9] else None
                access_data['access_list'] = strings[10] if len(strings) > 10 and strings[10] else None
                access_data['access_mask'] = strings[11] if len(strings) > 11 and strings[11] else None
            
            # Only return if we got a username and file path
            if access_data['username'] and access_data['object_name']:
                return access_data
            else:
                return None
        
        except Exception:
            return None



