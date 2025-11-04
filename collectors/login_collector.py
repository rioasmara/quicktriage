"""
Login event collector for triage analysis.
Windows-specific Security Event Log collection for user login events.
"""

from datetime import datetime
from collectors.base_collector import BaseCollector

try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


class LoginCollector(BaseCollector):
    """Collects Windows Security Event Log login events."""
    
    # Security event IDs for login events
    LOGIN_EVENT_IDS = {
        4624: "Successful logon",
        4625: "Failed logon",
        4648: "A logon was attempted using explicit credentials",
        4672: "Special privileges assigned to new logon",
        4647: "User initiated logoff",
        4634: "An account was logged off"
    }
    
    def __init__(self):
        """Initialize login collector."""
        super().__init__()
    
    def collect(self):
        """Collect Windows Security Event Log login events."""
        import sys
        print(f"[LoginCollector] Starting collection...", file=sys.stderr)
        
        if not WIN32_AVAILABLE:
            print(f"[LoginCollector] ERROR: win32evtlog not available", file=sys.stderr)
            return {
                'timestamp': datetime.now().isoformat(),
                'error': 'win32evtlog module not available. Please install pywin32.',
                'logins': [],
                'users': []
            }
        
        logins = []
        users = set()
        
        try:
            print(f"[LoginCollector] Opening Security event log...", file=sys.stderr)
            # Open Security event log
            hand = win32evtlog.OpenEventLog(None, "Security")
            
            try:
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                # Read all events without limit
                event_count = 0
                login_event_count = 0
                while True:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    if not events:
                        break
                    
                    event_count += len(events)
                    for event in events:
                        event_id = event.EventID
                        
                        # Filter for login-related events
                        if event_id in self.LOGIN_EVENT_IDS:
                            login_event_count += 1
                            try:
                                # Parse event data
                                login_data = self._parse_login_event(event, event_id)
                                if login_data:
                                    logins.append(login_data)
                                    
                                    # Track unique users
                                    if login_data.get('username'):
                                        users.add(login_data['username'])
                            except Exception as e:
                                # Skip events that can't be parsed
                                import sys
                                print(f"[LoginCollector] Error parsing login event: {e}", file=sys.stderr)
                                continue
                
                print(f"[LoginCollector] Processed {event_count} total events, found {login_event_count} login events, collected {len(logins)} valid logins", file=sys.stderr)
                
            finally:
                win32evtlog.CloseEventLog(hand)
        
        except Exception as e:
            import sys
            import traceback
            error_str = str(e)
            error_code = None
            
            # Check if this is a privilege error
            if '1314' in error_str or 'privilege' in error_str.lower() or 'A required privilege is not held' in error_str:
                error_message = (
                    "Insufficient privileges to read Security event log.\n\n"
                    "To collect login events, this application must be run as Administrator.\n"
                    "Please right-click the application and select 'Run as administrator'."
                )
                print(f"[LoginCollector] PRIVILEGE ERROR: {error_str}", file=sys.stderr)
            else:
                error_message = f"Error reading Security event log: {error_str}"
                print(f"[LoginCollector] EXCEPTION during collection: {e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
            
            return {
                'timestamp': datetime.now().isoformat(),
                'error': error_message,
                'error_code': error_code,
                'logins': [],
                'users': []
            }
        
        # Sort logins by time (newest first) - handle missing time fields
        try:
            logins.sort(key=lambda x: x.get('time', '') or '', reverse=True)
        except Exception as e:
            # If sorting fails, just return unsorted
            import sys
            print(f"[LoginCollector] Warning: Sorting failed: {e}", file=sys.stderr)
            pass
        
        # Convert users set to sorted list
        try:
            users_list = sorted(list(users))
        except Exception as e:
            import sys
            print(f"[LoginCollector] Warning: User list conversion failed: {e}", file=sys.stderr)
            users_list = []
        
        # Ensure we always return a valid structure
        result = {
            'timestamp': datetime.now().isoformat(),
            'logins': logins if logins else [],
            'users': users_list if users_list else [],
            'total_events': len(logins)
        }
        
        import sys
        print(f"[LoginCollector] Collection complete: returning {len(result['logins'])} logins, {len(result['users'])} users", file=sys.stderr)
        return result
    
    def _parse_login_event(self, event, event_id):
        """Parse a login event from Windows Event Log."""
        try:
            import sys
            # Get event time
            event_time = event.TimeGenerated
            time_str = event_time.strftime('%Y-%m-%d %H:%M:%S')
            time_iso = event_time.isoformat()
            
            # Get event message strings (these contain the user info)
            strings = event.StringInserts if event.StringInserts else []
            print(f"[LoginCollector] Parsing event {event_id}: {len(strings)} string inserts", file=sys.stderr)
            
            login_data = {
                'event_id': event_id,
                'event_type': self.LOGIN_EVENT_IDS.get(event_id, 'Unknown'),
                'time': time_iso,
                'time_display': time_str,
                'username': None,
                'domain': None,
                'logon_type': None,
                'source_ip': None,
                'workstation': None,
                'status': 'Success' if event_id == 4624 else 'Failed'
            }
            
            # Parse event strings based on event ID
            # Windows Event Log structure varies by event ID
            if event_id == 4624:  # Successful logon
                # String format for 4624:
                # [0] SubjectUserSid
                # [1] SubjectUserName
                # [2] SubjectDomainName
                # [3] SubjectLogonId
                # [4] TargetUserSid
                # [5] TargetUserName (username)
                # [6] TargetDomainName
                # [7] TargetLogonId
                # [8] LogonType
                # [9] LogonProcessName
                # [10] AuthenticationPackageName
                # [11] WorkstationName
                # [12] SourceNetworkAddress (IP)
                # [13] SourcePort
                if len(strings) >= 13:
                    login_data['username'] = strings[5] if strings[5] else None
                    login_data['domain'] = strings[6] if strings[6] else None
                    login_data['logon_type'] = strings[8] if len(strings) > 8 else None
                    login_data['workstation'] = strings[11] if len(strings) > 11 else None
                    login_data['source_ip'] = strings[12] if len(strings) > 12 else None
            
            elif event_id == 4625:  # Failed logon
                # String format for 4625:
                # [0] SubjectUserSid
                # [1] SubjectUserName
                # [2] SubjectDomainName
                # [3] SubjectLogonId
                # [4] TargetUserSid
                # [5] TargetUserName (username)
                # [6] TargetDomainName
                # [7] FailureReason
                # [8] Status
                # [9] SubStatus
                # [10] LogonProcessName
                # [11] AuthenticationPackageName
                # [12] WorkstationName
                # [13] SourceNetworkAddress (IP)
                # [14] SourcePort
                if len(strings) >= 14:
                    login_data['username'] = strings[5] if strings[5] else None
                    login_data['domain'] = strings[6] if strings[6] else None
                    login_data['workstation'] = strings[12] if len(strings) > 12 else None
                    login_data['source_ip'] = strings[13] if len(strings) > 13 else None
                    login_data['failure_reason'] = strings[7] if len(strings) > 7 else None
            
            elif event_id == 4648:  # Explicit credentials logon
                # String format for 4648:
                # [0] SubjectUserSid
                # [1] SubjectUserName
                # [2] SubjectDomainName
                # [3] SubjectLogonId
                # [4] LogonGuid
                # [5] TargetUserName (username)
                # [6] TargetDomainName
                # [7] TargetLogonId
                # [8] TargetServerName
                # [9] TargetInfo
                # [10] ProcessId
                # [11] ProcessName
                if len(strings) >= 12:
                    login_data['username'] = strings[5] if strings[5] else None
                    login_data['domain'] = strings[6] if strings[6] else None
            
            elif event_id == 4672:  # Special privileges logon
                # Similar structure to 4624
                if len(strings) >= 13:
                    login_data['username'] = strings[5] if strings[5] else None
                    login_data['domain'] = strings[6] if strings[6] else None
                    login_data['logon_type'] = strings[8] if len(strings) > 8 else None
            
            elif event_id in [4647, 4634]:  # Logoff events
                # String format for logoff:
                # [0] SubjectUserSid
                # [1] SubjectUserName (username)
                # [2] SubjectDomainName
                # [3] SubjectLogonId
                if len(strings) >= 4:
                    login_data['username'] = strings[1] if strings[1] else None
                    login_data['domain'] = strings[2] if strings[2] else None
            
            # Only return if we got a username
            if login_data['username']:
                import sys
                print(f"[LoginCollector] Successfully parsed login event: user={login_data['username']}, event={event_id}", file=sys.stderr)
                return login_data
            else:
                import sys
                print(f"[LoginCollector] Login event {event_id} parsed but no username found. Strings length: {len(strings) if 'strings' in locals() else 0}", file=sys.stderr)
                return None
        
        except Exception as e:
            import sys
            import traceback
            print(f"[LoginCollector] Exception parsing login event {event_id}: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return None

