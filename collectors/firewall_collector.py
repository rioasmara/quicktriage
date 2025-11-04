"""
Firewall collector for triage analysis.
Collects Windows Firewall rules from all profiles (Domain, Private, Public).
"""

from datetime import datetime
from collectors.base_collector import BaseCollector
import subprocess


class FirewallCollector(BaseCollector):
    """Collects Windows Firewall rules information."""
    
    # Profile types
    PROFILE_DOMAIN = 0x01
    PROFILE_PRIVATE = 0x02
    PROFILE_PUBLIC = 0x04
    
    PROFILE_NAMES = {
        PROFILE_DOMAIN: "Domain",
        PROFILE_PRIVATE: "Private",
        PROFILE_PUBLIC: "Public"
    }
    
    # Direction types
    DIRECTION_IN = 1
    DIRECTION_OUT = 2
    
    # Action types
    ACTION_ALLOW = 1
    ACTION_BLOCK = 0
    
    def collect(self):
        """Collect Windows Firewall rules."""
        import sys
        rules = []
        
        try:
            # Try using Windows Firewall COM API first (more reliable)
            # However, COM API often has access issues, so we'll try netsh directly
            rules = self._collect_via_com_api()
            # If COM API returns very few rules (likely due to access issues), use netsh
            if len(rules) < 50:
                # COM API likely failed due to access issues, use netsh fallback
                rules = self._collect_via_netsh()
        except Exception as e:
            # If COM API fails, try netsh
            print(f"[FirewallCollector] COM API exception: {e}, trying netsh fallback...", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            try:
                rules = self._collect_via_netsh()
                print(f"[FirewallCollector] Netsh fallback returned {len(rules)} rules", file=sys.stderr)
            except Exception as e2:
                print(f"[FirewallCollector] Both methods failed: {e}, {e2}", file=sys.stderr)
                return {
                    'timestamp': datetime.now().isoformat(),
                    'rules': [],
                    'total_count': 0,
                    'error': f'Failed to collect firewall rules: {str(e)}. Fallback error: {str(e2)}'
                }
        
        print(f"[FirewallCollector] Returning {len(rules)} rules total", file=sys.stderr)
        return {
            'timestamp': datetime.now().isoformat(),
            'rules': rules,
            'total_count': len(rules)
        }
    
    def _collect_via_com_api(self):
        """Collect firewall rules using Windows Firewall COM API."""
        rules = []
        
        try:
            import win32com.client
            
            # Use FwPolicy2 for Windows Firewall with Advanced Security
            fw_policy = win32com.client.Dispatch("HNetCfg.FwPolicy2")
            
            # Profile type constants
            NET_FW_PROFILE2_DOMAIN = 0x01
            NET_FW_PROFILE2_PRIVATE = 0x02
            NET_FW_PROFILE2_PUBLIC = 0x04
            
            # Direction constants
            NET_FW_RULE_DIR_IN = 1
            NET_FW_RULE_DIR_OUT = 2
            
            # Action constants
            NET_FW_ACTION_ALLOW = 1
            NET_FW_ACTION_BLOCK = 0
            
            # Protocol constants
            NET_FW_IP_PROTOCOL_TCP = 6
            NET_FW_IP_PROTOCOL_UDP = 17
            NET_FW_IP_PROTOCOL_ICMP = 1
            NET_FW_IP_PROTOCOL_ICMPv6 = 58
            
            # Get rules collection
            rules_collection = fw_policy.Rules
            
            # Get count of rules
            rule_count = rules_collection.Count
            
            # Limit how many rules we try to process via COM API to avoid excessive errors
            # If we hit too many errors, we'll fall back to netsh
            max_rules_to_try = min(rule_count, 50)  # Try first 50 rules max
            error_count = 0
            max_errors = 10  # If we hit 10 errors, give up on COM API
            
            # Enumerate all rules
            for i in range(max_rules_to_try):
                try:
                    rule = rules_collection.Item(i)
                    
                    # Get rule properties - access COM object properties directly
                    # Use getattr with default values as COM objects may not expose all properties
                    name = None
                    description = None
                    enabled = False
                    direction_val = 0
                    action_val = 0
                    protocol_val = 0
                    local_ports = None
                    remote_ports = None
                    local_addresses = None
                    remote_addresses = None
                    application_name = None
                    service_name = None
                    profiles_val = 0
                    
                    # Try to get properties using multiple methods
                    try:
                        # Method 1: Direct attribute access
                        name = rule.Name
                    except (AttributeError, TypeError, ValueError):
                        try:
                            # Method 2: Using getattr
                            name = getattr(rule, 'Name', None)
                        except:
                            name = None
                    
                    try:
                        description = rule.Description
                    except (AttributeError, TypeError, ValueError):
                        description = getattr(rule, 'Description', None)
                    
                    try:
                        enabled = rule.Enabled
                    except (AttributeError, TypeError, ValueError):
                        enabled = getattr(rule, 'Enabled', False)
                    
                    try:
                        direction_val = rule.Direction
                    except (AttributeError, TypeError, ValueError):
                        direction_val = getattr(rule, 'Direction', 0)
                    
                    try:
                        action_val = rule.Action
                    except (AttributeError, TypeError, ValueError):
                        action_val = getattr(rule, 'Action', 0)
                    
                    try:
                        protocol_val = rule.Protocol
                    except (AttributeError, TypeError, ValueError):
                        protocol_val = getattr(rule, 'Protocol', 0)
                    
                    try:
                        local_ports = rule.LocalPorts
                    except (AttributeError, TypeError, ValueError):
                        local_ports = getattr(rule, 'LocalPorts', None)
                    
                    try:
                        remote_ports = rule.RemotePorts
                    except (AttributeError, TypeError, ValueError):
                        remote_ports = getattr(rule, 'RemotePorts', None)
                    
                    try:
                        local_addresses = rule.LocalAddresses
                    except (AttributeError, TypeError, ValueError):
                        local_addresses = getattr(rule, 'LocalAddresses', None)
                    
                    try:
                        remote_addresses = rule.RemoteAddresses
                    except (AttributeError, TypeError, ValueError):
                        remote_addresses = getattr(rule, 'RemoteAddresses', None)
                    
                    try:
                        application_name = rule.ApplicationName
                    except (AttributeError, TypeError, ValueError):
                        application_name = getattr(rule, 'ApplicationName', None)
                    
                    try:
                        service_name = rule.ServiceName
                    except (AttributeError, TypeError, ValueError):
                        service_name = getattr(rule, 'ServiceName', None)
                    
                    try:
                        profiles_val = rule.Profiles
                    except (AttributeError, TypeError, ValueError):
                        profiles_val = getattr(rule, 'Profiles', 0)
                    
                    # Determine which profiles this rule applies to
                    profiles_list = []
                    if profiles_val & NET_FW_PROFILE2_DOMAIN:
                        profiles_list.append("Domain")
                    if profiles_val & NET_FW_PROFILE2_PRIVATE:
                        profiles_list.append("Private")
                    if profiles_val & NET_FW_PROFILE2_PUBLIC:
                        profiles_list.append("Public")
                    
                    # If no profiles specified, add to all
                    if not profiles_list:
                        profiles_list = ["Domain", "Private", "Public"]
                    
                    # Convert protocol number to string
                    protocol_map = {
                        NET_FW_IP_PROTOCOL_TCP: 'TCP',
                        NET_FW_IP_PROTOCOL_UDP: 'UDP',
                        NET_FW_IP_PROTOCOL_ICMP: 'ICMP',
                        NET_FW_IP_PROTOCOL_ICMPv6: 'ICMPv6'
                    }
                    protocol_str = protocol_map.get(protocol_val, f'Protocol {protocol_val}')
                    
                    # Convert direction to string
                    direction_str = "Inbound" if direction_val == NET_FW_RULE_DIR_IN else "Outbound"
                    
                    # Convert action to string
                    action_str = "Allow" if action_val == NET_FW_ACTION_ALLOW else "Block"
                    
                    # Create a rule entry for each profile
                    for profile_name in profiles_list:
                        rule_data = {
                            'name': str(name) if name and str(name).strip() else 'N/A',
                            'description': str(description) if description and str(description).strip() else 'N/A',
                            'profile': profile_name,
                            'direction': direction_str,
                            'enabled': bool(enabled),
                            'action': action_str,
                            'protocol': protocol_str,
                            'local_ports': str(local_ports) if local_ports and str(local_ports).strip() else 'N/A',
                            'remote_ports': str(remote_ports) if remote_ports and str(remote_ports).strip() else 'N/A',
                            'local_addresses': str(local_addresses) if local_addresses and str(local_addresses).strip() else 'N/A',
                            'remote_addresses': str(remote_addresses) if remote_addresses and str(remote_addresses).strip() else 'N/A',
                            'application_name': str(application_name) if application_name and str(application_name).strip() else 'N/A',
                            'service_name': str(service_name) if service_name and str(service_name).strip() else 'N/A'
                        }
                        rules.append(rule_data)
                        
                except Exception as e:
                    # Track errors - if too many, give up on COM API
                    error_count += 1
                    if error_count >= max_errors:
                        # Too many errors, COM API is not working - return empty to trigger netsh
                        return []
                    # Continue with next rule if this one fails
                    # Most COM errors are access denied or property not found - skip silently
                    continue
            
            return rules
            
        except ImportError:
            # pywin32 not available, return empty to trigger netsh fallback
            return []
        except Exception as e:
            # COM API failed, return empty to trigger netsh fallback
            return []
    
    
    def _collect_via_netsh(self):
        """Collect firewall rules using netsh command (fallback method)."""
        rules = []
        
        # Get rules for each profile
        for profile_name in self.PROFILE_NAMES.values():
            # Get inbound rules
            inbound_rules = self._get_netsh_rules(profile_name, "in")
            rules.extend(inbound_rules)
            
            # Get outbound rules
            outbound_rules = self._get_netsh_rules(profile_name, "out")
            rules.extend(outbound_rules)
        
        return rules
    
    def _get_netsh_rules(self, profile, direction):
        """Get firewall rules using netsh command for a specific profile and direction."""
        rules = []
        
        try:
            # Run netsh command - correct syntax: dir=in or dir=out
            cmd = ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 
                   'name=all', f'dir={direction}', f'profile={profile}', 'verbose']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            if result.returncode != 0:
                # Try without verbose flag
                cmd = ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 
                       'name=all', f'dir={direction}', f'profile={profile}']
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                
                if result.returncode != 0:
                    import sys
                    print(f"[FirewallCollector] Netsh command failed: {result.stderr}", file=sys.stderr)
                    return rules
            
            # Parse the output
            lines = result.stdout.split('\n')
            current_rule = {}
            
            for line in lines:
                line = line.strip()
                if not line:
                    # Empty line might indicate end of rule
                    if current_rule and 'name' in current_rule:
                        if 'profile' not in current_rule:
                            current_rule['profile'] = profile
                        if 'direction' not in current_rule:
                            # Convert direction to proper format
                            if direction.lower() == 'in':
                                current_rule['direction'] = 'Inbound'
                            elif direction.lower() == 'out':
                                current_rule['direction'] = 'Outbound'
                            else:
                                current_rule['direction'] = direction.capitalize()
                        rules.append(current_rule)
                        current_rule = {}
                    continue
                
                # Parse key-value pairs
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    # Map netsh keys to our format
                    if 'rule name' in key or 'name' in key:
                        if current_rule and 'name' in current_rule:
                            # Save previous rule
                            if 'direction' not in current_rule:
                                # Convert direction to proper format
                                if direction.lower() == 'in':
                                    current_rule['direction'] = 'Inbound'
                                elif direction.lower() == 'out':
                                    current_rule['direction'] = 'Outbound'
                                else:
                                    current_rule['direction'] = direction.capitalize()
                            if 'profile' not in current_rule:
                                current_rule['profile'] = profile
                            rules.append(current_rule)
                        current_rule = {'name': value}
                    elif 'enabled' in key:
                        current_rule['enabled'] = value.lower() in ('yes', 'true', '1')
                    elif 'direction' in key:
                        # Convert direction to proper format
                        if value.lower() == 'in':
                            current_rule['direction'] = 'Inbound'
                        elif value.lower() == 'out':
                            current_rule['direction'] = 'Outbound'
                        else:
                            current_rule['direction'] = value
                    elif 'profiles' in key or 'profile' in key:
                        current_rule['profile'] = value
                    elif 'action' in key:
                        current_rule['action'] = value
                    elif 'protocol' in key:
                        current_rule['protocol'] = value
                    elif 'localport' in key or 'local port' in key:
                        current_rule['local_ports'] = value
                    elif 'remoteport' in key or 'remote port' in key:
                        current_rule['remote_ports'] = value
                    elif 'localip' in key or 'local address' in key:
                        current_rule['local_addresses'] = value
                    elif 'remoteip' in key or 'remote address' in key:
                        current_rule['remote_addresses'] = value
                    elif 'program' in key or 'application' in key:
                        current_rule['application_name'] = value
                    elif 'service' in key:
                        current_rule['service_name'] = value
                    elif 'description' in key:
                        current_rule['description'] = value
            
            # Don't forget the last rule
            if current_rule and 'name' in current_rule:
                if 'direction' not in current_rule:
                    # Convert direction to proper format
                    if direction.lower() == 'in':
                        current_rule['direction'] = 'Inbound'
                    elif direction.lower() == 'out':
                        current_rule['direction'] = 'Outbound'
                    else:
                        current_rule['direction'] = direction.capitalize()
                if 'profile' not in current_rule:
                    current_rule['profile'] = profile
                # Ensure all required fields are present
                if 'enabled' not in current_rule:
                    current_rule['enabled'] = True
                if 'action' not in current_rule:
                    current_rule['action'] = 'Allow'
                if 'protocol' not in current_rule:
                    current_rule['protocol'] = 'Any'
                if 'local_ports' not in current_rule:
                    current_rule['local_ports'] = 'N/A'
                if 'remote_ports' not in current_rule:
                    current_rule['remote_ports'] = 'N/A'
                if 'local_addresses' not in current_rule:
                    current_rule['local_addresses'] = 'N/A'
                if 'remote_addresses' not in current_rule:
                    current_rule['remote_addresses'] = 'N/A'
                if 'application_name' not in current_rule:
                    current_rule['application_name'] = 'N/A'
                if 'service_name' not in current_rule:
                    current_rule['service_name'] = 'N/A'
                if 'description' not in current_rule:
                    current_rule['description'] = 'N/A'
                rules.append(current_rule)
                
        except subprocess.TimeoutExpired:
            # Timeout, return what we have
            pass
        except Exception:
            # Error parsing, return empty
            pass
        
        return rules

