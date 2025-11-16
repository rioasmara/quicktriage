"""
DLL collector for triage analysis.
Collects loaded DLL information and verifies digital signatures.
"""

import os
import subprocess
import psutil
from datetime import datetime
from collectors.base_collector import BaseCollector


class DLLCollector(BaseCollector):
    """Collects loaded DLL information and verifies digital signatures."""
    
    def __init__(self, incremental_callback=None):
        """
        Initialize DLL collector.
        
        Args:
            incremental_callback: Optional callback function(dll_info) called for each DLL as it's processed
        """
        super().__init__()
        self.seen_dlls = {}  # Cache for DLL signature verification
        self.common_paths = self._get_common_paths()
        self.suspicious_paths = self._get_suspicious_paths()
        self.system_processes = self._get_system_processes()
        self.incremental_callback = incremental_callback
    
    def _get_common_paths(self):
        """
        Get list of common/expected DLL paths on Windows.
        
        Returns:
            list: List of common path prefixes (lowercase)
        """
        common = []
        
        # Windows system directories
        windows_dir = os.environ.get('SystemRoot', 'C:\\Windows')
        common.extend([
            os.path.join(windows_dir, 'System32').lower(),
            os.path.join(windows_dir, 'SysWOW64').lower(),
            os.path.join(windows_dir, 'System').lower(),
            os.path.join(windows_dir, 'WinSxS').lower(),
            windows_dir.lower()
        ])
        
        # Program Files directories
        program_files = os.environ.get('ProgramFiles', 'C:\\Program Files')
        program_files_x86 = os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)')
        
        common.extend([
            program_files.lower(),
            program_files_x86.lower()
        ])
        
        return common
    
    def _get_suspicious_paths(self):
        """
        Get list of suspicious paths that are commonly used for DLL injection.
        
        Returns:
            list: List of suspicious path prefixes (lowercase)
        """
        suspicious = []
        
        # Temp directories
        temp_dirs = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.environ.get('LOCALAPPDATA', ''),
        ]
        for temp_dir in temp_dirs:
            if temp_dir:
                suspicious.append(os.path.normpath(temp_dir.lower()))
        
        # User profile AppData directories (often used for malware)
        appdata_local = os.environ.get('LOCALAPPDATA', '')
        appdata_roaming = os.environ.get('APPDATA', '')
        if appdata_local:
            suspicious.append(os.path.normpath(appdata_local.lower()))
        if appdata_roaming:
            suspicious.append(os.path.normpath(appdata_roaming.lower()))
        
        # Common malware locations
        user_profile = os.environ.get('USERPROFILE', '')
        if user_profile:
            # Check for DLLs directly in user profile (suspicious)
            suspicious.append(os.path.normpath(user_profile.lower()))
        
        return [p for p in suspicious if p]  # Filter out empty strings
    
    def _get_system_processes(self):
        """
        Get list of system process names that should only load DLLs from system paths.
        
        Returns:
            set: Set of system process names (lowercase)
        """
        return {
            'csrss.exe', 'winlogon.exe', 'services.exe', 'lsass.exe',
            'smss.exe', 'svchost.exe', 'spoolsv.exe', 'explorer.exe',
            'dwm.exe', 'wininit.exe', 'audiodg.exe', 'dllhost.exe',
            'taskhost.exe', 'taskhostw.exe', 'conhost.exe', 'sihost.exe',
            'runtimebroker.exe', 'searchindexer.exe', 'searchprotocolhost.exe',
            'searchfilterhost.exe', 'wmiprvse.exe', 'unsecapp.exe'
        }
    
    def _is_suspicious_path(self, dll_path):
        """
        Check if a DLL path is in a suspicious location commonly used for injection.
        
        Args:
            dll_path: Path to the DLL file
            
        Returns:
            bool: True if path is suspicious, False otherwise
        """
        dll_path_lower = os.path.normpath(dll_path.lower())
        
        for suspicious_path in self.suspicious_paths:
            if dll_path_lower.startswith(suspicious_path):
                return True
        
        return False
    
    def _is_system_process(self, process_name):
        """
        Check if a process is a system process.
        
        Args:
            process_name: Name of the process
            
        Returns:
            bool: True if process is a system process, False otherwise
        """
        return process_name.lower() in self.system_processes
    
    def _detect_injection(self, dll_info):
        """
        Detect if a DLL is likely injected based on various indicators.
        
        Args:
            dll_info: Dictionary containing DLL information
            
        Returns:
            tuple: (is_injected: bool, injection_reason: str)
        """
        dll_path = dll_info['dll_path']
        process_name = dll_info['process_name']
        is_trusted = dll_info['is_trusted']
        is_common_path = dll_info['is_common_path']
        dll_path_lower = os.path.normpath(dll_path.lower())
        
        reasons = []
        
        # Indicator 1: DLL from suspicious path (temp, AppData, etc.)
        if self._is_suspicious_path(dll_path):
            reasons.append("Suspicious Path")
        
        # Indicator 2: Unsigned DLL loaded into system process from non-system location
        if self._is_system_process(process_name) and not is_common_path and not is_trusted:
            reasons.append("Unsigned DLL in System Process")
        
        # Indicator 3: DLL from user profile loaded into system process
        if self._is_system_process(process_name) and not is_common_path:
            user_profile = os.environ.get('USERPROFILE', '').lower()
            if user_profile and dll_path_lower.startswith(user_profile):
                reasons.append("User DLL in System Process")
        
        # Indicator 4: Unsigned DLL from uncommon path
        if not is_trusted and not is_common_path:
            reasons.append("Unsigned Uncommon Path")
        
        # Indicator 5: DLL file doesn't exist on disk (memory-only injection)
        if not dll_info.get('exists', True):
            reasons.append("Memory-Only DLL")
        
        if reasons:
            return (True, " | ".join(reasons))
        
        return (False, "Normal")
    
    def _is_common_path(self, dll_path):
        """
        Check if a DLL path is in a common/expected location.
        
        Args:
            dll_path: Path to the DLL file
            
        Returns:
            bool: True if path is in a common location, False otherwise
        """
        dll_path_lower = os.path.normpath(dll_path.lower())
        
        for common_path in self.common_paths:
            if dll_path_lower.startswith(common_path):
                return True
        
        return False
    
    def _check_signature(self, dll_path):
        """
        Check if a DLL has a valid digital signature using PowerShell.
        
        Args:
            dll_path: Path to the DLL file
            
        Returns:
            tuple: (is_trusted: bool, status: str, signer: str)
        """
        if not os.path.exists(dll_path):
            return (False, "File Not Found", "N/A")
        
        # Check cache first
        if dll_path in self.seen_dlls:
            return self.seen_dlls[dll_path]
        
        try:
            import json
            
            # Properly escape the DLL path for PowerShell
            # Replace single quotes with double single quotes and wrap in single quotes
            escaped_path = dll_path.replace("'", "''")
            
            # Use PowerShell Get-AuthenticodeSignature to check signature
            # Use -LiteralPath to handle paths with special characters properly
            ps_command = f"""
            try {{
                $sig = Get-AuthenticodeSignature -LiteralPath '{escaped_path}' -ErrorAction Stop
                $result = @{{
                    Status = $sig.Status.ToString()
                    Signer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ 'N/A' }}
                    IsTrusted = ($sig.Status -eq 'Valid')
                }}
                $result | ConvertTo-Json -Compress
            }} catch {{
                $errorResult = @{{
                    Status = 'Error'
                    Signer = 'N/A'
                    IsTrusted = $false
                    ErrorMessage = $_.Exception.Message
                }}
                $errorResult | ConvertTo-Json -Compress
            }}
            """
            
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            # Check stderr for errors
            if result.stderr:
                # If there's stderr but returncode is 0, it might be warnings - still try to parse
                if result.returncode != 0:
                    error_msg = result.stderr.strip()[:100]  # Limit error message length
                    result_tuple = (False, f"PowerShell Error", error_msg)
                    self.seen_dlls[dll_path] = result_tuple
                    return result_tuple
            
            # Try to parse JSON output
            output = result.stdout.strip()
            if output:
                try:
                    sig_info = json.loads(output)
                    status = sig_info.get('Status', 'Unknown')
                    signer = sig_info.get('Signer', 'N/A')
                    is_trusted = sig_info.get('IsTrusted', False)
                    
                    # Check if there was an error message in the result
                    if 'ErrorMessage' in sig_info:
                        error_msg = sig_info.get('ErrorMessage', 'Unknown error')
                        result_tuple = (False, f"Error: {status}", error_msg[:100])
                    else:
                        result_tuple = (is_trusted, status, signer)
                    
                    self.seen_dlls[dll_path] = result_tuple
                    return result_tuple
                except json.JSONDecodeError as e:
                    # JSON parsing failed - log the actual output for debugging
                    error_msg = f"JSON Parse Error: {str(e)[:50]}"
                    if output:
                        error_msg += f" | Output: {output[:50]}"
                    result_tuple = (False, "Parse Error", error_msg)
                    self.seen_dlls[dll_path] = result_tuple
                    return result_tuple
            
            # If we get here, PowerShell returned no output or empty output
            result_tuple = (False, "No Output", "PowerShell returned empty response")
            self.seen_dlls[dll_path] = result_tuple
            return result_tuple
            
        except subprocess.TimeoutExpired:
            result_tuple = (False, "Timeout", "PowerShell command timed out after 10 seconds")
            self.seen_dlls[dll_path] = result_tuple
            return result_tuple
        except Exception as e:
            result_tuple = (False, f"Exception: {type(e).__name__}", str(e)[:100])
            self.seen_dlls[dll_path] = result_tuple
            return result_tuple
    
    def collect(self):
        """
        Collect DLL information from all running processes.
        
        Returns:
            dict: Collected DLL data with signature information
        """
        dll_data = []
        process_dlls = {}  # Track DLLs per process to avoid duplicates
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                process_name = pinfo['name'] or 'Unknown'
                
                # Get memory maps (includes loaded DLLs)
                try:
                    memory_maps = proc.memory_maps()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                
                for mem_map in memory_maps:
                    dll_path = mem_map.path
                    
                    # Filter for DLL files only
                    if not dll_path.lower().endswith('.dll'):
                        continue
                    
                    # Normalize path (handle case sensitivity)
                    dll_path_normalized = os.path.normpath(dll_path.lower())
                    
                    # Skip if we've already checked this DLL for this process
                    process_key = f"{pid}:{dll_path_normalized}"
                    if process_key in process_dlls:
                        continue
                    
                    process_dlls[process_key] = True
                    
                    # Check signature
                    is_trusted, status, signer = self._check_signature(dll_path)
                    
                    # Check if path is in common location
                    is_common_path = self._is_common_path(dll_path)
                    
                    # Get file creation time
                    creation_time = None
                    dll_exists = os.path.exists(dll_path)
                    if dll_exists:
                        try:
                            stat_info = os.stat(dll_path)
                            creation_time = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
                        except (OSError, ValueError):
                            creation_time = "N/A"
                    else:
                        creation_time = "N/A"
                    
                    dll_info = {
                        'pid': pid,
                        'process_name': process_name,
                        'dll_path': dll_path,
                        'dll_name': os.path.basename(dll_path),
                        'is_trusted': is_trusted,
                        'signature_status': status,
                        'signer': signer,
                        'exists': dll_exists,
                        'is_common_path': is_common_path,
                        'creation_time': creation_time
                    }
                    
                    # Detect DLL injection
                    is_injected, injection_reason = self._detect_injection(dll_info)
                    dll_info['is_injected'] = is_injected
                    dll_info['injection_reason'] = injection_reason
                    
                    dll_data.append(dll_info)
                    
                    # Call incremental callback if provided for real-time updates
                    if self.incremental_callback:
                        try:
                            self.incremental_callback(dll_info)
                        except Exception:
                            # Don't fail collection if callback fails
                            pass
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Count statistics (signature checking is cached, so this is efficient)
        trusted_count = sum(1 for d in dll_data if d['is_trusted'])
        untrusted_count = len(dll_data) - trusted_count
        injected_count = sum(1 for d in dll_data if d.get('is_injected', False))
        
        return {
            'timestamp': datetime.now().isoformat(),
            'dlls': dll_data,
            'total_count': len(dll_data),
            'trusted_count': trusted_count,
            'untrusted_count': untrusted_count,
            'injected_count': injected_count
        }

