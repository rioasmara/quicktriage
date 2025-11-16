"""
Summary view widget for displaying security-focused findings for incident responders.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHBoxLayout, QLabel, QGroupBox, QGridLayout,
    QTextEdit, QScrollArea, QFrame, QSizePolicy
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from datetime import datetime, timedelta
from collections import Counter
import os
import re


class SummaryView(QWidget):
    """Widget for displaying security-focused summary of all findings."""
    
    # Common LOLBINs (Living Off The Land Binaries)
    LOLBINS = {
        'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wmic.exe', 'reg.exe',
        'certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'rundll32.exe',
        'msbuild.exe', 'csc.exe', 'cscript.exe', 'wscript.exe',
        'msiexec.exe', 'schtasks.exe', 'sc.exe', 'net.exe', 'netstat.exe',
        'tasklist.exe', 'whoami.exe', 'systeminfo.exe', 'ipconfig.exe',
        'wevtutil.exe', 'bcdedit.exe', 'diskpart.exe', 'vssadmin.exe',
        'python.exe', 'pythonw.exe', 'perl.exe', 'ruby.exe', 'java.exe',
        'javaw.exe', 'node.exe', 'php.exe', 'regsvr32.exe', 'odbcconf.exe',
        'cmstp.exe', 'msxsl.exe', 'winrm.exe', 'winrs.exe'
    }
    
    # Suspicious paths
    SUSPICIOUS_PATHS = [
        r'\\temp\\', r'\\tmp\\', r'\\appdata\\', r'\\local\\temp\\',
        r'\\users\\[^\\]+\\appdata\\local\\temp\\', r'\\users\\[^\\]+\\appdata\\roaming\\',
        r'\\programdata\\', r'\\windows\\temp\\', r'\\perflogs\\'
    ]
    
    def __init__(self):
        super().__init__()
        self.all_data = {}
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(4)
        
        # Export button (outside scroll area)
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(4)
        button_layout.addStretch()
        self.export_btn = QPushButton("Export Security Summary")
        self.export_btn.clicked.connect(self.export_summary)
        button_layout.addWidget(self.export_btn)
        main_layout.addLayout(button_layout)
        
        # Create scroll area for scrollable content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Create scrollable widget
        scrollable_widget = QWidget()
        layout = QVBoxLayout(scrollable_widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # Security Alerts (High Priority)
        alerts_group = QGroupBox("🔴 Security Alerts (High Priority)")
        alerts_layout = QVBoxLayout()
        alerts_layout.setContentsMargins(8, 8, 8, 8)
        self.alerts_text = QTextEdit()
        self.alerts_text.setReadOnly(True)
        self.alerts_text.setMinimumHeight(350)
        self.alerts_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self.alerts_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.alerts_text.setStyleSheet("""
            background-color: #2a1a1a; 
            color: #ff6b6b; 
            font-size: 10pt;
            padding: 8px;
            line-height: 1.4;
        """)
        alerts_layout.addWidget(self.alerts_text)
        alerts_group.setLayout(alerts_layout)
        layout.addWidget(alerts_group)
        
        # Risk Assessment
        risk_group = QGroupBox("⚠️ Risk Assessment")
        risk_layout = QGridLayout()
        risk_layout.setContentsMargins(8, 8, 8, 8)
        risk_layout.setSpacing(8)
        self.risk_labels = {}
        risk_group.setLayout(risk_layout)
        layout.addWidget(risk_group)
        
        # Suspicious Findings
        suspicious_group = QGroupBox("🔍 Suspicious Findings")
        suspicious_layout = QVBoxLayout()
        suspicious_layout.setContentsMargins(8, 8, 8, 8)
        self.suspicious_text = QTextEdit()
        self.suspicious_text.setReadOnly(True)
        self.suspicious_text.setMinimumHeight(350)
        self.suspicious_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self.suspicious_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.suspicious_text.setStyleSheet("""
            font-size: 10pt;
            padding: 8px;
            line-height: 1.4;
        """)
        suspicious_layout.addWidget(self.suspicious_text)
        suspicious_group.setLayout(suspicious_layout)
        layout.addWidget(suspicious_group)
        
        # Recommendations
        recommendations_group = QGroupBox("💡 Recommendations for Incident Responders")
        recommendations_layout = QVBoxLayout()
        recommendations_layout.setContentsMargins(8, 8, 8, 8)
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        self.recommendations_text.setMinimumHeight(400)
        self.recommendations_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self.recommendations_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.recommendations_text.setStyleSheet("""
            font-size: 10pt;
            padding: 8px;
            line-height: 1.4;
        """)
        recommendations_layout.addWidget(self.recommendations_text)
        recommendations_group.setLayout(recommendations_layout)
        layout.addWidget(recommendations_group)
        
        # Detailed Security Analysis
        analysis_group = QGroupBox("📊 Detailed Security Analysis")
        analysis_layout = QVBoxLayout()
        analysis_layout.setContentsMargins(8, 8, 8, 8)
        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setMinimumHeight(450)
        self.analysis_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self.analysis_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.analysis_text.setStyleSheet("""
            font-family: 'Courier New', monospace;
            font-size: 9pt;
            padding: 8px;
            line-height: 1.4;
        """)
        analysis_layout.addWidget(self.analysis_text)
        analysis_group.setLayout(analysis_layout)
        layout.addWidget(analysis_group)
        
        # Overview Statistics
        overview_group = QGroupBox("📈 Overview Statistics")
        overview_layout = QGridLayout()
        overview_layout.setContentsMargins(8, 8, 8, 8)
        overview_layout.setSpacing(8)
        self.overview_labels = {}
        overview_group.setLayout(overview_layout)
        layout.addWidget(overview_group)
        
        # Add stretch at the end to push content to top
        layout.addStretch()
        
        # Set the scrollable widget as the scroll area's widget
        scroll_area.setWidget(scrollable_widget)
        
        # Add scroll area to main layout
        main_layout.addWidget(scroll_area)
        
        # Store layouts for later use
        self.alerts_layout = alerts_layout
        self.risk_layout = risk_layout
        self.suspicious_layout = suspicious_layout
        self.recommendations_layout = recommendations_layout
        self.analysis_layout = analysis_layout
        self.overview_layout = overview_layout
    
    def update_data(self, collector_name, data):
        """Update the view with data from a specific collector."""
        if data is None:
            return
        
        # Store the data
        self.all_data[collector_name] = data
        
        # Defer heavy work to make UI responsive
        QTimer.singleShot(0, lambda: self._update_summary())
    
    def _update_summary(self):
        """Update the security-focused summary display with all collected data."""
        # Update security alerts (highest priority)
        self._update_security_alerts()
        
        # Update risk assessment
        self._update_risk_assessment()
        
        # Update suspicious findings
        self._update_suspicious_findings()
        
        # Update recommendations
        self._update_recommendations()
        
        # Update detailed analysis
        self._update_detailed_analysis()
        
        # Update overview statistics
        self._update_overview()
    
    def _update_security_alerts(self):
        """Update security alerts section with high-priority findings."""
        alerts = []
        
        # Check for DLL injection
        if "dlls" in self.all_data and self.all_data["dlls"]:
            dll_data = self.all_data["dlls"]
            if isinstance(dll_data, dict) and "dlls" in dll_data and "error" not in dll_data:
                dlls = dll_data["dlls"]
                injected_dlls = [d for d in dlls if isinstance(d, dict) and d.get("is_injected", False)]
                if injected_dlls:
                    alerts.append(f"🚨 CRITICAL: Found {len(injected_dlls)} DLL injection(s) detected!")
                    for dll in injected_dlls[:10]:  # Show first 10
                        process = dll.get("process_name", "Unknown")
                        pid = dll.get("pid", "Unknown")
                        dll_path = dll.get("dll_path", "Unknown")
                        reason = dll.get("injection_reason", "Unknown")
                        is_trusted = dll.get("is_trusted", False)
                        exists = dll.get("exists", True)
                        alerts.append(f"   • Process: {process} (PID: {pid}) | DLL: {os.path.basename(dll_path)}")
                        alerts.append(f"     Path: {dll_path[:100]} | Reason: {reason}")
                        alerts.append(f"     Trusted: {is_trusted} | Exists on disk: {exists}")
        
        # Check for suspicious persistence mechanisms
        if "persistence" in self.all_data and self.all_data["persistence"]:
            persist_data = self.all_data["persistence"]
            if isinstance(persist_data, dict) and "mechanisms" in persist_data and "error" not in persist_data:
                mechanisms = persist_data["mechanisms"]
                suspicious_mech = []
                
                # Check registry run keys in suspicious locations
                if "registry_run_keys" in mechanisms:
                    for mech in mechanisms["registry_run_keys"]:
                        if isinstance(mech, dict):
                            path = mech.get("path", "").lower()
                            if any(re.search(sp, path) for sp in self.SUSPICIOUS_PATHS):
                                suspicious_mech.append(("Registry Run Key", mech.get("name", "Unknown"), path))
                
                # Check scheduled tasks in suspicious locations
                if "scheduled_tasks" in mechanisms:
                    for mech in mechanisms["scheduled_tasks"]:
                        if isinstance(mech, dict):
                            path = mech.get("path", "").lower()
                            if any(re.search(sp, path) for sp in self.SUSPICIOUS_PATHS):
                                suspicious_mech.append(("Scheduled Task", mech.get("name", "Unknown"), path))
                
                # Check services in suspicious locations
                if "services" in mechanisms:
                    for mech in mechanisms["services"]:
                        if isinstance(mech, dict):
                            path = mech.get("path", "").lower()
                            if any(re.search(sp, path) for sp in self.SUSPICIOUS_PATHS):
                                suspicious_mech.append(("Service", mech.get("name", "Unknown"), path))
                
                if suspicious_mech:
                    alerts.append(f"🚨 CRITICAL: Found {len(suspicious_mech)} suspicious persistence mechanism(s)!")
                    for mech_type, name, path in suspicious_mech[:10]:
                        alerts.append(f"   • {mech_type}: {name}")
                        alerts.append(f"     Path: {path[:120]}")
        
        # Check for unsigned binaries in system processes
        system_processes = {'svchost.exe', 'services.exe', 'lsass.exe', 'winlogon.exe', 
                           'csrss.exe', 'smss.exe', 'explorer.exe', 'dwm.exe', 'spoolsv.exe'}
        if "dlls" in self.all_data and self.all_data["dlls"]:
            dll_data = self.all_data["dlls"]
            if isinstance(dll_data, dict) and "dlls" in dll_data and "error" not in dll_data:
                dlls = dll_data["dlls"]
                unsigned_system = [d for d in dlls if isinstance(d, dict) and 
                                   not d.get("is_trusted", True) and 
                                   d.get("process_name", "").lower() in system_processes]
                if unsigned_system:
                    alerts.append(f"🚨 HIGH: Found {len(unsigned_system)} unsigned DLL(s) in system processes!")
                    for dll in unsigned_system[:5]:
                        process = dll.get("process_name", "Unknown")
                        pid = dll.get("pid", "Unknown")
                        dll_path = dll.get("dll_path", "Unknown")
                        alerts.append(f"   • Process: {process} (PID: {pid}) | DLL: {os.path.basename(dll_path)}")
                        alerts.append(f"     Path: {dll_path[:100]}")
        
        # Check for processes from suspicious locations
        if "processes" in self.all_data and self.all_data["processes"]:
            proc_data = self.all_data["processes"]
            if isinstance(proc_data, dict) and "processes" in proc_data and "error" not in proc_data:
                processes = proc_data["processes"]
                suspicious_procs = []
                for proc in processes:
                    if isinstance(proc, dict):
                        exe_path = proc.get("exe_path", "").lower()
                        if exe_path and any(re.search(sp, exe_path) for sp in self.SUSPICIOUS_PATHS):
                            name = proc.get("name", "Unknown")
                            pid = proc.get("pid", "Unknown")
                            suspicious_procs.append((name, pid, exe_path))
                
                if suspicious_procs:
                    alerts.append(f"🚨 HIGH: Found {len(suspicious_procs)} process(es) running from suspicious locations!")
                    for name, pid, path in suspicious_procs[:10]:
                        # Get additional process details
                        proc = next((p for p in processes if isinstance(p, dict) and p.get("pid") == pid), None)
                        username = proc.get("username", "Unknown") if proc else "Unknown"
                        cmdline = proc.get("cmdline", "")[:80] if proc else ""
                        alerts.append(f"   • {name} (PID: {pid}) | User: {username}")
                        alerts.append(f"     Path: {path[:100]}")
                        if cmdline:
                            alerts.append(f"     Command: {cmdline}")
        
        # Check for unusual network connections
        if "network" in self.all_data and self.all_data["network"]:
            net_data = self.all_data["network"]
            if isinstance(net_data, dict) and "connections" in net_data and "error" not in net_data:
                connections = net_data["connections"]
                # Check for connections to non-standard ports
                unusual_ports = [c for c in connections if isinstance(c, dict) and 
                               c.get("remote_port", 0) not in [80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389]]
                if len(unusual_ports) > 10:  # Threshold
                    alerts.append(f"⚠️ MEDIUM: Found {len(unusual_ports)} network connections to non-standard ports!")
                    # Show top unusual connections
                    port_counts = Counter(c.get("remote_port", 0) for c in unusual_ports)
                    alerts.append(f"   Top unusual ports: {', '.join(str(p) for p, _ in port_counts.most_common(5))}")
        
        if not alerts:
            alerts.append("✅ No critical security alerts detected at this time.")
            alerts.append("   Continue monitoring and review detailed findings below.")
        
        self.alerts_text.setPlainText("\n".join(alerts))
        # Ensure minimum height is maintained after update
        self.alerts_text.setMinimumHeight(350)
    
    def _update_risk_assessment(self):
        """Update risk assessment section."""
        self._clear_layout(self.risk_layout)
        
        row = 0
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        # Count DLL injections (high risk)
        if "dlls" in self.all_data and self.all_data["dlls"]:
            dll_data = self.all_data["dlls"]
            if isinstance(dll_data, dict) and "dlls" in dll_data and "error" not in dll_data:
                dlls = dll_data["dlls"]
                injected = sum(1 for d in dlls if isinstance(d, dict) and d.get("is_injected", False))
                high_risk += injected
        
        # Count suspicious persistence (high risk)
        if "persistence" in self.all_data and self.all_data["persistence"]:
            persist_data = self.all_data["persistence"]
            if isinstance(persist_data, dict) and "mechanisms" in persist_data and "error" not in persist_data:
                mechanisms = persist_data["mechanisms"]
                suspicious_count = 0
                for mech_list in mechanisms.values():
                    if isinstance(mech_list, list):
                        for mech in mech_list:
                            if isinstance(mech, dict):
                                path = mech.get("path", "").lower()
                                if any(re.search(sp, path) for sp in self.SUSPICIOUS_PATHS):
                                    suspicious_count += 1
                high_risk += suspicious_count
        
        # Count unsigned DLLs in system processes (medium risk)
        system_processes = {'svchost.exe', 'services.exe', 'lsass.exe', 'winlogon.exe', 
                           'csrss.exe', 'smss.exe', 'explorer.exe', 'dwm.exe', 'spoolsv.exe'}
        if "dlls" in self.all_data and self.all_data["dlls"]:
            dll_data = self.all_data["dlls"]
            if isinstance(dll_data, dict) and "dlls" in dll_data and "error" not in dll_data:
                dlls = dll_data["dlls"]
                unsigned = sum(1 for d in dlls if isinstance(d, dict) and 
                              not d.get("is_trusted", True) and 
                              d.get("process_name", "").lower() in system_processes)
                medium_risk += unsigned
        
        # Count processes from suspicious locations (medium risk)
        if "processes" in self.all_data and self.all_data["processes"]:
            proc_data = self.all_data["processes"]
            if isinstance(proc_data, dict) and "processes" in proc_data and "error" not in proc_data:
                processes = proc_data["processes"]
                suspicious = sum(1 for proc in processes if isinstance(proc, dict) and
                               any(re.search(sp, proc.get("exe_path", "").lower()) for sp in self.SUSPICIOUS_PATHS))
                medium_risk += suspicious
        
        # Count LOLBIN usage (low risk, but worth noting)
        if "processes" in self.all_data and self.all_data["processes"]:
            proc_data = self.all_data["processes"]
            if isinstance(proc_data, dict) and "processes" in proc_data and "error" not in proc_data:
                processes = proc_data["processes"]
                lolbins = sum(1 for proc in processes if isinstance(proc, dict) and
                            proc.get("name", "").lower() in self.LOLBINS)
                low_risk += lolbins
        
        # Display risk assessment
        label = QLabel(f"<b>High Risk Items:</b> {high_risk}")
        label.setStyleSheet("font-size: 11pt; padding: 4px;")
        if high_risk > 0:
            label.setStyleSheet("color: #ff6b6b; font-weight: bold; font-size: 11pt; padding: 4px;")
        self.risk_layout.addWidget(label, row, 0)
        row += 1
        
        label = QLabel(f"<b>Medium Risk Items:</b> {medium_risk}")
        label.setStyleSheet("font-size: 11pt; padding: 4px;")
        if medium_risk > 0:
            label.setStyleSheet("color: #ffa500; font-weight: bold; font-size: 11pt; padding: 4px;")
        self.risk_layout.addWidget(label, row, 0)
        row += 1
        
        label = QLabel(f"<b>Low Risk Items:</b> {low_risk}")
        label.setStyleSheet("font-size: 11pt; padding: 4px;")
        self.risk_layout.addWidget(label, row, 0)
        row += 1
        
        # Overall risk level
        if high_risk > 0:
            risk_level = "HIGH"
            risk_color = "#ff6b6b"
        elif medium_risk > 5:
            risk_level = "MEDIUM"
            risk_color = "#ffa500"
        elif medium_risk > 0 or low_risk > 10:
            risk_level = "LOW"
            risk_color = "#ffd700"
        else:
            risk_level = "MINIMAL"
            risk_color = "#90ee90"
        
        label = QLabel(f"<b>Overall Risk Level:</b> {risk_level}")
        label.setStyleSheet(f"color: {risk_color}; font-weight: bold; font-size: 13pt; padding: 8px;")
        self.risk_layout.addWidget(label, row, 0)
    
    def _update_suspicious_findings(self):
        """Update suspicious findings section."""
        findings = []
        
        # Check for LOLBIN usage
        if "processes" in self.all_data and self.all_data["processes"]:
            proc_data = self.all_data["processes"]
            if isinstance(proc_data, dict) and "processes" in proc_data and "error" not in proc_data:
                processes = proc_data["processes"]
                lolbins = [p for p in processes if isinstance(p, dict) and 
                          p.get("name", "").lower() in self.LOLBINS]
                if lolbins:
                    findings.append(f"• Found {len(lolbins)} LOLBIN process(es) - Review command lines for suspicious activity")
                    lolbin_names = Counter(p.get("name", "Unknown") for p in lolbins)
                    for name, count in lolbin_names.most_common(10):
                        findings.append(f"  - {name}: {count} instance(s)")
                    # Show sample command lines
                    sample_lolbins = lolbins[:5]
                    for proc in sample_lolbins:
                        cmdline = proc.get("cmdline", "")
                        if cmdline:
                            findings.append(f"    Example: {proc.get('name', 'Unknown')} - {cmdline[:100]}")
        
        # Check for processes with unusual parent-child relationships
        if "processes" in self.all_data and self.all_data["processes"]:
            proc_data = self.all_data["processes"]
            if isinstance(proc_data, dict) and "processes" in proc_data and "error" not in proc_data:
                processes = proc_data["processes"]
                # Check for processes spawned by unusual parents
                unusual_parents = []
                for proc in processes:
                    if isinstance(proc, dict):
                        parent_pid = proc.get("ppid", 0)
                        name = proc.get("name", "")
                        # Check if parent is not explorer.exe, services.exe, or winlogon.exe
                        if parent_pid > 0:
                            parent_proc = next((p for p in processes if isinstance(p, dict) and 
                                               p.get("pid") == parent_pid), None)
                            if parent_proc:
                                parent_name = parent_proc.get("name", "").lower()
                                if parent_name not in ["explorer.exe", "services.exe", "winlogon.exe", "smss.exe", "csrss.exe"]:
                                    unusual_parents.append((name, parent_name))
                
                if unusual_parents:
                    findings.append(f"• Found {len(unusual_parents)} process(es) with unusual parent processes")
                    # Show examples
                    for child_name, parent_name in unusual_parents[:10]:
                        findings.append(f"  - {child_name} spawned by {parent_name}")
        
        # Check for files in suspicious locations
        if "files" in self.all_data and self.all_data["files"]:
            file_data = self.all_data["files"]
            if isinstance(file_data, dict) and "files" in file_data and "error" not in file_data:
                files = file_data["files"]
                suspicious_files = [f for f in files if isinstance(f, dict) and
                                  any(re.search(sp, f.get("path", "").lower()) for sp in self.SUSPICIOUS_PATHS)]
                if suspicious_files:
                    findings.append(f"• Found {len(suspicious_files)} file(s) in suspicious locations (temp, appdata, etc.)")
                    # Show file types
                    extensions = Counter(f.get("extension", "No Extension") for f in suspicious_files)
                    findings.append(f"  File types: {', '.join(f'{ext} ({count})' for ext, count in extensions.most_common(5))}")
                    # Show sample files
                    for f in suspicious_files[:5]:
                        findings.append(f"  - {os.path.basename(f.get('path', 'Unknown'))} ({f.get('extension', 'No Ext')})")
        
        # Check for services with suspicious paths
        if "services" in self.all_data and self.all_data["services"]:
            svc_data = self.all_data["services"]
            if isinstance(svc_data, dict) and "services" in svc_data and "error" not in svc_data:
                services = svc_data["services"]
                suspicious_svcs = [s for s in services if isinstance(s, dict) and
                                 any(re.search(sp, s.get("path", "").lower()) for sp in self.SUSPICIOUS_PATHS)]
                if suspicious_svcs:
                    findings.append(f"• Found {len(suspicious_svcs)} service(s) with suspicious executable paths")
                    for svc in suspicious_svcs[:10]:
                        name = svc.get("name", "Unknown")
                        path = svc.get("path", "Unknown")
                        state = svc.get("state", "Unknown")
                        findings.append(f"  - {name} ({state}): {path[:100]}")
        
        # Check for network connections to external IPs
        if "network" in self.all_data and self.all_data["network"]:
            net_data = self.all_data["network"]
            if isinstance(net_data, dict) and "connections" in net_data and "error" not in net_data:
                connections = net_data["connections"]
                external_conns = [c for c in connections if isinstance(c, dict) and
                                c.get("remote_addr") and not c.get("remote_addr", "").startswith(("127.", "10.", "192.168.", "172."))]
                if external_conns:
                    findings.append(f"• Found {len(external_conns)} network connection(s) to external IP addresses")
                    # Show top external IPs
                    ip_counts = Counter(c.get("remote_addr", "Unknown") for c in external_conns)
                    findings.append(f"  Top external IPs: {', '.join(f'{ip} ({count})' for ip, count in ip_counts.most_common(5))}")
                    # Show sample connections
                    for conn in external_conns[:5]:
                        proc_name = conn.get("process_name", "Unknown")
                        remote_ip = conn.get("remote_addr", "Unknown")
                        remote_port = conn.get("remote_port", "Unknown")
                        findings.append(f"  - {proc_name} -> {remote_ip}:{remote_port}")
        
        if not findings:
            findings.append("• No suspicious findings detected at this time.")
        
        self.suspicious_text.setPlainText("\n".join(findings))
        # Ensure minimum height is maintained after update
        self.suspicious_text.setMinimumHeight(350)
    
    def _update_recommendations(self):
        """Update recommendations section for incident responders."""
        recommendations = []
        
        # Check what data we have
        has_dll_data = "dlls" in self.all_data and self.all_data["dlls"] and "error" not in self.all_data["dlls"]
        has_persistence = "persistence" in self.all_data and self.all_data["persistence"] and "error" not in self.all_data["persistence"]
        has_processes = "processes" in self.all_data and self.all_data["processes"] and "error" not in self.all_data["processes"]
        has_network = "network" in self.all_data and self.all_data["network"] and "error" not in self.all_data["network"]
        
        recommendations.append("IMMEDIATE ACTIONS:")
        recommendations.append("")
        
        # High priority recommendations
        if has_dll_data:
            dll_data = self.all_data["dlls"]
            if isinstance(dll_data, dict) and "dlls" in dll_data:
                dlls = dll_data["dlls"]
                injected = [d for d in dlls if isinstance(d, dict) and d.get("is_injected", False)]
                if injected:
                    recommendations.append("1. 🚨 PRIORITY: Investigate DLL injection detections")
                    recommendations.append("   - Review injected DLLs in the DLLs tab")
                    recommendations.append("   - Check process memory for malicious code")
                    recommendations.append("   - Consider process termination and memory dump")
        
        if has_persistence:
            persist_data = self.all_data["persistence"]
            if isinstance(persist_data, dict) and "mechanisms" in persist_data:
                mechanisms = persist_data["mechanisms"]
                suspicious = []
                for mech_list in mechanisms.values():
                    if isinstance(mech_list, list):
                        for mech in mech_list:
                            if isinstance(mech, dict):
                                path = mech.get("path", "").lower()
                                if any(re.search(sp, path) for sp in self.SUSPICIOUS_PATHS):
                                    suspicious.append(mech)
                
                if suspicious:
                    recommendations.append("2. 🚨 PRIORITY: Remove suspicious persistence mechanisms")
                    recommendations.append("   - Review persistence mechanisms in the Persistence tab")
                    recommendations.append("   - Remove or disable suspicious entries")
                    recommendations.append("   - Document changes for forensic analysis")
        
        recommendations.append("")
        recommendations.append("INVESTIGATION STEPS:")
        recommendations.append("")
        
        if has_processes:
            recommendations.append("3. Review suspicious processes:")
            recommendations.append("   - Check processes running from temp/appdata locations")
            recommendations.append("   - Investigate LOLBIN usage and command lines")
            recommendations.append("   - Correlate with network connections")
        
        if has_network:
            recommendations.append("4. Analyze network connections:")
            recommendations.append("   - Review external IP connections")
            recommendations.append("   - Check for connections to non-standard ports")
            recommendations.append("   - Correlate with process information")
        
        recommendations.append("5. Review all collected data:")
        recommendations.append("   - Check each tab for detailed findings")
        recommendations.append("   - Export data for further analysis")
        recommendations.append("   - Document all findings for incident report")
        
        recommendations.append("")
        recommendations.append("NEXT STEPS:")
        recommendations.append("")
        recommendations.append("6. If malicious activity confirmed:")
        recommendations.append("   - Isolate the system from network")
        recommendations.append("   - Preserve evidence (memory dump, disk image)")
        recommendations.append("   - Begin containment procedures")
        recommendations.append("   - Notify security team and management")
        
        self.recommendations_text.setPlainText("\n".join(recommendations))
        # Ensure minimum height is maintained after update
        self.recommendations_text.setMinimumHeight(400)
    
    def _update_detailed_analysis(self):
        """Update detailed security analysis section."""
        analysis = []
        
        analysis.append("DETAILED SECURITY ANALYSIS")
        analysis.append("=" * 50)
        analysis.append("")
        
        # Processes analysis
        if "processes" in self.all_data and self.all_data["processes"]:
            proc_data = self.all_data["processes"]
            if isinstance(proc_data, dict) and "processes" in proc_data and "error" not in proc_data:
                processes = proc_data["processes"]
                proc_count = len(processes)
                analysis.append(f"PROCESSES: {proc_count} total processes")
                
                # Count by state
                states = Counter(p.get("state", "Unknown") for p in processes)
                for state, count in states.items():
                    analysis.append(f"  - {state}: {count}")
                
                # Suspicious processes
                suspicious = sum(1 for p in processes if isinstance(p, dict) and
                               any(re.search(sp, p.get("exe_path", "").lower()) for sp in self.SUSPICIOUS_PATHS))
                if suspicious > 0:
                    analysis.append(f"  - Suspicious locations: {suspicious}")
                
                # LOLBIN usage
                lolbins = sum(1 for p in processes if isinstance(p, dict) and
                            p.get("name", "").lower() in self.LOLBINS)
                if lolbins > 0:
                    analysis.append(f"  - LOLBIN processes: {lolbins}")
                
                # Top processes by memory
                top_memory = sorted([p for p in processes if isinstance(p, dict) and p.get("memory_mb")],
                                  key=lambda x: x.get("memory_mb", 0), reverse=True)[:5]
                if top_memory:
                    analysis.append(f"  - Top memory consumers:")
                    for proc in top_memory:
                        analysis.append(f"    {proc.get('name', 'Unknown')}: {proc.get('memory_mb', 0):.1f} MB")
        
        # Network analysis
        if "network" in self.all_data and self.all_data["network"]:
            net_data = self.all_data["network"]
            if isinstance(net_data, dict) and "connections" in net_data and "error" not in net_data:
                connections = net_data["connections"]
                conn_count = len(connections)
                analysis.append(f"")
                analysis.append(f"NETWORK: {conn_count} total connections")
                
                # Count by state
                states = Counter(c.get("state", "Unknown") for c in connections)
                for state, count in states.items():
                    analysis.append(f"  - {state}: {count}")
                
                # External connections
                external = [c for c in connections if isinstance(c, dict) and
                           c.get("remote_addr") and not c.get("remote_addr", "").startswith(("127.", "10.", "192.168.", "172."))]
                if external:
                    analysis.append(f"  - External connections: {len(external)}")
                    # Top external IPs
                    ip_counts = Counter(c.get("remote_addr", "Unknown") for c in external)
                    analysis.append(f"    Top external IPs: {', '.join(f'{ip}' for ip, _ in ip_counts.most_common(5))}")
                
                # Top processes by connection count
                proc_conns = Counter(c.get("process_name", "Unknown") for c in connections)
                if proc_conns:
                    analysis.append(f"  - Top processes by connections:")
                    for proc_name, count in proc_conns.most_common(5):
                        analysis.append(f"    {proc_name}: {count} connections")
        
        # DLL analysis
        if "dlls" in self.all_data and self.all_data["dlls"]:
            dll_data = self.all_data["dlls"]
            if isinstance(dll_data, dict) and "dlls" in dll_data and "error" not in dll_data:
                dlls = dll_data["dlls"]
                dll_count = len(dlls)
                analysis.append(f"")
                analysis.append(f"DLLs: {dll_count} total DLLs loaded")
                
                injected = sum(1 for d in dlls if isinstance(d, dict) and d.get("is_injected", False))
                if injected > 0:
                    analysis.append(f"  - Injected: {injected}")
                
                unsigned = sum(1 for d in dlls if isinstance(d, dict) and not d.get("is_trusted", True))
                if unsigned > 0:
                    analysis.append(f"  - Unsigned: {unsigned}")
                
                # Top processes by DLL count
                proc_dlls = Counter(d.get("process_name", "Unknown") for d in dlls if isinstance(d, dict))
                if proc_dlls:
                    analysis.append(f"  - Top processes by DLL count:")
                    for proc_name, count in proc_dlls.most_common(5):
                        analysis.append(f"    {proc_name}: {count} DLLs")
        
        # Persistence analysis
        if "persistence" in self.all_data and self.all_data["persistence"]:
            persist_data = self.all_data["persistence"]
            if isinstance(persist_data, dict) and "mechanisms" in persist_data and "error" not in persist_data:
                mechanisms = persist_data["mechanisms"]
                total = sum(len(v) if isinstance(v, list) else 0 for v in mechanisms.values())
                analysis.append(f"")
                analysis.append(f"PERSISTENCE: {total} total mechanisms")
                
                for mech_type, mech_list in mechanisms.items():
                    if isinstance(mech_list, list) and mech_list:
                        count = len(mech_list)
                        analysis.append(f"  - {mech_type.replace('_', ' ').title()}: {count}")
                        # Show suspicious ones
                        suspicious_mech = [m for m in mech_list if isinstance(m, dict) and
                                         any(re.search(sp, m.get("path", "").lower()) for sp in self.SUSPICIOUS_PATHS)]
                        if suspicious_mech:
                            analysis.append(f"    Suspicious: {len(suspicious_mech)}")
        
        # Services analysis
        if "services" in self.all_data and self.all_data["services"]:
            svc_data = self.all_data["services"]
            if isinstance(svc_data, dict) and "services" in svc_data and "error" not in svc_data:
                services = svc_data["services"]
                svc_count = len(services)
                analysis.append(f"")
                analysis.append(f"SERVICES: {svc_count} total services")
                
                states = Counter(s.get("state", "Unknown") for s in services)
                for state, count in states.items():
                    analysis.append(f"  - {state}: {count}")
                
                # Suspicious services
                suspicious = sum(1 for s in services if isinstance(s, dict) and
                               any(re.search(sp, s.get("path", "").lower()) for sp in self.SUSPICIOUS_PATHS))
                if suspicious > 0:
                    analysis.append(f"  - Suspicious paths: {suspicious}")
        
        # Files analysis
        if "files" in self.all_data and self.all_data["files"]:
            file_data = self.all_data["files"]
            if isinstance(file_data, dict) and "files" in file_data and "error" not in file_data:
                files = file_data["files"]
                file_count = len(files)
                analysis.append(f"")
                analysis.append(f"FILES: {file_count} total files analyzed")
                
                # File types
                extensions = Counter(f.get("extension", "No Extension") for f in files if isinstance(f, dict))
                if extensions:
                    analysis.append(f"  - Top file types:")
                    for ext, count in extensions.most_common(5):
                        analysis.append(f"    {ext}: {count}")
                
                # Suspicious files
                suspicious = sum(1 for f in files if isinstance(f, dict) and
                               any(re.search(sp, f.get("path", "").lower()) for sp in self.SUSPICIOUS_PATHS))
                if suspicious > 0:
                    analysis.append(f"  - Suspicious locations: {suspicious}")
        
        if not analysis or len(analysis) <= 3:
            analysis.append("No detailed analysis available yet.")
            analysis.append("Collect data to see detailed security analysis.")
        
        self.analysis_text.setPlainText("\n".join(analysis))
        # Ensure minimum height is maintained after update
        self.analysis_text.setMinimumHeight(450)
    
    def _update_overview(self):
        """Update overview statistics."""
        self._clear_layout(self.overview_layout)
        
        row = 0
        total_collectors = len(self.all_data)
        collectors_with_data = sum(1 for data in self.all_data.values() if data and data != {} and not (isinstance(data, dict) and "error" in data))
        
        # Total collectors
        label = QLabel(f"<b>Total Collectors:</b> {total_collectors}")
        label.setStyleSheet("font-size: 11pt; padding: 4px;")
        self.overview_layout.addWidget(label, row, 0)
        row += 1
        
        # Collectors with data
        label = QLabel(f"<b>Collectors with Data:</b> {collectors_with_data}")
        label.setStyleSheet("font-size: 11pt; padding: 4px;")
        self.overview_layout.addWidget(label, row, 0)
        row += 1
        
        # Collection timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        label = QLabel(f"<b>Last Updated:</b> {timestamp}")
        label.setStyleSheet("font-size: 11pt; padding: 4px;")
        self.overview_layout.addWidget(label, row, 0)
        row += 1
    
    def _clear_layout(self, layout):
        """Clear all widgets from a layout."""
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
    
    def export_summary(self):
        """Export security summary to a file."""
        from PySide6.QtWidgets import QFileDialog
        import json
        
        # Collect security findings
        security_findings = {
            "timestamp": datetime.now().isoformat(),
            "overview": {
                "total_collectors": len(self.all_data),
                "collectors_with_data": sum(1 for data in self.all_data.values() if data and data != {} and not (isinstance(data, dict) and "error" in data))
            },
            "security_alerts": self.alerts_text.toPlainText(),
            "risk_assessment": {},
            "suspicious_findings": self.suspicious_text.toPlainText(),
            "recommendations": self.recommendations_text.toPlainText(),
            "detailed_analysis": self.analysis_text.toPlainText(),
            "raw_data": self.all_data
        }
        
        # Calculate risk assessment
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        if "dlls" in self.all_data and self.all_data["dlls"]:
            dll_data = self.all_data["dlls"]
            if isinstance(dll_data, dict) and "dlls" in dll_data and "error" not in dll_data:
                dlls = dll_data["dlls"]
                high_risk += sum(1 for d in dlls if isinstance(d, dict) and d.get("is_injected", False))
        
        security_findings["risk_assessment"] = {
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk
        }
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Security Summary", "security_summary.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(security_findings, f, indent=2, default=str)
