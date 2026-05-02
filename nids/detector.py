#!/usr/bin/env python3
"""
Detection Engine - Core detection logic for NIDS
Implements rules for port scans, brute force, and traffic spikes
"""

import time
from collections import defaultdict
from datetime import datetime, timedelta


class DetectionEngine:
    def __init__(self):
        # Port scan tracking: {src_ip: {timestamp: set(ports)}}
        self.port_scan_tracker = defaultdict(lambda: {'timestamps': [], 'ports': set()})
        
        # Brute force tracking: {(src_ip, dst_port): [timestamps]}
        self.brute_force_tracker = defaultdict(list)
        
        # Traffic spike tracking: {src_ip: [timestamps]}
        self.traffic_spike_tracker = defaultdict(list)
        
        # Configuration thresholds
        self.PORT_SCAN_THRESHOLD = 10  # ports in time window
        self.PORT_SCAN_WINDOW = 5  # seconds
        
        self.BRUTE_FORCE_THRESHOLD = 5  # attempts
        self.BRUTE_FORCE_WINDOW = 10  # seconds
        
        self.TRAFFIC_SPIKE_THRESHOLD = 100  # packets
        self.TRAFFIC_SPIKE_WINDOW = 5  # seconds
        
        # Common service ports to monitor for brute force
        self.MONITORED_PORTS = [22, 23, 21, 3389, 3306, 5432, 1433]  # SSH, Telnet, FTP, RDP, MySQL, PostgreSQL, MSSQL
    
    def analyze(self, packet_data):
        """Analyze a packet and return list of alerts"""
        alerts = []
        
        src_ip = packet_data['src_ip']
        dst_ip = packet_data['dst_ip']
        dst_port = packet_data.get('dst_port', 0)
        timestamp = packet_data['timestamp']
        
        # Check for port scan
        port_scan_alert = self._detect_port_scan(src_ip, dst_port, timestamp)
        if port_scan_alert:
            alerts.append(port_scan_alert)
        
        # Check for brute force
        brute_force_alert = self._detect_brute_force(src_ip, dst_ip, dst_port, timestamp)
        if brute_force_alert:
            alerts.append(brute_force_alert)
        
        # Check for traffic spike
        spike_alert = self._detect_traffic_spike(src_ip, timestamp)
        if spike_alert:
            alerts.append(spike_alert)
        
        return alerts
    
    def _detect_port_scan(self, src_ip, dst_port, timestamp):
        """Detect port scanning activity"""
        if dst_port == 0:  # Skip non-TCP/UDP
            return None
        
        current_time = datetime.fromisoformat(timestamp)
        tracker = self.port_scan_tracker[src_ip]
        
        # Clean old entries
        cutoff = current_time - timedelta(seconds=self.PORT_SCAN_WINDOW)
        tracker['timestamps'] = [t for t in tracker['timestamps'] if t > cutoff]
        
        # Add current port
        tracker['timestamps'].append(current_time)
        tracker['ports'].add(dst_port)
        
        # Check if threshold exceeded
        unique_ports = len(tracker['ports'])
        if unique_ports >= self.PORT_SCAN_THRESHOLD:
            alert = {
                'timestamp': timestamp,
                'attacker_ip': src_ip,
                'attack_type': 'PORT_SCAN',
                'severity': 'HIGH',
                'details': f"Port scan detected: {unique_ports} unique ports scanned in {self.PORT_SCAN_WINDOW}s",
                'ports_scanned': list(tracker['ports'])[-20:]  # Last 20 ports
            }
            
            # Reset tracker after alert
            tracker['ports'] = set()
            tracker['timestamps'] = []
            
            return alert
        
        return None
    
    def _detect_brute_force(self, src_ip, dst_ip, dst_port, timestamp):
        """Detect brute force attempts on common service ports"""
        if dst_port not in self.MONITORED_PORTS:
            return None
        
        current_time = datetime.fromisoformat(timestamp)
        key = (src_ip, dst_port)
        
        tracker = self.brute_force_tracker[key]
        
        # Clean old entries
        cutoff = current_time - timedelta(seconds=self.BRUTE_FORCE_WINDOW)
        tracker[:] = [t for t in tracker if t > cutoff]
        
        # Add current attempt
        tracker.append(current_time)
        
        # Check if threshold exceeded
        if len(tracker) >= self.BRUTE_FORCE_THRESHOLD:
            service_name = self._get_service_name(dst_port)
            alert = {
                'timestamp': timestamp,
                'attacker_ip': src_ip,
                'attack_type': 'BRUTE_FORCE',
                'severity': 'CRITICAL',
                'details': f"Brute force attack detected on {service_name} (port {dst_port}): {len(tracker)} attempts in {self.BRUTE_FORCE_WINDOW}s",
                'target_ip': dst_ip,
                'target_port': dst_port,
                'attempts': len(tracker)
            }
            
            # Reset tracker after alert
            tracker.clear()
            
            return alert
        
        return None
    
    def _detect_traffic_spike(self, src_ip, timestamp):
        """Detect sudden traffic bursts from a single IP"""
        current_time = datetime.fromisoformat(timestamp)
        tracker = self.traffic_spike_tracker[src_ip]
        
        # Clean old entries
        cutoff = current_time - timedelta(seconds=self.TRAFFIC_SPIKE_WINDOW)
        tracker[:] = [t for t in tracker if t > cutoff]
        
        # Add current packet
        tracker.append(current_time)
        
        # Check if threshold exceeded
        if len(tracker) >= self.TRAFFIC_SPIKE_THRESHOLD:
            alert = {
                'timestamp': timestamp,
                'attacker_ip': src_ip,
                'attack_type': 'TRAFFIC_SPIKE',
                'severity': 'MEDIUM',
                'details': f"Traffic spike detected: {len(tracker)} packets in {self.TRAFFIC_SPIKE_WINDOW}s",
                'packet_count': len(tracker)
            }
            
            # Reset tracker after alert
            tracker.clear()
            
            return alert
        
        return None
    
    def _get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            22: 'SSH',
            23: 'Telnet',
            21: 'FTP',
            3389: 'RDP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP'
        }
        return services.get(port, f'port {port}')
    
    def get_stats(self):
        """Get current detection statistics"""
        return {
            'port_scan_sources': len(self.port_scan_tracker),
            'brute_force_sources': len(self.brute_force_tracker),
            'traffic_spike_sources': len(self.traffic_spike_tracker)
        }
