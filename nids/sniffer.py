#!/usr/bin/env python3
"""
NIDS - Network Intrusion Detection System
Main sniffer module that captures live network traffic
"""

import os
import sys
import json
import sqlite3
from datetime import datetime
from collections import defaultdict
from threading import Thread, Lock

from scapy.all import sniff, IP, TCP, UDP, ICMP

# Import detection and alert modules
from detector import DetectionEngine
from alerts import AlertSystem

class PacketSniffer:
    def __init__(self, interface=None, packet_count=0):
        self.interface = interface
        self.packet_count = packet_count
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.packet_buffer = []
        self.lock = Lock()
        self.db_path = os.path.join(os.path.dirname(__file__), 'logs.db')
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for logging"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                flags TEXT,
                payload_size INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                attacker_ip TEXT,
                attack_type TEXT,
                severity TEXT,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def log_packet(self, packet_data):
        """Log packet to database and JSON file"""
        # Log to SQLite
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, flags, payload_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_data['timestamp'],
            packet_data['src_ip'],
            packet_data['dst_ip'],
            packet_data.get('src_port', 0),
            packet_data.get('dst_port', 0),
            packet_data['protocol'],
            packet_data.get('flags', ''),
            packet_data.get('payload_size', 0)
        ))
        
        conn.commit()
        conn.close()
        
        # Log to JSON file
        log_file = os.path.join(os.path.dirname(__file__), 'packet_logs.json')
        with open(log_file, 'a') as f:
            f.write(json.dumps(packet_data) + '\n')
    
    def process_packet(self, packet):
        """Process each captured packet"""
        if not packet.haslayer(IP):
            return
            
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Extract protocol info
        protocol = "Unknown"
        src_port = 0
        dst_port = 0
        flags = ""
        payload_size = len(packet.payload) if packet.payload else 0
        
        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = str(tcp_layer.flags)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        
        packet_data = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'flags': flags,
            'payload_size': payload_size
        }
        
        # Log the packet
        self.log_packet(packet_data)
        
        # Run detection engine
        alerts = self.detection_engine.analyze(packet_data)
        
        # Process any alerts
        for alert in alerts:
            self.alert_system.send_alert(alert)
        
        # Store in buffer for real-time dashboard
        with self.lock:
            self.packet_buffer.append(packet_data)
            if len(self.packet_buffer) > 1000:
                self.packet_buffer.pop(0)
        
        # Console output
        self.print_packet_info(packet_data)
    
    def print_packet_info(self, packet_data):
        """Print packet info to console with colors"""
        colors = {
            'TCP': '\033[92m',
            'UDP': '\033[94m',
            'ICMP': '\033[93m',
            'Unknown': '\033[0m'
        }
        reset = '\033[0m'
        
        color = colors.get(packet_data['protocol'], '')
        print(f"{color}[{packet_data['protocol']}]{reset} {packet_data['src_ip']}:{packet_data['src_port']} -> {packet_data['dst_ip']}:{packet_data['dst_port']}")
    
    def get_recent_packets(self, limit=100):
        """Get recent packets from buffer"""
        with self.lock:
            return self.packet_buffer[-limit:]
    
    def start_sniffing(self):
        """Start capturing packets"""
        print(f"\n{'='*60}")
        print(f"🛡️  NIDS - Network Intrusion Detection System")
        print(f"{'='*60}")
        print(f"Interface: {self.interface or 'default'}")
        print(f"Starting packet capture... Press Ctrl+C to stop\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                count=self.packet_count if self.packet_count > 0 else 0,
                store=False
            )
        except KeyboardInterrupt:
            print("\n\nStopping packet capture...")
        except PermissionError:
            print("\n❌ Permission denied. Try running with sudo:")
            print("   sudo python sniffer.py")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ Error: {e}")
            sys.exit(1)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='NIDS Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff on')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0=infinite)')
    
    args = parser.parse_args()
    
    sniffer = PacketSniffer(interface=args.interface, packet_count=args.count)
    sniffer.start_sniffing()


if __name__ == '__main__':
    main()
