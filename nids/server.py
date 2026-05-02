#!/usr/bin/env python3
"""
Flask Server - Dashboard API for NIDS
Provides REST API and serves the web dashboard
"""

import os
import sqlite3
from flask import Flask, jsonify, render_template, request
from alerts import AlertSystem

app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(__file__), 'dashboard'),
            static_folder=os.path.join(os.path.dirname(__file__), 'dashboard'))

alert_system = AlertSystem()


def get_db_connection():
    """Get database connection"""
    db_path = os.path.join(os.path.dirname(__file__), 'logs.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def dashboard():
    """Serve the main dashboard"""
    return render_template('index.html')


@app.route('/api/packets/recent', methods=['GET'])
def get_recent_packets():
    """Get recent packets from database"""
    limit = request.args.get('limit', 100, type=int)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, flags, payload_size
        FROM packets
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    
    packets = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({'packets': packets})


@app.route('/api/alerts/recent', methods=['GET'])
def get_recent_alerts():
    """Get recent alerts"""
    limit = request.args.get('limit', 50, type=int)
    alerts = alert_system.get_recent_alerts(limit)
    return jsonify({'alerts': alerts})


@app.route('/api/alerts/stats', methods=['GET'])
def get_alert_stats():
    """Get alert statistics"""
    stats = alert_system.get_alert_stats()
    return jsonify(stats)


@app.route('/api/traffic/stats', methods=['GET'])
def get_traffic_stats():
    """Get traffic statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total packets
    cursor.execute('SELECT COUNT(*) FROM packets')
    total_packets = cursor.fetchone()[0]
    
    # Packets by protocol
    cursor.execute('''
        SELECT protocol, COUNT(*) as count
        FROM packets
        GROUP BY protocol
    ''')
    by_protocol = dict(cursor.fetchall())
    
    # Top source IPs
    cursor.execute('''
        SELECT src_ip, COUNT(*) as count
        FROM packets
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT 10
    ''')
    top_sources = {row['src_ip']: row['count'] for row in cursor.fetchall()}
    
    # Top destination ports
    cursor.execute('''
        SELECT dst_port, COUNT(*) as count
        FROM packets
        WHERE dst_port > 0
        GROUP BY dst_port
        ORDER BY count DESC
        LIMIT 10
    ''')
    top_ports = {str(row['dst_port']): row['count'] for row in cursor.fetchall()}
    
    # Packets in last hour (time series)
    cursor.execute('''
        SELECT strftime('%Y-%m-%d %H:%M', timestamp) as time_bucket, COUNT(*) as count
        FROM packets
        WHERE datetime(timestamp) > datetime('now', '-1 hour')
        GROUP BY time_bucket
        ORDER BY time_bucket
    ''')
    time_series = {row['time_bucket']: row['count'] for row in cursor.fetchall()}
    
    conn.close()
    
    return jsonify({
        'total_packets': total_packets,
        'by_protocol': by_protocol,
        'top_sources': top_sources,
        'top_ports': top_ports,
        'time_series': time_series
    })


@app.route('/api/suspicious/ips', methods=['GET'])
def get_suspicious_ips():
    """Get list of suspicious IPs from alerts"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT attacker_ip, attack_type, severity, COUNT(*) as alert_count, MAX(timestamp) as last_seen
        FROM alerts
        GROUP BY attacker_ip
        ORDER BY alert_count DESC
        LIMIT 20
    ''')
    
    suspicious_ips = []
    for row in cursor.fetchall():
        suspicious_ips.append({
            'ip': row['attacker_ip'],
            'attack_types': row['attack_type'],
            'severity': row['severity'],
            'alert_count': row['alert_count'],
            'last_seen': row['last_seen']
        })
    
    conn.close()
    
    return jsonify({'suspicious_ips': suspicious_ips})


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get system configuration"""
    from detector import DetectionEngine
    engine = DetectionEngine()
    
    return jsonify({
        'detection_thresholds': {
            'port_scan': {
                'threshold': engine.PORT_SCAN_THRESHOLD,
                'window_seconds': engine.PORT_SCAN_WINDOW
            },
            'brute_force': {
                'threshold': engine.BRUTE_FORCE_THRESHOLD,
                'window_seconds': engine.BRUTE_FORCE_WINDOW
            },
            'traffic_spike': {
                'threshold': engine.TRAFFIC_SPIKE_THRESHOLD,
                'window_seconds': engine.TRAFFIC_SPIKE_WINDOW
            }
        },
        'monitored_ports': engine.MONITORED_PORTS,
        'telegram_enabled': alert_system.telegram_enabled,
        'email_enabled': alert_system.email_enabled
    })


if __name__ == '__main__':
    print("\n" + "="*60)
    print("🌐 NIDS Dashboard Server")
    print("="*60)
    print("Starting Flask server...")
    print("Dashboard URL: http://localhost:5000")
    print("Press Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
