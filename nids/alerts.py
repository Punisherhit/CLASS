#!/usr/bin/env python3
"""
Alert System - Handles alert notifications for NIDS
Supports console alerts, Telegram, and email
"""

import os
import sqlite3
from datetime import datetime


class AlertSystem:
    def __init__(self):
        self.db_path = os.path.join(os.path.dirname(__file__), 'logs.db')
        
        # Telegram configuration (optional)
        self.telegram_enabled = os.getenv('TELEGRAM_ENABLED', 'false').lower() == 'true'
        self.telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN', '')
        self.telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID', '')
        
        # Email configuration (optional)
        self.email_enabled = os.getenv('EMAIL_ENABLED', 'false').lower() == 'true'
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.email_user = os.getenv('EMAIL_USER', '')
        self.email_password = os.getenv('EMAIL_PASSWORD', '')
        self.alert_email = os.getenv('ALERT_EMAIL', '')
        
        # Severity colors for console output
        self.colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',       # Yellow
            'MEDIUM': '\033[94m',     # Blue
            'LOW': '\033[92m',        # Green
            'INFO': '\033[0m'         # White
        }
        self.reset = '\033[0m'
    
    def send_alert(self, alert):
        """Send alert through all configured channels"""
        # Log to database
        self._log_to_database(alert)
        
        # Console alert (always enabled)
        self._console_alert(alert)
        
        # Telegram alert (if enabled)
        if self.telegram_enabled:
            self._telegram_alert(alert)
        
        # Email alert (if enabled)
        if self.email_enabled:
            self._email_alert(alert)
    
    def _log_to_database(self, alert):
        """Store alert in SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, attacker_ip, attack_type, severity, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            alert['timestamp'],
            alert['attacker_ip'],
            alert['attack_type'],
            alert['severity'],
            alert['details']
        ))
        
        conn.commit()
        conn.close()
    
    def _console_alert(self, alert):
        """Print alert to console with colors"""
        color = self.colors.get(alert['severity'], '')
        
        print(f"\n{color}{'='*60}")
        print(f"🚨 ALERT - {alert['severity']}")
        print(f"{'='*60}{self.reset}")
        print(f"{color}Time: {alert['timestamp']}")
        print(f"Type: {alert['attack_type']}")
        print(f"Source IP: {alert['attacker_ip']}")
        print(f"Details: {alert['details']}{self.reset}")
        print(f"{color}{'='*60}\n{self.reset}")
    
    def _telegram_alert(self, alert):
        """Send alert via Telegram bot"""
        try:
            import requests
            
            message = f"""
🚨 *NIDS Alert - {alert['severity']}*

⏰ Time: `{alert['timestamp']}`
🎯 Type: *{alert['attack_type']}*
📍 Source: `{alert['attacker_ip']}`
📝 Details: {alert['details']}
            """.strip()
            
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            data = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }
            
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                print("✅ Telegram alert sent")
            else:
                print(f"❌ Telegram alert failed: {response.text}")
                
        except Exception as e:
            print(f"❌ Error sending Telegram alert: {e}")
    
    def _email_alert(self, alert):
        """Send alert via email"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            subject = f"[NIDS] {alert['severity']} - {alert['attack_type']} Detected"
            
            body = f"""
NETWORK INTRUSION DETECTION ALERT
==================================

Severity: {alert['severity']}
Time: {alert['timestamp']}
Attack Type: {alert['attack_type']}
Source IP: {alert['attacker_ip']}

Details:
{alert['details']}

---
NIDS - Network Intrusion Detection System
            """.strip()
            
            msg = MIMEMultipart()
            msg['From'] = self.email_user
            msg['To'] = self.alert_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_user, self.email_password)
            server.send_message(msg)
            server.quit()
            
            print("✅ Email alert sent")
            
        except Exception as e:
            print(f"❌ Error sending email alert: {e}")
    
    def get_recent_alerts(self, limit=50):
        """Get recent alerts from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, attacker_ip, attack_type, severity, details
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        columns = ['id', 'timestamp', 'attacker_ip', 'attack_type', 'severity', 'details']
        alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return alerts
    
    def get_alert_stats(self):
        """Get alert statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total alerts
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total = cursor.fetchone()[0]
        
        # Alerts by type
        cursor.execute('''
            SELECT attack_type, COUNT(*) as count
            FROM alerts
            GROUP BY attack_type
        ''')
        by_type = dict(cursor.fetchall())
        
        # Alerts by severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM alerts
            GROUP BY severity
        ''')
        by_severity = dict(cursor.fetchall())
        
        # Top attacker IPs
        cursor.execute('''
            SELECT attacker_ip, COUNT(*) as count
            FROM alerts
            GROUP BY attacker_ip
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_attackers = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total': total,
            'by_type': by_type,
            'by_severity': by_severity,
            'top_attackers': top_attackers
        }
