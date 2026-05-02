# NIDS - Network Intrusion Detection System

A lightweight, Python-based Network Intrusion Detection System that captures live network traffic, detects suspicious activity, and provides a real-time dashboard.

## 🛡️ Features

- **Packet Sniffing**: Capture live network traffic using Scapy
- **Detection Engine**: 
  - 🚨 Port Scan Detection
  - 🚨 Brute Force Detection (SSH, FTP, RDP, etc.)
  - 🚨 Traffic Spike Detection
- **Logging**: SQLite database + JSON logs
- **Alerts**: Console (colored), Telegram, Email
- **Dashboard**: Real-time web UI with Flask

## 📁 Project Structure

```
nids/
├── sniffer.py          # Main packet sniffer
├── detector.py         # Detection engine with rules
├── alerts.py           # Alert system (console/telegram/email)
├── server.py           # Flask dashboard API
├── logs.db             # SQLite database (auto-created)
└── dashboard/
    └── index.html      # Web dashboard
```

## ⚙️ Installation

### Prerequisites

```bash
pip install scapy flask
```

For optional features:
```bash
pip install requests  # For Telegram alerts
```

### Running on Linux/Mac

```bash
# Run the packet sniffer (requires sudo for raw socket access)
sudo python sniffer.py

# Optional: Specify network interface
sudo python sniffer.py -i eth0

# Run the dashboard server (in another terminal)
python server.py
```

### Running on Windows

```bash
# Install Npcap from https://nmap.org/npcap/
# Run as Administrator
python sniffer.py
python server.py
```

## 🎯 Usage

### Start Sniffing

```bash
# Basic usage
sudo python sniffer.py

# Capture specific number of packets
sudo python sniffer.py -c 1000

# Specify interface
sudo python sniffer.py -i wlan0
```

### Start Dashboard

Open a new terminal:

```bash
python server.py
```

Then visit: **http://localhost:5000**

## 🔔 Alert Configuration

### Console Alerts (Default)
Colored terminal output - always enabled.

### Telegram Alerts (Optional)

1. Create a Telegram bot via [@BotFather](https://t.me/botfather)
2. Get your chat ID from [@userinfobot](https://t.me/userinfobot)
3. Set environment variables:

```bash
export TELEGRAM_ENABLED=true
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
```

### Email Alerts (Optional)

```bash
export EMAIL_ENABLED=true
export EMAIL_USER="your_email@gmail.com"
export EMAIL_PASSWORD="your_app_password"
export ALERT_EMAIL="recipient@example.com"
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT=587
```

## 🧪 Testing Detection Rules

### Test Port Scan Detection

```bash
# In one terminal, start the sniffer
sudo python sniffer.py

# In another terminal, run nmap
nmap -sS 192.168.1.1
```

### Test Brute Force Detection

```bash
# Simulate SSH brute force (for testing only!)
for i in {1..10}; do nc target_ip 22; done
```

## 📊 Detection Thresholds

| Attack Type | Threshold | Time Window |
|-------------|-----------|-------------|
| Port Scan   | 10 ports  | 5 seconds   |
| Brute Force | 5 attempts| 10 seconds  |
| Traffic Spike| 100 packets | 5 seconds |

Modify these in `detector.py` to suit your network.

## 🗄️ Database Schema

### Packets Table
```sql
CREATE TABLE packets (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    flags TEXT,
    payload_size INTEGER
);
```

### Alerts Table
```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    attacker_ip TEXT,
    attack_type TEXT,
    severity TEXT,
    details TEXT
);
```

## 🔌 API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/packets/recent` | Get recent packets |
| `GET /api/alerts/recent` | Get recent alerts |
| `GET /api/alerts/stats` | Get alert statistics |
| `GET /api/traffic/stats` | Get traffic statistics |
| `GET /api/suspicious/ips` | Get suspicious IPs |
| `GET /api/config` | Get system configuration |

## 🚀 Future Enhancements

- [ ] ML-based anomaly detection
- [ ] Firewall integration (auto-block IPs)
- [ ] Raspberry Pi deployment guide
- [ ] Custom rule engine
- [ ] Packet payload inspection
- [ ] GeoIP lookup for IPs
- [ ] Export reports (PDF/CSV)

## ⚠️ Legal Disclaimer

This tool is for educational and authorized security testing purposes only. Ensure you have proper authorization before monitoring any network traffic. The authors are not responsible for misuse.

## 📝 License

MIT License - Feel free to use, modify, and distribute.

---

**Built with ❤️ using Python, Scapy, and Flask**
