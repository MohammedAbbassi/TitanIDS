# 🛡️ TITAN IDS v2.0

**A modular Intrusion Detection System (IDS) built in Python**  
Detects port scans, SYN floods, and brute-force attempts with real-time alerts.

---

## Features

- **Port Scan Detection**: Detects multiple ports accessed in a short time window.
- **SYN Flood Detection**: Identifies unusual TCP SYN traffic patterns.
- **Brute-Force Detection**: Monitors repeated connection attempts to protected services.
- **Whitelist Support**: Ignore trusted IPs or subnets to reduce false positives.
- **Severity Levels**: Alerts classified as LOW, MEDIUM, HIGH, or CRITICAL.
- **Live & Mock Mode**: Works on live network or generates synthetic traffic for testing.
- **Rich Logging**: Logs to file and console with colored output and timestamped alerts.

---

## Installation

1. **Clone the repository**  

```bash
git clone https://github.com/YOUR_USERNAME/SimpleIDS.git
cd SimpleIDS
```
2. **Create a virtual environment (optional but recommended)**

```bash
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS
```
3. **Install dependencies**

```bash
pip install -r requirements.txt
#Note: On Windows, ensure Npcap is installed for live packet capture. Without it, the IDS will run in Mock Mode.
```
4. **Configuration**

Edit config.py to adjust:
```python
PORT_SCAN_THRESHOLD = 10      # Number of unique ports to trigger alert
TIME_WINDOW = 60              # Time window in seconds
ALERT_COOLDOWN = 30           # Minimum seconds between repeated alerts
LOG_FILE = "ids.log"          # Log file name
INTERFACE = None              # Network interface to monitor (auto-detect if None)
CONSOLE_OUTPUT = True         # Print alerts to console
WHITELIST_IPS = ["127.0.0.1", "192.168.1.1", "192.168.1.50"]
```
You can set INTERFACE automatically by running from scapy.all import get_if_list and picking an interface that can send/receive packets on your LAN.
Usage

Run the IDS:
```python
py main.py
```

Press Ctrl+C to stop.
In Mock Mode, synthetic attacks are generated to test detection.
Alerts are shown in console and saved to ids.log.


**Safe Demo**

For a safe demonstration:
**Use Nmap to simulate a port scan on your local network:**

```bash
nmap -p 1-100 192.168.1.1
```
The IDS will log and display a port scan alert.

**Do not scan external IPs — only your own devices or lab network.**
