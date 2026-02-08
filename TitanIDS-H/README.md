# TitanIDS-H BETA 🚨

**TitanIDS-H** is a Host-based Intrusion Detection System (HIDS) designed to monitor Windows endpoints for suspicious activity in real-time. It detects persistence artifacts, suspicious processes, and other host-level anomalies to enhance endpoint security.

---

## Features

- **Persistence Monitoring** – Detects new or unauthorized startup entries, scheduled tasks, and registry modifications.
- **Process Monitoring** – Identifies suspicious process execution or risky command lines.
- **JSON Logging** – All alerts are logged in a structured JSON format for easy integration with SIEM tools.
- **Duplicate Alert Suppression** – Reduces alert noise by suppressing repeated alerts within a configurable window.
- **Lightweight & Modular** – Can run continuously on a Windows host with minimal resource usage.

---

## Getting Started

### Requirements

- Python 3.10+
- Windows 10 or higher

### Installation

1. Clone the repository:

```bash
git clone https://github.com/f1nezera/TitanIDS-H.git
cd TitanIDS-H
```
**(Optional) Create a virtual environment:**

```bash
python -m venv venv
.\venv\Scripts\activate
```


Install dependencies:

```bash
pip install -r requirements.txt
```


Running TitanIDS-H

**Start the IDS in live monitoring mode:**

```bash
python src/main.py
```
**Press q to stop monitoring.**

Alerts will be displayed in the console and saved in data/ids.log.

Contributing

Contributions are welcome! Please follow these steps:

Fork the repository.

Create a feature branch (git checkout -b feature/my-feature).

Commit your changes (git commit -m "Add feature").

Push to your branch (git push origin feature/my-feature).

Create a Pull Request.

License

This project is licensed under the MIT License. See the LICENSE
 file for details.

Disclaimer

This software is for educational and research purposes only. The author is not responsible for any misuse or damage caused by running this software on production systems.
