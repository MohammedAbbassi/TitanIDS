import csv
import json
import logging
import os
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.logging import RichHandler

# Initialize Rich Console
console = Console()

class OutputFormat(Enum):
    TEXT = "text"
    JSON = "json"
    CSV = "csv"

class OutputManager:
    """
    Manages all output channels: Console (Rich), Text Log, JSON Log, CSV Log.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = self._setup_logger()
        self.siem_format = config.get("SIEM_OUTPUT_FORMAT", "json").lower()
        self.json_file = config.get("JSON_LOG_FILE", "alerts.json")
        self.csv_file = config.get("CSV_LOG_FILE", "alerts.csv")
        
        # Initialize CSV header if file doesn't exist
        if self.siem_format == "csv" and not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "severity", "alert_type", "source_ip", "details"])

    def _setup_logger(self) -> logging.Logger:
        """Configure logging to write to a file and optionally to the console."""
        log_file = self.config.get("LOG_FILE", "ids.log")
        console_output = self.config.get("CONSOLE_OUTPUT", True)
        
        logger = logging.getLogger("IDS_Logger")
        logger.setLevel(logging.INFO)
        
        if logger.hasHandlers():
            logger.handlers.clear()

        file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        if console_output:
            console_handler = RichHandler(rich_tracebacks=True, markup=True)
            logger.addHandler(console_handler)
            
        return logger

    def log_alert(self, alert_type: str, source_ip: str, severity: str, details: Optional[Dict] = None):
        """
        Log an alert to all configured channels.
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"[{timestamp}] [ALERT][{severity}] {alert_type} detected from {source_ip}"
        
        # 1. Text Log
        if severity in ["HIGH", "CRITICAL"]:
            self.logger.error(message)
        else:
            self.logger.warning(message)
            
        # 2. Console Display (Rich)
        self._print_rich_alert(alert_type, source_ip, severity, timestamp)
        
        # 3. SIEM Output (JSON/CSV)
        self._write_siem_log(timestamp, severity, alert_type, source_ip, details)

    def log_suppressed(self, alert_type: str, source_ip: str, count: int):
        """
        Log a suppressed alert if enabled.
        """
        if self.config.get("LOG_SUPPRESSED_ALERTS", False):
            self.logger.info(f"Suppressed {count} {alert_type} alerts from {source_ip} (Cooldown active)")

    def _print_rich_alert(self, alert_type: str, source_ip: str, severity: str, timestamp: str):
        colors = {
            "INFO": "blue",
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "orange1",
            "CRITICAL": "bold red"
        }
        color = colors.get(severity, "white")
        panel_content = f"[bold]{alert_type}[/]\nSource: [bold cyan]{source_ip}[/]\nTime: {timestamp}"
        
        console.print(Panel(
            panel_content,
            title=f"🚨 {severity} ALERT",
            border_style=color,
            expand=False
        ))

    def _write_siem_log(self, timestamp: str, severity: str, alert_type: str, source_ip: str, details: Optional[Dict]):
        data = {
            "timestamp": timestamp,
            "severity": severity,
            "alert_type": alert_type,
            "source_ip": source_ip,
            "details": details or {}
        }
        
        try:
            if self.siem_format == "json":
                with open(self.json_file, 'a') as f:
                    f.write(json.dumps(data) + "\n")
            elif self.siem_format == "csv":
                with open(self.csv_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, severity, alert_type, source_ip, json.dumps(details or {})])
        except Exception as e:
            self.logger.error(f"Failed to write SIEM log: {e}")

    def print_banner(self):
        title = Text("🛡️ TITAN IDS", style="bold cyan")
        subtitle = Text("Intrusion Detection System", style="dim white")
        console.print(Panel(title, subtitle="BETA", border_style="blue", expand=False))

    def print_status(self):
        table = Table(title="System Configuration", show_header=True, header_style="bold magenta")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Log File", self.config.get("LOG_FILE"))
        table.add_row("SIEM Format", self.siem_format)
        table.add_row("Interface", str(self.config.get("INTERFACE", "Auto")))
        table.add_row("Mode", "Mock" if self.config.get("MOCK_MODE") else "Live")
        
        console.print(table)
        console.print()
