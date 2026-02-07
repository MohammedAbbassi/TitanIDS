from typing import Dict, Any

def load_config() -> Dict[str, Any]:
    """
    Load the IDS configuration settings.
    """
    return {
        # --- General ---
        "INTERFACE": r"\Device\NPF_{D1DE4557-ACD5-453C-B89D-CB34A2BF4417}", # None = Auto-detect
        "MOCK_MODE": False, # Can be overridden by CLI
        
        # --- Output & Logging ---
        "LOG_FILE": "ids.log",
        "CONSOLE_OUTPUT": True,
        "SIEM_OUTPUT_FORMAT": "json", # Options: "json", "csv"
        "JSON_LOG_FILE": "alerts.json",
        "CSV_LOG_FILE": "alerts.csv",
        "LOG_SUPPRESSED_ALERTS": True,
        "SUPPRESSION_LOG_INTERVAL": 15,
        "SUPPRESSION_LOG_MODE": "aggregate",
        
        # --- Live capture behavior ---
        "FALLBACK_ON_IDLE": True,       # Auto-switch to mock if no packets seen
        "LIVE_IDLE_TIMEOUT": 10,        # Seconds without packets before fallback
        
        # --- Detection Thresholds ---
        "TIME_WINDOW": 60, # Seconds
        "ALERT_COOLDOWN": 30, # Seconds
        
        "PORT_SCAN_THRESHOLD": 15,
        "SYN_FLOOD_THRESHOLD": 100, # SYN packets per time window
        "BRUTE_FORCE_THRESHOLD": 5, # Attempts per time window
        
        # --- Whitelist ---
        "WHITELIST_IPS": [
              
        ],
        
        # --- Signature Engine ---
        "ENABLE_SIGNATURES": True,
        "SIGNATURE_MIN_LEN": 20,
        "HTTP_PORTS": [80, 8080, 8000],
        "DB_PORTS": [3306, 5432, 1433],
        "SIGNATURES": {
            "cmd.exe": "Remote Command Execution",
            "/etc/passwd": "Path Traversal Attempt",
            "UNION SELECT": "SQL Injection Attempt",
            "eval(": "Code Injection Attempt"
        }
    }
