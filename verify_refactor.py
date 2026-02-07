import sys
import os

print("Verifying refactored structure...")

try:
    from config import load_config
    config = load_config()
    print("Config loaded successfully.")
    
    from logger import setup_logger, get_logger
    logger = setup_logger("test_log.log", console_output=False)
    print("Logger initialized.")
    
    from alerts import AlertManager
    alert_manager = AlertManager(cooldown=10)
    print("AlertManager initialized.")
    
    from rules import PortScanDetector
    detector = PortScanDetector(threshold=10, time_window=60)
    print("PortScanDetector initialized.")
    
    from capture import start_capture
    print("Capture module imported.")
    
    print("All checks passed!")

except ImportError as e:
    print(f"Import Error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Runtime Error: {e}")
    sys.exit(1)
