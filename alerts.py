import time
from typing import Dict, Optional
from output import OutputManager

class AlertManager:
    """
    Manages alert generation, cooldowns, and suppression tracking.
    """
    
    def __init__(self, output_manager: OutputManager, cooldown: int = 30):
        self.output_manager = output_manager
        self.alert_cooldown = cooldown
        self.last_alert_time: Dict[str, float] = {}
        self.suppressed_counts: Dict[str, int] = {}
        self.suppressed_last_log_time: Dict[str, float] = {}

    def raise_alert(self, alert_type: str, source_ip: str, severity: str, details: Optional[Dict] = None) -> None:
        """
        Raise an alert if cooldown has passed.
        """
        current_time = time.time()
        last_time = self.last_alert_time.get(source_ip, 0)
        
        # Unique key for tracking specific alert types per IP
        alert_key = f"{source_ip}:{alert_type}"
        
        if current_time - last_time < self.alert_cooldown:
            self.suppressed_counts[alert_key] = self.suppressed_counts.get(alert_key, 0) + 1
            mode = self.output_manager.config.get("SUPPRESSION_LOG_MODE", "aggregate")
            if mode == "immediate" and self.output_manager.config.get("LOG_SUPPRESSED_ALERTS", False):
                last_log = self.suppressed_last_log_time.get(alert_key, 0)
                interval = self.output_manager.config.get("SUPPRESSION_LOG_INTERVAL", 15)
                if current_time - last_log >= interval:
                    self.output_manager.log_suppressed(alert_type, source_ip, self.suppressed_counts[alert_key])
                    self.suppressed_last_log_time[alert_key] = current_time
            return

        # Cooldown passed, allow alert
        self.last_alert_time[source_ip] = current_time
        
        # Check if we suppressed any alerts previously
        suppressed = self.suppressed_counts.pop(alert_key, 0)
        self.suppressed_last_log_time.pop(alert_key, None)
        if suppressed > 0:
            if details is None:
                details = {}
            details['suppressed_count'] = suppressed
            
        self.output_manager.log_alert(alert_type, source_ip, severity, details)
