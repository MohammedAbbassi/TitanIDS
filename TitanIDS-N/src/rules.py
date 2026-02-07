from collections import defaultdict
import time
import re
from urllib.parse import unquote
from typing import Dict, List, Tuple, Set, Optional
from alerts import AlertManager

class BaseDetector:
    def __init__(self, alert_manager: AlertManager, time_window: int):
        self.alert_manager = alert_manager
        self.time_window = time_window
        self.ip_activity = defaultdict(list) # Generic activity store

    def prune_old_events(self, ip: str, current_time: float) -> List[Tuple]:
        valid_events = [
            ev for ev in self.ip_activity[ip]
            if current_time - ev[-1] < self.time_window # Assume timestamp is last element
        ]
        self.ip_activity[ip] = valid_events
        return valid_events

class PortScanDetector(BaseDetector):
    def __init__(self, alert_manager: AlertManager, threshold: int, time_window: int):
        super().__init__(alert_manager, time_window)
        self.threshold = threshold

    def analyze(self, packet, src_ip: str, current_time: float):
        if packet.haslayer("TCP"):
            dst_port = packet["TCP"].dport
            self.ip_activity[src_ip].append((dst_port, current_time))
            
            valid_events = self.prune_old_events(src_ip, current_time)
            unique_ports = {ev[0] for ev in valid_events}
            
            if len(unique_ports) > self.threshold:
                severity = self._calculate_severity(len(unique_ports))
                self.alert_manager.raise_alert(
                    "Port Scan", 
                    src_ip, 
                    severity, 
                    {"ports_scanned": len(unique_ports)}
                )

    def _calculate_severity(self, num_ports: int) -> str:
        if num_ports >= self.threshold * 10: return "CRITICAL"
        if num_ports >= self.threshold * 5: return "HIGH"
        if num_ports >= self.threshold * 2: return "MEDIUM"
        return "LOW"

class SYNFloodDetector(BaseDetector):
    def __init__(self, alert_manager: AlertManager, threshold: int, time_window: int):
        super().__init__(alert_manager, time_window)
        self.threshold = threshold

    def analyze(self, packet, src_ip: str, current_time: float):
        if packet.haslayer("TCP") and packet["TCP"].flags == "S":
            self.ip_activity[src_ip].append((1, current_time)) # 1 is placeholder
            
            valid_events = self.prune_old_events(src_ip, current_time)
            syn_count = len(valid_events)
            
            if syn_count > self.threshold:
                severity = "CRITICAL" if syn_count > self.threshold * 2 else "HIGH"
                self.alert_manager.raise_alert(
                    "SYN Flood", 
                    src_ip, 
                    severity,
                    {"syn_count": syn_count}
                )

class BruteForceDetector(BaseDetector):
    """
    Simulated Brute Force Detector: tracks rapid connections to sensitive ports.
    """
    SENSITIVE_PORTS = {22, 21, 23, 3389}

    def __init__(self, alert_manager: AlertManager, threshold: int, time_window: int):
        super().__init__(alert_manager, time_window)
        self.threshold = threshold

    def analyze(self, packet, src_ip: str, current_time: float):
        if packet.haslayer("TCP"):
            dst_port = packet["TCP"].dport
            if dst_port in self.SENSITIVE_PORTS:
                self.ip_activity[src_ip].append((dst_port, current_time))
                
                valid_events = self.prune_old_events(src_ip, current_time)
                count = len(valid_events)
                
                if count > self.threshold:
                    self.alert_manager.raise_alert(
                        f"Brute Force Attempt (Port {dst_port})",
                        src_ip,
                        "HIGH",
                        {"attempts": count, "target_port": dst_port}
                    )

class SignatureDetector:
    def __init__(self, alert_manager: AlertManager, config: Dict):
        self.alert_manager = alert_manager
        self.http_ports = set(config.get("HTTP_PORTS", [80, 8080, 8000]))
        self.db_ports = set(config.get("DB_PORTS", [3306, 5432, 1433]))
        self.min_len = int(config.get("SIGNATURE_MIN_LEN", 20))
        self.enabled = bool(config.get("ENABLE_SIGNATURES", True))
        # Compile regex rules (case-insensitive, word boundaries)
        self.rules = [
            (re.compile(r"\bunion\s+select\b", re.I), "SQL Injection" , "http|db"),
            (re.compile(r"/etc/passwd", re.I), "Path Traversal", "http"),
            (re.compile(r"\beval\s*\(", re.I), "Code Injection", "http"),
            (re.compile(r"\bcmd\.exe\b", re.I), "Remote Command Exec", "http"),
        ]
        # Include user-defined simple substrings from config as broad rules (any context)
        for sig, name in config.get("SIGNATURES", {}).items():
            try:
                self.rules.append((re.compile(re.escape(sig), re.I), name, "any"))
            except Exception:
                pass

    def _is_textual(self, s: str) -> bool:
        printable_ratio = sum(ch.isprintable() for ch in s) / max(1, len(s))
        return printable_ratio > 0.8

    def _looks_http(self, payload: str) -> bool:
        return payload.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ")) or "HTTP/1." in payload

    def analyze(self, packet, src_ip: str, current_time: float):
        if not self.enabled or not packet.haslayer("TCP") or not packet.haslayer("Raw"):
            return
        try:
            dport = packet["TCP"].dport
            payload = packet["Raw"].load.decode('utf-8', errors='ignore')
            payload_norm = unquote(payload).lower()
            if len(payload_norm) < self.min_len or not self._is_textual(payload_norm):
                return

            context = None
            if dport in self.http_ports and self._looks_http(payload):
                context = "http"
            elif dport in self.db_ports:
                context = "db"
            else:
                context = "any"

            indicators = []
            for regex, name, scope in self.rules:
                if scope == "any" or scope == context or scope == "http|db" and context in ("http", "db"):
                    if regex.search(payload_norm):
                        indicators.append(name)

            if not indicators:
                return

            # Elevate severity when multiple indicators match
            sev = "MEDIUM" if len(indicators) == 1 else ("HIGH" if len(indicators) == 2 else "CRITICAL")
            self.alert_manager.raise_alert(
                f"Signature Match", src_ip, sev, {"indicators": indicators, "context": context}
            )
        except Exception:
            return

class DetectionEngine:
    def __init__(self, alert_manager: AlertManager, config: Dict):
        self.detectors = [
            PortScanDetector(
                alert_manager, 
                config.get("PORT_SCAN_THRESHOLD", 10), 
                config.get("TIME_WINDOW", 60)
            ),
            SYNFloodDetector(
                alert_manager, 
                config.get("SYN_FLOOD_THRESHOLD", 100), 
                config.get("TIME_WINDOW", 60)
            ),
            BruteForceDetector(
                alert_manager, 
                config.get("BRUTE_FORCE_THRESHOLD", 5), 
                config.get("TIME_WINDOW", 60)
            ),
            SignatureDetector(
                alert_manager,
                config
            )
        ]

    def process_packet(self, packet) -> None:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            current_time = time.time()
            
            for detector in self.detectors:
                detector.analyze(packet, src_ip, current_time)
