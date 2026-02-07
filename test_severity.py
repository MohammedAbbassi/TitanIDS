from rules import PortScanDetector
from alerts import AlertSeverity
from scapy.all import IP, TCP
import unittest
from unittest.mock import MagicMock

class TestSeverity(unittest.TestCase):
    def setUp(self):
        self.detector = PortScanDetector(threshold=10, time_window=60, alert_cooldown=30)
        self.detector.alert_manager.raise_alert = MagicMock()

    def test_low_severity(self):
        # 11 ports -> LOW (Threshold is 10)
        self._simulate_scan(11)
        self.detector.alert_manager.raise_alert.assert_called_with(
            "Port Scan", "1.1.1.1", AlertSeverity.LOW
        )

    def test_medium_severity(self):
        # 21 ports -> MEDIUM (> 2*10)
        self._simulate_scan(21)
        self.detector.alert_manager.raise_alert.assert_called_with(
            "Port Scan", "1.1.1.1", AlertSeverity.MEDIUM
        )
        
    def test_high_severity(self):
        # 51 ports -> HIGH (> 5*10)
        self._simulate_scan(51)
        self.detector.alert_manager.raise_alert.assert_called_with(
            "Port Scan", "1.1.1.1", AlertSeverity.HIGH
        )

    def test_critical_severity(self):
        # 101 ports -> CRITICAL (> 10*10)
        self._simulate_scan(101)
        self.detector.alert_manager.raise_alert.assert_called_with(
            "Port Scan", "1.1.1.1", AlertSeverity.CRITICAL
        )

    def _simulate_scan(self, count):
        self.detector.ip_activity.clear()
        self.detector.alert_manager.last_alert_time.clear()
        for i in range(count):
            pkt = IP(src="1.1.1.1")/TCP(dport=i)
            self.detector.analyze_packet(pkt)

if __name__ == "__main__":
    unittest.main()
