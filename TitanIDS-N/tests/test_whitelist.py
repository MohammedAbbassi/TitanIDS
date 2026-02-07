from rules import PortScanDetector
from scapy.all import IP, TCP
import unittest

class TestWhitelistFix(unittest.TestCase):
    def test_cidr_whitelist(self):
        # Whitelist the entire 192.168.1.0/24 subnet
        detector = PortScanDetector(
            threshold=10, 
            time_window=60, 
            alert_cooldown=30,
            whitelist=["192.168.1.0/24", "10.0.0.1 "] # Note the trailing space
        )
        
        # Test 1: IP in subnet
        pkt_subnet = IP(src="192.168.1.50")/TCP(dport=80)
        detector.analyze_packet(pkt_subnet)
        
        if "192.168.1.50" in detector.ip_activity:
            self.fail("Failed to whitelist IP in CIDR range")
            
        # Test 2: IP with whitespace in config
        pkt_space = IP(src="10.0.0.1")/TCP(dport=80)
        detector.analyze_packet(pkt_space)
        
        if "10.0.0.1" in detector.ip_activity:
            self.fail("Failed to handle whitespace in whitelist")

        print("All whitelist tests passed!")

if __name__ == "__main__":
    unittest.main()
