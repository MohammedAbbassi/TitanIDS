import ipaddress
from typing import List, Optional
import logging

class PacketProcessor:
    """
    Handles packet admission control, including whitelisting and validation.
    """
    
    def __init__(self, whitelist: Optional[List[str]] = None):
        self.logger = logging.getLogger("IDS_Logger")
        self.whitelist_networks = []
        
        if whitelist:
            for ip_str in whitelist:
                try:
                    ip_str = ip_str.strip()
                    if not ip_str:
                        continue
                        
                    if '/' not in ip_str:
                        network = ipaddress.ip_network(f"{ip_str}/32", strict=False)
                    else:
                        network = ipaddress.ip_network(ip_str, strict=False)
                        
                    self.whitelist_networks.append(network)
                except ValueError:
                    self.logger.warning(f"Invalid whitelist entry ignored: {ip_str}")

    def is_whitelisted(self, src_ip: str) -> bool:
        """
        Check if an IP address is in the whitelist.
        """
        try:
            src_ip_obj = ipaddress.ip_address(src_ip)
            for network in self.whitelist_networks:
                if src_ip_obj in network:
                    return True
        except ValueError:
            return False
        return False

    def validate_packet(self, packet) -> bool:
        """
        Basic packet validation.
        """
        return packet.haslayer("IP")
