from scapy.all import sniff, IP, TCP, Raw, get_if_list, get_if_addr
from typing import Dict, Any
import time
import random
import logging
import threading
import sys
from rules import DetectionEngine
from processing import PacketProcessor

logger = logging.getLogger("IDS_Logger")

def start_capture(config: Dict[str, Any], processor: PacketProcessor, engine: DetectionEngine) -> None:
    """
    Start the packet capture and analysis process.
    Respects MOCK_MODE flag or falls back if capture fails.
    """
    stop_event = threading.Event()

    # Windows-friendly key listener using msvcrt
    def _start_key_listener():
        try:
            import msvcrt
        except ImportError:
            return  # Non-Windows: rely on Ctrl+C
        logger.info("Press 'q' to stop scanning.")
        while not stop_event.is_set():
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch.lower() == 'q':
                    logger.info("Stop key detected. Stopping capture...")
                    stop_event.set()
                    break
            time.sleep(0.05)

    threading.Thread(target=_start_key_listener, daemon=True).start()
    
    def _blocked(name: str) -> bool:
        n = name.lower()
        blocked = [
            "loopback", "npcap loopback", "bluetooth",
            "vmware", "virtual", "tunnel", "isatap",
            "hyper-v", "bridge", "tap", "tun", "wfp",
            "docker", "container"
        ]
        return any(b in n for b in blocked)

    def _auto_select_interface() -> str | None:
        best: tuple[str, int] | None = None
        fallback_ipv4: str | None = None
        candidates = [iface for iface in get_if_list() if not _blocked(iface)]
        logger.info(f"Discovered interfaces: {', '.join(candidates) if candidates else 'None'}")
        for iface in candidates:
            ipv4 = None
            try:
                ipv4 = get_if_addr(iface)
            except Exception:
                ipv4 = None
            if ipv4:
                fallback_ipv4 = fallback_ipv4 or iface
            try:
                pkts = sniff(iface=iface, timeout=3, store=True)
                count = len(pkts)
                logger.info(f"Probe {iface}: ipv4={bool(ipv4)} packets={count}")
                if count > 0 and (best is None or count > best[1]):
                    best = (iface, count)
            except Exception as e:
                logger.debug(f"Probe failed on {iface}: {e}")
                continue
        chosen = best[0] if best else fallback_ipv4
        if chosen:
            logger.info(f"Auto-selected interface: {chosen}")
        else:
            logger.warning("No usable interface found. Consider --iface or enabling MOCK mode.")
        return chosen

    def process_packet(packet):
        if not processor.validate_packet(packet):
            return
            
        src_ip = packet[IP].src
        if processor.is_whitelisted(src_ip):
            return
            
        engine.process_packet(packet)

    if config.get("MOCK_MODE", False):
        start_mock_capture(config, processor, engine, stop_event)
        return

    try:
        # Choose interface: manual override or auto-selection
        iface = config.get("INTERFACE")
        if not iface:
            iface = _auto_select_interface()
            if iface is None:
                logger.warning("Auto-selection failed; switching to MOCK MODE.")
                start_mock_capture(config, processor, engine, stop_event)
                return
            # Update config for visibility
            config["INTERFACE"] = iface

        logger.info(f"Attempting to start live packet capture... (Mode: LIVE, iface={iface})")
        idle_timeout = int(config.get("LIVE_IDLE_TIMEOUT", 10))
        fallback_on_idle = bool(config.get("FALLBACK_ON_IDLE", True))
        last_packet_time_ref = {"ts": time.time()}

        def _prn(pkt):
            last_packet_time_ref["ts"] = time.time()
            process_packet(pkt)

        # Loop with timeout to detect idle capture and optionally fallback
        while not stop_event.is_set():
            sniff(
                iface=iface,
                prn=_prn,
                store=False,
                timeout=idle_timeout,
                stop_filter=lambda p: stop_event.is_set()
            )
            if stop_event.is_set():
                break
            if fallback_on_idle and (time.time() - last_packet_time_ref["ts"] >= idle_timeout):
                logger.warning(f"No packets observed for {idle_timeout}s. Auto-switching to MOCK MODE.")
                start_mock_capture(config, processor, engine, stop_event)
                break
    except Exception as e:
        logger.warning(f"Live capture failed: {e}")
        logger.warning("Falling back to MOCK MODE. Generating synthetic traffic...")
        start_mock_capture(config, processor, engine, stop_event)

def start_mock_capture(config: Dict[str, Any], processor: PacketProcessor, engine: DetectionEngine, stop_event) -> None:
    """
    Generate synthetic traffic to test the IDS logic.
    Simulates: Normal traffic, Port Scans, SYN Floods, Brute Force, Signatures.
    """
    logger.info("Mock Mode Started. Press 'q' to stop.")
    
    attacker_ip = "192.168.1.100"
    syn_flood_ip = "10.10.10.50"
    brute_ip = "172.16.0.5"
    sig_ip = "192.168.99.99"
    safe_ip = "192.168.1.50"
    
    try:
        while not stop_event.is_set():
            # --- 1. Safe Traffic (70% chance) ---
            if random.random() < 0.7:
                pkt = IP(src=safe_ip) / TCP(dport=80)
                if not processor.is_whitelisted(safe_ip):
                    engine.process_packet(pkt)
            
            # --- 2. Port Scan Attack (10% chance) ---
            if random.random() < 0.1:
                # logger.info(f"Simulating Port Scan from {attacker_ip}...")
                for _ in range(config.get("PORT_SCAN_THRESHOLD", 15) + 5):
                    port = random.randint(20, 1000)
                    pkt = IP(src=attacker_ip) / TCP(dport=port)
                    engine.process_packet(pkt)
            
            # --- 3. SYN Flood Attack (5% chance) ---
            if random.random() < 0.05:
                # logger.info(f"Simulating SYN Flood from {syn_flood_ip}...")
                for _ in range(config.get("SYN_FLOOD_THRESHOLD", 50) + 10):
                    pkt = IP(src=syn_flood_ip) / TCP(dport=80, flags="S")
                    engine.process_packet(pkt)

            # --- 4. Brute Force Attack (5% chance) ---
            if random.random() < 0.05:
                # logger.info(f"Simulating Brute Force SSH from {brute_ip}...")
                for _ in range(config.get("BRUTE_FORCE_THRESHOLD", 5) + 2):
                    pkt = IP(src=brute_ip) / TCP(dport=22)
                    engine.process_packet(pkt)

            # --- 5. Signature Attack (5% chance) ---
            if random.random() < 0.05:
                # logger.info(f"Simulating Malicious Payload from {sig_ip}...")
                payloads = ["/etc/passwd", "cmd.exe", "UNION SELECT", "eval("]
                payload = random.choice(payloads)
                pkt = IP(src=sig_ip) / TCP(dport=80) / Raw(load=payload)
                engine.process_packet(pkt)
            
            time.sleep(0.2) # Throttle loop slightly
            
    except KeyboardInterrupt:
        logger.info("Mock capture stopped.")
    finally:
        logger.info("Capture loop stopped.")
