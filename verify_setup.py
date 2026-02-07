import sys

print("[*] Checking environment...")

# ---- Scapy check ----
try:
    from scapy.all import sniff, IP, TCP
    print("[OK] Scapy imported successfully")
except ImportError as e:
    print(f"[FAIL] Scapy import failed: {e}")
    sys.exit(1)
except Exception as e:
    print(f"[WARN] Scapy runtime issue: {e}")
    print("       (This is expected on Windows without Npcap)")

# ---- Local modules check ----
try:
    import config
    import logger
    import alerts
    import rules
    import capture
    print("[OK] All local modules imported successfully")
except Exception as e:
    print(f"[FAIL] Local module import failed: {e}")
    sys.exit(1)

print("[*] Verification complete.")
