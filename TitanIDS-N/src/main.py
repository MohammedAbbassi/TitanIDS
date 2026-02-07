import argparse
import json
import sys
from typing import Dict, Any

from capture import start_capture
from config import load_config
from output import OutputManager
from alerts import AlertManager
from processing import PacketProcessor
from rules import DetectionEngine

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TITAN IDS")
    parser.add_argument("--mock", action="store_true", help="Enable mock mode (synthetic traffic)")
    parser.add_argument("--live", action="store_true", help="Enable live capture mode")
    parser.add_argument("--config", type=str, help="Path to a JSON configuration file to override defaults")
    parser.add_argument("--iface", type=str, help="Interface name to use (manual override)")
    return parser.parse_args()

def merge_config(base_config: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
    """
    Merge default config with CLI arguments and external JSON config.
    """
    config = base_config.copy()
    
    # 1. Load external JSON config if provided
    if args.config:
        try:
            with open(args.config, 'r') as f:
                external_config = json.load(f)
                config.update(external_config)
                print(f"Loaded configuration from {args.config}")
        except Exception as e:
            print(f"Error loading config file: {e}")
            sys.exit(1)
            
    # 2. Apply CLI flags (Priority over config file)
    if args.mock:
        config["MOCK_MODE"] = True
    elif args.live:
        config["MOCK_MODE"] = False
    
    if args.iface:
        config["INTERFACE"] = args.iface
        
    return config

def main() -> None:
    """
    Main entry point for the Intrusion Detection System.
    """
    args = parse_arguments()
    
    # 1. Load & Merge Configuration
    default_config = load_config()
    config = merge_config(default_config, args)
    
    # 2. Initialize Output Manager (Logger, Console, SIEM)
    output_manager = OutputManager(config)
    output_manager.print_banner()
    output_manager.print_status()
    
    # 3. Initialize Pipeline Components
    try:
        # Alert Layer
        alert_manager = AlertManager(
            output_manager, 
            cooldown=config["ALERT_COOLDOWN"]
        )
        
        # Processing Layer (Admission Control)
        processor = PacketProcessor(
            whitelist=config["WHITELIST_IPS"]
        )
        
        # Detection Layer (Rules)
        engine = DetectionEngine(alert_manager, config)
        
        # 4. Start Capture Loop
        output_manager.logger.info(f"Starting IDS... Logging to {config['LOG_FILE']}")
        start_capture(config, processor, engine)
        
    except KeyboardInterrupt:
        output_manager.logger.info("\nStopping IDS...")
        output_manager.console.print("[bold red]IDS Stopped[/bold red]")
    except Exception as e:
        output_manager.logger.error(f"Critical Alert: {e}")
        output_manager.console.print_exception()

if __name__ == "__main__":
    main()
