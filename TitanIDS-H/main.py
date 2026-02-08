import json
import time
import argparse
from typing import List
from titanids_h.core.engine import DetectionEngine
from titanids_h.core.alert import Alert
from titanids_h.core.sink import MultiSink, pretty_console_sink, json_stdout_sink, json_file_sink
from titanids_h.core.config import DetectionConfig
from titanids_h.core.logging import setup_logger
import platform
from titanids_h.core.event import ProcessEvent, BaseEvent
from titanids_h.core.utils import list_processes, hostname
from titanids_h.detectors import SuspiciousProcessDetector, PersistenceDetector, BruteForceAuthDetector
from titanids_h.sources.windows_security import WindowsSecuritySource
from titanids_h.sources.process_creation import ProcessCreationSource
from titanids_h.sources.linux_logs import LinuxAuthSyslogSource
from titanids_h.core.agent import Agent
try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    HAS_RICH = True
    _banner_console = Console()
except ImportError:
    HAS_RICH = False

def show_banner() -> None:
    path = "ascii-text-art.txt"
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().rstrip("\n")
            lines = content.splitlines()
            print()
            if HAS_RICH:
                for i, line in enumerate(lines):
                    _banner_console.print(line, style=("cyan"))
                title = Text("🛡️ TITAN IDS-H", style="bold cyan")
                sub = Text("Host Intrusion Detection System", style="dim white")
                _banner_console.print(Panel(title, subtitle="BETA", border_style="blue", expand=False))
                _banner_console.print(sub)
            else:
                for i, line in enumerate(lines):
                    color = "\033[36m" if i % 2 == 0 else "\033[32m"
                    print(f"{color}{line}\033[0m")
            print()
    except Exception:
        print("\n🛡️  TITAN IDS-N\n")

def show_status(engine: DetectionEngine, interval: float) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    print(f"Status • Host: {hostname()} • Alerts: {engine.alerts_emitted} • Interval: {interval}s • Throttle: {engine.throttle_window_seconds}s • Time: {ts}")

def make_sink(output: str, log_file: str | None) -> MultiSink:
    sinks = []
    # STDOUT Handling
    if output == "json":
        # User explicitly requested JSON on stdout (e.g. for piping)
        sinks.append(json_stdout_sink)
    elif output == "pretty":
        # User explicitly requested Pretty on stdout
        sinks.append(pretty_console_sink)
    else:
        # Default/Both: Prefer Pretty on stdout, JSON goes to file only
        # This separates presentation (Pretty) from emission (JSON file)
        sinks.append(pretty_console_sink)
    
    # FILE Handling (Always active if log_file is present)
    if log_file:
        sinks.append(json_file_sink(log_file))
        
    return MultiSink(sinks)

def build_engine(output: str, log_file: str | None, config_path: str | None, app_log: str, console_log: bool, throttle_default: int | None) -> DetectionEngine:
    logger = setup_logger(log_file=app_log, console=console_log)
    cfg = DetectionConfig.load(config_path)
    detectors = [
        SuspiciousProcessDetector(),
        PersistenceDetector(),
        BruteForceAuthDetector(),
    ]
    tw = throttle_default if throttle_default is not None else cfg.throttle_default
    return DetectionEngine(detectors=detectors, alert_sink=make_sink(output, log_file), throttle_window_seconds=tw, config=cfg, logger=logger)

def collect_process_events(engine: DetectionEngine) -> None:
    h = hostname()
    for p in list_processes():
        try:
            pid = int(p.get("pid") or 0)
        except Exception:
            pid = 0
        event = ProcessEvent(
            time_utc=ProcessEvent.now(),
            host=h,
            source="process_scan",
            data={},
            pid=pid,
            name=p.get("name"),
            exe=p.get("exe"),
            cmdline=p.get("cmdline"),
            user=p.get("user"),
        )
        engine.process_event("process", event)

def run_once(engine: DetectionEngine, config_path: str | None) -> None:
    show_banner()
    agent = Agent(engine=engine, interval=0.0, config_path=config_path)
    agent.run_once()
    show_status(engine, 0.0)
    print("Tip: use --loop for continuous monitoring.")

def run_loop(engine: DetectionEngine, interval: float, config_path: str | None) -> None:
    show_banner()
    print("Press 'q' to stop.")
    agent = Agent(engine=engine, interval=interval, config_path=config_path)
    agent.start()
    while True:
        show_status(engine, interval)
        end_time = time.time() + interval
        while time.time() < end_time:
            if platform.system().lower().startswith("win"):
                import msvcrt
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key.lower() == b'q':
                        agent.stop()
                        print("\n[TitanIDS-H] Stopped.")
                        return
                    if key.lower() == b'r':
                        agent.reload(config_path)
                        print("[TitanIDS-H] Reloaded configuration.")
            time.sleep(0.1)

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--output", choices=["json", "pretty", "both"], default="both")
    parser.add_argument("--log-file", type=str, default="logs/alerts.jsonl")
    parser.add_argument("--config", type=str, default=None)
    parser.add_argument("--app-log", type=str, default="logs/app.log")
    parser.add_argument("--no-console-log", action="store_true")
    parser.add_argument("--throttle", type=int, default=None)
    args = parser.parse_args()
    engine = build_engine(
        output=args.output,
        log_file=args.log_file,
        config_path=args.config,
        app_log=args.app_log,
        console_log=not args.no_console_log,
        throttle_default=args.throttle,
    )
    if args.loop:
        run_loop(engine, args.interval, args.config)
    else:
        run_once(engine, args.config)

if __name__ == "__main__":
    main()
