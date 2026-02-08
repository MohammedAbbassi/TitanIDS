from __future__ import annotations
import json
import os
from typing import Callable, List
from .alert import Alert

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False

def _color_for_severity_rich(sev: str) -> str:
    s = (sev or "").upper()
    colors = {
        "INFO": "blue",
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "orange1",
        "CRITICAL": "bold red"
    }
    return colors.get(s, "white")

def pretty_console_sink(alert: Alert) -> None:
    if not HAS_RICH:
        # Fallback if rich is missing (though we added it to requirements)
        print(f"[{alert.severity}] {alert.title} ({alert.host})")
        return

    sev_color = _color_for_severity_rich(alert.severity)
    
    # Construct panel content matching TitanIDS style
    # Header: Type
    # Details: Host, Time, User, Source, Detector...
    
    content = f"[bold]{alert.type}[/]\n"
    content += f"Host: [bold cyan]{alert.host}[/]  Time: {alert.time_utc}\n"
    content += f"User: {alert.user or '-'}  Source: {alert.source}\n"
    content += f"Detector: {alert.detector}  Rule: {alert.rule_id}\n"
    if alert.mitre_id or alert.mitre_technique:
        mitre_line = f"MITRE: {alert.mitre_id or ''} {alert.mitre_tactic or ''} — {alert.mitre_technique or ''}"
        if alert.mitre_subtechnique:
            mitre_line += f" / {alert.mitre_subtechnique}"
        content += f"{mitre_line}\n"
    content += f"\n[bold]Title:[/]: {alert.title}\n"
    content += f"Explanation: {alert.description}\n"
    
    if alert.evidence:
        ev_pairs = ", ".join(f"{k}={v}" for k, v in list(alert.evidence.items())[:8])
        content += f"\n[dim]Evidence: {ev_pairs}[/]"
        
    if alert.remediation:
        content += f"\n\n[italic]Remediation: {alert.remediation}[/]"

    console.print(Panel(
        content,
        title=f"🚨 {alert.severity} ALERT",
        border_style=sev_color,
        expand=False
    ))

def json_file_sink(path: str) -> Callable[[Alert], None]:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    def sink(alert: Alert) -> None:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")
    return sink

def json_stdout_sink(alert: Alert) -> None:
    print(json.dumps(alert.to_dict(), ensure_ascii=False))

class MultiSink:
    def __init__(self, sinks: List[Callable[[Alert], None]]) -> None:
        self.sinks = list(sinks)
    def __call__(self, alert: Alert) -> None:
        for s in self.sinks:
            try:
                s(alert)
            except Exception:
                pass
