from __future__ import annotations
from typing import Iterable, List
import re
from ..core.detector import Detector
from ..core.event import BaseEvent, ProcessEvent
from ..core.alert import Alert
from ..core.utils import hostname
from ..core.severity import choose_severity

class SuspiciousProcessDetector(Detector):
    name = "suspicious_process"
    category = "process"

    def __init__(self) -> None:
        self.bad_names = {
            "psexec.exe",
            "wmic.exe",
            "certutil.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "mshta.exe",
            "curl.exe",
            "wget",
            "netcat",
            "nc",
            "ssh",
        }
        self.bad_cmd_patterns = [
            re.compile(r"(^|\\s)-EncodedCommand(\\s|$)", re.I),
            re.compile(r"(^|\\s)-enc(\\s|$)", re.I),
            re.compile(r"cmd\.exe.*?/c.*?(bitsadmin|certutil|powershell)", re.I),
            re.compile(r"rundll32\.exe.*?(javascript|url)", re.I),
            re.compile(r"regsvr32\.exe.*?/i.*?http", re.I),
            re.compile(r"(curl|wget).*(http|https)://", re.I),
            re.compile(r"powershell.*?(downloadstring|iwr|Invoke-WebRequest|New-Object Net\\.WebClient)", re.I),
            re.compile(r"ssh.*?-D\s*\d+", re.I),
        ]

    def on_event(self, event: BaseEvent) -> Iterable[Alert]:
        if isinstance(event, ProcessEvent):
            name = (event.name or "").lower()
            cmdline = event.cmdline or ""
            is_ps = name in {"powershell.exe", "powershell"}
            cmatch = any(p.search(cmdline) for p in self.bad_cmd_patterns)
            if is_ps:
                if not cmatch:
                    return []
                encoded = re.search(r"(^|\\s)-(EncodedCommand|enc)(\\s|$)", cmdline, re.I) is not None
                networky = re.search(r"(downloadstring|Invoke-WebRequest|iwr|http(s)?://)", cmdline, re.I) is not None
                impact = 0.9 if encoded else (0.8 if networky else 0.6)
                confidence = 0.9 if encoded else (0.8 if networky else 0.6)
                severity = choose_severity(impact=impact, confidence=confidence, rate_per_sec=None)
            else:
                nmatch = any(n == name for n in self.bad_names)
                if not (nmatch or cmatch):
                    return []
                impact = 0.6 if cmatch else 0.4
                confidence = 0.7 if cmatch else 0.5
                severity = choose_severity(impact=impact, confidence=confidence, rate_per_sec=None)
                yield Alert.new(
                    host=hostname(),
                    type="suspicious_process_execution",
                    detector=self.name,
                    category=self.category,
                    source=event.source,
                    user=event.user,
                    severity=severity,
                title="Suspicious process execution",
                description="Process matched risky PowerShell or denylist patterns" if is_ps else "Process matched denylist or risky commandline",
                    confidence=confidence,
                    rule_id="PROC-001",
                    evidence={
                        "pid": event.pid,
                        "name": event.name,
                        "cmdline": event.cmdline,
                        "exe": event.exe,
                    },
                    remediation="Review process and terminate if unauthorized",
                    mitre_tactic="Execution",
                    mitre_technique="Command and Scripting Interpreter",
                    mitre_subtechnique="PowerShell" if is_ps else None,
                    mitre_id="T1059.001" if is_ps else "T1059",
                )
        return []
