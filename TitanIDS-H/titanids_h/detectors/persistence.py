from __future__ import annotations
import os
import platform
import subprocess
import re
from typing import Iterable, List
from ..core.detector import Detector
from ..core.event import BaseEvent, FileEvent
from ..core.alert import Alert
from ..core.utils import hostname
from ..core.baseline import BaselineStore
from ..core.severity import choose_severity

class PersistenceDetector(Detector):
    name = "persistence"
    category = "persistence"

    def __init__(self) -> None:
        self.risky = [
            re.compile(r"\.(vbs|js|cmd|bat)$", re.I),
            re.compile(r"powershell", re.I),
            re.compile(r"http(s)?://", re.I),
        ]
        self.baseline = BaselineStore()
        self.auto_accept_runs = 3
        self.trusted_publishers = ["Microsoft", "Microsoft Corporation"]
        self.known_task_prefixes = [r"\\Microsoft\\Windows\\", r"Microsoft\\Windows"]

    def startup_entries(self) -> List[str]:
        entries: List[str] = []
        sys = platform.system().lower()
        if sys.startswith("win"):
            paths = [
                os.path.expandvars(r"%AppData%\Microsoft\Windows\Start Menu\Programs\Startup"),
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            ]
            for p in paths:
                if os.path.isdir(p):
                    for f in os.listdir(p):
                        entries.append(os.path.join(p, f))
            try:
                out = subprocess.check_output(["schtasks", "/query", "/fo", "CSV", "/v"], stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore")
                for line in out.splitlines()[1:]:
                    if line.strip():
                        entries.append(line)
            except Exception:
                pass
        else:
            paths = [
                os.path.expanduser("~/.config/autostart"),
                "/etc/xdg/autostart",
            ]
            for p in paths:
                if os.path.isdir(p):
                    for f in os.listdir(p):
                        entries.append(os.path.join(p, f))
            try:
                out = subprocess.check_output(["sh", "-lc", "crontab -l"], stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore")
                for line in out.splitlines():
                    entries.append(line)
            except Exception:
                pass
        return entries

    def on_event(self, event: BaseEvent) -> Iterable[Alert]:
        return []

    def flush(self):
        alerts: List[Alert] = []
        raw_entries = [str(e) for e in self.startup_entries()]
        curr = [self.entry_fingerprint(s) for s in raw_entries]
        key = "persistence_startup"
        old = self.baseline.get(key)
        if not old:
            self.baseline.set(key, curr)
            impact = 0.2
            confidence = 1.0
            severity = choose_severity(impact, confidence)
            alerts.append(Alert.new(
                host=hostname(),
                type="persistence_baseline",
                detector=self.name,
                category=self.category,
                source="persistence_scan",
                user=None,
                severity=severity,
                title="Baseline established for persistence entries",
                description="Recorded initial startup entries for baseline comparison",
                confidence=confidence,
                rule_id="PERS-BASELINE",
                evidence={"count": len(curr)},
                remediation="Review baseline and allowlist expected entries",
            ))
            return alerts
        new = self.baseline.diff_new(key, curr)
        if new:
            for fp in new:
                rep = next((s for s in raw_entries if self.entry_fingerprint(s) == fp), fp)
                coarse = self.entry_coarse_key(rep)
                prev_fp = self.baseline.get_coarse_fp(key, coarse) if coarse else None
                is_modified = bool(prev_fp and prev_fp != fp)
                if is_modified:
                    impact = 0.7
                    confidence = 0.7
                    severity = choose_severity(impact, confidence)
                    alerts.append(Alert.new(
                        host=hostname(),
                        type="persistence_modified",
                        detector=self.name,
                        category=self.category,
                        source="persistence_scan",
                        user=None,
                        severity=severity,
                        title="Persistence entry modified",
                        description="Existing startup entry changed from baseline",
                        confidence=confidence,
                        rule_id="PERS-MOD",
                        evidence={"entry": rep, "entry_fp_old": prev_fp, "entry_fp_new": fp, "coarse": coarse},
                        remediation="Verify change; revert or remove if unauthorized",
                        **self._mitre_for_entry(rep)
                    ))
                    # Update coarse mapping to new fingerprint
                    if coarse:
                        self.baseline.set_coarse(key, coarse, fp)
                    continue
                # Trusted allowlist: Microsoft-signed + known task path
                if platform.system().lower().startswith("win"):
                    exe_path = self.extract_exe_path(rep)
                    if exe_path and self.is_trusted_publisher(exe_path) and self.is_known_task_path(rep):
                        self.baseline.add(key, fp)
                        if coarse:
                            self.baseline.set_coarse(key, coarse, fp)
                        continue
                # Baseline auto-accept after N runs
                cnt = self.baseline.bump_count(key, fp)
                if cnt >= self.auto_accept_runs:
                    self.baseline.add(key, fp)
                    if coarse:
                        self.baseline.set_coarse(key, coarse, fp)
                    impact = 0.1
                    confidence = 0.9
                    severity = choose_severity(impact, confidence)
                    alerts.append(Alert.new(
                        host=hostname(),
                        type="persistence_auto_accepted",
                        detector=self.name,
                        category=self.category,
                        source="persistence_scan",
                        user=None,
                        severity=severity,
                        title="Baseline auto-accepted entry",
                        description="Entry seen repeatedly; auto-added to baseline",
                        confidence=confidence,
                        rule_id="PERS-AUTO",
                        evidence={"entry": rep, "entry_fp": fp, "observations": cnt},
                        remediation="If unintended, remove and mark denylist",
                        **self._mitre_for_entry(rep)
                    ))
                    continue
                # Otherwise, alert as new artifact (assess risk)
                risk = any(r.search(fp) for r in self.risky)
                impact = 0.7 if risk else 0.4
                confidence = 0.7 if risk else 0.5
                severity = choose_severity(impact, confidence)
                alerts.append(Alert.new(
                    host=hostname(),
                    type="persistence_artifact",
                    detector=self.name,
                    category=self.category,
                    source="persistence_scan",
                    user=None,
                    severity=severity,
                    title="New persistence entry observed",
                    description="Startup entry not in baseline; risk assessed",
                    confidence=confidence,
                    rule_id="PERS-001" if risk else "PERS-NEW",
                    evidence={"entry": rep, "entry_fp": fp, "observations": self.baseline.get_count(key, fp)},
                    remediation="Investigate and remove if unauthorized",
                    **self._mitre_for_entry(rep)
                ))
        return alerts

    def entry_fingerprint(self, s: str) -> str:
        t = (s or "").strip()
        lower = t.lower()
        # If CSV-like with quoted fields, try to find the field containing .exe
        if '"' in t and ',' in t:
            fields = []
            buf = ""
            in_q = False
            for ch in t:
                if ch == '"':
                    in_q = not in_q
                    continue
                if ch == ',' and not in_q:
                    fields.append(buf)
                    buf = ""
                else:
                    buf += ch
            if buf:
                fields.append(buf)
            exe_field = next((f for f in fields if ".exe" in f.lower()), "")
            if exe_field:
                exe_field = exe_field.strip()
                return f"exe:{exe_field}"
        # Windows or Linux path entry
        if "\\" in t or "/" in t:
            base = t.split("\\")[-1].split("/")[-1]
            return f"file:{base}"
        # Fallback: strip dates/times and collapse
        clean = re.sub(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", "", lower)
        clean = re.sub(r"\b\d{1,2}:\d{2}(:\d{2})?\b", "", clean)
        clean = re.sub(r"\s+", " ", clean).strip()
        return f"text:{clean}"

    def entry_coarse_key(self, s: str) -> str:
        t = (s or "").strip()
        # Try to extract a task name field from CSV lines
        if '"' in t and ',' in t:
            fields = []
            buf = ""
            in_q = False
            for ch in t:
                if ch == '"':
                    in_q = not in_q
                    continue
                if ch == ',' and not in_q:
                    fields.append(buf)
                    buf = ""
                else:
                    buf += ch
            if buf:
                fields.append(buf)
            # Prefer TaskName-like field or last component after backslashes
            task_field = next((f for f in fields if "\\" in f), "")
            if task_field:
                name = task_field.split("\\")[-1].strip()
                if name:
                    return f"task:{name.lower()}"
        # For file paths, use basename
        if "\\" in t or "/" in t:
            base = t.split("\\")[-1].split("/")[-1].lower()
            return f"file:{base}"
        return f"text:{re.sub(r'\\s+', ' ', t.lower())}"

    def extract_exe_path(self, s: str) -> str | None:
        t = (s or "").strip()
        if '"' in t and ',' in t:
            fields = []
            buf = ""
            in_q = False
            for ch in t:
                if ch == '"':
                    in_q = not in_q
                    continue
                if ch == ',' and not in_q:
                    fields.append(buf)
                    buf = ""
                else:
                    buf += ch
            if buf:
                fields.append(buf)
            exe_field = next((f for f in fields if ".exe" in f.lower()), "")
            if exe_field:
                return exe_field.strip().strip('"')
        return None

    def is_trusted_publisher(self, exe_path: str) -> bool:
        try:
            # Use PowerShell to query Authenticode signature
            cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f"(Get-AuthenticodeSignature '{exe_path}').SignerCertificate.Subject"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore")
            subj = (out or "").strip()
            if not subj:
                return False
            subj_lower = subj.lower()
            return any(p.lower() in subj_lower for p in self.trusted_publishers)
        except Exception:
            return False

    def is_known_task_path(self, s: str) -> bool:
        t = (s or "").lower()
        return any(pref.lower() in t for pref in self.known_task_prefixes)

    def _mitre_for_entry(self, s: str) -> dict:
        t = (s or "").lower()
        if "\\microsoft\\windows\\" in t or "microsoft\\windows" in t:
            return {
                "mitre_tactic": "Persistence",
                "mitre_technique": "Scheduled Task/Job",
                "mitre_subtechnique": "Scheduled Task",
                "mitre_id": "T1053.005",
            }
        if "startup" in t or "autostart" in t:
            return {
                "mitre_tactic": "Persistence",
                "mitre_technique": "Boot or Logon Autostart Execution",
                "mitre_subtechnique": "Startup Items",
                "mitre_id": "T1547.009",
            }
        return {
            "mitre_tactic": "Persistence",
            "mitre_technique": "Boot or Logon Autostart Execution",
            "mitre_id": "T1547",
        }
