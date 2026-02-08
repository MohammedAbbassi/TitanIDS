from __future__ import annotations
import platform
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Iterable, List, Dict, Tuple
from ..core.detector import Detector
from ..core.event import BaseEvent, AuthEvent
from ..core.alert import Alert
from ..core.utils import hostname
from ..core.severity import choose_severity

class BruteForceAuthDetector(Detector):
    name = "bruteforce_auth"
    category = "authentication"

    def __init__(self, threshold: int = 5, window_minutes: int = 5) -> None:
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.events: List[AuthEvent] = []

    def on_event(self, event: BaseEvent) -> Iterable[Alert]:
        if isinstance(event, AuthEvent) and not event.success:
            try:
                t = datetime.fromisoformat(event.time_utc.replace("Z", "+00:00"))
            except Exception:
                t = datetime.now(timezone.utc)
            self.events.append(AuthEvent(
                time_utc=t.isoformat(),
                host=event.host,
                source=event.source,
                data=event.data,
                user=event.user,
                action=event.action,
                success=event.success,
                reason=event.reason,
            ))
        return []

    def read_failed_logons(self) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        for e in self.events:
            rows.append({
                "time": e.time_utc,
                "account": e.user,
                "ip": str(e.data.get("ip") or ""),
                "workstation": str(e.data.get("workstation") or ""),
                "source": e.source,
            })
        return rows

    def flush(self) -> List[Alert]:
        alerts: List[Alert] = []
        now = datetime.now(timezone.utc)
        rows = self.read_failed_logons()
        by_key: Dict[Tuple[str, str], List[datetime]] = {}
        src_by_key: Dict[Tuple[str, str], str] = {}
        for r in rows:
            try:
                t = datetime.fromisoformat(r["time"].replace("Z", "+00:00"))
            except Exception:
                continue
            if now - t > self.window:
                continue
            key = (r.get("account") or "", r.get("ip") or "")
            by_key.setdefault(key, []).append(t)
            src_by_key[key] = r.get("source") or ""
        for (acct, ip), times in by_key.items():
            if len(times) >= self.threshold:
                span = (max(times) - min(times)).total_seconds() or 1.0
                rate = len(times) / span
                impact = 0.7 if ip else 0.6
                confidence = 0.85
                severity = choose_severity(impact=impact, confidence=confidence, rate_per_sec=rate)
                alerts.append(Alert.new(
                    host=hostname(),
                    type="authentication_bruteforce",
                    detector=self.name,
                    category=self.category,
                    source=src_by_key.get((acct, ip), ""),
                    user=acct,
                    severity=severity,
                    title="Brute-force authentication suspected",
                    description="Multiple failed logon attempts within short window",
                    confidence=confidence,
                    rule_id="AUTH-001",
                    evidence={
                        "account": acct,
                        "ip": ip,
                        "count": len(times),
                        "span_seconds": int(span),
                        "rate_per_sec": round(rate, 3),
                    },
                    remediation="Lock account, enforce MFA, investigate source",
                    mitre_tactic="Credential Access",
                    mitre_technique="Brute Force",
                    mitre_subtechnique="Password Guessing",
                    mitre_id="T1110.001",
                ))
        return alerts
