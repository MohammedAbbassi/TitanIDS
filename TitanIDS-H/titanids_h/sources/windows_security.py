from __future__ import annotations
import platform
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List
from ..core.event import AuthEvent, BaseEvent
from .base import Source

class WindowsSecuritySource(Source):
    def __init__(self) -> None:
        self.last_ts: datetime | None = None

    def collect(self) -> List[BaseEvent]:
        events: List[BaseEvent] = []
        if not platform.system().lower().startswith("win"):
            return events
        try:
            cmd = [
                "wevtutil",
                "qe",
                "Security",
                "/q:*[System[(EventID=4625)]]",
                "/f:xml",
                "/c:200",
                "/rd:true",
            ]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore")
            for xml_str in out.split("\r\n\r\n"):
                s = xml_str.strip()
                if not s:
                    continue
                try:
                    root = ET.fromstring(s)
                    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    tnode = root.find(".//e:System/e:TimeCreated", ns)
                    ts_raw = tnode.attrib.get("SystemTime") if tnode is not None else None
                    if not ts_raw:
                        continue
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    if self.last_ts and ts <= self.last_ts:
                        continue
                    data_nodes = root.findall(".//e:EventData/e:Data", ns)
                    kv = {n.attrib.get("Name"): (n.text or "") for n in data_nodes}
                    events.append(AuthEvent(
                        time_utc=ts.isoformat(),
                        host="",
                        source="windows_security",
                        data={"event_id": 4625},
                        user=kv.get("TargetUserName") or "",
                        action="logon",
                        success=False,
                        reason=kv.get("Status") or kv.get("FailureReason") or "",
                    ))
                    if not self.last_ts or ts > self.last_ts:
                        self.last_ts = ts
                except Exception:
                    continue
        except Exception:
            return events
        return events
