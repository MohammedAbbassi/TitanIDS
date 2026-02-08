from __future__ import annotations
from typing import List
from ..core.event import ProcessEvent, BaseEvent
from ..core.utils import list_processes

class ProcessCreationSource:
    def __init__(self) -> None:
        self._seen: set[int] = set()

    def collect(self) -> List[BaseEvent]:
        events: List[BaseEvent] = []
        for p in list_processes():
            try:
                pid = int(p.get("pid") or 0)
            except Exception:
                pid = 0
            if pid and pid not in self._seen:
                self._seen.add(pid)
                events.append(ProcessEvent(
                    time_utc=ProcessEvent.now(),
                    host="",
                    source="process_creation",
                    data={},
                    pid=pid,
                    name=p.get("name"),
                    exe=p.get("exe"),
                    cmdline=p.get("cmdline"),
                    user=p.get("user"),
                ))
        return events
