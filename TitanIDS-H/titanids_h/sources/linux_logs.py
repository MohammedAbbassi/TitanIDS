from __future__ import annotations
import os
import platform
from typing import List
from ..core.event import AuthEvent, BaseEvent
from .base import Source

class LinuxAuthSyslogSource(Source):
    def __init__(self) -> None:
        self._seen_lines_auth = 0
        self._seen_lines_syslog = 0

    def parse_auth_line(self, line: str) -> AuthEvent | None:
        s = line.strip()
        if "Failed password for" in s:
            parts = s.split()
            user = ""
            ip = ""
            for i, t in enumerate(parts):
                if t == "for" and i + 1 < len(parts):
                    user = parts[i + 1]
                if t == "from" and i + 1 < len(parts):
                    ip = parts[i + 1]
            return AuthEvent(
                time_utc=AuthEvent.now(),
                host="",
                source="linux_auth_log",
                data={"ip": ip},
                user=user,
                action="ssh",
                success=False,
                reason="Failed password",
            )
        return None

    def collect(self) -> List[BaseEvent]:
        events: List[BaseEvent] = []
        if not platform.system().lower().startswith("linux"):
            return events
        auth_path = "/var/log/auth.log"
        syslog_path = "/var/log/syslog"
        if os.path.isfile(auth_path):
            with open(auth_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                new = lines[self._seen_lines_auth:]
                self._seen_lines_auth = len(lines)
                for line in new:
                    e = self.parse_auth_line(line)
                    if e:
                        events.append(e)
        if os.path.isfile(syslog_path):
            with open(syslog_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                new = lines[self._seen_lines_syslog:]
                self._seen_lines_syslog = len(lines)
                for line in new:
                    s = line.strip()
                    if "sudo:" in s and "authentication failure" in s:
                        events.append(AuthEvent(
                            time_utc=AuthEvent.now(),
                            host="",
                            source="linux_syslog",
                            data={},
                            user="",
                            action="sudo",
                            success=False,
                            reason="sudo authentication failure",
                        ))
        return events
