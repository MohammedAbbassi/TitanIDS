from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime, timezone

@dataclass
class BaseEvent:
    time_utc: str
    host: str
    source: str
    data: Dict[str, Any]

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

@dataclass
class ProcessEvent(BaseEvent):
    pid: int
    name: str
    exe: Optional[str]
    cmdline: Optional[str]
    user: Optional[str]

@dataclass
class AuthEvent(BaseEvent):
    user: str
    action: str
    success: bool
    reason: Optional[str]

@dataclass
class FileEvent(BaseEvent):
    path: str
    operation: str
    result: Optional[str]
