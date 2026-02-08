from __future__ import annotations
from typing import List
from ..core.event import BaseEvent

class Source:
    def collect(self) -> List[BaseEvent]:
        return []
