from __future__ import annotations
from typing import List, Iterable
from abc import ABC, abstractmethod
from .event import BaseEvent
from .alert import Alert

class Detector(ABC):
    name: str
    category: str

    @abstractmethod
    def on_event(self, event: BaseEvent) -> Iterable[Alert]:
        ...

    def flush(self) -> List[Alert]:
        return []
