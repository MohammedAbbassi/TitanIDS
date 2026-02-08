from __future__ import annotations
from typing import Callable, Dict, List, Any
from threading import Lock

class EventBus:
    def __init__(self) -> None:
        self._subs: Dict[str, List[Callable[[Any], None]]] = {}
        self._lock = Lock()

    def subscribe(self, topic: str, fn: Callable[[Any], None]) -> None:
        with self._lock:
            self._subs.setdefault(topic, []).append(fn)

    def publish(self, topic: str, event: Any) -> None:
        with self._lock:
            subs = list(self._subs.get(topic, []))
        for fn in subs:
            try:
                fn(event)
            except Exception:
                pass
