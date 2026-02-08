from __future__ import annotations
from typing import List, Callable, Iterable, Dict, Tuple
from time import time
from .config import DetectionConfig
import logging
from .detector import Detector
from .bus import EventBus
from .alert import Alert
from .event import BaseEvent

class DetectionEngine:
    def __init__(self, detectors: List[Detector], alert_sink: Callable[[Alert], None], throttle_window_seconds: int = 60, config: DetectionConfig | None = None, logger: logging.Logger | None = None) -> None:
        self.detectors = detectors
        self.alert_sink = alert_sink
        self.bus = EventBus()
        self.throttle_window_seconds = throttle_window_seconds
        self._last_emitted: Dict[str, float] = {}
        self.config = config or DetectionConfig()
        self.logger = logger
        self._suppressed: Dict[str, int] = {}
        self.alerts_emitted: int = 0
        self.running: bool = False
        self.reloaded: int = 0

    def _dedupe_key(self, alert: Alert) -> str:
        parts: List[str] = [
            alert.detector or "",
            alert.rule_id or "",
            alert.category or "",
        ]
        ev = alert.evidence or {}
        keys = self.config.dedupe_key_map.get(alert.detector or "", [])
        if keys:
            for k in keys:
                parts.append(f"{k}:{ev.get(k,'')}")
        else:
            if "entry" in ev:
                parts.append(f"entry:{ev.get('entry')}")
            elif "account" in ev or "ip" in ev:
                parts.append(f"acct:{ev.get('account','')}")
                parts.append(f"ip:{ev.get('ip','')}")
            elif "name" in ev or "cmdline" in ev:
                parts.append(f"name:{ev.get('name','')}")
                parts.append(f"cmd:{ev.get('cmdline','')}")
            else:
                parts.append("generic")
        return "|".join(parts)

    def _emit(self, alert: Alert) -> None:
        key = self._dedupe_key(alert)
        now = time()
        last = self._last_emitted.get(key, 0.0)
        window = self.config.throttle_detectors.get(alert.detector or "", self.throttle_window_seconds or self.config.throttle_default)
        if now - last >= window:
            cnt = self._suppressed.get(key, 0)
            if self.logger and cnt > 0:
                self.logger.info(f"Suppressed {cnt} duplicate alerts in last {int(window)}s: {alert.detector} {alert.rule_id} key={key}")
                self._suppressed[key] = 0
            self._last_emitted[key] = now
            self.alert_sink(alert)
            self.alerts_emitted += 1
        else:
            self._suppressed[key] = self._suppressed.get(key, 0) + 1

    def start(self) -> None:
        self.running = True
        self._suppressed = {}
        self._last_emitted = {}
        self.alerts_emitted = 0

    def process_event(self, topic: str, event: BaseEvent) -> None:
        for d in self.detectors:
            for alert in d.on_event(event):
                self._emit(alert)
        self.bus.publish(topic, event)

    def flush(self) -> None:
        for d in self.detectors:
            for alert in d.flush():
                self._emit(alert)

    def update_config(self, cfg: DetectionConfig) -> None:
        self.config = cfg or DetectionConfig()
        if not self.throttle_window_seconds:
            self.throttle_window_seconds = self.config.throttle_default
        self.reloaded += 1

    def stop(self) -> None:
        self.running = False
