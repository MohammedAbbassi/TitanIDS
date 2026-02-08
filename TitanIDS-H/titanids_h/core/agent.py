import threading
import time
import platform
from typing import List, Optional
from .engine import DetectionEngine
from .utils import list_processes, hostname
from .event import ProcessEvent
from ..sources.process_creation import ProcessCreationSource
from ..sources.windows_security import WindowsSecuritySource
from ..sources.linux_logs import LinuxAuthSyslogSource
from .config import DetectionConfig

class Agent:
    def __init__(self, engine: DetectionEngine, interval: float = 30.0, config_path: Optional[str] = None) -> None:
        self.engine = engine
        self.interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._config_path = config_path

    def _sources(self) -> List:
        if platform.system().lower().startswith("win"):
            return [ProcessCreationSource(), WindowsSecuritySource()]
        return [ProcessCreationSource(), LinuxAuthSyslogSource()]

    def _collect_process_events(self) -> None:
        h = hostname()
        for p in list_processes():
            try:
                pid = int(p.get("pid") or 0)
            except Exception:
                pid = 0
            ev = ProcessEvent(
                time_utc=ProcessEvent.now(),
                host=h,
                source="process_scan",
                data={},
                pid=pid,
                name=p.get("name"),
                exe=p.get("exe"),
                cmdline=p.get("cmdline"),
                user=p.get("user"),
            )
            self.engine.process_event("process", ev)

    def run_once(self) -> None:
        for src in self._sources():
            for ev in src.collect():
                ev.host = hostname()
                self.engine.process_event("source", ev)
        self._collect_process_events()
        self.engine.flush()

    def _loop(self) -> None:
        self.engine.start()
        while not self._stop.is_set():
            self.run_once()
            end_time = time.time() + self.interval
            while time.time() < end_time:
                if self._stop.is_set():
                    break
                time.sleep(0.1)
        self.engine.stop()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)

    def reload(self, config_path: Optional[str] = None) -> None:
        p = config_path if config_path is not None else self._config_path
        cfg = DetectionConfig.load(p)
        self.engine.update_config(cfg)
