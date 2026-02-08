from __future__ import annotations
import json
import os
from typing import Dict, List, Optional, Any

class DetectionConfig:
    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        d = data or {}
        thr = d.get("throttle", {})
        self.throttle_default: int = int(thr.get("default", 60))
        self.throttle_detectors: Dict[str, int] = {str(k): int(v) for k, v in thr.get("detectors", {}).items()}
        dk = d.get("dedupe_key", {})
        self.dedupe_key_map: Dict[str, List[str]] = {str(k): list(v) for k, v in dk.items()}

    @staticmethod
    def load(path: Optional[str]) -> "DetectionConfig":
        if not path:
            return DetectionConfig()
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    return DetectionConfig(json.load(f))
        except Exception:
            return DetectionConfig()
        return DetectionConfig()
