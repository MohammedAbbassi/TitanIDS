from __future__ import annotations
import os
import json
from typing import Dict, List, Set

class BaselineStore:
    def __init__(self, path: str = "state/baseline.json") -> None:
        self.path = path
        # Structured layout:
        # {
        #   "values": { key: [fingerprints...] },
        #   "counts": { key: { fingerprint: int } },
        #   "coarse": { key: { coarse_key: fingerprint } }
        # }
        self.values: Dict[str, List[str]] = {}
        self.counts: Dict[str, Dict[str, int]] = {}
        self.coarse: Dict[str, Dict[str, str]] = {}
        self._load()

    def _load(self) -> None:
        try:
            if os.path.isfile(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                    if isinstance(raw, dict) and ("values" in raw or "counts" in raw or "coarse" in raw):
                        self.values = dict(raw.get("values", {}))
                        self.counts = {k: dict(v) for k, v in dict(raw.get("counts", {})).items()}
                        self.coarse = {k: dict(v) for k, v in dict(raw.get("coarse", {})).items()}
                    else:
                        # Backward compatibility with flat layout
                        self.values = {k: list(v) for k, v in (raw or {}).items() if isinstance(v, list)}
                        self.counts = {}
                        self.coarse = {}
        except Exception:
            self.values = {}
            self.counts = {}
            self.coarse = {}

    def _save(self) -> None:
        try:
            d = os.path.dirname(self.path)
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            payload = {
                "values": self.values,
                "counts": self.counts,
                "coarse": self.coarse,
            }
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(payload, f)
        except Exception:
            pass

    def get(self, key: str) -> Set[str]:
        return set(self.values.get(key, []))

    def set(self, key: str, values: List[str]) -> None:
        self.values[key] = list(dict.fromkeys(values))
        self._save()
    
    def add(self, key: str, fp: str) -> None:
        s = set(self.values.get(key, []))
        s.add(fp)
        self.values[key] = list(sorted(s))
        self._save()

    def diff_new(self, key: str, current: List[str]) -> List[str]:
        old = self.get(key)
        new = [v for v in current if v not in old]
        return new

    def bump_count(self, key: str, fp: str) -> int:
        m = self.counts.setdefault(key, {})
        m[fp] = int(m.get(fp, 0)) + 1
        self._save()
        return m[fp]

    def get_count(self, key: str, fp: str) -> int:
        return int(self.counts.get(key, {}).get(fp, 0))

    def set_coarse(self, key: str, coarse_key: str, fp: str) -> None:
        m = self.coarse.setdefault(key, {})
        m[coarse_key] = fp
        self._save()

    def get_coarse_fp(self, key: str, coarse_key: str) -> str | None:
        return self.coarse.get(key, {}).get(coarse_key)
