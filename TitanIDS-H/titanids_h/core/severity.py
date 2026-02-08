from __future__ import annotations
from typing import Literal, Optional

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def choose_severity(impact: float, confidence: float, rate_per_sec: Optional[float] = None) -> Severity:
    i = max(0.0, min(1.0, impact))
    c = max(0.0, min(1.0, confidence))
    r = 0.0
    if rate_per_sec is not None:
        r = max(0.0, min(1.0, rate_per_sec / 5.0))
    score = 0.5 * i + 0.35 * c + 0.15 * r
    if score < 0.2:
        return "INFO"
    if score < 0.4:
        return "LOW"
    if score < 0.6:
        return "MEDIUM"
    if score < 0.8:
        return "HIGH"
    return "CRITICAL"
