from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid

@dataclass
class Alert:
    id: str
    time_utc: str
    host: str
    type: str
    detector: str
    category: str
    source: str
    user: Optional[str]
    severity: str
    title: str
    description: str
    confidence: float
    rule_id: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    correlations: List[str] = field(default_factory=list)
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_subtechnique: Optional[str] = None
    mitre_id: Optional[str] = None

    @staticmethod
    def new(host: str, type: str, detector: str, category: str, source: str, user: Optional[str], severity: str, title: str, description: str, confidence: float, rule_id: str, evidence: Dict[str, Any], remediation: Optional[str] = None, correlations: Optional[List[str]] = None, mitre_tactic: Optional[str] = None, mitre_technique: Optional[str] = None, mitre_subtechnique: Optional[str] = None, mitre_id: Optional[str] = None) -> "Alert":
        return Alert(
            id=str(uuid.uuid4()),
            time_utc=datetime.now(timezone.utc).isoformat(),
            host=host,
            type=type,
            detector=detector,
            category=category,
            source=source,
            user=user,
            severity=severity,
            title=title,
            description=description,
            confidence=confidence,
            rule_id=rule_id,
            evidence=evidence or {},
            remediation=remediation,
            correlations=correlations or [],
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            mitre_subtechnique=mitre_subtechnique,
            mitre_id=mitre_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
