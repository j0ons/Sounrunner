"""Simple, explicit risk scoring for normalized findings."""

from __future__ import annotations

from app.core.models import Finding


SEVERITY_SCORE = {
    "critical": 100,
    "high": 80,
    "medium": 55,
    "low": 25,
    "info": 5,
}

CONFIDENCE_MULTIPLIER = {
    "confirmed": 1.0,
    "strong": 0.85,
    "weak": 0.55,
    "unknown": 0.35,
}

CRITICALITY_MULTIPLIER = {
    "critical": 1.25,
    "high": 1.1,
    "medium": 1.0,
    "low": 0.85,
}


def score_finding(finding: Finding) -> int:
    """Return deterministic risk score from severity and confidence."""

    base = SEVERITY_SCORE[finding.severity]
    multiplier = CONFIDENCE_MULTIPLIER[finding.confidence]
    criticality = CRITICALITY_MULTIPLIER.get(finding.asset_criticality or "medium", 1.0)
    return max(1, min(100, int(base * multiplier * criticality)))
