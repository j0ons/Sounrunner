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


def score_finding(finding: Finding) -> int:
    """Return deterministic risk score from severity and confidence."""

    base = SEVERITY_SCORE[finding.severity]
    multiplier = CONFIDENCE_MULTIPLIER[finding.confidence]
    return max(1, int(base * multiplier))
