from app.core.models import Finding
from app.engine.risk import score_finding


def test_risk_scoring_uses_severity_and_confidence() -> None:
    high_confirmed = Finding(
        finding_id="T-1",
        title="High confirmed",
        category="Test",
        package="basic",
        severity="high",
        confidence="confirmed",
        asset="host",
        evidence_summary="evidence",
        evidence_files=[],
        why_it_matters="risk",
        likely_business_impact="impact",
        remediation_steps=["fix"],
        validation_steps=["validate"],
        owner_role="owner",
        effort="low",
    )
    high_weak = Finding(
        **{
            **high_confirmed.to_dict(),
            "finding_id": "T-2",
            "confidence": "weak",
        }
    )

    assert score_finding(high_confirmed) > score_finding(high_weak)
