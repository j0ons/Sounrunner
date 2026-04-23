from app.core.models import Finding
from app.modules.ransomware_readiness import ransomware_readiness_score


def test_ransomware_readiness_score_penalizes_key_risk_categories() -> None:
    findings = [
        _finding("Backup Readiness", "high"),
        _finding("Network Exposure", "medium"),
        _finding("Privileged Access", "medium"),
    ]

    score, factors = ransomware_readiness_score(findings)

    assert score < 100
    assert any(factor.startswith("Backup:") for factor in factors)


def _finding(category: str, severity: str) -> Finding:
    return Finding(
        finding_id=f"{category}-{severity}",
        title="Test finding",
        category=category,
        package="standard",
        severity=severity,  # type: ignore[arg-type]
        confidence="strong",
        asset="asset",
        evidence_summary="evidence",
        evidence_files=[],
        why_it_matters="why",
        likely_business_impact="impact",
        remediation_steps=["fix"],
        validation_steps=["validate"],
        owner_role="owner",
        effort="medium",
    )
