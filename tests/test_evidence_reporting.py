from app.core.models import Finding
from app.reporting.report_generator import group_findings_by_basis


def _finding(finding_id: str, basis: str) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="Test",
        category="Test",
        package="basic",
        severity="info",
        confidence="weak",
        asset="asset",
        evidence_summary="evidence",
        evidence_files=[],
        why_it_matters="why",
        likely_business_impact="impact",
        remediation_steps=["fix"],
        validation_steps=["validate"],
        owner_role="owner",
        effort="low",
        finding_basis=basis,  # type: ignore[arg-type]
    )


def test_reporting_groups_evidence_backed_and_partial_findings() -> None:
    grouped = group_findings_by_basis(
        [
            _finding("direct", "direct_system_evidence"),
            _finding("directory", "directory_evidence"),
            _finding("network", "network_discovery_evidence"),
            _finding("imported-config", "imported_configuration_evidence"),
            _finding("partial", "inferred_partial"),
        ]
    )

    assert [finding.finding_id for finding in grouped["direct_system_evidence"]] == ["direct"]
    assert [finding.finding_id for finding in grouped["directory_evidence"]] == ["directory"]
    assert [finding.finding_id for finding in grouped["network_discovery_evidence"]] == ["network"]
    assert [finding.finding_id for finding in grouped["imported_configuration_evidence"]] == ["imported-config"]
    assert [finding.finding_id for finding in grouped["inferred_partial"]] == ["partial"]
