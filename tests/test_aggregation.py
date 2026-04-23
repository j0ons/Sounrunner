from pathlib import Path

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.models import Finding
from app.core.session import AssessmentIntake, SessionManager
from app.engine.aggregation import estate_summary, generate_aggregate_findings
from app.scanners.base import NetworkAsset


def test_aggregation_generates_repeated_control_findings(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.asset_classification.criticality_by_asset = {"server-b": "critical"}
    session = SessionManager(config).create_session(_intake())
    inventory = AssetInventory(session, config)
    inventory.record_discovery(NetworkAsset(address="10.0.0.10", hostnames=["server-a"]))
    inventory.record_discovery(NetworkAsset(address="10.0.0.11", hostnames=["server-b"]))

    findings = [
        inventory.enrich_finding(_finding("server-a")),
        inventory.enrich_finding(_finding("server-b")),
    ]

    aggregates = generate_aggregate_findings(
        findings=findings,
        inventory=inventory,
        package="standard",
    )
    summary = estate_summary(inventory=inventory, findings=[*findings, *aggregates])

    assert any(item.asset == "organization" for item in aggregates)
    assert any("2 assets" in item.title for item in aggregates)
    assert summary["top_repeated_findings"]
    assert summary["top_repeated_findings_on_critical_assets"]
    assert summary["finding_counts_by_role"]["server"] == 2
    assert summary["finding_counts_by_criticality"]["critical"] == 1


def _finding(asset: str) -> Finding:
    return Finding(
        finding_id=f"F-{asset}",
        title="Windows Firewall appears disabled",
        category="Endpoint Security",
        package="standard",
        severity="high",
        confidence="confirmed",
        asset=asset,
        evidence_summary="Get-NetFirewallProfile reported disabled.",
        evidence_files=["evidence/firewall.json.enc"],
        why_it_matters="why",
        likely_business_impact="impact",
        remediation_steps=["Enable firewall."],
        validation_steps=["Re-run check."],
        owner_role="Endpoint Administrator",
        effort="medium",
        evidence_source_type="windows_native",
        finding_basis="direct_system_evidence",
    )


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="10.0.0.0/24",
        scope_notes="test",
        consent_confirmed=True,
    )
