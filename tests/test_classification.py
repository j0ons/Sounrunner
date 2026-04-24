from __future__ import annotations

from pathlib import Path

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.models import Finding
from app.core.session import AssessmentIntake, SessionManager
from app.scanners.base import NetworkAsset


def test_inventory_classifies_role_and_criticality_with_operator_overrides(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.asset_classification.role_overrides = {"hq-fw": "network_device"}
    config.asset_classification.criticality_by_site = {"Branch-A": "critical"}
    session = SessionManager(config).create_session(_intake())
    inventory = AssetInventory(session, config)

    asset = inventory.record_discovery(NetworkAsset(address="10.0.20.5", hostnames=["hq-fw"]))
    finding = inventory.enrich_finding(_finding("hq-fw"))

    assert asset.asset_role == "network_device"
    assert asset.role_source == "operator_provided"
    assert asset.criticality == "critical"
    assert asset.criticality_source == "operator_provided"
    assert finding.asset_role == "network_device"
    assert finding.asset_criticality == "critical"
    assert finding.asset_classification_source == "operator_provided"


def test_imported_metadata_is_not_downgraded_by_weaker_discovery_heuristics(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake())
    inventory = AssetInventory(session, config)

    imported = inventory.record_imported_asset(
        hostname="core-sql-01",
        ip_address="10.0.20.15",
        role_hint="server",
        criticality_hint="critical",
        source="backup_platform_import",
    )
    discovered = inventory.record_discovery(NetworkAsset(address="10.0.20.15", hostnames=["core-sql-01"]))

    assert imported.asset_role == "server"
    assert imported.role_source == "imported_metadata"
    assert discovered.asset_role == "server"
    assert discovered.role_source == "imported_metadata"
    assert discovered.criticality == "critical"
    assert discovered.criticality_source == "imported_metadata"


def _finding(asset: str) -> Finding:
    return Finding(
        finding_id="F-1",
        title="Test",
        category="Test",
        package="standard",
        severity="medium",
        confidence="strong",
        asset=asset,
        evidence_summary="evidence",
        evidence_files=[],
        why_it_matters="why",
        likely_business_impact="impact",
        remediation_steps=["fix"],
        validation_steps=["validate"],
        owner_role="Owner",
        effort="low",
    )


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="Branch-A",
        operator_name="Operator",
        package="standard",
        authorized_scope="10.0.20.0/24",
        scope_notes="authorized",
        consent_confirmed=True,
        scope_labels={"10.0.20.0/24": "Branch-A"},
    )
