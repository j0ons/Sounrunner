from __future__ import annotations

import json
from pathlib import Path

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.session import AssessmentIntake, SessionManager
from app.engine.network_analysis import (
    build_network_assessment_summary,
    build_network_findings,
    classify_service,
)
from app.modules.firewall_vpn_import import FirewallVpnImportModule
from app.scanners.base import NetworkAsset, NetworkService


def test_service_classification_maps_enterprise_service_categories() -> None:
    assert classify_service(port=3389, service_name="ms-wbt-server")[0] == "remote_admin"
    assert classify_service(port=445, service_name="microsoft-ds")[0] == "file_sharing"
    assert classify_service(port=389, service_name="ldap")[0] == "directory_identity"
    assert classify_service(port=1433, service_name="ms-sql-s")[0] == "database"
    assert classify_service(port=23, service_name="telnet")[0] == "insecure_cleartext"
    assert classify_service(port=8443, service_name="https-alt")[0] == "web_admin"


def test_network_analysis_generates_management_insecure_and_inferred_segmentation_findings(
    tmp_path: Path,
) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake())
    inventory = AssetInventory(session, config)
    server = inventory.record_discovery(
        NetworkAsset(
            address="10.0.0.10",
            hostnames=["srv-app01"],
            services=[
                NetworkService(protocol="tcp", port=3389, state="open", service_name="ms-wbt-server"),
                NetworkService(protocol="tcp", port=1433, state="open", service_name="ms-sql-s"),
            ],
            os_family="Windows",
        )
    )
    workstation = inventory.record_discovery(
        NetworkAsset(
            address="10.0.0.40",
            hostnames=["win10-user01"],
            services=[
                NetworkService(protocol="tcp", port=3389, state="open", service_name="ms-wbt-server"),
                NetworkService(protocol="tcp", port=23, state="open", service_name="telnet"),
            ],
            os_family="Windows",
        )
    )

    summary = build_network_assessment_summary(session=session, config=config, inventory=inventory)
    evidence_path = session.crypto.write_text(
        session.evidence_dir / "network_assessment_summary.json",
        json.dumps(summary.to_dict(), sort_keys=True),
    )
    findings = build_network_findings(summary=summary, package="standard", evidence_path=evidence_path)

    assert server.asset_id
    assert workstation.asset_id
    assert summary.services_by_category["remote_admin"] == 2
    assert summary.services_by_category["insecure_cleartext"] == 1
    assert any(item.evidence_type == "inferred_network_posture" for item in summary.segmentation_observations)
    assert any("management-plane exposure" in finding.title for finding in findings)
    assert any("Telnet" in finding.title for finding in findings)
    assert any(finding.finding_basis == "inferred_partial" for finding in findings)
    assert not any(
        finding.finding_basis == "imported_configuration_evidence" and "Segmentation" in finding.category
        for finding in findings
    )


def test_network_device_classification_uses_hostname_and_services(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake())
    inventory = AssetInventory(session, config)
    record = inventory.record_discovery(
        NetworkAsset(
            address="10.0.0.1",
            hostnames=["fw-hq-core"],
            services=[
                NetworkService(protocol="tcp", port=443, state="open", service_name="https"),
                NetworkService(protocol="udp", port=161, state="open", service_name="snmp"),
            ],
        )
    )

    summary = build_network_assessment_summary(session=session, config=config, inventory=inventory)
    refreshed = inventory.find_asset(record.asset_id)

    assert summary.network_devices
    assert summary.network_devices[0]["role"] == "firewall"
    assert refreshed is not None
    assert refreshed.asset_role == "network_device"


def test_firewall_vpn_import_feeds_confirmed_configuration_findings(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.firewall_vpn_import.enabled = True
    import_path = tmp_path / "firewall.yaml"
    import_path.write_text(
        """
policies:
  - device_name: fw-hq
    rule_name: Allow-Any-Any
    source: any
    destination: any
    service: any
    action: allow
""",
        encoding="utf-8",
    )
    config.firewall_vpn_import.import_paths = [str(import_path)]
    session = SessionManager(config).create_session(_intake())

    import_result = FirewallVpnImportModule(session, config).run()
    inventory = AssetInventory(session, config)
    summary = build_network_assessment_summary(session=session, config=config, inventory=inventory)
    evidence_path = session.crypto.write_text(
        session.evidence_dir / "network_assessment_summary.json",
        json.dumps(summary.to_dict(), sort_keys=True),
    )
    findings = build_network_findings(summary=summary, package="standard", evidence_path=evidence_path)

    assert import_result.status == "complete"
    assert session.database.get_metadata("firewall_vpn_normalized", [])
    assert any(rule.any_any for evidence in summary.firewall_evidence for rule in evidence.rules)
    assert any(finding.finding_basis == "imported_configuration_evidence" for finding in findings)


def test_network_score_uses_missing_firewall_evidence_as_confidence_not_failure(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake())
    inventory = AssetInventory(session, config)
    inventory.record_discovery(
        NetworkAsset(
            address="10.0.0.20",
            hostnames=["server01"],
            services=[NetworkService(protocol="tcp", port=22, state="open", service_name="ssh")],
        )
    )

    summary = build_network_assessment_summary(session=session, config=config, inventory=inventory)

    assert summary.network_score.network_score < 100
    assert summary.network_score.network_score >= 70
    assert summary.network_score.confidence in {"weak", "strong"}
    assert any("not provided" in item for item in summary.network_score.key_drivers)


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="10.0.0.0/24",
        scope_notes="authorized",
        consent_confirmed=True,
        scope_labels={"10.0.0.0/24": "HQ"},
    )
