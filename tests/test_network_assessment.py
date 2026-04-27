from __future__ import annotations

import json
from pathlib import Path

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.session import AssessmentIntake, SessionManager
from app.modules.network_assessment import NetworkAssessmentModule
from app.reporting.report_generator import _appendix_payload
from app.scanners.base import NetworkAsset, NetworkService
from app.scanners.nmap import NmapAdapter


def test_network_assessment_module_persists_summary_and_findings(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake())
    inventory = AssetInventory(session, config)
    inventory.record_discovery(
        NetworkAsset(
            address="10.0.0.10",
            hostnames=["server01"],
            services=[
                NetworkService(protocol="tcp", port=3389, state="open", service_name="ms-wbt-server"),
                NetworkService(protocol="tcp", port=23, state="open", service_name="telnet"),
            ],
        )
    )

    result = NetworkAssessmentModule(session, config).run()
    summary = session.database.get_metadata("network_assessment_summary", {})

    assert result.status == "complete"
    assert result.evidence_files
    assert summary["services_by_category"]["remote_admin"] == 1
    assert summary["services_by_category"]["insecure_cleartext"] == 1
    assert any(finding.category == "Network Assessment" for finding in result.findings)


def test_report_appendix_includes_network_scan_profile_and_summary(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake())
    session.database.set_metadata(
        "network_assessment_summary",
        {
            "scan_profile": "exposure",
            "services": [{"asset": "server01"}],
            "management_exposures": [{"asset": "server01"}],
            "insecure_protocols": [],
            "network_devices": [],
            "network_score": {"network_score": 82, "confidence": "weak"},
        },
    )

    appendix = _appendix_payload(session, [], "not_configured")

    assert appendix["network_scan_profile"] == "exposure"
    assert "score=82" in appendix["network_assessment_summary"]


def test_safe_nmap_enterprise_profile_generation(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.network_assessment.profile = "deep_safe"
    config.network_assessment.include_service_version_detection = True
    config.network_assessment.include_deep_safe_scripts = True
    config.network_assessment.approved_safe_scripts = ["banner", "vuln", "http-title"]
    session = SessionManager(config).create_session(_intake())
    command = NmapAdapter(
        session,
        config.nmap,
        package="standard",
        network_config=config.network_assessment,
    )._build_command(["10.0.0.0/24"], tmp_path / "scan.xml")

    assert "-sT" in command
    assert "-sV" in command
    assert "-A" not in command
    assert "-sS" not in command
    assert "vuln" not in " ".join(command)
    assert "--script" in command


def test_network_assessment_summary_json_is_report_ready(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake())
    inventory = AssetInventory(session, config)
    inventory.record_discovery(
        NetworkAsset(
            address="10.0.0.1",
            hostnames=["sw-core"],
            services=[NetworkService(protocol="tcp", port=443, state="open", service_name="https")],
        )
    )

    result = NetworkAssessmentModule(session, config).run()
    payload = json.loads(session.crypto.read_text(result.evidence_files[0]))

    assert payload["scan_profile"] == "exposure"
    assert "services_by_category" in payload
    assert "network_score" in payload


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="10.0.0.0/24",
        scope_notes="authorized",
        consent_confirmed=True,
    )
