from pathlib import Path

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.session import AssessmentIntake, SessionManager
from app.reporting.report_generator import _asset_appendix_rows, _coverage_rows
from app.scanners.base import NetworkAsset


def test_company_reporting_helpers_render_coverage_and_host_appendix(tmp_path: Path) -> None:
    session = SessionManager(
        AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    ).create_session(_intake())
    inventory = AssetInventory(session)
    first = inventory.record_discovery(NetworkAsset(address="10.0.0.10", hostnames=["server-a"]))
    second = inventory.record_discovery(NetworkAsset(address="10.0.1.10", hostnames=["server-b"]))
    inventory.mark_status(first.asset_id, assessment_status="assessed", collector_status="complete")
    inventory.mark_status(second.asset_id, assessment_status="discovery_only", collector_status="skipped")
    session.database.set_metadata(
        "estate_summary",
        {
            "coverage": inventory.coverage_summary(),
            "by_site": {"HQ": {"assessed": 1, "discovery_only": 1, "partial": 0, "unreachable": 0, "imported_evidence_only": 0}},
            "by_subnet": {
                "10.0.0.0/24": {"assessed": 1, "discovery_only": 0, "partial": 0, "unreachable": 0, "imported_evidence_only": 0},
                "10.0.1.0/24": {"assessed": 0, "discovery_only": 1, "partial": 0, "unreachable": 0, "imported_evidence_only": 0},
            },
            "top_repeated_findings": [
                {
                    "finding_id": "AGG-1",
                    "title": "Windows Firewall appears disabled observed across 2 assets",
                    "severity": "high",
                    "risk_score": 90,
                    "asset": "organization",
                    "evidence_summary": "server-a, server-b",
                }
            ],
            "coverage_gaps": ["Coverage is discovery-heavy."],
        },
    )

    coverage_rows = _coverage_rows(session.database.get_metadata("estate_summary", {})["by_site"], "Site")
    appendix_rows = _asset_appendix_rows(session)

    assert coverage_rows[0] == ["Site", "Assessed", "Partial", "Unreachable", "Discovery-only", "Imported-evidence-only"]
    assert any("server-a" in row[0] for row in appendix_rows[1:])
    assert any("server" in row[2] for row in appendix_rows[1:])
    assert any("discovery_only" in row[5] for row in appendix_rows[1:])
    assert appendix_rows[0][6] == "Last Evidence"


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="10.0.0.0/24,10.0.1.0/24",
        scope_notes="test",
        consent_confirmed=True,
        scope_labels={
            "10.0.0.0/24": "HQ",
            "10.0.1.0/24": "HQ",
        },
    )
