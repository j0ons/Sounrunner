from __future__ import annotations

from app.core.config import AppConfig
from app.core.session import AssessmentIntake, SessionManager
from app.engine.planner import build_assessment_plan


def test_planner_marks_connectors_active_when_configured(tmp_path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.remote_windows.enabled = True
    config.active_directory.enabled = True
    config.firewall_vpn_import.enabled = True
    config.firewall_vpn_import.import_paths = ["fw.json"]
    config.backup_platform_import.enabled = True
    config.backup_platform_import.import_paths = ["backup.json"]
    session = SessionManager(config).create_session(_intake("10.0.0.0/24"))

    plan = build_assessment_plan(session=session, config=config, package="standard")

    assert plan.estate_mode is True
    assert plan.should_run("estate_orchestration") is True
    assert plan.entry("active_directory").activation == "active"
    assert plan.entry("firewall_vpn_import").activation == "active"
    assert plan.entry("backup_platform_import").activation == "active"
    assert any(item["source"] == "remote_windows" and item["status"] == "active" for item in plan.discovery_sources)


def test_planner_warns_when_standard_is_localhost_only(tmp_path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake("local-host-only"))

    plan = build_assessment_plan(session=session, config=config, package="standard")

    assert plan.entry("estate_orchestration").activation == "limited"
    assert any("localhost-only scope" in item for item in plan.warnings)


def _intake(scope: str) -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope=scope,
        scope_notes="authorized",
        consent_confirmed=True,
    )
