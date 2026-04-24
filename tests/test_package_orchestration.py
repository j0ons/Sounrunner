from pathlib import Path

from app.core.config import AppConfig
from app.core.session import AssessmentIntake, SessionManager
from app.engine.advanced import AdvancedPackageRunner
from app.engine.standard import StandardPackageRunner
from app.ui.console import ConsoleUi


def test_standard_package_smoke_run(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.nmap.enabled = False
    session = SessionManager(config).create_session(_intake("standard"))

    result = StandardPackageRunner(config=config, session=session, ui=ConsoleUi()).run()
    activation_plan = session.database.get_metadata("module_activation_plan", [])
    assessment_plan = session.database.get_metadata("assessment_plan", {})

    assert result.package == "standard"
    assert result.report_pdf.exists()
    assert result.additional_artifacts
    assert any(item["module_name"] == "estate_orchestration" for item in activation_plan)
    assert assessment_plan["estate_mode"] is True
    assert assessment_plan["warnings"]


def test_advanced_package_smoke_run(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.nmap.enabled = False
    session = SessionManager(config).create_session(_intake("advanced"))

    result = AdvancedPackageRunner(config=config, session=session, ui=ConsoleUi()).run()
    activation_plan = session.database.get_metadata("module_activation_plan", [])
    assessment_plan = session.database.get_metadata("assessment_plan", {})

    assert result.package == "advanced"
    assert result.report_pdf.exists()
    assert any("30_60_90" in artifact.name for artifact in result.additional_artifacts)
    assert any(item["module_name"] == "advanced_guided" for item in activation_plan)
    assert assessment_plan["estate_mode"] is True


def _intake(package: str) -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package=package,
        authorized_scope="local-host-only",
        scope_notes="test",
        consent_confirmed=True,
    )
