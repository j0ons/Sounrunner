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

    assert result.package == "standard"
    assert result.report_pdf.exists()
    assert result.additional_artifacts


def test_advanced_package_smoke_run(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.nmap.enabled = False
    session = SessionManager(config).create_session(_intake("advanced"))

    result = AdvancedPackageRunner(config=config, session=session, ui=ConsoleUi()).run()

    assert result.package == "advanced"
    assert result.report_pdf.exists()
    assert any("30_60_90" in artifact.name for artifact in result.additional_artifacts)


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
