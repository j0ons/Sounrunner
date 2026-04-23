from pathlib import Path

import pytest

from app.core.config import AppConfig
from app.core.session import AssessmentIntake, SessionManager


def _intake(consent: bool = True) -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="basic",
        authorized_scope="local-host-only",
        scope_notes="test",
        consent_confirmed=consent,
    )


def test_session_requires_consent(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path)
    manager = SessionManager(config)

    with pytest.raises(ValueError, match="Consent"):
        manager.create_session(_intake(consent=False))


def test_session_creates_workspace(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path)
    session = SessionManager(config).create_session(_intake())

    assert session.root.exists()
    assert session.evidence_dir.exists()
    assert (session.root / "checkpoint.json.enc").exists()
    assert (session.root / "session_intake.json.enc").exists()


def test_session_uses_external_log_root(tmp_path: Path) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake())

    assert session.root.is_relative_to(tmp_path / "data")
    assert session.report_dir.is_relative_to(tmp_path / "data")
    assert session.evidence_dir.is_relative_to(tmp_path / "data")
    assert session.export_dir.is_relative_to(tmp_path / "data")
    assert session.log_dir.is_relative_to(tmp_path / "logs")
