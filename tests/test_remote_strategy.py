from __future__ import annotations

from pathlib import Path

from app.core.config import AppConfig
from app.core.session import AssessmentIntake, SessionManager
from app.engine.remote_strategy import (
    effective_remote_windows_config,
    plan_remote_collection_strategy,
)


def test_configured_credential_strategy_wins_when_configured(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.remote_windows.enabled = True
    config.remote_windows.username = "CORP\\assessment"
    config.remote_windows.password_env = "SOUN_RUNNER_REMOTE_WINDOWS_PASSWORD"
    session = SessionManager(config).create_session(_intake())

    monkeypatch.setattr("app.engine.remote_strategy.is_windows", lambda: False)
    monkeypatch.setattr("app.engine.remote_strategy.powershell_available", lambda: False)

    strategy = plan_remote_collection_strategy(session=session, config=config)
    metadata = strategy.to_metadata()

    assert strategy.mode == "configured_credentials"
    assert strategy.enabled is True
    assert metadata["configured_username"] is True
    assert metadata["secret_reference_configured"] is True
    assert "SOUN_RUNNER_REMOTE_WINDOWS_PASSWORD" not in str(metadata)


def test_current_user_strategy_selected_with_domain_context(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake())
    session.database.set_metadata(
        "auto_context",
        {
            "domain_joined": True,
            "domain_name": "corp.example.local",
            "operator_name": "CORP\\operator",
        },
    )

    monkeypatch.setattr("app.engine.remote_strategy.is_windows", lambda: True)
    monkeypatch.setattr("app.engine.remote_strategy.powershell_available", lambda: True)

    strategy = plan_remote_collection_strategy(session=session, config=config)
    effective = effective_remote_windows_config(config.remote_windows, strategy)

    assert strategy.mode == "current_user_integrated_auth"
    assert strategy.enabled is True
    assert strategy.current_user_context is True
    assert strategy.auth == "negotiate"
    assert effective.enabled is True
    assert effective.username == ""


def test_discovery_only_strategy_selected_without_domain_or_config(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    session = SessionManager(config).create_session(_intake())

    monkeypatch.setattr("app.engine.remote_strategy.is_windows", lambda: True)
    monkeypatch.setattr("app.engine.remote_strategy.powershell_available", lambda: True)

    strategy = plan_remote_collection_strategy(session=session, config=config)

    assert strategy.mode == "discovery_only_fallback"
    assert strategy.enabled is False
    assert "domain context" in strategy.reason.lower()


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
