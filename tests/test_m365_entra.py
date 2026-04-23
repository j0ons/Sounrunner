from pathlib import Path

from app.core.config import AppConfig
from app.core.session import AssessmentIntake, SessionManager
from app.modules.m365_entra import GraphApiError, GraphEvidenceClient, M365EntraModule


def test_m365_entra_graph_normalization(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.m365_entra.enabled = True
    config.m365_entra.tenant_id = "tenant-id"
    config.m365_entra.client_id = "client-id"
    monkeypatch.setenv(config.m365_entra.client_secret_env, "secret")
    session = SessionManager(config).create_session(_intake())

    monkeypatch.setattr(
        GraphEvidenceClient,
        "fetch_evidence",
        lambda self: {
            "security_defaults": {"isEnabled": False},
            "authentication_methods_policy": {
                "registrationEnforcement": {
                    "authenticationMethodsRegistrationCampaign": {"state": "disabled"}
                }
            },
            "user_registration_details": {
                "value": [
                    {"userPrincipalName": "user1@example.com", "userType": "member", "isMfaRegistered": False},
                    {"userPrincipalName": "user2@example.com", "userType": "member", "isMfaRegistered": True},
                ]
            },
            "legacy_auth_signins": {
                "value": [
                    {"userPrincipalName": "user1@example.com", "clientAppUsed": "IMAP"}
                ]
            },
            "privileged_role_members": [
                {"display_name": "Global Administrator", "members": [1, 2, 3, 4, 5]}
            ],
        },
    )

    result = M365EntraModule(session, config.m365_entra).run()

    assert result.status == "complete"
    assert len(result.findings) >= 4
    assert any(finding.finding_id == "STANDARD-M365-004" for finding in result.findings)


def test_m365_entra_graph_auth_failure_is_partial(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.m365_entra.enabled = True
    config.m365_entra.tenant_id = "tenant-id"
    config.m365_entra.client_id = "client-id"
    monkeypatch.setenv(config.m365_entra.client_secret_env, "secret")
    session = SessionManager(config).create_session(_intake())
    monkeypatch.setattr(
        GraphEvidenceClient,
        "fetch_evidence",
        lambda self: (_ for _ in ()).throw(GraphApiError("HTTP 403")),
    )

    result = M365EntraModule(session, config.m365_entra).run()

    assert result.status == "partial"
    assert "failed cleanly" in result.detail


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="local-host-only",
        scope_notes="test",
        consent_confirmed=True,
        m365_connector=True,
    )
