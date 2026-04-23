from pathlib import Path

from app.collectors.windows_native import WindowsCommandEvidence, WindowsEvidence
from app.core.config import AppConfig
from app.core.session import AssessmentIntake, SessionManager
from app.modules.backup_readiness import BackupReadinessModule, backup_readiness_score


def test_backup_readiness_score_uses_indicators_and_prompts() -> None:
    prompts = [{"status": "answered"}, {"status": "unanswered"}]
    assert backup_readiness_score(indicators=["Veeam"], prompts=prompts) == 60
    assert backup_readiness_score(indicators=[], prompts=prompts) == 35


def test_backup_module_labels_missing_restore_as_questionnaire(tmp_path: Path) -> None:
    session = SessionManager(AppConfig(workspace_root=tmp_path)).create_session(_intake())
    evidence = WindowsEvidence(
        supported=True,
        collected_at="2026-04-23T00:00:00+00:00",
        raw_evidence_path=tmp_path / "windows.json.enc",
        sections={
            "backup_indicators": WindowsCommandEvidence(
                name="backup_indicators",
                command="test",
                returncode=0,
                stdout="{}",
                stderr="",
                parsed_json={"Services": []},
            )
        },
    )

    result = BackupReadinessModule(session, evidence).run()

    assert result.status == "complete"
    assert any(finding.finding_basis == "advisory_questionnaire" for finding in result.findings)


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="standard",
        authorized_scope="local-host-only",
        scope_notes="test",
        consent_confirmed=True,
    )
