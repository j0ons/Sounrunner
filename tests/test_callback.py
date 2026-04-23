from pathlib import Path

from app.core.config import AppConfig
from app.core.models import Finding
from app.core.session import AssessmentIntake, SessionManager
from app.export.callback import CallbackAttempt, CallbackManager, CallbackQueue, sanitized_summary_payload


def test_sanitized_summary_payload_excludes_raw_evidence(tmp_path: Path) -> None:
    session = SessionManager(AppConfig(workspace_root=tmp_path)).create_session(_intake())
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(b"encrypted")
    payload = sanitized_summary_payload(
        session=session,
        package="standard",
        findings=[_finding()],
        encrypted_bundle=bundle,
    )

    assert payload["client_name"] == "Client"
    assert payload["severity_counts"]["high"] == 1  # type: ignore[index]
    assert "raw_evidence_path" not in str(payload)


def test_callback_queue_persists_failed_attempt(tmp_path: Path) -> None:
    queue = CallbackQueue(tmp_path)
    path = queue.enqueue(
        provider="https",
        payload={"callback_id": "abc"},
        bundle_path=tmp_path / "bundle.zip",
        error="failed",
    )

    assert path.exists()
    assert queue.pending() == [path]


def test_callback_retry_updates_queue_and_status(tmp_path: Path, monkeypatch) -> None:
    config = AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    config.callback.enabled = True
    config.callback.upload_bundle = True
    config.callback.https.enabled = True
    config.callback.https.url = "https://callback.example"
    session = SessionManager(config).create_session(_intake())
    bundle = session.export_dir / "results_bundle.zip"
    bundle.write_bytes(b"bundle")
    manager = CallbackManager(config, session)

    class FlakyProvider:
        name = "https"
        delivery_type = "bundle_upload"

        def __init__(self) -> None:
            self.calls = 0

        def send(self, payload: dict[str, object], bundle_path: Path) -> CallbackAttempt:
            self.calls += 1
            if self.calls == 1:
                raise ValueError("temporary failure")
            return CallbackAttempt(
                provider="https",
                delivery_type="bundle_upload",
                status="sent",
                detail="retried successfully",
                callback_id=str(payload["callback_id"]),
            )

    provider = FlakyProvider()
    monkeypatch.setattr(manager, "_providers", lambda: [provider])

    status = manager.run("standard", [_finding()], bundle)
    queued_items = manager.inspect_queue(session.session_id)

    assert status == "queued"
    assert len(queued_items) == 1

    retry_results = manager.retry_pending(force=True, session_id=session.session_id)

    assert retry_results
    assert manager.inspect_queue(session.session_id) == []


def _finding() -> Finding:
    return Finding(
        finding_id="F-1",
        title="High finding",
        category="Test",
        package="standard",
        severity="high",
        confidence="strong",
        asset="asset",
        evidence_summary="summary",
        evidence_files=["secret.enc"],
        why_it_matters="why",
        likely_business_impact="impact",
        remediation_steps=["fix"],
        validation_steps=["validate"],
        owner_role="owner",
        effort="medium",
        raw_evidence_path="secret.enc",
    )


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
