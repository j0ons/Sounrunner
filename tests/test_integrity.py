import json
from pathlib import Path

from app.core.config import AppConfig
from app.core.integrity import SessionAuditor, generate_evidence_manifest, store_bundle_hash, store_preflight_report
from app.core.session import AssessmentIntake, SessionManager


def test_manifest_and_audit_metadata_are_recorded(tmp_path: Path) -> None:
    session = SessionManager(
        AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    ).create_session(_intake())

    assert session.database.get_metadata("session_context")["consent_confirmed"] is True

    store_preflight_report(
        session,
        {
            "executed_at_utc": "2026-04-23T00:00:00+00:00",
            "overall_status": "ready",
            "config_loaded": True,
            "config_path": "",
            "data_dir": str(session.root.parent.parent),
            "log_dir": str(session.log_dir.parent.parent),
            "checks": [],
        },
    )

    evidence_file = session.crypto.write_text(session.evidence_dir / "sample.json", json.dumps({"ok": True}))
    SessionAuditor(session).record_event(
        "module_completed",
        {
            "source_module": "sample_module",
            "status": "complete",
            "detail": "sample",
            "evidence_files": [str(evidence_file)],
        },
    )

    manifest_path, manifest = generate_evidence_manifest(session, package="basic")

    assert manifest_path.exists()
    assert any(entry.source_module == "sample_module" for entry in manifest.entries)

    bundle = session.export_dir / "results_bundle.zip"
    bundle.write_bytes(b"bundle")
    hash_path = store_bundle_hash(session, bundle)

    assert hash_path.exists()
    assert session.database.get_metadata("bundle_hash")["bundle_filename"] == "results_bundle.zip"


def _intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="Client",
        site="HQ",
        operator_name="Operator",
        package="basic",
        authorized_scope="local-host-only",
        scope_notes="test",
        consent_confirmed=True,
    )
