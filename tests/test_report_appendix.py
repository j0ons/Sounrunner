import json
from pathlib import Path

from app.core.config import AppConfig
from app.core.models import Finding
from app.core.session import AssessmentIntake, SessionManager
from app.reporting.report_generator import _appendix_payload


def test_report_appendix_includes_manifest_and_callback_status(tmp_path: Path) -> None:
    session = SessionManager(
        AppConfig(workspace_root=tmp_path / "data", log_root=tmp_path / "logs")
    ).create_session(_intake())
    session.database.set_metadata(
        "callback_status",
        {
            "overall_status": "partial",
            "status_message": "summary_email via smtp: sent | bundle_upload via https: queued",
        },
    )
    session.database.set_metadata("evidence_manifest", {"entry_count": 1})
    session.database.set_metadata(
        "scanner_sources",
        [{"source": "nessus_api", "path": "evidence/nessus_export.nessus.enc"}],
    )
    session.database.set_metadata(
        "assessment_plan",
        {
            "discovery_sources": [
                {"source": "nmap_discovery", "status": "active", "reason": "configured"}
            ]
        },
    )
    session.database.set_metadata("assessment_warnings", ["Remote Windows collection not configured."])
    session.crypto.write_text(
        session.manifest_path,
        json.dumps(
            {
                "entries": [
                    {
                        "relative_path": "evidence/sample.json.enc",
                        "source_module": "sample_module",
                        "sha256": "abc123",
                    }
                ]
            }
        ),
    )

    appendix = _appendix_payload(session, [_finding()], "partial")

    assert appendix["consent_confirmed"] is True
    assert appendix["manifest_entry_count"] == 1
    assert "smtp" in str(appendix["callback_summary"])
    assert "nessus_api" in str(appendix["import_sources"])
    assert appendix["assessment_warnings"]
    assert appendix["discovery_sources"]


def _finding() -> Finding:
    return Finding(
        finding_id="NESSUS-1",
        title="Imported scanner finding",
        category="Imported Scanner",
        package="standard",
        severity="high",
        confidence="strong",
        asset="host",
        evidence_summary="summary",
        evidence_files=["evidence/nessus_export.nessus.enc"],
        why_it_matters="why",
        likely_business_impact="impact",
        remediation_steps=["fix"],
        validation_steps=["validate"],
        owner_role="owner",
        effort="medium",
        evidence_source_type="nessus",
        finding_basis="imported_scanner_evidence",
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
