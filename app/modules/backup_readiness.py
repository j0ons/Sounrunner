"""Standard package backup readiness review."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.collectors.windows_native import WindowsEvidence
from app.core.evidence import confidence_for_basis, utc_now
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession


@dataclass(slots=True)
class BackupReadinessModule:
    """Assess backup readiness using local indicators plus explicit unanswered prompts."""

    session: AssessmentSession
    windows_evidence: WindowsEvidence

    name: str = "backup_readiness"

    def run(self) -> ModuleResult:
        collected_at = utc_now()
        backup_payload = self.windows_evidence.section_json("backup_indicators")
        import_summary = self.session.database.get_metadata("backup_platform_import_summary", {})
        indicators = _backup_labels(backup_payload)
        if import_summary.get("job_count"):
            indicators.append(
                f"Imported backup platform evidence: {import_summary.get('job_count')} job(s)"
            )
        prompts = backup_questionnaire_prompts(import_summary=import_summary)
        summary = {
            "collected_at": collected_at,
            "technical_indicators": indicators,
            "imported_backup_summary": import_summary,
            "questionnaire_prompts": prompts,
            "readiness_score": backup_readiness_score(indicators=indicators, prompts=prompts),
            "score_basis": "Technical software indicators plus unanswered guided prompts.",
        }
        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "backup_readiness_summary.json",
            json.dumps(summary, indent=2, sort_keys=True),
        )
        findings: list[Finding] = []

        if not indicators:
            findings.append(
                _finding(
                    finding_id="STANDARD-BACKUP-001",
                    title="Backup software indicator not confirmed locally",
                    severity="medium",
                    confidence=confidence_for_basis("inferred_partial"),
                    basis="inferred_partial",
                    asset=self.session.intake.client_name,
                    evidence_summary=(
                        "No common backup software/service indicator was confirmed from local Windows evidence. "
                        "This does not prove backups are absent."
                    ),
                    why_it_matters="Unconfirmed backup coverage is a major ransomware recovery risk until validated.",
                    likely_business_impact="Recovery may depend on unverified or unavailable backups.",
                    remediation_steps=[
                        "Confirm endpoint/server backup coverage in the backup platform.",
                        "Record backup scope, destination, retention, and ownership.",
                    ],
                    validation_steps=[
                        "Provide backup console evidence showing protected assets and latest successful backup.",
                    ],
                    evidence_path=str(evidence_file),
                    collected_at=collected_at,
                    source_type="windows_native",
                )
            )

        for prompt in prompts:
            if prompt["status"] == "unanswered":
                findings.append(
                    _finding(
                        finding_id=f"STANDARD-BACKUP-Q-{prompt['id']}",
                        title=prompt["finding_title"],
                        severity=prompt["severity"],
                        confidence=confidence_for_basis("advisory_questionnaire"),
                        basis="advisory_questionnaire",
                        asset=self.session.intake.client_name,
                        evidence_summary=prompt["question"],
                        why_it_matters=prompt["why_it_matters"],
                        likely_business_impact=prompt["impact"],
                        remediation_steps=prompt["remediation_steps"],
                        validation_steps=prompt["validation_steps"],
                        evidence_path=str(evidence_file),
                        collected_at=collected_at,
                        source_type="operator_questionnaire",
                    )
                )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail=(
                f"Backup readiness score {summary['readiness_score']}/100 with {len(indicators)} indicator(s) "
                f"and imported backup jobs={import_summary.get('job_count', 0)}."
            ),
            findings=findings,
            evidence_files=[evidence_file],
        )


def backup_questionnaire_prompts(import_summary: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    import_summary = import_summary or {}
    restore_status = "answered" if int(import_summary.get("restore_test_confirmed_count", 0)) > 0 else "unanswered"
    immutable_status = (
        "answered"
        if int(import_summary.get("immutable_count", 0)) > 0 or int(import_summary.get("offline_count", 0)) > 0
        else "unanswered"
    )
    return [
        {
            "id": "RESTORE_TEST",
            "question": "Provide evidence of the most recent successful restore test.",
            "status": restore_status,
            "finding_title": "Backup restore test evidence not provided",
            "severity": "medium",
            "why_it_matters": "Backups are not operationally reliable until restore has been tested.",
            "impact": "Recovery may fail during ransomware or outage response.",
            "remediation_steps": ["Run and document a restore test for priority systems."],
            "validation_steps": ["Attach restore test record with date, system, result, and owner."],
        },
        {
            "id": "OFFLINE_IMMUTABLE",
            "question": "Confirm whether offline or immutable backup copies exist.",
            "status": immutable_status,
            "finding_title": "Offline or immutable backup evidence not provided",
            "severity": "high",
            "why_it_matters": "Ransomware can delete or encrypt reachable backups.",
            "impact": "Recovery options may be destroyed during the same incident.",
            "remediation_steps": ["Implement immutable, offline, or access-isolated backup copies."],
            "validation_steps": ["Provide configuration or vendor evidence of immutability/offline retention."],
        },
        {
            "id": "RPO_RTO",
            "question": "Document approved RPO and RTO for critical systems.",
            "status": "unanswered",
            "finding_title": "RPO/RTO evidence not provided",
            "severity": "medium",
            "why_it_matters": "Recovery targets are needed to judge whether backup design meets business need.",
            "impact": "Recovery may be technically successful but still miss business tolerances.",
            "remediation_steps": ["Define RPO/RTO by system owner and business process."],
            "validation_steps": ["Review approved recovery targets against backup policy and test results."],
        },
    ]


def backup_readiness_score(*, indicators: list[str], prompts: list[dict[str, Any]]) -> int:
    score = 40 if indicators else 15
    answered = sum(1 for prompt in prompts if prompt["status"] != "unanswered")
    score += answered * 20
    return min(score, 100)


def _backup_labels(payload: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    for key in ("Services", "InstalledApps"):
        value = payload.get(key)
        items = value if isinstance(value, list) else [value] if isinstance(value, dict) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            label = str(item.get("DisplayName") or item.get("Name") or "").strip()
            if label:
                labels.append(label)
    return sorted(set(labels))


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    confidence: str,
    basis: str,
    asset: str,
    evidence_summary: str,
    why_it_matters: str,
    likely_business_impact: str,
    remediation_steps: list[str],
    validation_steps: list[str],
    evidence_path: str,
    collected_at: str,
    source_type: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        category="Backup Readiness",
        package="standard",
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        asset=asset,
        evidence_summary=evidence_summary,
        evidence_files=[evidence_path],
        why_it_matters=why_it_matters,
        likely_business_impact=likely_business_impact,
        remediation_steps=remediation_steps,
        validation_steps=validation_steps,
        owner_role="Backup Owner",
        effort="medium",
        evidence_source_type=source_type,
        evidence_collected_at=collected_at,
        raw_evidence_path=evidence_path,
        finding_basis=basis,  # type: ignore[arg-type]
    )
