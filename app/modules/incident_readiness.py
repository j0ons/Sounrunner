"""Standard package incident response readiness review."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.collectors.windows_native import WindowsEvidence
from app.core.evidence import confidence_for_basis, utc_now
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession


@dataclass(slots=True)
class IncidentReadinessModule:
    session: AssessmentSession
    windows_evidence: WindowsEvidence

    name: str = "incident_readiness"

    def run(self) -> ModuleResult:
        collected_at = utc_now()
        logging_payload = self.windows_evidence.section_json("logging_visibility")
        prompts = incident_prompts()
        score = incident_readiness_score(logging_payload=logging_payload, prompts=prompts)
        evidence = {
            "collected_at": collected_at,
            "logging_visibility": logging_payload,
            "questionnaire_prompts": prompts,
            "ir_readiness_score": score,
        }
        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "incident_readiness_summary.json",
            json.dumps(evidence, indent=2, sort_keys=True),
        )

        findings: list[Finding] = []
        if str(logging_payload.get("EventLogStatus", "")).lower() not in {"running", ""}:
            findings.append(
                _finding(
                    finding_id="STANDARD-IR-001",
                    title="Windows Event Log service is not running",
                    severity="high",
                    confidence=confidence_for_basis("direct_system_evidence"),
                    basis="direct_system_evidence",
                    source_type="windows_native",
                    asset=self.session.intake.client_name,
                    evidence_summary=f"EventLog service status: {logging_payload.get('EventLogStatus')}",
                    why_it_matters="Incident response depends on reliable local event collection.",
                    likely_business_impact="Investigation and containment may be delayed or incomplete.",
                    remediation_steps=["Restore Windows Event Log service operation and investigate root cause."],
                    validation_steps=["Confirm EventLog service status is Running and logs are being written."],
                    evidence_path=str(evidence_file),
                    collected_at=collected_at,
                )
            )

        for prompt in prompts:
            findings.append(
                _finding(
                    finding_id=f"STANDARD-IR-Q-{prompt['id']}",
                    title=prompt["finding_title"],
                    severity=prompt["severity"],
                    confidence=confidence_for_basis("advisory_questionnaire"),
                    basis="advisory_questionnaire",
                    source_type="operator_questionnaire",
                    asset=self.session.intake.client_name,
                    evidence_summary=prompt["question"],
                    why_it_matters=prompt["why_it_matters"],
                    likely_business_impact=prompt["impact"],
                    remediation_steps=prompt["remediation_steps"],
                    validation_steps=prompt["validation_steps"],
                    evidence_path=str(evidence_file),
                    collected_at=collected_at,
                )
            )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail=f"Incident readiness score {score}/100.",
            findings=findings,
            evidence_files=[evidence_file],
        )


def incident_prompts() -> list[dict[str, Any]]:
    return [
        {
            "id": "CONTACTS",
            "question": "Provide the current critical incident contact list and escalation owner.",
            "finding_title": "Critical incident contact list evidence not provided",
            "severity": "medium",
            "why_it_matters": "Containment speed depends on knowing who can approve action.",
            "impact": "Response delays can increase outage time and ransomware blast radius.",
            "remediation_steps": ["Create and test an incident contact and escalation list."],
            "validation_steps": ["Review dated contact list and escalation rota."],
        },
        {
            "id": "ISOLATION",
            "question": "Confirm who can isolate endpoints, disable accounts, and block network paths.",
            "finding_title": "Isolation authority evidence not provided",
            "severity": "high",
            "why_it_matters": "Ransomware containment requires fast, authorized isolation actions.",
            "impact": "Attackers may continue spreading while teams seek approval.",
            "remediation_steps": ["Document emergency isolation authority and access paths."],
            "validation_steps": ["Walk through isolation decision and execution steps."],
        },
        {
            "id": "INVENTORY",
            "question": "Provide critical system inventory and owners.",
            "finding_title": "Critical system inventory evidence not provided",
            "severity": "medium",
            "why_it_matters": "IR teams need to prioritize containment and restoration.",
            "impact": "Critical services may be missed during triage and recovery.",
            "remediation_steps": ["Maintain critical system inventory with owners and dependencies."],
            "validation_steps": ["Review inventory freshness and owner approval."],
        },
        {
            "id": "EVIDENCE",
            "question": "Confirm evidence preservation process for logs, disk images, and affected hosts.",
            "finding_title": "Evidence preservation process evidence not provided",
            "severity": "low",
            "why_it_matters": "Preserved evidence improves root-cause analysis and legal defensibility.",
            "impact": "Incident scope and cause may remain unknown.",
            "remediation_steps": ["Define evidence preservation steps and storage location."],
            "validation_steps": ["Review IR SOP evidence preservation section."],
        },
    ]


def incident_readiness_score(*, logging_payload: dict[str, Any], prompts: list[dict[str, Any]]) -> int:
    score = 25
    if str(logging_payload.get("EventLogStatus", "")).lower() == "running":
        score += 25
    answered = sum(1 for prompt in prompts if prompt.get("status") == "answered")
    score += answered * 12
    return min(score, 100)


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    confidence: str,
    basis: str,
    source_type: str,
    asset: str,
    evidence_summary: str,
    why_it_matters: str,
    likely_business_impact: str,
    remediation_steps: list[str],
    validation_steps: list[str],
    evidence_path: str,
    collected_at: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        category="Incident Readiness",
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
        owner_role="Incident Response Lead",
        effort="medium",
        evidence_source_type=source_type,
        evidence_collected_at=collected_at,
        raw_evidence_path=evidence_path,
        finding_basis=basis,  # type: ignore[arg-type]
    )
