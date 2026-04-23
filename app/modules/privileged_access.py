"""Standard package shared and privileged access review."""

from __future__ import annotations

import json
from dataclasses import dataclass

from app.collectors.windows_native import WindowsEvidence, evidence_items
from app.core.evidence import confidence_for_basis, utc_now
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession


@dataclass(slots=True)
class PrivilegedAccessModule:
    session: AssessmentSession
    windows_evidence: WindowsEvidence

    name: str = "privileged_access"

    def run(self) -> ModuleResult:
        collected_at = utc_now()
        admins = evidence_items(self.windows_evidence.section_json("local_administrators"))
        admin_names = [str(item.get("Name", "")) for item in admins if item.get("Name")]
        evidence = {
            "collected_at": collected_at,
            "local_administrators": admin_names,
            "prompts": privileged_prompts(),
        }
        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "privileged_access_review.json",
            json.dumps(evidence, indent=2, sort_keys=True),
        )
        findings: list[Finding] = []

        shared_like = [name for name in admin_names if _looks_shared_or_service(name)]
        if shared_like:
            findings.append(
                _finding(
                    finding_id="STANDARD-PRIV-001",
                    title="Shared or service-account-like local administrator principal observed",
                    severity="medium",
                    confidence=confidence_for_basis("direct_system_evidence"),
                    basis="direct_system_evidence",
                    source_type="windows_native",
                    evidence_summary=", ".join(shared_like),
                    why_it_matters="Shared or service-style privileged accounts reduce accountability and increase credential reuse risk.",
                    impact="Unauthorized privileged activity may be harder to attribute and contain.",
                    remediation=["Replace shared privileged accounts with named accounts or managed service identities."],
                    validation=["Review local Administrators membership and account ownership records."],
                    evidence_path=str(evidence_file),
                    collected_at=collected_at,
                    asset=self.session.intake.client_name,
                )
            )

        for prompt in privileged_prompts():
            findings.append(
                _finding(
                    finding_id=f"STANDARD-PRIV-Q-{prompt['id']}",
                    title=prompt["finding_title"],
                    severity=prompt["severity"],
                    confidence=confidence_for_basis("advisory_questionnaire"),
                    basis="advisory_questionnaire",
                    source_type="operator_questionnaire",
                    evidence_summary=prompt["question"],
                    why_it_matters=prompt["why_it_matters"],
                    impact=prompt["impact"],
                    remediation=prompt["remediation_steps"],
                    validation=prompt["validation_steps"],
                    evidence_path=str(evidence_file),
                    collected_at=collected_at,
                    asset=self.session.intake.client_name,
                )
            )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail=f"Reviewed {len(admin_names)} local administrator principal(s) plus privileged access prompts.",
            findings=findings,
            evidence_files=[evidence_file],
        )


def privileged_prompts() -> list[dict[str, object]]:
    return [
        {
            "id": "DORMANT_PRIV",
            "question": "Provide evidence that dormant privileged accounts are reviewed and disabled.",
            "finding_title": "Dormant privileged access evidence not provided",
            "severity": "medium",
            "why_it_matters": "Dormant privileged accounts are high-value takeover targets.",
            "impact": "An unused account may provide persistent privileged access if compromised.",
            "remediation_steps": ["Run a privileged account review and disable stale accounts."],
            "validation_steps": ["Review dated privileged access recertification evidence."],
        },
        {
            "id": "SERVICE_ACCOUNTS",
            "question": "Provide service account inventory, owner, and rotation evidence.",
            "finding_title": "Service account governance evidence not provided",
            "severity": "medium",
            "why_it_matters": "Unowned service accounts often have static credentials and broad access.",
            "impact": "Credential compromise may provide durable privileged access.",
            "remediation_steps": ["Inventory service accounts and assign owners plus rotation rules."],
            "validation_steps": ["Review service account inventory and last rotation evidence."],
        },
    ]


def _looks_shared_or_service(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in ["shared", "svc", "service", "admin"])


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    confidence: str,
    basis: str,
    source_type: str,
    evidence_summary: str,
    why_it_matters: str,
    impact: str,
    remediation: list[str],
    validation: list[str],
    evidence_path: str,
    collected_at: str,
    asset: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        category="Privileged Access",
        package="standard",
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        asset=asset,
        evidence_summary=evidence_summary,
        evidence_files=[evidence_path],
        why_it_matters=why_it_matters,
        likely_business_impact=impact,
        remediation_steps=remediation,
        validation_steps=validation,
        owner_role="Identity Owner",
        effort="medium",
        evidence_source_type=source_type,
        evidence_collected_at=collected_at,
        raw_evidence_path=evidence_path,
        finding_basis=basis,  # type: ignore[arg-type]
    )
