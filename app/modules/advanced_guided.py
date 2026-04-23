"""Advanced guided assessment foundation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.core.evidence import confidence_for_basis, utc_now
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession


@dataclass(slots=True)
class AdvancedGuidedModule:
    session: AssessmentSession

    name: str = "advanced_guided_assessment"

    def run(self) -> ModuleResult:
        collected_at = utc_now()
        plan = advanced_plan_template()
        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "advanced_guided_assessment.json",
            json.dumps(
                {
                    "collected_at": collected_at,
                    "guidance": "Guided assessment foundation. Unanswered prompts are advisory, not confirmed technical findings.",
                    "plan": plan,
                },
                indent=2,
                sort_keys=True,
            ),
        )
        findings = [
            Finding(
                finding_id=f"ADV-GUIDED-{item['id']}",
                title=item["finding_title"],
                category=item["category"],
                package="advanced",
                severity=item["severity"],  # type: ignore[arg-type]
                confidence=confidence_for_basis("advisory_questionnaire"),
                asset=self.session.intake.client_name,
                evidence_summary=item["prompt"],
                evidence_files=[str(evidence_file)],
                why_it_matters=item["why_it_matters"],
                likely_business_impact=item["impact"],
                remediation_steps=item["actions"],
                validation_steps=item["validation"],
                owner_role=item["owner_role"],
                effort="medium",
                evidence_source_type="operator_questionnaire",
                evidence_collected_at=collected_at,
                raw_evidence_path=str(evidence_file),
                finding_basis="advisory_questionnaire",
            )
            for item in plan
        ]
        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail="Advanced guided assessment prompts and planning outputs generated.",
            findings=findings,
            evidence_files=[evidence_file],
        )


def advanced_plan_template() -> list[dict[str, Any]]:
    return [
        {
            "id": "BCP",
            "category": "Business Continuity",
            "prompt": "Document critical business services, tolerated downtime, manual fallback, and decision owners.",
            "finding_title": "Business continuity risk review requires guided completion",
            "severity": "medium",
            "why_it_matters": "Technical recovery does not equal business recovery unless priorities and fallback plans are known.",
            "impact": "Business interruption may continue after systems are technically restored.",
            "actions": ["Run a business continuity workshop and document critical process dependencies."],
            "validation": ["Review approved BCP document, owner sign-off, and last exercise date."],
            "owner_role": "Business Continuity Owner",
        },
        {
            "id": "RECOVERY_PRIORITY",
            "category": "Recovery Planning",
            "prompt": "Map recovery priority by system, department, data dependency, and RTO/RPO.",
            "finding_title": "Recovery priority mapping requires guided completion",
            "severity": "medium",
            "why_it_matters": "Recovery order must match business priority during ransomware or outage response.",
            "impact": "Teams may restore low-value systems while critical services remain down.",
            "actions": ["Create a tiered recovery priority map for critical systems."],
            "validation": ["Review recovery priority map with executive and system owner approval."],
            "owner_role": "IT Operations Lead",
        },
        {
            "id": "VENDOR_ACCESS",
            "category": "Vendor Access",
            "prompt": "Review third-party/vendor remote access, MFA, ownership, expiry, and logging.",
            "finding_title": "Vendor access review requires guided completion",
            "severity": "high",
            "why_it_matters": "Vendor access is a common unmanaged trust path.",
            "impact": "Compromised vendor access may bypass normal perimeter controls.",
            "actions": ["Inventory vendor access paths and enforce MFA, logging, and expiry."],
            "validation": ["Review vendor access list and access-control evidence."],
            "owner_role": "IT Governance Owner",
        },
        {
            "id": "POLICY_SOP",
            "category": "Policy/SOP",
            "prompt": "Review incident, backup, access, remote support, and evidence preservation SOPs.",
            "finding_title": "Policy/SOP gap review requires guided completion",
            "severity": "low",
            "why_it_matters": "SOP gaps slow execution and create inconsistent decisions during incidents.",
            "impact": "Response quality depends on individual memory instead of repeatable process.",
            "actions": ["Update SOPs and assign review cadence plus owners."],
            "validation": ["Review approved SOP set and last tabletop evidence."],
            "owner_role": "Security Governance Owner",
        },
        {
            "id": "AWARENESS_PACK",
            "category": "Awareness",
            "prompt": "Prepare awareness session output pack for ransomware, phishing, escalation, and reporting.",
            "finding_title": "Awareness output pack requires guided completion",
            "severity": "info",
            "why_it_matters": "Users and managers need clear escalation expectations during suspicious activity.",
            "impact": "Delayed reporting can increase dwell time and damage.",
            "actions": ["Create awareness pack and run targeted session for key departments."],
            "validation": ["Record attendance and post-session action items."],
            "owner_role": "Security Awareness Owner",
        },
    ]
