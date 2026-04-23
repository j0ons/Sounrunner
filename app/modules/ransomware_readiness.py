"""Standard package ransomware readiness scoring."""

from __future__ import annotations

import json
from dataclasses import dataclass

from app.core.evidence import confidence_for_basis, utc_now
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession


@dataclass(slots=True)
class RansomwareReadinessModule:
    session: AssessmentSession
    warn_threshold: int = 70

    name: str = "ransomware_readiness"

    def run(self) -> ModuleResult:
        collected_at = utc_now()
        existing = self.session.database.list_findings()
        score, factors = ransomware_readiness_score(existing)
        evidence = {
            "collected_at": collected_at,
            "readiness_score": score,
            "contributing_factors": factors,
            "basis": "Aggregated assessment findings. No malware simulation was performed.",
        }
        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "ransomware_readiness_summary.json",
            json.dumps(evidence, indent=2, sort_keys=True),
        )

        findings: list[Finding] = []
        if score < self.warn_threshold:
            findings.append(
                Finding(
                    finding_id="STANDARD-RW-001",
                    title="Ransomware readiness score below target",
                    category="Ransomware Readiness",
                    package="standard",
                    severity="high" if score < 50 else "medium",
                    confidence=confidence_for_basis("inferred_partial"),
                    asset=self.session.intake.client_name,
                    evidence_summary=f"Readiness score {score}/100. Factors: " + "; ".join(factors),
                    evidence_files=[str(evidence_file)],
                    why_it_matters="Ransomware readiness depends on layered controls, recoverability, and response speed.",
                    likely_business_impact="The organization may experience longer outage and higher data-loss risk during ransomware.",
                    remediation_steps=[
                        "Prioritize high-risk findings in backup readiness, exposed management services, privileged access, and IR process.",
                        "Validate recovery and isolation procedures with a tabletop exercise.",
                    ],
                    validation_steps=[
                        "Re-run Standard assessment after remediation and confirm readiness score improves.",
                    ],
                    owner_role="Security Lead",
                    effort="high",
                    evidence_source_type="assessment_aggregate",
                    evidence_collected_at=collected_at,
                    raw_evidence_path=str(evidence_file),
                    finding_basis="inferred_partial",
                )
            )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail=f"Ransomware readiness score {score}/100.",
            findings=findings,
            evidence_files=[evidence_file],
        )


def ransomware_readiness_score(findings: list[Finding]) -> tuple[int, list[str]]:
    score = 100
    factors: list[str] = []
    for finding in findings:
        if finding.category in {"Backup Readiness"}:
            score -= 15 if finding.severity in {"high", "critical"} else 8
            factors.append(f"Backup: {finding.title}")
        elif finding.category in {"Network Exposure", "Network Discovery", "Remote Access"}:
            score -= 12 if finding.severity in {"high", "critical"} else 6
            factors.append(f"Exposure: {finding.title}")
        elif finding.category in {"Identity", "Privileged Access"}:
            score -= 10 if finding.severity in {"high", "critical"} else 5
            factors.append(f"Access: {finding.title}")
        elif finding.category == "Incident Readiness":
            score -= 8 if finding.severity in {"high", "critical"} else 4
            factors.append(f"IR: {finding.title}")
    return max(score, 0), factors[:10]
