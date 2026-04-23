"""Identity and local administrator checks."""

from __future__ import annotations

import json
from dataclasses import dataclass

from app.collectors.shell import run_command
from app.collectors.windows import is_windows
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession
from app.profiling.environment import EnvironmentProfile


@dataclass(slots=True)
class IdentityModule:
    session: AssessmentSession
    profile: EnvironmentProfile

    name: str = "identity"

    def run(self) -> ModuleResult:
        if not is_windows():
            return ModuleResult(
                module_name=self.name,
                status="partial",
                detail="Windows local administrator and password policy checks skipped on non-Windows host.",
            )

        admins = run_command(["net", "localgroup", "administrators"], timeout_seconds=20)
        accounts = run_command(["net", "accounts"], timeout_seconds=20)
        evidence = {
            "local_administrators": admins.stdout,
            "local_administrators_error": admins.stderr,
            "password_policy": accounts.stdout,
            "password_policy_error": accounts.stderr,
        }
        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "identity_local_admins_policy.json",
            json.dumps(evidence, indent=2),
        )

        findings: list[Finding] = []
        if self.profile.is_admin:
            findings.append(
                Finding(
                    finding_id="BASIC-ID-001",
                    title="Assessment ran with local administrator privileges",
                    category="Identity",
                    package="basic",
                    severity="medium",
                    confidence="confirmed",
                    asset=self.profile.hostname,
                    evidence_summary="Current token indicates local administrator privilege.",
                    evidence_files=[str(evidence_file)],
                    why_it_matters="Routine use of local admin increases blast radius if the operator session is compromised.",
                    likely_business_impact="Malware or attacker tooling launched in this session may inherit admin rights.",
                    remediation_steps=[
                        "Use standard user context for routine operations.",
                        "Use just-in-time elevation only for approved administrative tasks.",
                    ],
                    validation_steps=[
                        "Confirm daily-use accounts are not members of local Administrators.",
                    ],
                    owner_role="IT Operations",
                    effort="medium",
                )
            )

        if "Maximum password age (days):            Unlimited" in accounts.stdout:
            findings.append(
                Finding(
                    finding_id="BASIC-ID-002",
                    title="Local password maximum age appears unlimited",
                    category="Identity",
                    package="basic",
                    severity="low",
                    confidence="strong",
                    asset=self.profile.hostname,
                    evidence_summary="net accounts output indicates unlimited maximum password age.",
                    evidence_files=[str(evidence_file)],
                    why_it_matters="Static local passwords increase long-term credential reuse risk.",
                    likely_business_impact="A leaked local credential may remain valid indefinitely.",
                    remediation_steps=[
                        "Apply an approved local account policy or LAPS-style management.",
                        "Disable unused local accounts.",
                    ],
                    validation_steps=[
                        "Run net accounts and confirm the maximum password age matches policy.",
                    ],
                    owner_role="IT Operations",
                    effort="low",
                )
            )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail="Reviewed local administrators and local password policy.",
            findings=findings,
            evidence_files=[evidence_file],
        )
