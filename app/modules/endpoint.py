"""Endpoint security posture checks."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession
from app.profiling.environment import EnvironmentProfile


@dataclass(slots=True)
class EndpointModule:
    session: AssessmentSession
    profile: EnvironmentProfile

    name: str = "endpoint"

    def run(self) -> ModuleResult:
        if self.profile.domain_or_workgroup == "unsupported-non-windows":
            return ModuleResult(
                module_name=self.name,
                status="partial",
                detail="Windows endpoint checks skipped on non-Windows host.",
            )

        findings: list[Finding] = []
        evidence_files = [str(path) for path in self.profile.evidence_files]

        if self.profile.firewall_status.lower() in {"disabled", "off"}:
            findings.append(
                Finding(
                    finding_id="BASIC-ENDPOINT-001",
                    title="Windows Firewall appears disabled",
                    category="Endpoint Security",
                    package="basic",
                    severity="high",
                    confidence="strong",
                    asset=self.profile.hostname,
                    evidence_summary=f"Firewall status reported as {self.profile.firewall_status}.",
                    evidence_files=evidence_files,
                    why_it_matters="Disabled host firewall increases exposure from local and routed networks.",
                    likely_business_impact="RDP, SMB, and management services can be reachable without host filtering.",
                    remediation_steps=[
                        "Enable Windows Firewall for domain, private, and public profiles.",
                        "Restrict inbound rules to explicit business requirements.",
                    ],
                    validation_steps=[
                        "Run Get-NetFirewallProfile and confirm all profiles are enabled.",
                    ],
                    owner_role="Endpoint Administrator",
                    effort="low",
                )
            )

        if self.profile.os_name.lower() != "unknown" and not self.profile.av_indicators:
            findings.append(
                Finding(
                    finding_id="BASIC-ENDPOINT-002",
                    title="AV/EDR indicator not confirmed",
                    category="Endpoint Security",
                    package="basic",
                    severity="medium",
                    confidence="weak",
                    asset=self.profile.hostname,
                    evidence_summary="The profiler did not confirm Defender or third-party AV/EDR indicators.",
                    evidence_files=evidence_files,
                    why_it_matters="Unprotected endpoints are easier to compromise and harder to investigate.",
                    likely_business_impact="Malware execution or ransomware staging may go undetected.",
                    remediation_steps=[
                        "Confirm the approved endpoint protection agent is installed and healthy.",
                        "Verify alert forwarding to the monitoring process.",
                    ],
                    validation_steps=[
                        "Check Microsoft Defender status or the client EDR console for this host.",
                    ],
                    owner_role="Endpoint Administrator",
                    effort="medium",
                )
            )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail="Reviewed AV/EDR indicators and firewall status.",
            findings=findings,
        )
