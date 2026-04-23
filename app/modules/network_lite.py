"""Local network exposure checks for Basic package."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession
from app.profiling.environment import EnvironmentProfile


@dataclass(slots=True)
class NetworkExposureLiteModule:
    session: AssessmentSession
    profile: EnvironmentProfile

    name: str = "network_exposure_lite"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        evidence_files = [str(path) for path in self.profile.evidence_files]

        if self.session.scope.local_only:
            scope_detail = "Scope is local-host-only. No remote network scan performed."
        else:
            scope_detail = (
                "Authorized subnet is recorded, but Basic package performs local exposure checks only."
            )

        if self.profile.rdp_enabled:
            findings.append(
                Finding(
                    finding_id="BASIC-NET-001",
                    title="RDP exposure indicator confirmed",
                    category="Network Exposure",
                    package="basic",
                    severity="high",
                    confidence="strong",
                    asset=self.profile.hostname,
                    evidence_summary="RDP appears enabled or listening locally.",
                    evidence_files=evidence_files,
                    why_it_matters="RDP is a high-value initial access and ransomware path when exposed or weakly controlled.",
                    likely_business_impact="Compromise can lead to interactive attacker access and rapid privilege abuse.",
                    remediation_steps=[
                        "Restrict RDP to approved admin sources or VPN paths only.",
                        "Require MFA where remote access architecture supports it.",
                        "Disable RDP where there is no documented business need.",
                    ],
                    validation_steps=[
                        "Confirm RDP service state and inbound firewall rules.",
                        "Validate access is limited to approved source networks.",
                    ],
                    owner_role="Infrastructure Administrator",
                    effort="medium",
                )
            )

        if self.profile.smb_enabled:
            findings.append(
                Finding(
                    finding_id="BASIC-NET-002",
                    title="SMB exposure indicator confirmed",
                    category="Network Exposure",
                    package="basic",
                    severity="medium",
                    confidence="strong",
                    asset=self.profile.hostname,
                    evidence_summary="SMB appears enabled or listening locally.",
                    evidence_files=evidence_files,
                    why_it_matters="SMB exposure can support credential relay, data access, and lateral movement.",
                    likely_business_impact="Shared data and privileged sessions may be exposed to unauthorized access.",
                    remediation_steps=[
                        "Restrict SMB to required internal networks.",
                        "Disable SMBv1 and remove unused shares.",
                        "Review share and NTFS permissions for least privilege.",
                    ],
                    validation_steps=[
                        "Confirm port 445 exposure and enumerate required shares only.",
                    ],
                    owner_role="Infrastructure Administrator",
                    effort="medium",
                )
            )

        if self.profile.remote_access_indicators:
            findings.append(
                Finding(
                    finding_id="BASIC-NET-003",
                    title="Remote access software indicators found",
                    category="Remote Access",
                    package="basic",
                    severity="medium",
                    confidence="strong",
                    asset=self.profile.hostname,
                    evidence_summary=", ".join(self.profile.remote_access_indicators),
                    evidence_files=evidence_files,
                    why_it_matters="Remote access tools are valid business utilities and common attacker persistence paths.",
                    likely_business_impact="Uncontrolled vendor or support access can bypass normal perimeter controls.",
                    remediation_steps=[
                        "Validate each remote access tool has an owner and business justification.",
                        "Remove unauthorized tools.",
                        "Require MFA and logging for approved remote access.",
                    ],
                    validation_steps=[
                        "Compare installed remote access tools against the approved vendor access list.",
                    ],
                    owner_role="IT Operations",
                    effort="medium",
                )
            )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail=f"Reviewed local RDP, SMB, and remote access indicators. {scope_detail}",
            findings=findings,
        )
