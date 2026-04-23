"""Local network exposure checks for Basic package."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.collectors.windows_native import WindowsEvidence
from app.core.config import AppConfig
from app.core.evidence import confidence_for_basis
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession
from app.profiling.environment import EnvironmentProfile
from app.scanners.nmap import NmapAdapter


@dataclass(slots=True)
class NetworkExposureLiteModule:
    session: AssessmentSession
    profile: EnvironmentProfile
    config: AppConfig
    windows_evidence: WindowsEvidence | None = None
    run_scope_scan: bool = True

    name: str = "network_exposure_lite"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        detail_parts: list[str] = []
        evidence_files: list[str] = []

        if self.windows_evidence and self.windows_evidence.supported:
            evidence_path = str(self.windows_evidence.raw_evidence_path or "")
            evidence_files = [evidence_path] if evidence_path else []
            findings.extend(
                build_local_exposure_findings(
                    asset_name=self.profile.hostname,
                    windows_evidence=self.windows_evidence,
                    package="basic",
                    finding_prefix="BASIC-NET",
                )
            )
            detail_parts.append("Reviewed local RDP, SMB, and remote access indicators.")
        else:
            detail_parts.append("Windows local exposure checks skipped on unsupported host.")

        if self.run_scope_scan:
            nmap_result = NmapAdapter(
                self.session,
                self.config.nmap,
                package=self.session.intake.package,
            ).scan(self.session.scope)
            findings.extend(nmap_result.findings)
            if nmap_result.raw_evidence_path:
                evidence_files.append(str(nmap_result.raw_evidence_path))
            detail_parts.append(f"Nmap status={nmap_result.status}: {nmap_result.detail}")
        else:
            nmap_result = None
            detail_parts.append("Approved-scope Nmap discovery handled by estate orchestrator.")

        return ModuleResult(
            module_name=self.name,
            status=(
                "complete"
                if nmap_result is None or nmap_result.status in {"complete", "skipped"}
                else "partial"
            ),
            detail=" ".join(detail_parts),
            findings=findings,
            evidence_files=[
                path
                for path in [
                    self.windows_evidence.raw_evidence_path if self.windows_evidence else None,
                    nmap_result.raw_evidence_path if nmap_result else None,
                ]
                if path
            ],
        )


def build_local_exposure_findings(
    *,
    asset_name: str,
    windows_evidence: WindowsEvidence,
    package: str,
    finding_prefix: str,
) -> list[Finding]:
    findings: list[Finding] = []
    evidence_path = str(windows_evidence.raw_evidence_path or "")
    evidence_files = [evidence_path] if evidence_path else []
    collected_at = windows_evidence.collected_at

    rdp_status = windows_evidence.section_json("rdp_status")
    if _rdp_enabled(rdp_status):
        findings.append(
            _local_finding(
                finding_id=f"{finding_prefix}-001",
                title="RDP enablement or listener indicator confirmed",
                category="Network Exposure",
                severity="high",
                evidence_summary="Windows evidence indicates RDP is enabled or listening locally.",
                why_it_matters="RDP is a high-value initial access and ransomware path when exposed or weakly controlled.",
                likely_business_impact="Compromise can lead to interactive attacker access and rapid privilege abuse.",
                remediation_steps=[
                    "Restrict RDP to approved admin sources or VPN paths only.",
                    "Require MFA where remote access architecture supports it.",
                    "Disable RDP where there is no documented business need.",
                ],
                validation_steps=[
                    "Confirm RDP registry state, TermService status, listener state, and inbound firewall rules.",
                ],
                owner_role="Infrastructure Administrator",
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )

    smb_status = windows_evidence.section_json("smb_status")
    if smb_status.get("EnableSMB1Protocol") is True:
        findings.append(
            _local_finding(
                finding_id=f"{finding_prefix}-002",
                title="SMBv1 is enabled",
                category="Network Exposure",
                severity="high",
                evidence_summary="Get-SmbServerConfiguration reported EnableSMB1Protocol=True.",
                why_it_matters="SMBv1 is obsolete and materially increases exposure to known attack paths.",
                likely_business_impact="Legacy SMB exposure can support malware propagation and unauthorized data access.",
                remediation_steps=[
                    "Disable SMBv1 unless a documented legacy dependency exists.",
                    "Replace or isolate systems that still require SMBv1.",
                ],
                validation_steps=[
                    "Run Get-SmbServerConfiguration and confirm EnableSMB1Protocol=False.",
                ],
                owner_role="Infrastructure Administrator",
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )
    if _int_value(smb_status.get("ListenerCount")) > 0:
        findings.append(
            _local_finding(
                finding_id=f"{finding_prefix}-003",
                title="SMB listener is active",
                category="Network Exposure",
                severity="medium",
                evidence_summary="Windows evidence indicates TCP/445 is listening locally.",
                why_it_matters="SMB exposure can support data access, credential relay, and lateral movement if poorly controlled.",
                likely_business_impact="Shared data and privileged sessions may be exposed to unauthorized access.",
                remediation_steps=[
                    "Restrict SMB to required internal networks.",
                    "Remove unused shares and review share plus NTFS permissions.",
                ],
                validation_steps=[
                    "Confirm TCP/445 exposure and enumerate required shares only.",
                ],
                owner_role="Infrastructure Administrator",
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )

    remote_access = windows_evidence.section_json("remote_access_software")
    remote_labels = _remote_access_labels(remote_access)
    if remote_labels:
        findings.append(
            _local_finding(
                finding_id=f"{finding_prefix}-004",
                title="Remote access software indicators found",
                category="Remote Access",
                severity="medium",
                evidence_summary=", ".join(remote_labels),
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
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )
    return findings


def _local_finding(
    *,
    finding_id: str,
    title: str,
    category: str,
    severity: str,
    evidence_summary: str,
    why_it_matters: str,
    likely_business_impact: str,
    remediation_steps: list[str],
    validation_steps: list[str],
    owner_role: str,
    evidence_files: list[str],
    evidence_path: str,
    collected_at: str,
    asset_name: str,
    package: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        category=category,
        package=package,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence_for_basis("direct_system_evidence"),
        asset=asset_name,
        evidence_summary=evidence_summary,
        evidence_files=evidence_files,
        why_it_matters=why_it_matters,
        likely_business_impact=likely_business_impact,
        remediation_steps=remediation_steps,
        validation_steps=validation_steps,
        owner_role=owner_role,
        effort="medium",
        evidence_source_type="windows_native",
        evidence_collected_at=collected_at,
        raw_evidence_path=evidence_path,
        finding_basis="direct_system_evidence",
    )


def _rdp_enabled(payload: dict[str, Any]) -> bool:
    return payload.get("fDenyTSConnections") in {0, "0"} or _int_value(payload.get("ListenerCount")) > 0


def _int_value(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _remote_access_labels(payload: dict[str, Any]) -> list[str]:
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
