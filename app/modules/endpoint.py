"""Endpoint security posture checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.collectors.windows_native import WindowsEvidence, evidence_items
from app.core.evidence import confidence_for_basis
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession
from app.profiling.environment import EnvironmentProfile


@dataclass(slots=True)
class EndpointModule:
    session: AssessmentSession
    profile: EnvironmentProfile
    windows_evidence: WindowsEvidence | None = None

    name: str = "endpoint"

    def run(self) -> ModuleResult:
        if not self.windows_evidence or not self.windows_evidence.supported:
            return ModuleResult(
                module_name=self.name,
                status="partial",
                detail="Windows endpoint checks skipped on non-Windows host.",
            )

        findings = build_endpoint_findings(
            asset_name=self.profile.hostname,
            windows_evidence=self.windows_evidence,
            package="basic",
            finding_prefix="BASIC-ENDPOINT",
        )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail="Reviewed Defender, firewall, BitLocker, and patch posture from Windows-native evidence.",
            findings=findings,
            evidence_files=[self.windows_evidence.raw_evidence_path]
            if self.windows_evidence.raw_evidence_path
            else [],
        )


def build_endpoint_findings(
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

    defender_status = windows_evidence.section_json("defender_status")
    defender_preferences = windows_evidence.section_json("defender_preferences")
    firewall_profiles = evidence_items(windows_evidence.section_json("firewall_profiles"))
    bitlocker_volumes = evidence_items(windows_evidence.section_json("bitlocker_status"))
    hotfixes = evidence_items(windows_evidence.section_json("hotfixes"))

    if defender_status and not defender_status.get("Unavailable"):
        if defender_status.get("AntivirusEnabled") is False:
            findings.append(
                _finding(
                    finding_id=f"{finding_prefix}-001",
                    title="Microsoft Defender antivirus is disabled",
                    severity="high",
                    evidence_summary="Get-MpComputerStatus reported AntivirusEnabled=False.",
                    why_it_matters="Disabled antivirus materially reduces malware prevention and detection.",
                    likely_business_impact="Commodity malware, ransomware staging, or attacker tools may execute with less resistance.",
                    remediation_steps=[
                        "Re-enable Microsoft Defender or confirm an approved replacement EDR is active.",
                        "Verify alert forwarding to the monitoring process.",
                    ],
                    validation_steps=[
                        "Run Get-MpComputerStatus and confirm AntivirusEnabled=True or verify approved EDR coverage.",
                    ],
                    evidence_files=evidence_files,
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    asset_name=asset_name,
                    package=package,
                )
            )
        if defender_status.get("RealTimeProtectionEnabled") is False:
            findings.append(
                _finding(
                    finding_id=f"{finding_prefix}-002",
                    title="Microsoft Defender real-time protection is disabled",
                    severity="high",
                    evidence_summary="Get-MpComputerStatus reported RealTimeProtectionEnabled=False.",
                    why_it_matters="Real-time protection is a primary control against execution and staging of malicious files.",
                    likely_business_impact="Malware may run or persist long enough to damage systems before detection.",
                    remediation_steps=[
                        "Re-enable Defender real-time protection unless a documented replacement control exists.",
                        "Investigate why protection was disabled.",
                    ],
                    validation_steps=[
                        "Run Get-MpComputerStatus and confirm RealTimeProtectionEnabled=True.",
                    ],
                    evidence_files=evidence_files,
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    asset_name=asset_name,
                    package=package,
                )
            )

    if defender_preferences and not defender_preferences.get("Unavailable"):
        disabled_preferences = [
            key
            for key in [
                "DisableRealtimeMonitoring",
                "DisableIOAVProtection",
                "DisableBehaviorMonitoring",
                "DisableBlockAtFirstSeen",
            ]
            if defender_preferences.get(key) is True
        ]
        if disabled_preferences:
            findings.append(
                _finding(
                    finding_id=f"{finding_prefix}-003",
                    title="Defender protection preferences are disabled",
                    severity="medium",
                    evidence_summary=(
                        "Get-MpPreference reported disabled controls: "
                        + ", ".join(disabled_preferences)
                    ),
                    why_it_matters="Disabled Defender controls reduce prevention depth even when the service is present.",
                    likely_business_impact="Endpoint compromise may be easier and detection quality may be reduced.",
                    remediation_steps=[
                        "Review the Defender policy source and re-enable disabled protections where business-approved.",
                        "Document any replacement control if these settings are intentionally disabled.",
                    ],
                    validation_steps=[
                        "Run Get-MpPreference and confirm the disabled settings are restored or documented.",
                    ],
                    evidence_files=evidence_files,
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    asset_name=asset_name,
                    package=package,
                )
            )

    disabled_profiles = [
        str(profile.get("Name", "unknown"))
        for profile in firewall_profiles
        if profile.get("Enabled") is False
    ]
    if disabled_profiles:
        findings.append(
            _finding(
                finding_id=f"{finding_prefix}-004",
                title="Windows Firewall appears disabled",
                severity="high",
                evidence_summary=(
                    "Get-NetFirewallProfile reported disabled profile(s): "
                    + ", ".join(disabled_profiles)
                ),
                why_it_matters="Disabled host firewall increases exposure from local and routed networks.",
                likely_business_impact="RDP, SMB, and management services can be reachable without host filtering.",
                remediation_steps=[
                    "Enable Windows Firewall for domain, private, and public profiles.",
                    "Restrict inbound rules to explicit business requirements.",
                ],
                validation_steps=[
                    "Run Get-NetFirewallProfile and confirm all profiles are enabled.",
                ],
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )

    unprotected_volumes = [
        volume
        for volume in bitlocker_volumes
        if _bitlocker_protection_off(volume)
    ]
    if unprotected_volumes:
        mounts = ", ".join(str(volume.get("MountPoint", "unknown")) for volume in unprotected_volumes)
        findings.append(
            _finding(
                finding_id=f"{finding_prefix}-005",
                title="BitLocker protection is not enabled on one or more volumes",
                severity="medium",
                evidence_summary=f"Get-BitLockerVolume reported protection off or not active for: {mounts}.",
                why_it_matters="Unencrypted disks increase data exposure risk if devices are lost, stolen, or removed.",
                likely_business_impact="Sensitive client or business data may be recoverable from physical media.",
                remediation_steps=[
                    "Enable BitLocker or approved disk encryption for protected endpoints.",
                    "Escrow recovery keys in the approved management system.",
                ],
                validation_steps=[
                    "Run Get-BitLockerVolume and confirm ProtectionStatus is On for required volumes.",
                ],
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )

    stale_patch_days = _latest_hotfix_age_days(hotfixes)
    if stale_patch_days is not None and stale_patch_days > 60:
        findings.append(
            _finding(
                finding_id=f"{finding_prefix}-006",
                title="No recent Windows hotfix observed",
                severity="medium",
                evidence_summary=f"Get-HotFix latest parsed InstalledOn value is {stale_patch_days} days old.",
                why_it_matters="Stale patch posture increases exposure to known, commodity exploitation paths.",
                likely_business_impact="Known vulnerabilities may remain exploitable if patch management is not current.",
                remediation_steps=[
                    "Validate Windows Update, WSUS, or endpoint management patch status.",
                    "Apply missing approved security updates through the normal change process.",
                ],
                validation_steps=[
                    "Run Get-HotFix or the endpoint management report and confirm recent security updates.",
                ],
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )
    return findings


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    evidence_summary: str,
    why_it_matters: str,
    likely_business_impact: str,
    remediation_steps: list[str],
    validation_steps: list[str],
    evidence_files: list[str],
    evidence_path: str,
    collected_at: str,
    asset_name: str,
    package: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        category="Endpoint Security",
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
        owner_role="Endpoint Administrator",
        effort="medium",
        evidence_source_type="windows_native",
        evidence_collected_at=collected_at,
        raw_evidence_path=evidence_path,
        finding_basis="direct_system_evidence",
    )


def _bitlocker_protection_off(volume: dict[str, Any]) -> bool:
    if volume.get("Unavailable"):
        return False
    protection = str(volume.get("ProtectionStatus", "")).lower()
    if not protection:
        return False
    return protection not in {"on", "1"}


def _latest_hotfix_age_days(hotfixes: list[dict[str, Any]]) -> int | None:
    dates: list[datetime] = []
    for hotfix in hotfixes:
        parsed = _parse_windows_date(str(hotfix.get("InstalledOn", "")))
        if parsed:
            dates.append(parsed)
    if not dates:
        return None
    latest = max(dates)
    return (datetime.now(timezone.utc) - latest.astimezone(timezone.utc)).days


def _parse_windows_date(value: str) -> datetime | None:
    if not value:
        return None
    cleaned = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y"):
        try:
            return datetime.strptime(cleaned[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError:
        return None
