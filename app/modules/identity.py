"""Identity and local administrator checks."""

from __future__ import annotations

from dataclasses import dataclass

from app.collectors.windows_native import WindowsEvidence, evidence_items, parse_password_policy
from app.core.evidence import confidence_for_basis
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession
from app.profiling.environment import EnvironmentProfile


@dataclass(slots=True)
class IdentityModule:
    session: AssessmentSession
    profile: EnvironmentProfile
    windows_evidence: WindowsEvidence | None = None

    name: str = "identity"

    def run(self) -> ModuleResult:
        if not self.windows_evidence or not self.windows_evidence.supported:
            return ModuleResult(
                module_name=self.name,
                status="partial",
                detail="Windows local administrator and password policy checks skipped on non-Windows host.",
            )

        findings = build_identity_findings(
            asset_name=self.profile.hostname,
            windows_evidence=self.windows_evidence,
            package="basic",
            is_admin=self.profile.is_admin,
            finding_prefix="BASIC-ID",
        )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail="Reviewed local administrators and local password policy.",
            findings=findings,
            evidence_files=[self.windows_evidence.raw_evidence_path]
            if self.windows_evidence.raw_evidence_path
            else [],
        )


def build_identity_findings(
    *,
    asset_name: str,
    windows_evidence: WindowsEvidence,
    package: str,
    is_admin: bool,
    finding_prefix: str,
) -> list[Finding]:
    findings: list[Finding] = []
    evidence_path = str(windows_evidence.raw_evidence_path or "")
    evidence_files = [evidence_path] if evidence_path else []
    collected_at = windows_evidence.collected_at

    if is_admin:
        findings.append(
            _finding(
                finding_id=f"{finding_prefix}-001",
                title="Assessment ran with local administrator privileges",
                severity="medium",
                evidence_summary="Current token indicates local administrator privilege.",
                why_it_matters="Routine use of local admin increases blast radius if the operator session is compromised.",
                likely_business_impact="Malware or attacker tooling launched in this session may inherit admin rights.",
                remediation_steps=[
                    "Use standard user context for routine operations.",
                    "Use just-in-time elevation only for approved administrative tasks.",
                ],
                validation_steps=[
                    "Confirm daily-use accounts are not members of local Administrators.",
                ],
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )

    admin_members = evidence_items(windows_evidence.section_json("local_administrators"))
    broad_admins = [
        str(item.get("Name", ""))
        for item in admin_members
        if _is_broad_admin_principal(str(item.get("Name", "")))
    ]
    if broad_admins:
        findings.append(
            _finding(
                finding_id=f"{finding_prefix}-002",
                title="Broad principal is a local administrator",
                severity="high",
                evidence_summary="Local Administrators includes broad principal(s): " + ", ".join(broad_admins),
                why_it_matters="Broad local administrator membership creates immediate privilege exposure.",
                likely_business_impact="Any user in the broad group may gain local administrative control of the endpoint.",
                remediation_steps=[
                    "Remove broad principals from local Administrators.",
                    "Use named admin groups with documented ownership and least privilege.",
                ],
                validation_steps=[
                    "Run Get-LocalGroupMember -Group Administrators and confirm broad principals are removed.",
                ],
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )

    password_policy = parse_password_policy(windows_evidence.section_text("password_policy"))
    min_length = _parse_int(password_policy.get("minimum password length"))
    if min_length is not None and min_length < 12:
        findings.append(
            _finding(
                finding_id=f"{finding_prefix}-003",
                title="Local password minimum length is below 12 characters",
                severity="medium",
                evidence_summary=f"net accounts reported minimum password length: {min_length}.",
                why_it_matters="Short local passwords are more vulnerable to guessing and reuse attacks.",
                likely_business_impact="A compromised local credential may enable unauthorized local access.",
                remediation_steps=[
                    "Set local minimum password length to the approved baseline.",
                    "Use managed local administrator passwords where supported.",
                ],
                validation_steps=[
                    "Run net accounts and confirm minimum password length meets policy.",
                ],
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )

    lockout_threshold = _parse_int(password_policy.get("lockout threshold"))
    if lockout_threshold == 0:
        findings.append(
            _finding(
                finding_id=f"{finding_prefix}-004",
                title="Local account lockout threshold is disabled",
                severity="medium",
                evidence_summary="net accounts reported lockout threshold: Never or 0.",
                why_it_matters="No lockout threshold allows unlimited online password attempts against local accounts.",
                likely_business_impact="Password guessing against local accounts may proceed without account lockout friction.",
                remediation_steps=[
                    "Configure an approved lockout threshold for local accounts.",
                    "Monitor lockout and failed logon telemetry.",
                ],
                validation_steps=[
                    "Run net accounts and confirm lockout threshold is set to the approved value.",
                ],
                evidence_files=evidence_files,
                evidence_path=evidence_path,
                collected_at=collected_at,
                asset_name=asset_name,
                package=package,
            )
        )

    max_age = password_policy.get("maximum password age (days)")
    if max_age and max_age.lower() == "unlimited":
        findings.append(
            _finding(
                finding_id=f"{finding_prefix}-005",
                title="Local password maximum age appears unlimited",
                severity="low",
                evidence_summary="net accounts output indicates unlimited maximum password age.",
                why_it_matters="Static local passwords increase long-term credential reuse risk.",
                likely_business_impact="A leaked local credential may remain valid indefinitely.",
                remediation_steps=[
                    "Apply an approved local account policy or LAPS-style management.",
                    "Disable unused local accounts.",
                ],
                validation_steps=[
                    "Run net accounts and confirm the maximum password age matches policy.",
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
        category="Identity",
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
        owner_role="IT Operations",
        effort="medium",
        evidence_source_type="windows_native",
        evidence_collected_at=collected_at,
        raw_evidence_path=evidence_path,
        finding_basis="direct_system_evidence",
    )


def _is_broad_admin_principal(name: str) -> bool:
    lowered = name.lower()
    broad_markers = [
        "\\domain users",
        "\\authenticated users",
        "\\everyone",
        "nt authority\\authenticated users",
        "everyone",
    ]
    return any(marker in lowered for marker in broad_markers)


def _parse_int(value: str | None) -> int | None:
    if not value:
        return None
    cleaned = value.strip().lower()
    if cleaned in {"never", "unlimited"}:
        return 0
    digits = "".join(char for char in cleaned if char.isdigit())
    return int(digits) if digits else None
