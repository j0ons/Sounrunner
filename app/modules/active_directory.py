"""Active Directory read-only evidence module."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.collectors.ad_directory import ActiveDirectoryCollector
from app.collectors.ad_directory import ActiveDirectoryEvidence
from app.collectors.windows_native import evidence_items
from app.core.config import ActiveDirectoryConfig, AppConfig
from app.core.evidence import confidence_for_basis
from app.core.inventory import AssetInventory
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession


@dataclass(slots=True)
class ActiveDirectoryModule:
    session: AssessmentSession
    config: AppConfig

    name: str = "active_directory"

    def run(self) -> ModuleResult:
        collector = ActiveDirectoryCollector(self.session, self.config.active_directory)
        evidence = collector.collect()
        evidence_files = [evidence.raw_evidence_path] if evidence.raw_evidence_path else []
        if not self.config.active_directory.enabled:
            return ModuleResult(
                module_name=self.name,
                status="skipped",
                detail="Active Directory evidence module disabled in config.",
                evidence_files=evidence_files,
            )
        if not evidence.supported:
            detail = _unsupported_detail(evidence)
            return ModuleResult(
                module_name=self.name,
                status="partial",
                detail=detail,
                evidence_files=evidence_files,
            )

        inventory = AssetInventory(self.session, self.config)
        domain_info = evidence.section_json("domain_info")
        domain_controllers = evidence_items(evidence.section_json("domain_controllers"))
        computers = evidence_items(evidence.section_json("computers"))
        users = evidence_items(evidence.section_json("users"))
        privileged_groups = evidence_items(evidence.section_json("privileged_groups"))
        password_policy = evidence.section_json("password_policy")

        dc_names = {
            item
            for controller in domain_controllers
            for item in [
                str(controller.get("HostName", "")).strip().lower(),
                str(controller.get("IPv4Address", "")).strip().lower(),
            ]
            if item
        }
        for computer in computers:
            record = inventory.record_directory_asset(computer, dc_names)
            if evidence.raw_evidence_path:
                inventory.attach_evidence(record.asset_id, str(evidence.raw_evidence_path), self.name)
            self.session.database.upsert_asset_module_status(
                record.asset_id,
                self.name,
                "complete",
                "Asset enriched from Active Directory evidence.",
            )

        summary = _summary(
            config=self.config.active_directory,
            domain_info=domain_info,
            domain_controllers=domain_controllers,
            computers=computers,
            users=users,
            privileged_groups=privileged_groups,
            password_policy=password_policy,
        )
        summary_path = self.session.crypto.write_text(
            self.session.evidence_dir / "active_directory_summary.json",
            json.dumps(summary, indent=2, sort_keys=True),
        )
        self.session.database.set_metadata("active_directory_summary", {"path": str(summary_path), **summary})

        findings: list[Finding] = []
        evidence_path = str(summary_path)
        collected_at = evidence.collected_at
        min_length = _to_int(password_policy.get("MinPasswordLength"))
        lockout_threshold = _to_int(password_policy.get("LockoutThreshold"))
        if min_length is not None and min_length < 12:
            findings.append(
                _finding(
                    finding_id="STANDARD-AD-001",
                    title="AD default password policy minimum length is below 12 characters",
                    severity="medium",
                    asset=str(domain_info.get("DNSRoot") or self.session.intake.client_name),
                    evidence_summary=f"Get-ADDefaultDomainPasswordPolicy reported MinPasswordLength={min_length}.",
                    why="Short domain password policy increases identity exposure across the estate.",
                    impact="A weak directory password baseline increases risk of password guessing and reuse across many systems.",
                    remediation=["Raise the minimum AD password length to the approved baseline."],
                    validation=["Re-run Get-ADDefaultDomainPasswordPolicy and confirm MinPasswordLength meets policy."],
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    package=self.session.intake.package,
                )
            )
        if lockout_threshold == 0:
            findings.append(
                _finding(
                    finding_id="STANDARD-AD-002",
                    title="AD default lockout threshold is disabled",
                    severity="medium",
                    asset=str(domain_info.get("DNSRoot") or self.session.intake.client_name),
                    evidence_summary="Get-ADDefaultDomainPasswordPolicy reported LockoutThreshold=0.",
                    why="Unlimited directory password attempts reduce resistance to online guessing.",
                    impact="A weak directory lockout baseline can increase identity compromise risk across multiple hosts and services.",
                    remediation=["Set the AD lockout threshold to the approved baseline."],
                    validation=["Re-run Get-ADDefaultDomainPasswordPolicy and confirm LockoutThreshold is set."],
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    package=self.session.intake.package,
                )
            )

        stale_users = [
            user for user in users
            if bool(user.get("Enabled")) and _is_stale(user.get("LastLogonDate"), self.config.active_directory.stale_account_days)
        ]
        if stale_users:
            findings.append(
                _finding(
                    finding_id="STANDARD-AD-003",
                    title="Enabled AD user accounts appear stale",
                    severity="medium",
                    asset=str(domain_info.get("DNSRoot") or self.session.intake.client_name),
                    evidence_summary=(
                        f"{len(stale_users)} enabled sampled account(s) have LastLogonDate older than "
                        f"{self.config.active_directory.stale_account_days} days."
                    ),
                    why="Enabled stale accounts expand the credential attack surface and often evade ownership review.",
                    impact="A dormant enabled account can provide reusable access without immediate detection.",
                    remediation=["Review stale enabled accounts and disable or justify them."],
                    validation=["Provide account recertification or disablement evidence for stale accounts."],
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    package=self.session.intake.package,
                )
            )

        for group_name, threshold in {"Domain Admins": 5, "Enterprise Admins": 2}.items():
            group = _group_entry(privileged_groups, group_name)
            if group and _to_int(group.get("MemberCount")) and _to_int(group.get("MemberCount")) > threshold:
                findings.append(
                    _finding(
                        finding_id=f"STANDARD-AD-GRP-{group_name.replace(' ', '-').upper()}",
                        title=f"{group_name} membership exceeds review threshold",
                        severity="high",
                        asset=str(domain_info.get("DNSRoot") or self.session.intake.client_name),
                        evidence_summary=f"{group_name} sampled member count={group.get('MemberCount')}.",
                        why=f"{group_name} is a high-value privileged group and broad membership increases blast radius.",
                        impact="Excessive privileged directory membership can accelerate full-domain compromise if one credential is abused.",
                        remediation=[f"Review and reduce {group_name} membership to named, justified roles."],
                        validation=[f"Re-run AD group membership review and confirm {group_name} membership is minimized."],
                        evidence_path=evidence_path,
                        collected_at=collected_at,
                        package=self.session.intake.package,
                    )
                )

        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail=(
                f"Collected AD evidence for domain {summary.get('domain_name', 'unknown')} with "
                f"{summary.get('computer_count', 0)} sampled computer object(s)."
            ),
            findings=findings,
            evidence_files=[*evidence_files, summary_path],
        )


def _unsupported_detail(evidence: ActiveDirectoryEvidence) -> str:
    module_check = evidence.section("module_check")
    if module_check and module_check.stdout.strip().lower() == "missing":
        return "Active Directory cmdlets are unavailable. AD evidence skipped cleanly."
    if module_check and module_check.stderr:
        return f"AD evidence unavailable: {module_check.stderr}"
    return "AD evidence unavailable on this host or in this execution context."


def _summary(
    *,
    config: ActiveDirectoryConfig,
    domain_info: dict[str, Any],
    domain_controllers: list[dict[str, Any]],
    computers: list[dict[str, Any]],
    users: list[dict[str, Any]],
    privileged_groups: list[dict[str, Any]],
    password_policy: dict[str, Any],
) -> dict[str, Any]:
    enabled_users = sum(1 for user in users if bool(user.get("Enabled")))
    disabled_users = sum(1 for user in users if not bool(user.get("Enabled")))
    stale_users = sum(
        1
        for user in users
        if bool(user.get("Enabled")) and _is_stale(user.get("LastLogonDate"), config.stale_account_days)
    )
    return {
        "domain_name": str(domain_info.get("DNSRoot", "")),
        "domain_mode": str(domain_info.get("DomainMode", "")),
        "domain_controllers": domain_controllers,
        "domain_controller_count": len(domain_controllers),
        "computer_count": len(computers),
        "enabled_user_count_sample": enabled_users,
        "disabled_user_count_sample": disabled_users,
        "stale_enabled_user_count_sample": stale_users,
        "privileged_group_counts": {
            str(item.get("Group", "")): _to_int(item.get("MemberCount")) or 0
            for item in privileged_groups
        },
        "password_policy": password_policy,
        "sample_limits": {
            "computer_limit": config.computer_limit,
            "user_limit": config.user_limit,
        },
    }


def _group_entry(groups: list[dict[str, Any]], group_name: str) -> dict[str, Any] | None:
    for group in groups:
        if str(group.get("Group", "")).strip().lower() == group_name.lower():
            return group
    return None


def _is_stale(value: object, days: int) -> bool:
    parsed = _parse_date(value)
    if not parsed:
        return False
    return (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).days > days


def _parse_date(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y"):
        try:
            return datetime.strptime(text[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _to_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    asset: str,
    evidence_summary: str,
    why: str,
    impact: str,
    remediation: list[str],
    validation: list[str],
    evidence_path: str,
    collected_at: str,
    package: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        category="Active Directory",
        package=package,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence_for_basis("directory_evidence"),
        asset=asset,
        evidence_summary=evidence_summary,
        evidence_files=[evidence_path],
        why_it_matters=why,
        likely_business_impact=impact,
        remediation_steps=remediation,
        validation_steps=validation,
        owner_role="Identity Owner",
        effort="medium",
        evidence_source_type="active_directory",
        evidence_collected_at=collected_at,
        raw_evidence_path=evidence_path,
        finding_basis="directory_evidence",
    )
