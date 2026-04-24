"""Finding correlation and deduplication helpers."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from app.core.models import Finding


@dataclass(slots=True)
class CorrelationResult:
    findings: list[Finding]
    merged_count: int
    suppressed_count: int
    groups: list[dict[str, object]]


def correlate_findings(findings: list[Finding]) -> CorrelationResult:
    passthrough: list[Finding] = []
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)

    for finding in findings:
        family = _correlation_family(finding)
        if not family:
            passthrough.append(finding)
            continue
        if finding.finding_id.startswith("AGG-") or finding.asset.lower() in {"organization", "estate"}:
            passthrough.append(finding)
            continue
        groups[(finding.asset.strip().lower(), family)].append(finding)

    merged: list[Finding] = []
    summaries: list[dict[str, object]] = []
    suppressed = 0
    for (_, family), items in groups.items():
        if not _should_merge(items):
            passthrough.extend(items)
            continue
        merged.append(_merge_group(family, items))
        suppressed += len(items) - 1
        summaries.append(
            {
                "family": family,
                "asset": items[0].asset,
                "merged_finding_ids": [item.finding_id for item in items],
                "evidence_sources": sorted(
                    {
                        f"{item.finding_basis}/{item.evidence_source_type}"
                        for item in items
                    }
                ),
            }
        )
    final_findings = sorted(
        [*passthrough, *merged],
        key=lambda item: (-int(item.risk_score), item.finding_id),
    )
    return CorrelationResult(
        findings=final_findings,
        merged_count=len(merged),
        suppressed_count=suppressed,
        groups=summaries,
    )


def _should_merge(findings: list[Finding]) -> bool:
    if len(findings) < 2:
        return False
    distinct_sources = {
        (finding.finding_basis, finding.evidence_source_type, finding.title)
        for finding in findings
    }
    return len(distinct_sources) >= 2


def _merge_group(family: str, findings: list[Finding]) -> Finding:
    strongest = max(findings, key=lambda item: (_severity_rank(item.severity), _confidence_rank(item.confidence)))
    evidence_files = sorted({path for item in findings for path in item.evidence_files})
    merged_sources = sorted(
        {
            f"{item.finding_basis}/{item.evidence_source_type}"
            for item in findings
        }
    )
    merged_ids = [item.finding_id for item in findings]
    summary = "; ".join(dict.fromkeys(item.evidence_summary for item in findings if item.evidence_summary))[:1200]
    why = " ".join(dict.fromkeys(item.why_it_matters for item in findings if item.why_it_matters))[:1400]
    impact = " ".join(
        dict.fromkeys(item.likely_business_impact for item in findings if item.likely_business_impact)
    )[:1400]
    remediation = _merged_steps(findings, "remediation_steps")
    validation = _merged_steps(findings, "validation_steps")
    title, category = _family_presentation(family, strongest)
    return Finding(
        finding_id=f"CORR-{family.upper()}-{_stable_suffix(strongest.asset, merged_ids)}",
        title=title,
        category=category,
        package=strongest.package,
        severity=_highest_severity(findings),
        confidence=_highest_confidence(findings),
        asset=strongest.asset,
        evidence_summary=summary,
        evidence_files=evidence_files,
        why_it_matters=why or strongest.why_it_matters,
        likely_business_impact=impact or strongest.likely_business_impact,
        remediation_steps=remediation or strongest.remediation_steps,
        validation_steps=validation or strongest.validation_steps,
        owner_role=strongest.owner_role,
        effort=strongest.effort,
        evidence_source_type="correlated",
        evidence_collected_at=max((item.evidence_collected_at for item in findings), default=""),
        raw_evidence_path=strongest.raw_evidence_path,
        finding_basis=_strongest_basis(findings),
        correlation_key=family,
        merged_finding_ids=merged_ids,
        merged_evidence_sources=merged_sources,
        asset_role=strongest.asset_role,
        asset_criticality=strongest.asset_criticality,
        asset_classification_source=strongest.asset_classification_source,
        status=strongest.status,
        risk_score=max((item.risk_score for item in findings), default=strongest.risk_score),
    )


def _correlation_family(finding: Finding) -> str:
    blob = f"{finding.title} {finding.category} {finding.evidence_summary}".lower()
    if "rdp" in blob or "3389" in blob or "termservice" in blob:
        return "rdp_exposure"
    if "smb" in blob or "netbios" in blob or "445" in blob:
        return "smb_exposure"
    if "local admin" in blob or "administrators group" in blob or "privileged" in blob or "shared account" in blob:
        return "privileged_access"
    if "backup" in blob and "restore" in blob:
        return "backup_restore"
    if "backup" in blob and ("immutable" in blob or "offline" in blob):
        return "backup_protection"
    if "backup" in blob:
        return "backup_coverage"
    if "vpn" in blob or "remote access" in blob:
        return "remote_access"
    return ""


def _family_presentation(family: str, sample: Finding) -> tuple[str, str]:
    mapping = {
        "rdp_exposure": ("RDP exposure confirmed by correlated evidence", "Remote Access Exposure"),
        "smb_exposure": ("SMB exposure confirmed by correlated evidence", "Network Exposure"),
        "privileged_access": (
            "Privileged access risk supported by correlated evidence",
            "Privileged Access",
        ),
        "backup_restore": (
            "Backup restore readiness gap supported by correlated evidence",
            "Backup Readiness",
        ),
        "backup_protection": (
            "Backup protection gap supported by correlated evidence",
            "Backup Readiness",
        ),
        "backup_coverage": (
            "Backup coverage gap supported by correlated evidence",
            "Backup Readiness",
        ),
        "remote_access": (
            "Remote access exposure supported by correlated evidence",
            "Remote Access Exposure",
        ),
    }
    return mapping.get(family, (sample.title, sample.category))


def _strongest_basis(findings: list[Finding]) -> str:
    order = {
        "direct_system_evidence": 7,
        "directory_evidence": 6,
        "imported_scanner_evidence": 5,
        "imported_configuration_evidence": 4,
        "network_discovery_evidence": 3,
        "inferred_partial": 2,
        "advisory_questionnaire": 1,
    }
    return max(findings, key=lambda item: order.get(item.finding_basis, 0)).finding_basis


def _highest_severity(findings: list[Finding]) -> str:
    return max(findings, key=lambda item: _severity_rank(item.severity)).severity


def _highest_confidence(findings: list[Finding]) -> str:
    return max(findings, key=lambda item: _confidence_rank(item.confidence)).confidence


def _severity_rank(value: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(value, 0)


def _confidence_rank(value: str) -> int:
    return {"confirmed": 4, "strong": 3, "weak": 2, "unknown": 1}.get(value, 0)


def _merged_steps(findings: list[Finding], field_name: str) -> list[str]:
    merged: list[str] = []
    for finding in findings:
        for step in getattr(finding, field_name):
            if step not in merged:
                merged.append(step)
    return merged[:12]


def _stable_suffix(asset: str, finding_ids: list[str]) -> str:
    import hashlib

    value = f"{asset}|{'|'.join(sorted(finding_ids))}".encode("utf-8")
    return hashlib.sha1(value).hexdigest()[:10].upper()
