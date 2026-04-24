"""Estate-wide aggregation helpers."""

from __future__ import annotations

from collections import defaultdict
from typing import Callable

from app.core.evidence import confidence_for_basis, utc_now
from app.core.inventory import AssetInventory, AssetRecord
from app.core.models import Finding


def generate_aggregate_findings(
    *,
    findings: list[Finding],
    inventory: AssetInventory,
    package: str,
) -> list[Finding]:
    """Build repeated-control aggregate findings from host-level evidence."""

    records = inventory.list_assets()
    asset_index = _asset_index(records)
    aggregates: list[Finding] = []
    grouped: dict[tuple[str, str, str, str], list[Finding]] = defaultdict(list)
    grouped_by_scope: dict[tuple[str, str, str, str, str], list[Finding]] = defaultdict(list)

    for finding in findings:
        if finding.asset.lower() in {"organization", "estate"}:
            continue
        if finding.finding_basis == "advisory_questionnaire":
            continue
        key = (finding.title, finding.category, finding.severity, finding.finding_basis)
        grouped[key].append(finding)
        scope_label = _asset_scope_label(asset_index.get(finding.asset.lower()))
        if scope_label:
            grouped_by_scope[(scope_label, *key)].append(finding)

    for key, items in grouped.items():
        aggregate = _aggregate_from_group(
            title=key[0],
            category=key[1],
            severity=key[2],
            basis=key[3],
            scope_label="organization",
            findings=items,
            package=package,
            asset_index=asset_index,
        )
        if aggregate:
            aggregates.append(aggregate)

    for key, items in grouped_by_scope.items():
        aggregate = _aggregate_from_group(
            title=key[1],
            category=key[2],
            severity=key[3],
            basis=key[4],
            scope_label=key[0],
            findings=items,
            package=package,
            asset_index=asset_index,
        )
        if aggregate:
            aggregates.append(aggregate)
    return aggregates


def estate_summary(
    *,
    inventory: AssetInventory,
    findings: list[Finding],
) -> dict[str, object]:
    coverage = inventory.coverage_summary()
    records = inventory.list_assets()
    by_site: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_subnet: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_business_unit: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    remoting_failures: dict[str, int] = defaultdict(int)
    last_evidence_source_counts: dict[str, int] = defaultdict(int)

    for asset in records:
        site = asset.site_label or "unlabeled"
        subnet = asset.subnet_label or "unlabeled"
        business_unit = asset.business_unit or "unlabeled"
        by_site[site][asset.assessment_status or "unknown"] += 1
        by_subnet[subnet][asset.assessment_status or "unknown"] += 1
        by_business_unit[business_unit][asset.assessment_status or "unknown"] += 1
        if asset.error_state:
            remoting_failures[asset.error_state] += 1
        last_evidence_source_counts[
            asset.last_successful_evidence_source or "none"
        ] += 1

    top_repeated = []
    top_repeated_critical = []
    estate_findings = [finding for finding in findings if not finding.finding_id.startswith("AGG-")]
    for finding in findings:
        if not finding.finding_id.startswith("AGG-"):
            continue
        item = {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
            "asset": finding.asset,
            "evidence_summary": finding.evidence_summary,
            "asset_criticality": finding.asset_criticality,
            "asset_role": finding.asset_role,
        }
        top_repeated.append(item)
        if finding.asset_criticality == "critical":
            top_repeated_critical.append(item)
    top_repeated.sort(key=lambda item: (-int(item["risk_score"]), item["title"]))
    top_repeated_critical.sort(key=lambda item: (-int(item["risk_score"]), item["title"]))

    finding_counts_by_role = _dimension_count(estate_findings, lambda item: item.asset_role or "unclassified")
    finding_counts_by_criticality = _dimension_count(estate_findings, lambda item: item.asset_criticality or "unclassified")
    asset_index = _asset_index(records)
    finding_counts_by_site = _dimension_count(
        estate_findings,
        lambda item: (_asset_scope_label(asset_index.get(item.asset.lower())) or "unlabeled"),
    )
    finding_counts_by_business_unit = _dimension_count(
        estate_findings,
        lambda item: (asset_index.get(item.asset.lower()).business_unit if asset_index.get(item.asset.lower()) else "unlabeled") or "unlabeled",
    )
    coverage_gaps = _coverage_gaps(coverage)
    assessment_plan = inventory.session.database.get_metadata("assessment_plan", {})
    assessment_warnings = inventory.session.database.get_metadata("assessment_warnings", [])

    return {
        "generated_at": utc_now(),
        "coverage": coverage,
        "by_site": {key: dict(value) for key, value in sorted(by_site.items())},
        "by_subnet": {key: dict(value) for key, value in sorted(by_subnet.items())},
        "by_business_unit": {key: dict(value) for key, value in sorted(by_business_unit.items())},
        "asset_counts_by_role": coverage.get("by_role", {}),
        "asset_counts_by_criticality": coverage.get("by_criticality", {}),
        "finding_counts_by_role": finding_counts_by_role,
        "finding_counts_by_criticality": finding_counts_by_criticality,
        "finding_counts_by_site": finding_counts_by_site,
        "finding_counts_by_business_unit": finding_counts_by_business_unit,
        "remoting_failures": dict(sorted(remoting_failures.items())),
        "last_evidence_source_counts": dict(sorted(last_evidence_source_counts.items())),
        "coverage_gaps": coverage_gaps,
        "assessment_warnings": assessment_warnings if isinstance(assessment_warnings, list) else [],
        "discovery_sources": assessment_plan.get("discovery_sources", []) if isinstance(assessment_plan, dict) else [],
        "top_repeated_findings": top_repeated[:10],
        "top_repeated_findings_on_critical_assets": top_repeated_critical[:10],
    }


def _aggregate_from_group(
    *,
    title: str,
    category: str,
    severity: str,
    basis: str,
    scope_label: str,
    findings: list[Finding],
    package: str,
    asset_index: dict[str, AssetRecord],
) -> Finding | None:
    unique_assets = sorted({finding.asset for finding in findings if finding.asset})
    if len(unique_assets) < 2:
        return None
    sample = findings[0]
    evidence_paths = sorted({path for finding in findings for path in finding.evidence_files})[:20]
    asset_records = [
        asset_index.get(asset.lower())
        for asset in unique_assets
        if asset_index.get(asset.lower())
    ]
    criticality = _highest_criticality(
        [record.criticality for record in asset_records if record and record.criticality]
    )
    roles = sorted({record.asset_role for record in asset_records if record and record.asset_role})
    asset_role = roles[0] if len(roles) == 1 else ("mixed" if roles else "")
    aggregate_title = (
        f"{title} observed across {len(unique_assets)} assets"
        if scope_label == "organization"
        else f"{title} observed across {len(unique_assets)} assets in {scope_label}"
    )
    return Finding(
        finding_id=_aggregate_id(scope_label, title),
        title=aggregate_title,
        category=category,
        package=package,
        severity=severity,  # type: ignore[arg-type]
        confidence=_aggregate_confidence(findings, basis),
        asset=scope_label,
        evidence_summary=", ".join(unique_assets[:8])
        + (f" and {len(unique_assets) - 8} more" if len(unique_assets) > 8 else ""),
        evidence_files=evidence_paths,
        why_it_matters=sample.why_it_matters,
        likely_business_impact=(
            f"This control gap is repeated across {len(unique_assets)} assets, which raises estate-wide risk concentration. "
            + sample.likely_business_impact
        ),
        remediation_steps=sample.remediation_steps,
        validation_steps=sample.validation_steps,
        owner_role=sample.owner_role,
        effort=sample.effort,
        evidence_source_type="aggregate",
        evidence_collected_at=utc_now(),
        raw_evidence_path=sample.raw_evidence_path,
        finding_basis=basis if basis != "advisory_questionnaire" else "inferred_partial",  # type: ignore[arg-type]
        asset_role=asset_role,
        asset_criticality=criticality,
        asset_classification_source="inventory_aggregate" if asset_records else "",
    )


def _aggregate_id(scope_label: str, title: str) -> str:
    normalized = f"{scope_label}|{title}".lower().encode("utf-8")
    import hashlib

    return "AGG-" + hashlib.sha1(normalized).hexdigest()[:12].upper()


def _aggregate_confidence(findings: list[Finding], basis: str) -> str:
    if basis in {
        "direct_system_evidence",
        "directory_evidence",
        "network_discovery_evidence",
        "imported_scanner_evidence",
        "imported_configuration_evidence",
    }:
        return confidence_for_basis(basis)  # type: ignore[return-value]
    if any(finding.confidence == "strong" for finding in findings):
        return "strong"
    if any(finding.confidence == "weak" for finding in findings):
        return "weak"
    return "unknown"


def _asset_index(records: list[AssetRecord]) -> dict[str, AssetRecord]:
    index: dict[str, AssetRecord] = {}
    for record in records:
        for key in {record.asset_id, record.hostname, record.fqdn, record.ip_address, record.display_name}:
            cleaned = key.strip().lower()
            if cleaned:
                index[cleaned] = record
    return index


def _asset_scope_label(record: AssetRecord | None) -> str:
    if not record:
        return ""
    return record.site_label or record.subnet_label or record.business_unit or ""


def _dimension_count(findings: list[Finding], selector: Callable[[Finding], str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        label = selector(finding)
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def _highest_criticality(values: list[str]) -> str:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest = ""
    highest_rank = 0
    for value in values:
        current_rank = rank.get(value, 0)
        if current_rank > highest_rank:
            highest = value
            highest_rank = current_rank
    return highest


def _coverage_gaps(coverage: dict[str, object]) -> list[str]:
    gaps: list[str] = []
    total_assets = int(coverage.get("total_assets", 0) or 0)
    assessed = int(coverage.get("assessed", 0) or 0)
    partial = int(coverage.get("partial", 0) or 0)
    unreachable = int(coverage.get("unreachable", 0) or 0)
    discovery_only = int(coverage.get("discovery_only", 0) or 0)
    imported_only = int(coverage.get("imported_evidence_only", 0) or 0)
    if total_assets == 0:
        gaps.append("No in-scope assets were tracked. Scope or discovery inputs may be invalid or empty.")
        return gaps
    if assessed == 0 and discovery_only:
        gaps.append("Coverage is discovery-only. No remote or direct host validation succeeded for estate assets.")
    elif discovery_only >= max(1, assessed):
        gaps.append("Coverage is discovery-heavy. Many assets were identified but not directly validated.")
    if partial:
        gaps.append("Some assets returned only partial evidence. Validate connector reach, privilege, and host readiness.")
    if unreachable:
        gaps.append("Some assets were unreachable. Estate coverage is limited by remoting or path availability.")
    if imported_only:
        gaps.append("Some assets rely only on imported evidence and were not directly validated by the runner.")
    return gaps
