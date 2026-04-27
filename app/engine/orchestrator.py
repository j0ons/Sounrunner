"""Company-wide discovery and remote collection orchestration."""

from __future__ import annotations

import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from app.collectors.windows_remote import RemoteWindowsCollector
from app.collectors.windows_remote import RemoteWindowsCollectionResult
from app.core.config import AppConfig
from app.core.integrity import SessionAuditor
from app.core.inventory import AssetInventory, AssetRecord
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession
from app.engine.aggregation import estate_summary
from app.engine.remote_strategy import (
    RemoteCollectionStrategy,
    effective_remote_windows_config,
    plan_remote_collection_strategy,
)
from app.modules.endpoint import build_endpoint_findings
from app.modules.identity import build_identity_findings
from app.modules.network_lite import build_local_exposure_findings
from app.scanners.base import NetworkAsset
from app.scanners.nmap import NmapAdapter, findings_from_nmap_assets


@dataclass(slots=True)
class HostCollectionOutcome:
    asset: AssetRecord
    status: str
    detail: str
    findings: list[Finding]
    evidence_files: list[Path]
    failure_category: str = ""
    operator_hint: str = ""


@dataclass(slots=True)
class EstateAssessmentModule:
    """Standard/Advanced multi-host orchestration module."""

    session: AssessmentSession
    config: AppConfig
    package: str

    name: str = "estate_orchestration"

    def run(self) -> ModuleResult:
        logger = logging.getLogger("soun_runner")
        auditor = SessionAuditor(self.session)
        inventory = AssetInventory(self.session, self.config)
        evidence_files: list[Path] = []
        findings: list[Finding] = []
        details: list[str] = []
        seed_records = inventory.list_assets()
        details.append(f"Inventory seeds={len(seed_records)} from local, directory, and import evidence.")

        discovery_result = NmapAdapter(
            self.session,
            self.config.nmap,
            package=self.package,
        ).scan(self.session.scope)
        if discovery_result.raw_evidence_path:
            evidence_files.append(discovery_result.raw_evidence_path)

        eligible_assets = [
            asset
            for asset in discovery_result.assets
            if self.session.scope.allows_asset(asset.address, asset.hostnames)
        ]
        discovered_records: list[AssetRecord] = []
        for asset in eligible_assets:
            record = inventory.record_discovery(asset, source="nmap")
            discovered_records.append(record)
            self.session.database.upsert_asset_module_status(
                record.asset_id,
                "network_discovery",
                "complete",
                f"Discovered {len(asset.services)} open service(s).",
            )
            if discovery_result.raw_evidence_path:
                inventory.attach_evidence(
                    record.asset_id,
                    str(discovery_result.raw_evidence_path),
                    "network_discovery",
                )
        if discovery_result.raw_evidence_path:
            findings.extend(
                findings_from_nmap_assets(
                    eligible_assets,
                    discovery_result.raw_evidence_path,
                    package=self.package,
                )
            )
        details.append(
            f"Discovery status={discovery_result.status}; discovered={len(discovery_result.assets)}; in_scope={len(eligible_assets)}."
        )
        auditor.record_event(
            "estate_discovery_completed",
            {
                "source_module": self.name,
                "status": discovery_result.status,
                "detail": discovery_result.detail,
                "discovered_assets": len(discovery_result.assets),
                "eligible_assets": len(eligible_assets),
                "evidence_files": [str(path) for path in evidence_files],
            },
        )

        strategy = plan_remote_collection_strategy(session=self.session, config=self.config)
        self.session.database.set_metadata("remote_collection_strategy", strategy.to_metadata())
        details.append(f"Remote collection strategy={strategy.mode}; {strategy.reason}")

        planned_targets, eligible_records, planning_notes = self._plan_remote_targets(inventory, strategy)
        details.extend(planning_notes)
        remote_outcomes: list[HostCollectionOutcome] = []
        if strategy.enabled and planned_targets:
            remote_outcomes = self._collect_remote_hosts(
                inventory=inventory,
                planned_targets=planned_targets,
                strategy=strategy,
            )
            for outcome in remote_outcomes:
                findings.extend(outcome.findings)
                evidence_files.extend(outcome.evidence_files)
                details.append(f"{outcome.asset.display_name}: {outcome.status} - {outcome.detail}")
        else:
            details.append("Remote Windows collection unavailable or no eligible estate targets were planned.")
            self._mark_uncollected_targets(
                inventory=inventory,
                records=eligible_records,
                reason=(
                    f"Remote collection strategy unavailable: {strategy.reason}"
                    if not strategy.enabled
                    else "No eligible remote Windows targets were planned from approved evidence sources."
                ),
                error_state="" if strategy.enabled else "remote_collection_unavailable",
            )

        baseline_findings = self.session.database.list_findings()
        summary = estate_summary(
            inventory=inventory,
            findings=[*baseline_findings, *findings],
        )
        self.session.database.set_metadata("estate_summary", summary)
        self.session.database.set_metadata(
            "inventory_assets",
            [record.to_db_payload() for record in inventory.list_assets()],
        )
        self.session.database.set_metadata(
            "estate_discovery",
            {
                "seed_asset_count": len(seed_records),
                "discovery_status": discovery_result.status,
                "discovery_detail": discovery_result.detail,
                "discovered_assets": len(discovery_result.assets),
                "in_scope_assets": len(eligible_assets),
                "eligible_remote_assets": len(eligible_records),
                "planned_remote_targets": len(planned_targets),
                "remote_collection_strategy": strategy.to_metadata(),
                "remote_collection_summary": _remote_collection_summary(remote_outcomes, strategy, len(eligible_records), len(planned_targets)),
            },
        )
        self.session.database.set_metadata(
            "remote_collection_summary",
            _remote_collection_summary(remote_outcomes, strategy, len(eligible_records), len(planned_targets)),
        )
        status = _estate_status(discovery_result.status, remote_outcomes, inventory.list_assets())
        logger.info(
            "Estate orchestration complete package=%s discovered=%s planned_targets=%s remote_outcomes=%s status=%s",
            self.package,
            len(discovered_records),
            len(planned_targets),
            len(remote_outcomes),
            status,
        )
        return ModuleResult(
            module_name=self.name,
            status=status,
            detail=" ".join(details),
            findings=findings,
            evidence_files=evidence_files,
        )

    def _collect_remote_hosts(
        self,
        *,
        inventory: AssetInventory,
        planned_targets: list[tuple[str, AssetRecord]],
        strategy: RemoteCollectionStrategy,
    ) -> list[HostCollectionOutcome]:
        collector = RemoteWindowsCollector(
            self.session,
            effective_remote_windows_config(self.config.remote_windows, strategy),
        )
        outcomes: list[HostCollectionOutcome] = []
        with ThreadPoolExecutor(max_workers=self.config.orchestration.max_workers) as executor:
            futures = {
                executor.submit(
                    self._collect_with_retry,
                    collector,
                    target,
                    record,
                ): (target, record)
                for target, record in planned_targets
            }
            for future in as_completed(futures):
                target, record = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 - isolate one host failure.
                    inventory.mark_status(
                        record.asset_id,
                        assessment_status="partial",
                        collector_status="failed",
                        error_state=str(exc),
                    )
                    self.session.database.upsert_asset_module_status(
                        record.asset_id,
                        "remote_windows_collection",
                        "failed",
                        str(exc),
                    )
                    self._write_host_log(record, "failed", str(exc), {})
                    outcomes.append(
                        HostCollectionOutcome(
                            asset=record,
                            status="failed",
                            detail=str(exc),
                            findings=[],
                            evidence_files=[],
                            failure_category="unexpected_error",
                            operator_hint="Review runner logs for the remoting worker exception before retrying.",
                        )
                    )
                    continue
                outcomes.append(self._normalize_host_result(result, record, inventory))
        return outcomes

    def _plan_remote_targets(
        self,
        inventory: AssetInventory,
        strategy: RemoteCollectionStrategy,
    ) -> tuple[list[tuple[str, AssetRecord]], list[AssetRecord], list[str]]:
        records = inventory.list_assets()
        planned: list[tuple[str, AssetRecord]] = []
        eligible_records: list[AssetRecord] = []
        notes: list[str] = []
        seen_targets: set[str] = set()
        skipped = 0
        reason_counts: dict[str, int] = {}
        for record in records:
            eligibility = self._remote_collection_eligibility(record, strategy)
            inventory.update_remoting_eligibility(
                record.asset_id,
                eligible=eligibility["eligible"],
                reason=eligibility["reason"],
            )
            if not eligibility["eligible"]:
                reason_counts[eligibility["reason"]] = reason_counts.get(eligibility["reason"], 0) + 1
                inventory.mark_status(
                    record.asset_id,
                    assessment_status=record.assessment_status or "discovery_only",
                    collector_status="skipped",
                    error_state=_reason_code(str(eligibility["reason"])),
                )
                self.session.database.upsert_asset_module_status(
                    record.asset_id,
                    "remote_windows_collection",
                    "skipped",
                    str(eligibility["reason"]),
                )
                continue
            eligible_records.append(inventory.find_asset(record.asset_id) or record)
            target = self._resolve_remote_target(record, inventory)
            if not target:
                skipped += 1
                inventory.update_remoting_eligibility(
                    record.asset_id,
                    eligible=False,
                    reason="No approved in-scope IP or resolvable hostname was available for WinRM collection.",
                )
                self.session.database.upsert_asset_module_status(
                    record.asset_id,
                    "remote_windows_collection",
                    "skipped",
                    "Asset could not be mapped to an approved in-scope WinRM target.",
                )
                continue
            if target.lower() in seen_targets:
                continue
            seen_targets.add(target.lower())
            planned.append((target, inventory.find_asset(record.asset_id) or record))
            if len(planned) >= strategy.max_auto_attempts:
                notes.append(
                    f"Remote collection planning reached max_auto_attempts={strategy.max_auto_attempts}; remaining eligible assets stay discovery-only."
                )
                break
        notes.append(
            f"Remote collection planning considered {len(records)} inventory asset(s) and queued {len(planned)} target(s)."
        )
        if reason_counts:
            notes.append(
                "Remote eligibility rejections: "
                + ", ".join(f"{reason}={count}" for reason, count in sorted(reason_counts.items()))
                + "."
            )
        if skipped:
            notes.append(
                f"{skipped} asset(s) remained discovery-only or imported-only because no approved in-scope WinRM target could be resolved."
            )
        return planned, eligible_records, notes

    def _remote_collection_eligibility(
        self,
        record: AssetRecord,
        strategy: RemoteCollectionStrategy,
    ) -> dict[str, str | bool]:
        if not strategy.enabled:
            return {
                "eligible": False,
                "reason": "skipped_discovery_only: no safe remote collection strategy is available.",
            }
        if record.discovery_source == "local_environment_profile":
            return {
                "eligible": False,
                "reason": "skipped_discovery_only: local host baseline is already collected directly.",
            }
        if record.asset_role == "network_device":
            return {
                "eligible": False,
                "reason": "not_windows_candidate: network devices are out of scope for the Windows remote collector.",
            }
        if record.collector_status == "complete" and record.assessment_status == "assessed":
            return {
                "eligible": False,
                "reason": "skipped_discovery_only: asset already has complete direct collection evidence.",
            }
        os_blob = f"{record.os_family} {record.os_guess}".lower()
        if os_blob and "windows" not in os_blob and record.asset_role not in {
            "server",
            "workstation",
            "domain_controller",
            "unknown",
        }:
            return {
                "eligible": False,
                "reason": "not_windows_candidate: available evidence does not indicate a Windows-compatible remote collection target.",
            }
        services = self.session.database.list_asset_services(record.asset_id)
        ports = {int(item.get("port", 0)) for item in services if str(item.get("state", "")).lower() in {"open", "open|filtered", ""}}
        if ports and not _windows_candidate_ports(ports) and record.asset_role == "unknown":
            return {
                "eligible": False,
                "reason": "not_windows_candidate: discovered services do not look Windows-compatible.",
            }
        has_winrm = bool({5985, 5986} & ports)
        if strategy.require_winrm_port_observed and not has_winrm:
            return {
                "eligible": False,
                "reason": "no_winrm_service_detected: WinRM port 5985/5986 was not observed in approved discovery evidence.",
            }
        return {
            "eligible": True,
            "reason": "eligible: asset is in scope, Windows-compatible, and has observed WinRM or policy allows attempt.",
        }

    def _resolve_remote_target(
        self,
        record: AssetRecord,
        inventory: AssetInventory,
    ) -> str:
        aliases = [record.ip_address, record.fqdn, record.hostname]
        for alias in aliases:
            target = alias.strip()
            if not target:
                continue
            if _looks_like_ip(target) and self.session.scope.allows_asset(target, [record.hostname, record.fqdn]):
                return target
        for alias in [record.fqdn, record.hostname]:
            target = alias.strip()
            if not target:
                continue
            resolved_ips = _resolve_host_ips(target)
            for ip_value in resolved_ips:
                if not self.session.scope.allows_asset(ip_value, [record.hostname, record.fqdn, target]):
                    continue
                if not record.ip_address:
                    record.ip_address = ip_value
                    record.subnet_label = record.subnet_label or self.session.scope.label_for_ip(ip_value)
                    inventory.upsert(record)
                return ip_value if self.config.remote_windows.require_discovery_match else target
        return ""

    def _mark_uncollected_targets(
        self,
        *,
        inventory: AssetInventory,
        records: list[AssetRecord],
        reason: str,
        error_state: str,
    ) -> None:
        for record in records:
            if record.discovery_source == "local_environment_profile":
                continue
            if record.assessment_status == "assessed":
                continue
            inventory.mark_status(
                record.asset_id,
                assessment_status=record.assessment_status or "discovery_only",
                collector_status="skipped",
                error_state=error_state,
            )
            self.session.database.upsert_asset_module_status(
                record.asset_id,
                "remote_windows_collection",
                "skipped",
                reason,
            )

    def _collect_with_retry(
        self,
        collector: RemoteWindowsCollector,
        target: str,
        record: AssetRecord | None,
    ) -> RemoteWindowsCollectionResult:
        if not record:
            raise ValueError(f"Inventory record missing for target {target}")
        last_result: RemoteWindowsCollectionResult | None = None
        attempts = max(1, self.config.orchestration.retry_count + 1)
        for _ in range(attempts):
            last_result = collector.collect(target=target, asset_id=record.asset_id)
            if last_result.status == "complete":
                return last_result
        assert last_result is not None
        return last_result

    def _normalize_host_result(
        self,
        result: RemoteWindowsCollectionResult,
        record: AssetRecord,
        inventory: AssetInventory,
    ) -> HostCollectionOutcome:
        evidence = result.evidence
        evidence_path = result.evidence_path
        if evidence_path:
            inventory.attach_evidence(record.asset_id, str(evidence_path), "remote_windows_collection")

        normalized_status = _normalize_remote_status(result)
        inventory.mark_status(
            record.asset_id,
            assessment_status=normalized_status["assessment_status"],
            collector_status=normalized_status["collector_status"],
            error_state=normalized_status["error_state"],
        )
        self.session.database.upsert_asset_module_status(
            record.asset_id,
            "remote_windows_collection",
            normalized_status["collector_status"],
            result.detail,
        )

        findings: list[Finding] = []
        if result.status in {"complete", "partial"}:
            inventory.record_successful_source(record.asset_id, "remote_windows_collection")
            findings.extend(
                build_identity_findings(
                    asset_name=record.display_name,
                    windows_evidence=evidence,
                    package=self.package,
                    is_admin=False,
                    finding_prefix=f"{self.package.upper()}-ESTATE-ID-{record.asset_id[-4:]}",
                )
            )
            findings.extend(
                build_endpoint_findings(
                    asset_name=record.display_name,
                    windows_evidence=evidence,
                    package=self.package,
                    finding_prefix=f"{self.package.upper()}-ESTATE-ENDPOINT-{record.asset_id[-4:]}",
                )
            )
            findings.extend(
                build_local_exposure_findings(
                    asset_name=record.display_name,
                    windows_evidence=evidence,
                    package=self.package,
                    finding_prefix=f"{self.package.upper()}-ESTATE-NET-{record.asset_id[-4:]}",
                )
            )
        host_log_payload = {
            "target": result.target,
            "status": result.status,
            "detail": result.detail,
            "assessment_status": normalized_status["assessment_status"],
            "collector_status": normalized_status["collector_status"],
            "failure_category": normalized_status["failure_category"],
            "operator_hint": normalized_status["operator_hint"],
            "finding_count": len(findings),
            "evidence_path": str(evidence_path) if evidence_path else "",
        }
        self._write_host_log(record, result.status, result.detail, host_log_payload)
        SessionAuditor(self.session).record_event(
            "host_collection_completed",
            {
                "source_module": self.name,
                "asset_id": record.asset_id,
                "hostname": record.hostname,
                "ip_address": record.ip_address,
                "status": result.status,
                "assessment_status": normalized_status["assessment_status"],
                "collector_status": normalized_status["collector_status"],
                "failure_category": normalized_status["failure_category"],
                "operator_hint": normalized_status["operator_hint"],
                "detail": result.detail,
                "evidence_files": [str(evidence_path)] if evidence_path else [],
            },
        )
        return HostCollectionOutcome(
            asset=record,
            status=result.status,
            detail=result.detail,
            findings=findings,
            evidence_files=[evidence_path] if evidence_path else [],
            failure_category=normalized_status["failure_category"],
            operator_hint=normalized_status["operator_hint"],
        )

    def _write_host_log(
        self,
        record: AssetRecord,
        status: str,
        detail: str,
        payload: dict[str, object],
    ) -> None:
        host_log_dir = self.session.log_dir / "hosts"
        host_log_dir.mkdir(parents=True, exist_ok=True)
        path = host_log_dir / f"{record.asset_id}.log"
        entry = {
            "asset_id": record.asset_id,
            "hostname": record.hostname,
            "ip_address": record.ip_address,
            "status": status,
            "detail": detail,
            **payload,
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")


def _normalize_remote_status(result: RemoteWindowsCollectionResult) -> dict[str, str]:
    stderr_blob = " ".join(
        [
            section.stderr
            for section in result.evidence.sections.values()
            if section.stderr
        ]
    ).lower()
    detail_blob = f"{result.detail} {stderr_blob} {result.failure_category}".lower()
    if result.status == "complete":
        return {
            "assessment_status": "assessed",
            "collector_status": "complete",
            "error_state": "",
            "failure_category": "",
            "operator_hint": "",
        }
    if "dns" in detail_blob or "resolve" in detail_blob or "name could not be resolved" in detail_blob:
        return {
            "assessment_status": "unreachable",
            "collector_status": "failed",
            "error_state": "dns_resolution",
            "failure_category": "dns_resolution",
            "operator_hint": "Confirm hostname resolution or use the approved IP address for the remote host.",
        }
    if "authentication failed" in detail_blob or "logon failure" in detail_blob or "user name or password is incorrect" in detail_blob or "auth_failed" in detail_blob:
        return {
            "assessment_status": "partial",
            "collector_status": "denied",
            "error_state": "auth_failed",
            "failure_category": "auth_failed",
            "operator_hint": "Confirm the current user or approved credential can authenticate to the remote host over WinRM.",
        }
    if "access is denied" in detail_blob or "unauthorized" in detail_blob or "credential" in detail_blob:
        return {
            "assessment_status": "partial",
            "collector_status": "denied",
            "error_state": "access_denied",
            "failure_category": "access_denied",
            "operator_hint": "Confirm the approved credential has WinRM and local read access on the remote host.",
        }
    if "firewall" in detail_blob:
        return {
            "assessment_status": "unreachable",
            "collector_status": "failed",
            "error_state": "firewall_blocked",
            "failure_category": "firewall_blocked",
            "operator_hint": "Validate host firewall policy allows approved WinRM traffic from the assessment source.",
        }
    if "timed out" in detail_blob or "timeout" in detail_blob:
        return {
            "assessment_status": "unreachable",
            "collector_status": "failed",
            "error_state": "timeout",
            "failure_category": "timeout",
            "operator_hint": "Check routing, host availability, and WinRM responsiveness before retrying.",
        }
    if "winrm" in detail_blob or "cannot connect" in detail_blob or "network path was not found" in detail_blob:
        return {
            "assessment_status": "unreachable",
            "collector_status": "failed",
            "error_state": "winrm_unavailable",
            "failure_category": "winrm_unavailable",
            "operator_hint": "Confirm the WinRM service is enabled and reachable on the approved host.",
        }
    return {
        "assessment_status": "partial",
        "collector_status": "partial",
        "error_state": "partial_remote_evidence",
        "failure_category": result.failure_category or "partial_remote_evidence",
        "operator_hint": result.operator_hint or "Review remote evidence stderr for command-level blockers.",
    }


def _remote_collection_summary(
    outcomes: list[HostCollectionOutcome],
    strategy: RemoteCollectionStrategy,
    candidate_count: int,
    planned_count: int,
) -> dict[str, object]:
    failure_counts: dict[str, int] = {}
    for outcome in outcomes:
        if outcome.failure_category:
            failure_counts[outcome.failure_category] = failure_counts.get(outcome.failure_category, 0) + 1
    top_failure = ""
    if failure_counts:
        top_failure = sorted(failure_counts.items(), key=lambda item: item[1], reverse=True)[0][0]
    return {
        "strategy": strategy.mode,
        "strategy_reason": strategy.reason,
        "windows_candidates": candidate_count,
        "collection_attempted": planned_count,
        "collection_successful": sum(1 for item in outcomes if item.status == "complete"),
        "collection_partial": sum(1 for item in outcomes if item.status == "partial"),
        "collection_failed": sum(1 for item in outcomes if item.status not in {"complete", "partial"}),
        "failure_counts": failure_counts,
        "top_failure_reason": top_failure,
    }


def _windows_candidate_ports(ports: set[int]) -> bool:
    return bool(ports & {135, 139, 445, 3389, 5985, 5986})


def _reason_code(reason: str) -> str:
    return reason.split(":", 1)[0].strip() if ":" in reason else reason.strip()


def _estate_status(
    discovery_status: str,
    outcomes: list[HostCollectionOutcome],
    records: list[AssetRecord],
) -> str:
    if discovery_status == "failed" and not records:
        return "failed"
    if not records:
        return "partial"
    if discovery_status == "failed":
        return "partial"
    if outcomes and all(item.status == "complete" for item in outcomes):
        return "complete"
    return "partial"


def _resolve_host_ips(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    addresses = []
    for info in infos:
        address = str(info[4][0]).strip()
        if address and address not in addresses:
            addresses.append(address)
    return addresses


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
