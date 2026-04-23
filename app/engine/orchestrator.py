"""Company-wide discovery and remote collection orchestration."""

from __future__ import annotations

import json
import logging
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
from app.engine.aggregation import estate_summary, generate_aggregate_findings
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

        discovery_result = NmapAdapter(
            self.session,
            self.config.nmap,
            package=self.package,
        ).scan(self.session.scope)
        if discovery_result.raw_evidence_path:
            evidence_files.append(discovery_result.raw_evidence_path)
        if discovery_result.status == "failed":
            self.session.database.set_metadata(
                "estate_summary",
                {
                    "coverage": inventory.coverage_summary(),
                    "top_repeated_findings": [],
                    "discovery_status": discovery_result.status,
                    "discovery_detail": discovery_result.detail,
                },
            )
            return ModuleResult(
                module_name=self.name,
                status="partial",
                detail=f"Discovery failed safely: {discovery_result.detail}",
                evidence_files=evidence_files,
            )

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
        findings.extend(
            findings_from_nmap_assets(
                eligible_assets,
                discovery_result.raw_evidence_path or self.session.evidence_dir / "nmap_scan.xml.enc",
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

        remote_outcomes: list[HostCollectionOutcome] = []
        if self.config.remote_windows.enabled and eligible_assets:
            remote_outcomes = self._collect_remote_hosts(
                inventory=inventory,
                assets=eligible_assets,
                records=discovered_records,
            )
            for outcome in remote_outcomes:
                findings.extend(outcome.findings)
                evidence_files.extend(outcome.evidence_files)
                details.append(f"{outcome.asset.display_name}: {outcome.status} - {outcome.detail}")
        else:
            details.append("Remote Windows collection disabled or no discovered assets were eligible.")
            for record in discovered_records:
                inventory.mark_status(
                    record.asset_id,
                    assessment_status="discovery_only",
                    collector_status="skipped",
                    error_state="" if self.config.remote_windows.enabled else "remote_collection_disabled",
                )
                self.session.database.upsert_asset_module_status(
                    record.asset_id,
                    "remote_windows_collection",
                    "skipped",
                    "Remote collection disabled or no eligible remote collection configuration.",
                )

        baseline_findings = self.session.database.list_findings()
        aggregate_findings = generate_aggregate_findings(
            findings=[*baseline_findings, *findings],
            inventory=inventory,
            package=self.package,
        )
        findings.extend(aggregate_findings)
        summary = estate_summary(
            inventory=inventory,
            findings=[*baseline_findings, *findings],
        )
        self.session.database.set_metadata("estate_summary", summary)
        self.session.database.set_metadata(
            "inventory_assets",
            [record.to_db_payload() for record in inventory.list_assets()],
        )
        status = _estate_status(discovery_result.status, remote_outcomes, discovered_records)
        logger.info(
            "Estate orchestration complete package=%s discovered=%s remote_outcomes=%s status=%s",
            self.package,
            len(discovered_records),
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
        assets: list[NetworkAsset],
        records: list[AssetRecord],
    ) -> list[HostCollectionOutcome]:
        collector = RemoteWindowsCollector(self.session, self.config.remote_windows)
        record_map = {record.ip_address: record for record in records if record.ip_address}
        outcomes: list[HostCollectionOutcome] = []
        with ThreadPoolExecutor(max_workers=self.config.orchestration.max_workers) as executor:
            futures = {
                executor.submit(
                    self._collect_with_retry,
                    collector,
                    asset.address,
                    record_map.get(asset.address),
                ): asset.address
                for asset in assets
                if record_map.get(asset.address)
            }
            for future in as_completed(futures):
                address = futures[future]
                record = record_map[address]
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


def _estate_status(
    discovery_status: str,
    outcomes: list[HostCollectionOutcome],
    discovered_records: list[AssetRecord],
) -> str:
    if discovery_status == "failed":
        return "failed"
    if not discovered_records:
        return "partial"
    if outcomes and all(item.status == "complete" for item in outcomes):
        return "complete"
    return "partial"
