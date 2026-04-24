"""Standard package orchestration."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.models import AssessmentResult, ModuleResult
from app.core.session import AssessmentSession
from app.engine.common import collect_evidence_context, finalize_assessment, run_modules
from app.engine.orchestrator import EstateAssessmentModule
from app.modules.active_directory import ActiveDirectoryModule
from app.modules.backup_readiness import BackupReadinessModule
from app.modules.backup_platform_import import BackupPlatformImportModule
from app.modules.email_security import EmailSecurityModule
from app.modules.endpoint import EndpointModule
from app.modules.identity import IdentityModule
from app.modules.incident_readiness import IncidentReadinessModule
from app.modules.m365_entra import M365EntraModule
from app.modules.network_lite import NetworkExposureLiteModule
from app.modules.privileged_access import PrivilegedAccessModule
from app.modules.ransomware_readiness import RansomwareReadinessModule
from app.modules.firewall_vpn_import import FirewallVpnImportModule
from app.scanners.greenbone_api import GreenboneApiClient
from app.scanners.greenbone_import import GreenboneImportAdapter
from app.scanners.nessus_api import NessusApiClient
from app.scanners.nessus_import import NessusImportAdapter
from app.ui.console import ConsoleUi


@dataclass(slots=True)
class StandardPackageRunner:
    config: AppConfig
    session: AssessmentSession
    ui: ConsoleUi
    report_mode: str = "standard"

    def run(self) -> AssessmentResult:
        context = collect_evidence_context(self.session)
        AssetInventory(self.session, self.config).record_local_profile(
            context.profile,
            evidence_paths=[
                str(path)
                for path in [
                    *(context.profile.evidence_files or []),
                    context.windows_evidence.raw_evidence_path,
                ]
                if path
            ],
        )
        standard_config = copy.copy(self.config)
        standard_config.nmap = copy.copy(self.config.nmap)
        standard_config.nmap.top_ports = self.config.standard.extended_nmap_top_ports

        modules = [
            IdentityModule(self.session, context.profile, context.windows_evidence),
            EndpointModule(self.session, context.profile, context.windows_evidence),
            NetworkExposureLiteModule(
                self.session,
                context.profile,
                standard_config,
                context.windows_evidence,
                run_scope_scan=False,
            ),
            EmailSecurityModule(self.session, context.profile, self.config.email_security),
            M365EntraModule(self.session, self.config.m365_entra),
            ScannerImportModule(self.session, self.config),
            FirewallVpnImportModule(self.session, self.config),
            BackupPlatformImportModule(self.session, self.config),
            ActiveDirectoryModule(self.session, self.config),
            EstateAssessmentModule(self.session, self.config, package="standard"),
            BackupReadinessModule(self.session, context.windows_evidence),
            PrivilegedAccessModule(self.session, context.windows_evidence),
            IncidentReadinessModule(self.session, context.windows_evidence),
            RansomwareReadinessModule(
                self.session,
                warn_threshold=self.config.standard.ransomware_score_warn_threshold,
            ),
        ]
        activation_plan = _standard_activation_plan(self.session, self.config)
        self.session.database.set_metadata("module_activation_plan", activation_plan)
        self.ui.print_module_activation_plan(activation_plan)
        run_modules(config=self.config, session=self.session, ui=self.ui, modules=modules)
        return finalize_assessment(
            config=self.config,
            session=self.session,
            package="standard",
            report_mode=self.report_mode or "standard",
            include_roadmap=True,
        )


@dataclass(slots=True)
class ScannerImportModule:
    session: AssessmentSession
    config: AppConfig

    name: str = "scanner_imports"

    def run(self) -> ModuleResult:
        if not self.config.standard.import_scanner_results:
            return ModuleResult(
                module_name=self.name,
                status="skipped",
                detail="Scanner import disabled in Standard config.",
            )
        findings = []
        evidence_files = []
        details: list[str] = []
        statuses: list[str] = []
        sources: list[dict[str, str]] = []
        inventory = AssetInventory(self.session, self.config)

        for path_value, adapter, source_name in [
            (
                self.config.scanner_integrations.nessus_import_path,
                NessusImportAdapter(self.session),
                "nessus_file_import",
            ),
            (
                self.config.scanner_integrations.greenbone_import_path,
                GreenboneImportAdapter(self.session),
                "greenbone_file_import",
            ),
        ]:
            if not path_value:
                continue
            result = adapter.import_file(Path(path_value))
            statuses.append(result.status)
            findings.extend(result.findings)
            if result.raw_evidence_path:
                evidence_files.append(result.raw_evidence_path)
                sources.append({"source": source_name, "path": str(result.raw_evidence_path)})
            _record_scanner_assets(
                inventory=inventory,
                findings=result.findings,
                evidence_path=str(result.raw_evidence_path) if result.raw_evidence_path else "",
            )
            details.append(f"{result.scanner_name}: {result.detail}")

        for result, source_name in [
            (
                NessusApiClient(self.session, self.config.scanner_integrations.nessus_api).fetch_scan_export(),
                "nessus_api",
            ),
            (
                GreenboneApiClient(self.session, self.config.scanner_integrations.greenbone_api).fetch_report(),
                "greenbone_api",
            ),
        ]:
            if result.status == "skipped" and not result.raw_evidence_path and not result.findings:
                if "disabled" in result.detail.lower() or "requires" in result.detail.lower():
                    details.append(f"{result.scanner_name}: {result.detail}")
                    statuses.append(result.status)
                    continue
            statuses.append(result.status)
            findings.extend(result.findings)
            if result.raw_evidence_path:
                evidence_files.append(result.raw_evidence_path)
                sources.append({"source": source_name, "path": str(result.raw_evidence_path)})
            _record_scanner_assets(
                inventory=inventory,
                findings=result.findings,
                evidence_path=str(result.raw_evidence_path) if result.raw_evidence_path else "",
            )
            details.append(f"{result.scanner_name}: {result.detail}")

        if not details:
            return ModuleResult(
                module_name=self.name,
                status="skipped",
                detail="No Nessus or Greenbone file imports or API connectors were configured.",
            )
        self.session.database.set_metadata("scanner_sources", sources)
        overall_status = _aggregate_scanner_status(statuses)
        return ModuleResult(
            module_name=self.name,
            status=overall_status,
            detail=" ".join(details),
            findings=findings,
            evidence_files=evidence_files,
        )


def _aggregate_scanner_status(statuses: list[str]) -> str:
    if not statuses:
        return "skipped"
    if all(status == "complete" for status in statuses):
        return "complete"
    if any(status == "complete" for status in statuses):
        return "partial"
    if all(status == "skipped" for status in statuses):
        return "skipped"
    return "partial"


def _record_scanner_assets(
    *,
    inventory: AssetInventory,
    findings: list,
    evidence_path: str,
) -> None:
    for finding in findings:
        target = str(getattr(finding, "asset", "")).strip()
        if not target:
            continue
        is_ip = _looks_like_ip(target)
        record = inventory.record_imported_asset(
            hostname="" if is_ip else target,
            ip_address=target if is_ip else "",
            source="scanner_import",
        )
        if evidence_path:
            inventory.attach_evidence(record.asset_id, evidence_path, "scanner_imports")
        inventory.session.database.upsert_asset_module_status(
            record.asset_id,
            "scanner_imports",
            "complete",
            "Asset identified from imported scanner evidence.",
        )


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _standard_activation_plan(session: AssessmentSession, config: AppConfig) -> list[dict[str, str]]:
    return [
        {
            "module_name": "identity",
            "activation": "active",
            "reason": "Core local host evidence is always collected for Standard.",
        },
        {
            "module_name": "endpoint",
            "activation": "active",
            "reason": "Core local host evidence is always collected for Standard.",
        },
        {
            "module_name": "network_lite",
            "activation": "active",
            "reason": "Local exposure checks support host baseline and remote exposure correlation.",
        },
        {
            "module_name": "email_security",
            "activation": "active" if session.intake.domain else "not_configured",
            "reason": "Client email domain provided." if session.intake.domain else "No client email domain configured.",
        },
        {
            "module_name": "m365_entra",
            "activation": "active" if config.m365_entra.enabled or config.m365_entra.evidence_json_path else "not_configured",
            "reason": (
                "M365/Entra evidence is configured."
                if config.m365_entra.enabled or config.m365_entra.evidence_json_path
                else "No M365/Entra connector or import configured."
            ),
        },
        {
            "module_name": "scanner_imports",
            "activation": "active" if _scanner_sources_present(config) else "not_configured",
            "reason": (
                "Scanner imports or APIs are configured."
                if _scanner_sources_present(config)
                else "No Nessus or Greenbone import/API source configured."
            ),
        },
        {
            "module_name": "firewall_vpn_import",
            "activation": "active" if config.firewall_vpn_import.import_paths else "not_configured",
            "reason": (
                "Firewall/VPN import paths configured."
                if config.firewall_vpn_import.import_paths
                else "No firewall/VPN import paths configured."
            ),
        },
        {
            "module_name": "backup_platform_import",
            "activation": "active" if config.backup_platform_import.import_paths else "not_configured",
            "reason": (
                "Backup platform import paths configured."
                if config.backup_platform_import.import_paths
                else "No backup platform import paths configured."
            ),
        },
        {
            "module_name": "active_directory",
            "activation": "active" if config.active_directory.enabled else "not_configured",
            "reason": (
                "Active Directory evidence is enabled."
                if config.active_directory.enabled
                else "AD evidence disabled in config."
            ),
        },
        {
            "module_name": "estate_orchestration",
            "activation": "active",
            "reason": "Standard defaults to company-wide discovery and collection inside approved scope.",
        },
        {
            "module_name": "backup_readiness",
            "activation": "active",
            "reason": "Backup readiness combines endpoint, import, and questionnaire evidence.",
        },
        {
            "module_name": "privileged_access",
            "activation": "active",
            "reason": "Privileged access review correlates local, directory, and governance evidence.",
        },
        {
            "module_name": "incident_readiness",
            "activation": "active",
            "reason": "Incident readiness remains part of Standard reporting.",
        },
        {
            "module_name": "ransomware_readiness",
            "activation": "active",
            "reason": "Ransomware readiness is derived from collected estate evidence.",
        },
    ]


def _scanner_sources_present(config: AppConfig) -> bool:
    return any(
        [
            config.scanner_integrations.nessus_import_path,
            config.scanner_integrations.greenbone_import_path,
            config.scanner_integrations.nessus_api.enabled,
            config.scanner_integrations.greenbone_api.enabled,
        ]
    )
