"""Assessment planning for scope-driven Standard and Advanced runs."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field

from app.core.config import AppConfig
from app.core.session import AssessmentSession
from app.engine.remote_strategy import plan_remote_collection_strategy


@dataclass(slots=True)
class ModuleActivation:
    """One module activation decision."""

    module_name: str
    activation: str
    reason: str
    phase: str
    should_run: bool = True

    def to_dict(self) -> dict[str, str]:
        return {
            "module_name": self.module_name,
            "activation": self.activation,
            "reason": self.reason,
            "phase": self.phase,
        }


@dataclass(slots=True)
class AssessmentPlan:
    """Scope-driven execution plan for company-wide assessment modes."""

    package: str
    estate_mode: bool
    approved_scopes: list[str]
    discovery_sources: list[dict[str, str]]
    warnings: list[str]
    modules: list[ModuleActivation] = field(default_factory=list)

    def module_activation_plan(self) -> list[dict[str, str]]:
        return [entry.to_dict() for entry in self.modules]

    def metadata(self) -> dict[str, object]:
        return {
            "package": self.package,
            "estate_mode": self.estate_mode,
            "approved_scopes": list(self.approved_scopes),
            "discovery_sources": list(self.discovery_sources),
            "warnings": list(self.warnings),
            "module_activation_plan": self.module_activation_plan(),
        }

    def should_run(self, module_name: str) -> bool:
        entry = self.entry(module_name)
        return entry.should_run if entry else False

    def entry(self, module_name: str) -> ModuleActivation | None:
        for entry in self.modules:
            if entry.module_name == module_name:
                return entry
        return None

    def skipped_modules(self) -> list[ModuleActivation]:
        return [entry for entry in self.modules if not entry.should_run]


def build_assessment_plan(
    *,
    session: AssessmentSession,
    config: AppConfig,
    package: str,
) -> AssessmentPlan:
    """Build a plan from approved scope and configured evidence sources."""

    estate_mode = package in {"standard", "advanced"}
    approved_scopes = session.scope.scan_targets()
    auto_context = session.database.get_metadata("auto_context", {})
    scope_source = (
        str(auto_context.get("scope_source", "config_scope" if approved_scopes else "localhost_only_fallback"))
        if isinstance(auto_context, dict)
        else "config_scope"
    )
    scanner_enabled = _scanner_sources_present(config)
    firewall_import = bool(
        config.firewall_vpn_import.enabled and config.firewall_vpn_import.import_paths
    )
    backup_import = bool(
        config.backup_platform_import.enabled and config.backup_platform_import.import_paths
    )
    m365_enabled = bool(
        config.m365_entra.enabled or config.m365_entra.evidence_json_path
    )
    email_enabled = bool(session.intake.domain)
    ad_enabled = bool(config.active_directory.enabled)
    nmap_available = _nmap_available(config)
    nmap_enabled = bool(config.nmap.enabled and nmap_available and approved_scopes and not session.scope.local_only)
    remote_strategy = plan_remote_collection_strategy(session=session, config=config)
    remote_windows_enabled = bool(remote_strategy.enabled)

    warnings: list[str] = []
    if estate_mode and session.scope.local_only:
        warnings.append(
            "Standard/Advanced launched with localhost-only scope. Coverage is limited to the local host and imported or directory evidence."
        )
    if estate_mode and not remote_windows_enabled:
        warnings.append(
            f"Remote Windows collection strategy is unavailable. Direct host validation will be limited. Reason: {remote_strategy.reason}"
        )
    if estate_mode and not any(
        [
            nmap_enabled,
            remote_windows_enabled,
            ad_enabled,
            scanner_enabled,
            firewall_import,
            backup_import,
            m365_enabled,
        ]
    ):
        warnings.append(
            "No company-wide discovery or connector source is configured. Standard/Advanced coverage will collapse to local evidence only."
        )
    elif estate_mode and not any(
        [
            remote_windows_enabled,
            ad_enabled,
            scanner_enabled,
            firewall_import,
            backup_import,
            m365_enabled,
        ]
    ):
        warnings.append(
            "Company-wide evidence will be discovery-heavy because remote collection, directory evidence, imports, and cloud evidence are not configured."
        )

    discovery_sources = [
        _source_entry(
            "approved_scope",
            "active" if approved_scopes or session.scope.local_only else "missing",
            (
                f"{scope_source}: {', '.join(approved_scopes)}"
                if approved_scopes
                else f"{scope_source}: local-host-only"
                if session.scope.local_only
                else "No approved scope configured."
            ),
        ),
        _source_entry(
            "nmap_discovery",
            "active" if nmap_enabled else "skipped",
            (
                f"Approved scope discovery will target {', '.join(approved_scopes)}."
                if nmap_enabled
                else "Nmap disabled, unavailable, local-only scope, or no scan targets are available."
            ),
        ),
        _source_entry(
            "active_directory",
            "active" if ad_enabled else "not_configured",
            (
                f"AD evidence enabled for {config.active_directory.domain or session.intake.ad_domain or 'configured domain'}."
                if ad_enabled
                else "AD evidence not configured."
            ),
        ),
        _source_entry(
            "remote_windows",
            "active" if remote_windows_enabled else "not_configured",
            (
                f"WinRM remote collection strategy: {remote_strategy.mode}."
                if remote_windows_enabled
                else f"Remote Windows collection unavailable: {remote_strategy.reason}"
            ),
        ),
        _source_entry(
            "scanner_imports",
            "active" if scanner_enabled else "not_configured",
            (
                "Scanner import or API source configured."
                if scanner_enabled
                else "No Nessus or Greenbone import/API source configured."
            ),
        ),
        _source_entry(
            "firewall_vpn_import",
            "active" if firewall_import else "not_configured",
            (
                "Firewall/VPN imports configured."
                if firewall_import
                else "No firewall/VPN import configured."
            ),
        ),
        _source_entry(
            "backup_platform_import",
            "active" if backup_import else "not_configured",
            (
                "Backup platform imports configured."
                if backup_import
                else "No backup platform import configured."
            ),
        ),
        _source_entry(
            "email_security",
            "active" if email_enabled else "not_configured",
            (
                f"Email posture checks will query {session.intake.domain}."
                if email_enabled
                else "No client email domain configured."
            ),
        ),
        _source_entry(
            "m365_entra",
            "active" if m365_enabled else "not_configured",
            (
                "M365/Entra evidence configured."
                if m365_enabled
                else "No M365/Entra connector or evidence import configured."
            ),
        ),
    ]

    modules = [
        _module("identity", "active", "Core local host evidence is always collected.", phase="baseline"),
        _module("endpoint", "active", "Core local host evidence is always collected.", phase="baseline"),
        _module(
            "network_lite",
            "active",
            "Local network exposure checks anchor host evidence and estate correlation.",
            phase="baseline",
        ),
        _module(
            "email_security",
            "active" if email_enabled else "not_configured",
            "Client email domain available." if email_enabled else "No client email domain configured.",
            phase="connectors",
            should_run=email_enabled,
        ),
        _module(
            "m365_entra",
            "active" if m365_enabled else "not_configured",
            "M365/Entra evidence configured." if m365_enabled else "No M365/Entra connector or evidence import configured.",
            phase="connectors",
            should_run=m365_enabled,
        ),
        _module(
            "scanner_imports",
            "active" if scanner_enabled else "not_configured",
            "Scanner import/API source configured." if scanner_enabled else "No Nessus or Greenbone source configured.",
            phase="ingestion",
            should_run=scanner_enabled,
        ),
        _module(
            "firewall_vpn_import",
            "active" if firewall_import else "not_configured",
            "Firewall/VPN imports configured." if firewall_import else "No firewall/VPN import configured.",
            phase="ingestion",
            should_run=firewall_import,
        ),
        _module(
            "backup_platform_import",
            "active" if backup_import else "not_configured",
            "Backup platform imports configured." if backup_import else "No backup platform import configured.",
            phase="ingestion",
            should_run=backup_import,
        ),
        _module(
            "active_directory",
            "active" if ad_enabled else "not_configured",
            "AD evidence is enabled." if ad_enabled else "AD evidence not configured.",
            phase="connectors",
            should_run=ad_enabled,
        ),
        _module(
            "estate_orchestration",
            "limited" if session.scope.local_only else "active",
            (
                "Estate orchestration will run with localhost-only scope and imported evidence only."
                if session.scope.local_only
                else "Estate orchestration will automatically discover, enrich, and assess approved in-scope assets."
            ),
            phase="orchestration",
            should_run=estate_mode,
        ),
        _module(
            "backup_readiness",
            "active",
            "Backup readiness correlates direct, imported, and guided evidence.",
            phase="analysis",
        ),
        _module(
            "privileged_access",
            "active",
            "Privileged access review correlates endpoint, directory, and governance evidence.",
            phase="analysis",
        ),
        _module(
            "incident_readiness",
            "active",
            "Incident readiness combines telemetry visibility and guided process review.",
            phase="analysis",
        ),
        _module(
            "ransomware_readiness",
            "active",
            "Ransomware readiness is calculated from the available evidence set.",
            phase="analysis",
        ),
    ]
    if package == "advanced":
        modules.append(
            _module(
                "advanced_guided",
                "active",
                "Advanced adds guided planning outputs on top of the correlated evidence base.",
                phase="guided",
            )
        )

    return AssessmentPlan(
        package=package,
        estate_mode=estate_mode,
        approved_scopes=approved_scopes,
        discovery_sources=discovery_sources,
        warnings=warnings,
        modules=modules,
    )


def persist_assessment_plan(session: AssessmentSession, plan: AssessmentPlan) -> None:
    """Store the plan for reporting and callback outputs."""

    session.database.set_metadata("module_activation_plan", plan.module_activation_plan())
    session.database.set_metadata("assessment_plan", plan.metadata())
    session.database.set_metadata("assessment_warnings", list(plan.warnings))


def _scanner_sources_present(config: AppConfig) -> bool:
    return any(
        [
            config.scanner_integrations.nessus_import_path,
            config.scanner_integrations.greenbone_import_path,
            config.scanner_integrations.nessus_api.enabled,
            config.scanner_integrations.greenbone_api.enabled,
        ]
    )


def _nmap_available(config: AppConfig) -> bool:
    if not config.nmap.enabled:
        return False
    return bool(shutil.which(config.nmap.path))


def _module(
    module_name: str,
    activation: str,
    reason: str,
    *,
    phase: str,
    should_run: bool = True,
) -> ModuleActivation:
    return ModuleActivation(
        module_name=module_name,
        activation=activation,
        reason=reason,
        phase=phase,
        should_run=should_run,
    )


def _source_entry(source: str, status: str, reason: str) -> dict[str, str]:
    return {
        "source": source,
        "status": status,
        "reason": reason,
    }
