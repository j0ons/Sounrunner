"""Advanced package orchestration."""

from __future__ import annotations

import copy
from dataclasses import dataclass

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.models import AssessmentResult
from app.core.session import AssessmentSession
from app.engine.common import (
    collect_evidence_context,
    finalize_assessment,
    record_planned_skips,
    run_modules,
)
from app.engine.orchestrator import EstateAssessmentModule
from app.engine.planner import build_assessment_plan, persist_assessment_plan
from app.engine.standard import ScannerImportModule
from app.modules.active_directory import ActiveDirectoryModule
from app.modules.advanced_guided import AdvancedGuidedModule
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
from app.ui.console import ConsoleUi


@dataclass(slots=True)
class AdvancedPackageRunner:
    config: AppConfig
    session: AssessmentSession
    ui: ConsoleUi
    report_mode: str = "advanced"

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
        advanced_config = copy.copy(self.config)
        advanced_config.nmap = copy.copy(self.config.nmap)
        advanced_config.nmap.top_ports = self.config.standard.extended_nmap_top_ports
        plan = build_assessment_plan(session=self.session, config=self.config, package="advanced")
        persist_assessment_plan(self.session, plan)
        self.ui.print_module_activation_plan(plan.module_activation_plan())
        for warning in plan.warnings:
            self.ui.warn(warning)
        record_planned_skips(session=self.session, plan=plan)

        candidate_modules = {
            "identity": IdentityModule(self.session, context.profile, context.windows_evidence),
            "endpoint": EndpointModule(self.session, context.profile, context.windows_evidence),
            "network_lite": NetworkExposureLiteModule(
                self.session,
                context.profile,
                advanced_config,
                context.windows_evidence,
                run_scope_scan=False,
            ),
            "email_security": EmailSecurityModule(self.session, context.profile, self.config.email_security),
            "m365_entra": M365EntraModule(self.session, self.config.m365_entra),
            "scanner_imports": ScannerImportModule(self.session, self.config),
            "firewall_vpn_import": FirewallVpnImportModule(self.session, self.config),
            "backup_platform_import": BackupPlatformImportModule(self.session, self.config),
            "active_directory": ActiveDirectoryModule(self.session, self.config),
            "estate_orchestration": EstateAssessmentModule(self.session, self.config, package="advanced"),
            "backup_readiness": BackupReadinessModule(self.session, context.windows_evidence),
            "privileged_access": PrivilegedAccessModule(self.session, context.windows_evidence),
            "incident_readiness": IncidentReadinessModule(self.session, context.windows_evidence),
            "ransomware_readiness": RansomwareReadinessModule(
                self.session,
                warn_threshold=self.config.standard.ransomware_score_warn_threshold,
            ),
            "advanced_guided": AdvancedGuidedModule(self.session),
        }
        modules = [
            candidate_modules[entry.module_name]
            for entry in plan.modules
            if entry.should_run and entry.module_name in candidate_modules
        ]
        run_modules(config=self.config, session=self.session, ui=self.ui, modules=modules)
        return finalize_assessment(
            config=self.config,
            session=self.session,
            package="advanced",
            report_mode=self.report_mode or "advanced",
            include_roadmap=True,
            include_30_60_90=self.config.advanced.generate_30_60_90_plan,
        )
