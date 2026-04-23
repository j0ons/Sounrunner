"""Basic package orchestration."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app import __version__
from app.core.config import AppConfig
from app.core.models import AssessmentResult, Finding, ModuleResult
from app.core.session import AssessmentSession
from app.engine.risk import score_finding
from app.export.bundle import BundleExporter
from app.export.smtp_summary import SmtpSummarySender
from app.modules.email_security import EmailSecurityModule
from app.modules.endpoint import EndpointModule
from app.modules.identity import IdentityModule
from app.modules.network_lite import NetworkExposureLiteModule
from app.profiling.environment import EnvironmentProfiler
from app.reporting.report_generator import ReportGenerator
from app.ui.console import ConsoleUi


@dataclass(slots=True)
class BasicPackageRunner:
    """Runs relevant Basic checks and records skipped or partial modules."""

    config: AppConfig
    session: AssessmentSession
    ui: ConsoleUi

    def run(self) -> AssessmentResult:
        logger = logging.getLogger("soun_runner")
        logger.info("Starting Basic package")
        self.session.state.update({"phase": "profiling"})

        profiler = EnvironmentProfiler(self.session)
        if "environment_profile" in self.session.state.completed_modules():
            profile = profiler.load_existing()
            logger.info("Loaded environment profile from checkpoint")
        else:
            profile_result = profiler.collect()
            self.session.database.upsert_module_status(profile_result.to_status())
            self.session.state.mark_module_complete(profile_result.module_name)
            profile = profiler.profile

        modules = [
            IdentityModule(self.session, profile),
            EndpointModule(self.session, profile),
            NetworkExposureLiteModule(self.session, profile),
            EmailSecurityModule(self.session, profile, self.config.email_security),
        ]

        for module in modules:
            module_name = getattr(module, "name", module.__class__.__name__)
            if module_name in self.session.state.completed_modules():
                logger.info("Skipping completed module from checkpoint: %s", module_name)
                continue
            result = self._run_module(module)
            for finding in result.findings:
                finding.risk_score = score_finding(finding)
            self.session.database.upsert_module_status(result.to_status())
            self.session.database.insert_findings(result.findings)

        stored_findings = self.session.database.list_findings()
        report_generator = ReportGenerator(
            session=self.session,
            company_name=self.config.report_company_name,
            app_version=__version__,
        )
        report_pdf = report_generator.generate_pdf(stored_findings)
        action_csv = report_generator.generate_action_csv(stored_findings)
        findings_json = report_generator.generate_findings_json(stored_findings)
        encrypted_bundle = BundleExporter(self.session).export(
            [report_pdf, action_csv, findings_json]
        )

        if self.config.smtp_enabled:
            SmtpSummarySender(self.config.smtp, self.session).send(stored_findings)

        self.session.state.update({"phase": "complete"})
        logger.info("Basic package complete with %s findings", len(stored_findings))

        return AssessmentResult(
            app_version=__version__,
            session_id=self.session.session_id,
            report_pdf=report_pdf,
            action_csv=action_csv,
            findings_json=findings_json,
            encrypted_bundle=encrypted_bundle,
            findings_count=len(stored_findings),
        )

    def _run_module(self, module: object) -> ModuleResult:
        module_name = getattr(module, "name", module.__class__.__name__)
        logger = logging.getLogger("soun_runner")
        try:
            self.ui.info(f"Running module: {module_name}")
            result = module.run()
            self.session.state.mark_module_complete(module_name)
            logger.info("Module complete: %s status=%s", module_name, result.status)
            return result
        except Exception as exc:  # noqa: BLE001 - modules must fail isolated.
            logger.exception("Module failed safely: %s", module_name)
            self.session.state.mark_module_failed(module_name, str(exc))
            return ModuleResult(
                module_name=module_name,
                status="failed",
                detail=f"Module failed safely: {exc}",
            )
