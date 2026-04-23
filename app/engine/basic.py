"""Basic package orchestration."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.models import AssessmentResult
from app.core.session import AssessmentSession
from app.engine.common import collect_evidence_context, finalize_assessment, run_modules
from app.modules.email_security import EmailSecurityModule
from app.modules.endpoint import EndpointModule
from app.modules.identity import IdentityModule
from app.modules.network_lite import NetworkExposureLiteModule
from app.ui.console import ConsoleUi


@dataclass(slots=True)
class BasicPackageRunner:
    """Runs relevant Basic checks and records skipped or partial modules."""

    config: AppConfig
    session: AssessmentSession
    ui: ConsoleUi

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

        modules = [
            IdentityModule(self.session, context.profile, context.windows_evidence),
            EndpointModule(self.session, context.profile, context.windows_evidence),
            NetworkExposureLiteModule(
                self.session,
                context.profile,
                self.config,
                context.windows_evidence,
            ),
            EmailSecurityModule(self.session, context.profile, self.config.email_security),
        ]
        run_modules(config=self.config, session=self.session, ui=self.ui, modules=modules)
        return finalize_assessment(
            config=self.config,
            session=self.session,
            package="basic",
            report_mode="basic",
        )
