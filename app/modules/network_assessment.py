"""Enterprise network security assessment module."""

from __future__ import annotations

import json
from dataclasses import dataclass

from app.core.config import AppConfig
from app.core.inventory import AssetInventory
from app.core.models import ModuleResult
from app.core.session import AssessmentSession
from app.engine.network_analysis import (
    build_network_assessment_summary,
    build_network_findings,
)


@dataclass(slots=True)
class NetworkAssessmentModule:
    """Analyze approved-scope network evidence without exploit or intrusive logic."""

    session: AssessmentSession
    config: AppConfig

    name: str = "network_assessment"

    def run(self) -> ModuleResult:
        if not self.config.network_assessment.enabled:
            return ModuleResult(
                module_name=self.name,
                status="skipped",
                detail="Network assessment module disabled in config.",
            )

        inventory = AssetInventory(self.session, self.config)
        summary = build_network_assessment_summary(
            session=self.session,
            config=self.config,
            inventory=inventory,
        )
        evidence_path = self.session.crypto.write_text(
            self.session.evidence_dir / "network_assessment_summary.json",
            json.dumps(summary.to_dict(), indent=2, sort_keys=True),
        )
        findings = build_network_findings(
            summary=summary,
            package=self.session.intake.package,
            evidence_path=evidence_path,
        )
        self.session.database.set_metadata("network_assessment_summary", summary.to_dict())
        detail = (
            f"Network assessment analyzed {len(summary.services)} service(s), "
            f"{len(summary.network_devices)} likely network device(s), "
            f"{len(summary.management_exposures)} management exposure(s), "
            f"{len(summary.insecure_protocols)} insecure protocol observation(s), "
            f"score={summary.network_score.network_score}."
        )
        status = "complete" if summary.services or summary.firewall_evidence else "partial"
        return ModuleResult(
            module_name=self.name,
            status=status,
            detail=detail,
            findings=findings,
            evidence_files=[evidence_path],
        )
