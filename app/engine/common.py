"""Shared package orchestration helpers."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from app import __version__
from app.collectors.windows_native import WindowsEvidence, WindowsNativeCollector
from app.core.config import AppConfig
from app.core.integrity import SessionAuditor, generate_evidence_manifest, store_bundle_hash
from app.core.inventory import AssetInventory
from app.core.models import AssessmentResult, Finding, ModuleResult
from app.core.session import AssessmentSession
from app.engine.aggregation import estate_summary, generate_aggregate_findings
from app.engine.correlation import correlate_findings
from app.engine.planner import AssessmentPlan
from app.engine.risk import score_finding
from app.export.bundle import BundleExporter
from app.profiling.environment import EnvironmentProfile, EnvironmentProfiler
from app.reporting.report_generator import ReportGenerator
from app.ui.console import ConsoleUi


@dataclass(slots=True)
class EvidenceContext:
    profile: EnvironmentProfile
    windows_evidence: WindowsEvidence


def collect_evidence_context(session: AssessmentSession) -> EvidenceContext:
    """Collect Basic shared evidence for every package."""

    logger = logging.getLogger("soun_runner")
    session.state.update({"phase": "profiling"})

    profiler = EnvironmentProfiler(session)
    auditor = SessionAuditor(session)
    if "environment_profile" in session.state.completed_modules():
        profile = profiler.load_existing()
        logger.info("Loaded environment profile from checkpoint")
    else:
        profile_result = profiler.collect()
        session.database.upsert_module_status(profile_result.to_status())
        session.state.mark_module_complete(profile_result.module_name)
        auditor.record_event(
            "module_completed",
            {
                "source_module": profile_result.module_name,
                "status": profile_result.status,
                "detail": profile_result.detail,
                "evidence_files": [str(path) for path in profile_result.evidence_files],
            },
        )
        profile = profiler.profile

    windows_collector = WindowsNativeCollector(session)
    windows_evidence = windows_collector.collect()
    windows_status = ModuleResult(
        module_name=windows_collector.name,
        status="complete" if windows_evidence.supported else "partial",
        detail=(
            "Windows-native evidence collected."
            if windows_evidence.supported
            else "Windows-native evidence skipped on unsupported host."
        ),
        evidence_files=[windows_evidence.raw_evidence_path]
        if windows_evidence.raw_evidence_path
        else [],
    )
    session.database.upsert_module_status(windows_status.to_status())
    session.state.mark_module_complete(windows_status.module_name)
    auditor.record_event(
        "module_completed",
        {
            "source_module": windows_status.module_name,
            "status": windows_status.status,
            "detail": windows_status.detail,
            "evidence_files": [str(path) for path in windows_status.evidence_files],
        },
    )
    return EvidenceContext(profile=profile, windows_evidence=windows_evidence)


def run_modules(
    *,
    config: AppConfig,
    session: AssessmentSession,
    ui: ConsoleUi,
    modules: Iterable[object],
) -> list[Finding]:
    findings: list[Finding] = []
    logger = logging.getLogger("soun_runner")
    inventory = AssetInventory(session, config)
    for module in modules:
        module_name = getattr(module, "name", module.__class__.__name__)
        if module_name in session.state.completed_modules():
            logger.info("Skipping completed module from checkpoint: %s", module_name)
            continue
        result = run_module_safe(session=session, ui=ui, module=module)
        for finding in result.findings:
            inventory.enrich_finding(finding)
            finding.risk_score = score_finding(finding)
        session.database.upsert_module_status(result.to_status())
        session.database.insert_findings(result.findings)
        findings.extend(result.findings)
    return findings


def record_planned_skips(
    *,
    session: AssessmentSession,
    plan: AssessmentPlan,
) -> None:
    """Persist skipped/not-configured modules so reporting is explicit."""

    for entry in plan.skipped_modules():
        session.database.upsert_module_status(
            ModuleResult(
                module_name=entry.module_name,
                status="skipped",
                detail=entry.reason,
            ).to_status()
        )


def run_module_safe(session: AssessmentSession, ui: ConsoleUi, module: object) -> ModuleResult:
    module_name = getattr(module, "name", module.__class__.__name__)
    logger = logging.getLogger("soun_runner")
    auditor = SessionAuditor(session)
    try:
        ui.info(f"Running module: {module_name}")
        auditor.record_event(
            "module_started",
            {
                "source_module": module_name,
            },
        )
        result = module.run()
        session.state.mark_module_complete(module_name)
        logger.info("Module complete: %s status=%s", module_name, result.status)
        auditor.record_event(
            "module_completed",
            {
                "source_module": module_name,
                "status": result.status,
                "detail": result.detail,
                "evidence_files": [str(path) for path in result.evidence_files],
            },
        )
        return result
    except Exception as exc:  # noqa: BLE001 - modules must fail isolated.
        logger.exception("Module failed safely: %s", module_name)
        session.state.mark_module_failed(module_name, str(exc))
        auditor.record_event(
            "module_failed",
            {
                "source_module": module_name,
                "status": "failed",
                "detail": str(exc),
                "evidence_files": [],
            },
        )
        return ModuleResult(
            module_name=module_name,
            status="failed",
            detail=f"Module failed safely: {exc}",
        )


def finalize_assessment(
    *,
    config: AppConfig,
    session: AssessmentSession,
    package: str,
    report_mode: str,
    include_roadmap: bool = False,
    include_30_60_90: bool = False,
) -> AssessmentResult:
    """Generate reports, bundle, and optional callback without failing the assessment."""

    raw_findings = session.database.list_findings()
    inventory = AssetInventory(session, config)
    correlation = correlate_findings(raw_findings)
    correlated_findings = [inventory.enrich_finding(finding) for finding in correlation.findings]
    for finding in correlated_findings:
        finding.risk_score = score_finding(finding)
    aggregate_findings = generate_aggregate_findings(
        findings=correlated_findings,
        inventory=inventory,
        package=package,
    )
    for finding in aggregate_findings:
        inventory.enrich_finding(finding)
        finding.risk_score = score_finding(finding)
    stored_findings = sorted(
        [*correlated_findings, *aggregate_findings],
        key=lambda item: (-int(item.risk_score), item.finding_id),
    )
    session.database.set_metadata("estate_summary", estate_summary(inventory=inventory, findings=stored_findings))
    session.database.set_metadata(
        "inventory_assets",
        [record.to_db_payload() for record in inventory.list_assets()],
    )
    session.database.set_metadata(
        "finding_correlation",
        {
            "merged_count": correlation.merged_count,
            "suppressed_count": correlation.suppressed_count,
            "groups": correlation.groups,
        },
    )
    report_generator = ReportGenerator(
        session=session,
        company_name=config.report_company_name,
        app_version=__version__,
        report_mode=report_mode,
    )
    report_pdf = report_generator.generate_pdf(stored_findings)
    action_csv = report_generator.generate_action_csv(stored_findings)
    findings_json = report_generator.generate_findings_json(stored_findings)
    additional_artifacts: list[Path] = []
    if include_roadmap:
        additional_artifacts.append(report_generator.generate_roadmap_csv(stored_findings))
    if include_30_60_90:
        additional_artifacts.append(report_generator.generate_30_60_90_plan(stored_findings))

    encrypted_bundle = BundleExporter(session).export(
        [report_pdf, action_csv, findings_json, *additional_artifacts]
    )

    callback_status = "not_configured"
    try:
        from app.export.callback import CallbackManager

        callback_status = CallbackManager(config=config, session=session).run(
            package=package,
            findings=stored_findings,
            encrypted_bundle=encrypted_bundle,
        )
    except Exception as exc:  # noqa: BLE001 - callback must never break local assessment.
        logging.getLogger("soun_runner").exception("Callback pipeline failed safely: %s", exc)
        callback_status = "failed_safely"

    if callback_status != "not_configured":
        report_generator = ReportGenerator(
            session=session,
            company_name=config.report_company_name,
            app_version=__version__,
            report_mode=report_mode,
            callback_status=callback_status,
        )
        report_pdf = report_generator.generate_pdf(stored_findings)
        findings_json = report_generator.generate_findings_json(stored_findings)

    manifest_path, _manifest = generate_evidence_manifest(session, package=package)
    report_generator = ReportGenerator(
        session=session,
        company_name=config.report_company_name,
        app_version=__version__,
        report_mode=report_mode,
        callback_status=callback_status,
    )
    report_pdf = report_generator.generate_pdf(stored_findings)
    findings_json = report_generator.generate_findings_json(stored_findings)
    encrypted_bundle = BundleExporter(session).export(
        [report_pdf, action_csv, findings_json, *additional_artifacts, manifest_path]
    )
    bundle_hash_path = store_bundle_hash(session, encrypted_bundle)

    session.state.update({"phase": "complete"})
    session.database.set_metadata("final_outputs", {
        "report_pdf": str(report_pdf),
        "action_csv": str(action_csv),
        "findings_json": str(findings_json),
        "encrypted_bundle": str(encrypted_bundle),
        "callback_status": callback_status,
        "manifest_path": str(manifest_path),
        "bundle_hash_path": str(bundle_hash_path),
        "correlated_findings": len(stored_findings),
    })
    logging.getLogger("soun_runner").info(
        "%s package complete with %s findings", package, len(stored_findings)
    )
    return AssessmentResult(
        app_version=__version__,
        package=package,
        session_id=session.session_id,
        report_pdf=report_pdf,
        action_csv=action_csv,
        findings_json=findings_json,
        encrypted_bundle=encrypted_bundle,
        findings_count=len(stored_findings),
        callback_status=callback_status,
        additional_artifacts=[*additional_artifacts, manifest_path, bundle_hash_path],
    )
