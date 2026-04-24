"""Entry point for Soun Al Hosn Assessment Runner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app import __version__
from app.core.config import AppConfig
from app.core.input_normalization import normalize_prompt_value
from app.core.integrity import store_preflight_report
from app.core.preflight import preflight_exit_code, run_preflight
from app.core.scope import ScopePolicy
from app.core.session import AssessmentIntake, SessionManager
from app.engine.advanced import AdvancedPackageRunner
from app.engine.basic import BasicPackageRunner
from app.engine.standard import StandardPackageRunner
from app.export.callback import CallbackManager, inspect_callback_queue, retry_callback_queue
from app.ui.console import ConsoleUi


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser for the terminal launcher."""

    parser = argparse.ArgumentParser(
        prog="soun-runner",
        description="Windows-first, read-only cybersecurity assessment runner.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional path to YAML or JSON config file.",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Run with safe sample intake values for local smoke testing.",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="External data directory for sessions, evidence, reports, and bundles.",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=None,
        help="External log directory. Session logs are written below this path.",
    )
    parser.add_argument(
        "--package",
        type=str,
        default="",
        help="Assessment package override: basic, standard, or advanced.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Run headless. Fail cleanly instead of prompting when required launch values are missing.",
    )
    parser.add_argument(
        "--client-name",
        type=str,
        default="",
        help="Client/entity name override for headless or config-first runs.",
    )
    parser.add_argument(
        "--site",
        type=str,
        default="",
        help="Site/branch override for headless or config-first runs.",
    )
    parser.add_argument(
        "--operator",
        type=str,
        default="",
        help="Operator name override for headless or config-first runs.",
    )
    parser.add_argument(
        "--scope-from-config",
        action="store_true",
        help="Use approved scopes from config without prompting for scope.",
    )
    parser.add_argument(
        "--consent-confirmed",
        action="store_true",
        help="Confirm that written authorization and approved scope have already been validated for this run.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the application version and exit.",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run startup dependency validation and exit.",
    )
    parser.add_argument(
        "--healthcheck",
        action="store_true",
        help="Run compact startup validation and exit with non-zero only on fatal failures.",
    )
    parser.add_argument(
        "--report-mode",
        type=str,
        default="",
        help="Report mode override: auto, basic, standard, or advanced.",
    )
    parser.add_argument(
        "--show-queue",
        action="store_true",
        help="Show queued callback items and exit.",
    )
    parser.add_argument(
        "--retry-callbacks",
        action="store_true",
        help="Retry queued callback items immediately and exit.",
    )
    parser.add_argument(
        "--resend-session",
        type=str,
        default="",
        help="Manually resend callback deliveries for an existing session ID and exit.",
    )
    return parser


def sample_intake() -> AssessmentIntake:
    """Return safe sample intake that performs no subnet scanning."""

    return AssessmentIntake(
        client_name="Sample Client",
        site="Main Site",
        operator_name="Operator",
        package="basic",
        authorized_scope="local-host-only",
        scope_notes="Smoke test scope. No subnet scanning.",
        consent_confirmed=True,
        domain=None,
        m365_connector=False,
        host_allowlist=[],
        host_denylist=[],
        ad_domain=None,
        business_unit="",
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"Soun Al Hosn Assessment Runner {__version__}")
        return 0

    ui = ConsoleUi(app_version=__version__)
    ui.banner()

    try:
        config, preflight = run_preflight(
            config_path=args.config,
            data_dir=args.data_dir,
            log_dir=args.log_dir,
        )
        if args.preflight or args.healthcheck:
            ui.print_preflight(preflight, compact=args.healthcheck)
            return preflight_exit_code(preflight)
        if preflight.overall_status == "failed":
            ui.print_preflight(preflight)
            return preflight_exit_code(preflight)
        if config is None:
            ui.error("Configuration could not be loaded.")
            return 2
        if args.show_queue:
            ui.print_queue(inspect_callback_queue(config))
            return 0
        if args.retry_callbacks:
            ui.print_queue(retry_callback_queue(config, force=True), title="Callback Retry Results")
            return 0
        if args.resend_session:
            session = SessionManager(config).load_session(args.resend_session)
            status = CallbackManager(config=config, session=session).resend_session()
            ui.success(f"Manual callback resend completed with status: {status}")
            return 0

        intake = _resolve_intake(args=args, config=config, ui=ui)
        report_mode = _resolve_report_mode(args.report_mode, config, intake.package)
        launch_warnings = _launch_warnings(intake, config)
        ui.print_launch_summary(
            intake,
            non_interactive=bool(args.non_interactive),
            report_mode=report_mode,
            warnings=launch_warnings,
        )
        session = SessionManager(config).create_session(intake)
        store_preflight_report(session, preflight.to_dict())
        session.database.set_metadata(
            "launch_context",
            {
                "non_interactive": bool(args.non_interactive),
                "report_mode": report_mode,
                "warnings": launch_warnings,
                "scope_from_config": bool(args.scope_from_config),
                "consent_confirmed_via_cli": bool(args.consent_confirmed),
            },
        )
        if preflight.overall_status == "degraded":
            ui.warn(
                "Preflight degraded. Missing dependencies or limited access will be marked as partial or skipped."
            )
        if intake.package == "basic":
            result = BasicPackageRunner(config=config, session=session, ui=ui, report_mode=report_mode).run()
        elif intake.package == "standard":
            result = StandardPackageRunner(config=config, session=session, ui=ui, report_mode=report_mode).run()
        elif intake.package == "advanced":
            result = AdvancedPackageRunner(config=config, session=session, ui=ui, report_mode=report_mode).run()
        else:
            ui.error(f"Unsupported assessment package: {intake.package}")
            return 2
    except KeyboardInterrupt:
        ui.error("Operator cancelled the assessment. No remediation was attempted.")
        return 130
    except Exception as exc:  # noqa: BLE001 - terminal launcher must fail closed.
        ui.error(f"Fatal runner error: {exc}")
        return 1

    ui.success("Assessment complete.")
    ui.print_result(result)
    return 0


def _apply_config_defaults(intake: AssessmentIntake, config: AppConfig) -> AssessmentIntake:
    """Apply external config defaults without overriding explicit intake values."""

    intake.authorized_scope = normalize_prompt_value(intake.authorized_scope)
    intake.business_unit = normalize_prompt_value(intake.business_unit)
    intake.ad_domain = normalize_prompt_value(intake.ad_domain) or None
    intake.domain = normalize_prompt_value(intake.domain) or None
    if not intake.domain and config.assessment.client_domain:
        intake.domain = config.assessment.client_domain
    if not intake.client_name and config.assessment.client_name:
        intake.client_name = config.assessment.client_name
    if not intake.site and config.assessment.site:
        intake.site = config.assessment.site
    if not intake.operator_name and config.assessment.operator_name:
        intake.operator_name = config.assessment.operator_name
    if not intake.package and config.assessment.package:
        intake.package = config.assessment.package
    if not intake.scope_notes and config.assessment.scope_notes:
        intake.scope_notes = config.assessment.scope_notes
    if not intake.consent_confirmed and config.assessment.consent_confirmed:
        intake.consent_confirmed = True
    if intake.authorized_scope.lower() in {"", "config"}:
        if config.assessment.approved_scopes:
            intake.authorized_scope = ",".join(config.assessment.approved_scopes)
        elif config.assessment.approved_scope:
            intake.authorized_scope = config.assessment.approved_scope
    if not intake.host_allowlist and config.assessment.host_allowlist:
        intake.host_allowlist = list(config.assessment.host_allowlist)
    if not intake.host_denylist and config.assessment.host_denylist:
        intake.host_denylist = list(config.assessment.host_denylist)
    if not intake.ad_domain and config.assessment.ad_domain:
        intake.ad_domain = config.assessment.ad_domain
    if not intake.business_unit and config.assessment.business_unit:
        intake.business_unit = config.assessment.business_unit
    if not intake.scope_labels and config.assessment.scope_labels:
        intake.scope_labels = dict(config.assessment.scope_labels)
    if not intake.cloud_tenants and config.assessment.cloud_tenants:
        intake.cloud_tenants = list(config.assessment.cloud_tenants)
    if not intake.scanner_sources and config.assessment.scanner_sources:
        intake.scanner_sources = list(config.assessment.scanner_sources)
    return intake


def _resolve_intake(
    *,
    args: argparse.Namespace,
    config: AppConfig,
    ui: ConsoleUi,
) -> AssessmentIntake:
    if args.sample:
        return _apply_config_defaults(sample_intake(), config)

    intake = _build_seed_intake(args, config)
    intake = _apply_config_defaults(intake, config)
    if args.non_interactive:
        errors = _launch_validation_errors(intake)
        if errors:
            raise ValueError(
                "Non-interactive launch validation failed: "
                + "; ".join(errors)
                + ". Supply valid values via CLI or config."
            )
        return intake
    if _launch_validation_errors(intake):
        return ui.complete_intake(intake, prompt_optional=False)
    return intake


def _build_seed_intake(args: argparse.Namespace, config: AppConfig) -> AssessmentIntake:
    package = normalize_prompt_value(args.package or config.assessment.package).lower()
    configured_scope = _scope_value_from_config(config)
    scope = configured_scope if (args.scope_from_config or configured_scope) else ""
    return AssessmentIntake(
        client_name=normalize_prompt_value(args.client_name or config.assessment.client_name),
        site=normalize_prompt_value(args.site or config.assessment.site),
        operator_name=normalize_prompt_value(args.operator or config.assessment.operator_name),
        package=package,
        authorized_scope=scope,
        scope_notes=normalize_prompt_value(config.assessment.scope_notes),
        consent_confirmed=bool(args.consent_confirmed or config.assessment.consent_confirmed),
        domain=normalize_prompt_value(config.assessment.client_domain) or None,
        m365_connector=bool(config.m365_entra.enabled or config.m365_entra.evidence_json_path),
        host_allowlist=list(config.assessment.host_allowlist),
        host_denylist=list(config.assessment.host_denylist),
        ad_domain=normalize_prompt_value(config.assessment.ad_domain or config.active_directory.domain) or None,
        business_unit=normalize_prompt_value(config.assessment.business_unit),
        scope_labels=dict(config.assessment.scope_labels),
        scanner_sources=list(config.assessment.scanner_sources),
        cloud_tenants=list(config.assessment.cloud_tenants),
    )


def _scope_value_from_config(config: AppConfig) -> str:
    if config.assessment.approved_scopes:
        return ",".join(config.assessment.approved_scopes)
    return normalize_prompt_value(config.assessment.approved_scope)


def _missing_required_values(intake: AssessmentIntake) -> list[str]:
    missing: list[str] = []
    if not normalize_prompt_value(intake.client_name):
        missing.append("client_name")
    if not normalize_prompt_value(intake.site):
        missing.append("site")
    if not normalize_prompt_value(intake.operator_name):
        missing.append("operator_name")
    if normalize_prompt_value(intake.package).lower() not in {"basic", "standard", "advanced"}:
        missing.append("package")
    if not normalize_prompt_value(intake.authorized_scope):
        missing.append("authorized_scope")
    if not intake.consent_confirmed:
        missing.append("consent_confirmed")
    return missing


def _launch_validation_errors(intake: AssessmentIntake) -> list[str]:
    errors = [f"missing {item}" for item in _missing_required_values(intake)]
    package = normalize_prompt_value(intake.package).lower()
    if package and package not in {"basic", "standard", "advanced"}:
        errors.append("invalid package")
    scope = normalize_prompt_value(intake.authorized_scope)
    if scope:
        try:
            ScopePolicy.parse(
                scope,
                host_allowlist=intake.host_allowlist,
                host_denylist=intake.host_denylist,
                ad_domain=intake.ad_domain or "",
                business_unit=intake.business_unit,
                scope_labels=intake.scope_labels,
            )
        except ValueError as exc:
            errors.append(str(exc))
    return errors


def _resolve_report_mode(cli_value: str, config: AppConfig, package: str) -> str:
    requested = normalize_prompt_value(cli_value).lower()
    if not requested or requested == "auto":
        requested = normalize_prompt_value(config.report.mode).lower()
    if requested in {"basic", "standard", "advanced"}:
        return requested
    return package


def _launch_warnings(intake: AssessmentIntake, config: AppConfig) -> list[str]:
    warnings: list[str] = []
    if intake.package in {"standard", "advanced"} and intake.authorized_scope.lower() in {
        "local",
        "localhost",
        "local-host-only",
        "host-only",
    }:
        warnings.append(
            "Standard/Advanced selected with localhost-only scope. Coverage will be limited to the local host and any imported evidence."
        )
    if intake.package in {"standard", "advanced"} and not config.remote_windows.enabled:
        warnings.append(
            "Remote Windows collection is not configured. Estate coverage will rely on discovery, directory, cloud, and import evidence only."
        )
    if intake.package in {"standard", "advanced"} and not any(
        [
            config.active_directory.enabled,
            config.remote_windows.enabled,
            config.firewall_vpn_import.import_paths,
            config.backup_platform_import.import_paths,
            config.scanner_integrations.nessus_import_path,
            config.scanner_integrations.greenbone_import_path,
            config.m365_entra.enabled,
        ]
    ):
        warnings.append(
            "No enterprise connectors or imports are configured. Standard/Advanced will rely primarily on in-scope network discovery."
        )
    return warnings


if __name__ == "__main__":
    sys.exit(main())
