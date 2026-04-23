"""Entry point for Soun Al Hosn Assessment Runner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app import __version__
from app.core.config import AppConfig
from app.core.integrity import store_preflight_report
from app.core.preflight import preflight_exit_code, run_preflight
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

        intake = sample_intake() if args.sample else ui.collect_intake()
        intake = _apply_config_defaults(intake, config)
        session = SessionManager(config).create_session(intake)
        store_preflight_report(session, preflight.to_dict())
        if preflight.overall_status == "degraded":
            ui.warn(
                "Preflight degraded. Missing dependencies or limited access will be marked as partial or skipped."
            )
        if intake.package == "basic":
            result = BasicPackageRunner(config=config, session=session, ui=ui).run()
        elif intake.package == "standard":
            result = StandardPackageRunner(config=config, session=session, ui=ui).run()
        elif intake.package == "advanced":
            result = AdvancedPackageRunner(config=config, session=session, ui=ui).run()
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

    if not intake.domain and config.assessment.client_domain:
        intake.domain = config.assessment.client_domain
    if intake.authorized_scope.strip().lower() in {"", "config"}:
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


if __name__ == "__main__":
    sys.exit(main())
