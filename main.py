"""Entry point for Soun Al Hosn Assessment Runner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app import __version__
from app.core.config import AppConfig
from app.core.session import AssessmentIntake, SessionManager
from app.engine.basic import BasicPackageRunner
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
        config = AppConfig.load(
            args.config,
            data_dir=args.data_dir,
            log_dir=args.log_dir,
        )
        intake = sample_intake() if args.sample else ui.collect_intake()
        if intake.package != "basic":
            ui.error(
                "Only the Basic package is executable in this MVP. "
                "Standard and Advanced are scaffolded but intentionally blocked."
            )
            return 2

        session = SessionManager(config).create_session(intake)
        result = BasicPackageRunner(config=config, session=session, ui=ui).run()
    except KeyboardInterrupt:
        ui.error("Operator cancelled the assessment. No remediation was attempted.")
        return 130
    except Exception as exc:  # noqa: BLE001 - terminal launcher must fail closed.
        ui.error(f"Fatal runner error: {exc}")
        return 1

    ui.success("Assessment complete.")
    ui.print_result(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
