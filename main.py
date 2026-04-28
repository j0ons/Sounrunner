"""Entry point for Soun Al Hosn Assessment Runner."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path

from app import __version__
from app.core.auto_context import (
    AutoEnterpriseContext,
    apply_auto_context_to_config,
    auto_scope_debug_report,
    detect_enterprise_context,
)
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

_DOMAIN_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_RESERVED_HOST_TOKENS = {"cidr", "subnet", "scope", "network", "ip", "fqdn", "hostname"}


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
        "--company-name",
        type=str,
        default="",
        help="Company/client name override. Alias for --client-name.",
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
        "--approved-scope",
        type=str,
        default="",
        help="Explicit approved CIDR scope override. Example: --approved-scope 10.0.180.0/24",
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
        "--debug-auto-scope",
        action="store_true",
        help="Print raw auto-scope adapter decisions and exit.",
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

    if args.debug_auto_scope:
        try:
            config = AppConfig.load(args.config, data_dir=args.data_dir, log_dir=args.log_dir)
            cli_scope = _apply_cli_scope_override(args, config)
            context = detect_enterprise_context(config)
            if cli_scope:
                _mark_cli_scope(context, cli_scope)
        except Exception as exc:  # noqa: BLE001 - debug command must report exact blocker.
            print(f"Auto-scope debug failed: {exc}")
            return 1
        print(auto_scope_debug_report(context))
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
        cli_scope = _apply_cli_scope_override(args, config)
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

        auto_context = detect_enterprise_context(config)
        if cli_scope:
            _mark_cli_scope(auto_context, cli_scope)
        apply_auto_context_to_config(config, auto_context)
        intake = _resolve_intake(args=args, config=config, ui=ui, auto_context=auto_context)
        ui.print_phase("Scope", f"Resolved scope from {auto_context.scope_source}.")
        report_mode = _resolve_report_mode(args.report_mode, config, intake.package)
        launch_warnings = _launch_warnings(intake, config, auto_context)
        launch_warnings.extend(auto_context.warnings)
        launch_context = auto_context.to_dict()
        launch_context.update(
            {
                "assessment_mode": _assessment_mode_label(intake.package),
                "remote_strategy": _launch_remote_strategy(config, auto_context),
                "network_assessment": _network_assessment_label(config, intake.package),
            }
        )
        ui.print_launch_summary(
            intake,
            non_interactive=bool(args.non_interactive),
            report_mode=report_mode,
            warnings=launch_warnings,
            context=launch_context,
        )
        session = SessionManager(config).create_session(intake)
        store_preflight_report(session, preflight.to_dict())
        session.database.set_metadata("auto_context", auto_context.to_dict())
        session.database.set_metadata(
            "launch_context",
            {
                "non_interactive": bool(args.non_interactive),
                "report_mode": report_mode,
                "warnings": launch_warnings,
                "scope_from_config": bool(args.scope_from_config),
                "consent_confirmed_via_cli": bool(args.consent_confirmed),
                "auto_scope_source": auto_context.scope_source,
            },
        )
        if preflight.overall_status == "degraded":
            ui.warn(
                "Preflight degraded. Missing dependencies or limited access will be marked as partial or skipped."
            )
        if intake.package == "basic":
            ui.print_phase("Execution", "Running Basic local validation package.")
            result = BasicPackageRunner(config=config, session=session, ui=ui, report_mode=report_mode).run()
        elif intake.package == "standard":
            ui.print_phase("Execution", "Running Standard company assessment package.")
            result = StandardPackageRunner(config=config, session=session, ui=ui, report_mode=report_mode).run()
        elif intake.package == "advanced":
            ui.print_phase("Execution", "Running Advanced company assessment package.")
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
    ui.print_estate_dashboard(session)
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
    auto_context: AutoEnterpriseContext | None = None,
) -> AssessmentIntake:
    if args.sample:
        return _apply_config_defaults(sample_intake(), config)

    context = auto_context or detect_enterprise_context(config)
    intake = _build_seed_intake(args, config, context)
    intake = _apply_config_defaults(intake, config)
    if args.non_interactive:
        errors = _launch_validation_errors(intake, config)
        if errors:
            raise ValueError(
                "Non-interactive launch validation failed: "
                + "; ".join(errors)
                + ". Supply valid values via CLI or config."
            )
        return intake

    if _needs_interactive_identity_prompt(intake, args):
        intake = ui.complete_intake(intake, prompt_optional=False)
    intake = _prompt_for_scope_if_company_mode_needs_it(intake, args, config, ui, context)
    errors = _launch_validation_errors(intake, config)
    if errors:
        raise ValueError("Launch validation failed: " + "; ".join(errors) + ". Fix CLI or config values.")
    return intake


def _build_seed_intake(
    args: argparse.Namespace,
    config: AppConfig,
    context: AutoEnterpriseContext,
) -> AssessmentIntake:
    package = _package_from_launch_sources(args, config)
    cli_scope = normalize_prompt_value(getattr(args, "approved_scope", ""))
    configured_scope = _scope_value_from_config(config)
    scope = cli_scope or configured_scope or context.default_scope
    company_name = normalize_prompt_value(
        args.company_name or args.client_name or config.assessment.client_name
    )
    return AssessmentIntake(
        client_name=company_name,
        site=normalize_prompt_value(args.site or config.assessment.site or context.site_label),
        operator_name=normalize_prompt_value(args.operator or config.assessment.operator_name or context.operator_name),
        package=package,
        authorized_scope=scope,
        scope_notes=_scope_notes(config, context),
        consent_confirmed=bool(
            args.consent_confirmed
            or config.assessment.consent_confirmed
            or not args.non_interactive
        ),
        domain=normalize_prompt_value(config.assessment.client_domain or context.email_domain) or None,
        m365_connector=bool(config.m365_entra.enabled or config.m365_entra.evidence_json_path),
        host_allowlist=list(config.assessment.host_allowlist),
        host_denylist=list(config.assessment.host_denylist),
        ad_domain=normalize_prompt_value(config.assessment.ad_domain or config.active_directory.domain or context.ad_domain) or None,
        business_unit=normalize_prompt_value(config.assessment.business_unit or context.business_unit),
        scope_labels=dict(config.assessment.scope_labels),
        scanner_sources=list(config.assessment.scanner_sources),
        cloud_tenants=list(config.assessment.cloud_tenants),
    )


def _scope_value_from_config(config: AppConfig) -> str:
    if config.assessment.approved_scopes:
        return ",".join(config.assessment.approved_scopes)
    return normalize_prompt_value(config.assessment.approved_scope)


def _package_from_launch_sources(args: argparse.Namespace, config: AppConfig) -> str:
    cli_package = normalize_prompt_value(args.package).lower()
    if cli_package:
        return cli_package
    if _use_config_package(args):
        return normalize_prompt_value(config.assessment.package).lower()
    return ""


def _use_config_package(args: argparse.Namespace) -> bool:
    return bool(args.non_interactive or args.scope_from_config)


def _prompt_for_scope_if_company_mode_needs_it(
    intake: AssessmentIntake,
    args: argparse.Namespace,
    config: AppConfig,
    ui: ConsoleUi,
    context: AutoEnterpriseContext,
) -> AssessmentIntake:
    if not _needs_interactive_company_scope(intake, args, config):
        return intake
    intake.authorized_scope = ui.ask_approved_scope(intake.package)
    context.scope_source = "cli_scope"
    context.default_scope = intake.authorized_scope
    try:
        parsed = ScopePolicy.parse(intake.authorized_scope)
        context.private_subnets = [str(network) for network in parsed.networks]
    except ValueError:
        context.private_subnets = [intake.authorized_scope]
    return intake


def _needs_interactive_company_scope(
    intake: AssessmentIntake,
    args: argparse.Namespace,
    config: AppConfig,
) -> bool:
    if normalize_prompt_value(getattr(args, "approved_scope", "")):
        return False
    if _scope_value_from_config(config):
        return False
    if config.assessment.allow_localhost_fallback_for_company_modes:
        return False
    package = normalize_prompt_value(intake.package).lower()
    scope = normalize_prompt_value(intake.authorized_scope).lower()
    return package in {"standard", "advanced"} and scope in {
        "local",
        "localhost",
        "local-host-only",
        "host-only",
    }


def _missing_required_values(intake: AssessmentIntake) -> list[str]:
    missing: list[str] = []
    if not normalize_prompt_value(intake.client_name):
        missing.append("client_name")
    if normalize_prompt_value(intake.package).lower() not in {"basic", "standard", "advanced"}:
        missing.append("package")
    if not normalize_prompt_value(intake.authorized_scope):
        missing.append("authorized_scope")
    if not intake.consent_confirmed:
        missing.append("consent_confirmed")
    return missing


def _launch_validation_errors(intake: AssessmentIntake, config: AppConfig) -> list[str]:
    errors = [f"missing {item}" for item in _missing_required_values(intake)]
    package = normalize_prompt_value(intake.package).lower()
    if package and package not in {"basic", "standard", "advanced"}:
        errors.append("invalid package")
    localhost_guard = _localhost_fallback_guard_error(intake, config)
    if localhost_guard:
        errors.append(localhost_guard)
    for label, values in [("host allowlist", intake.host_allowlist), ("host denylist", intake.host_denylist)]:
        error = _host_list_validation_error(label, values)
        if error:
            errors.append(error)
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


def _apply_cli_scope_override(args: argparse.Namespace, config: AppConfig) -> str:
    scope = normalize_prompt_value(getattr(args, "approved_scope", ""))
    if not scope:
        return ""
    ScopePolicy.parse(scope)
    config.assessment.approved_scope = scope
    config.assessment.approved_scopes = []
    return scope


def _mark_cli_scope(context: AutoEnterpriseContext, scope: str) -> None:
    context.scope_source = "cli_scope"
    context.default_scope = scope
    try:
        parsed = ScopePolicy.parse(scope)
        context.private_subnets = [str(network) for network in parsed.networks]
    except ValueError:
        context.private_subnets = [scope]


def _localhost_fallback_guard_error(intake: AssessmentIntake, config: AppConfig) -> str:
    package = normalize_prompt_value(intake.package).lower()
    scope = normalize_prompt_value(intake.authorized_scope).lower()
    if package not in {"standard", "advanced"}:
        return ""
    if scope not in {"local", "localhost", "local-host-only", "host-only"}:
        return ""
    if config.assessment.allow_localhost_fallback_for_company_modes:
        return ""
    return (
        "Standard/Advanced require an approved or auto-detected private company scope. "
        "localhost-only fallback is blocked unless "
        "assessment.allow_localhost_fallback_for_company_modes is true."
    )


def _needs_interactive_identity_prompt(intake: AssessmentIntake, args: argparse.Namespace) -> bool:
    if not normalize_prompt_value(intake.client_name):
        return True
    package = normalize_prompt_value(intake.package).lower()
    cli_package = normalize_prompt_value(args.package)
    if cli_package:
        return False
    return package not in {"basic", "standard", "advanced"}


def _host_list_validation_error(label: str, values: list[str]) -> str | None:
    for value in values:
        candidate = normalize_prompt_value(value).rstrip(".")
        if not _is_valid_host_selector(candidate):
            return f"invalid {label} entry '{value}'. Expected IP address, hostname, or FQDN."
    return None


def _is_valid_host_selector(value: str) -> bool:
    if not value or value.lower() in _RESERVED_HOST_TOKENS:
        return False
    if value.lower() in {"local", "localhost", "local-host-only", "host-only"}:
        return True
    if "/" in value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        if ".." in value or len(value) > 253:
            return False
        return all(_DOMAIN_LABEL_PATTERN.fullmatch(label) for label in value.split("."))


def _resolve_report_mode(cli_value: str, config: AppConfig, package: str) -> str:
    requested = normalize_prompt_value(cli_value).lower()
    if not requested or requested == "auto":
        requested = normalize_prompt_value(config.report.mode).lower()
    if requested in {"basic", "standard", "advanced"}:
        return requested
    return package


def _scope_notes(config: AppConfig, context: AutoEnterpriseContext) -> str:
    configured = normalize_prompt_value(config.assessment.scope_notes)
    source = f"Scope source: {context.scope_source}."
    if configured and configured != "No additional notes.":
        return f"{configured} {source}"
    if context.private_subnets:
        return f"{source} Auto-detected directly connected private subnet(s): {', '.join(context.private_subnets)}."
    return source


def _launch_warnings(
    intake: AssessmentIntake,
    config: AppConfig,
    auto_context: AutoEnterpriseContext | None = None,
) -> list[str]:
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
    auto_current_user_available = bool(
        auto_context
        and config.remote_windows.auto_current_user
        and config.remote_windows.attempt_current_user_when_domain_joined
        and auto_context.os_name.lower() == "windows"
        and (auto_context.domain_joined or auto_context.ad_domain)
    )
    if intake.package in {"standard", "advanced"} and not config.remote_windows.enabled and not auto_current_user_available:
        warnings.append(
            "Remote Windows collection has no configured credential path and no current-user domain-auth path was detected. Estate coverage will rely on discovery, directory, cloud, and import evidence only."
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


def _assessment_mode_label(package: str) -> str:
    if package == "basic":
        return "Basic local"
    if package == "advanced":
        return "Advanced company-level"
    return "Standard company-level"


def _network_assessment_label(config: AppConfig, package: str) -> str:
    if package not in {"standard", "advanced"}:
        return "disabled"
    return "enabled" if config.network_assessment.enabled else "disabled"


def _launch_remote_strategy(config: AppConfig, context: AutoEnterpriseContext) -> str:
    if config.remote_windows.enabled and config.remote_windows.username:
        return "configured_credentials"
    if (
        config.remote_windows.auto_current_user
        and config.remote_windows.attempt_current_user_when_domain_joined
        and context.os_name.lower() == "windows"
        and (context.domain_joined or context.ad_domain)
    ):
        return "current_user_integrated_auth"
    return "unavailable"


if __name__ == "__main__":
    sys.exit(main())
