"""Rich-based terminal UI with safe fallback."""

from __future__ import annotations

import getpass
import ipaddress
import re

from app.core.input_normalization import normalize_prompt_value
from app.core.preflight import PreflightReport
from app.core.scope import LOCAL_ONLY_MARKERS, ScopePolicy
from app.core.models import AssessmentResult
from app.core.session import AssessmentIntake, AssessmentSession

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
except ImportError:  # pragma: no cover - fallback for minimal environments.
    Console = None
    Panel = None
    Confirm = None
    Prompt = None
    Table = None


HEADER_ART = """███████╗ ██████╗ ██╗   ██╗███╗   ██╗     █████╗ ██╗         ██╗  ██╗ ██████╗ ███████╗███╗   ██╗
██╔════╝██╔═══██╗██║   ██║████╗  ██║    ██╔══██╗██║         ██║  ██║██╔═══██╗██╔════╝████╗  ██║
███████╗██║   ██║██║   ██║██╔██╗ ██║    ███████║██║         ███████║██║   ██║███████╗██╔██╗ ██║
╚════██║██║   ██║██║   ██║██║╚██╗██║    ██╔══██║██║         ██╔══██║██║   ██║╚════██║██║╚██╗██║
███████║╚██████╔╝╚██████╔╝██║ ╚████║    ██║  ██║███████╗    ██║  ██║╚██████╔╝███████║██║ ╚████║
╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝

 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝"""

VALID_PACKAGES = {"basic", "standard", "advanced"}
YES_VALUES = {"y", "yes", "true", "1"}
NO_VALUES = {"n", "no", "false", "0"}
RESERVED_HOST_TOKENS = {"cidr", "subnet", "scope", "network", "ip", "fqdn", "hostname"}
DOMAIN_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class ConsoleUi:
    """Terminal-style operator interface."""

    def __init__(self, app_version: str = "unknown") -> None:
        self.app_version = app_version
        self.console = Console() if Console else None

    def banner(self) -> None:
        text = (
            f"Soun Al Hosn Assessment Runner v{self.app_version}\n"
            "Authorized, read-only cybersecurity assessment orchestration.\n"
            "No stealth. No exploitation. No persistence. No auto-remediation."
        )
        if self.console and Panel:
            self.console.print(HEADER_ART, style="bold bright_green", overflow="ignore", crop=False)
            self.console.print(
                Panel(
                    text,
                    title="Authorized Use Only",
                    subtitle="Scope-Controlled Company Assessment",
                    border_style="bright_cyan",
                )
            )
        else:
            print(HEADER_ART)
            print(text)

    def collect_intake(self) -> AssessmentIntake:
        return self.complete_intake(_blank_intake(), prompt_optional=True)

    def complete_intake(
        self,
        seed: AssessmentIntake,
        *,
        prompt_optional: bool = False,
    ) -> AssessmentIntake:
        normalized = _normalize_intake_seed(seed)
        client = normalized.client_name or self._ask_required("Company/entity name")
        package = _validated_package(normalized.package) or self._ask_package()
        site = normalized.site or "Auto-detected"
        operator = normalized.operator_name or getpass.getuser()
        scope = _validated_scope(normalized.authorized_scope) or "local-host-only"
        allowlist = _safe_host_list(normalized.host_allowlist, ui=self)
        denylist = _safe_host_list(normalized.host_denylist, ui=self)
        ad_domain = _safe_domain(normalized.ad_domain or "", field_name="AD domain", ui=self)
        business_unit = _safe_business_unit(normalized.business_unit, ui=self)
        notes = normalized.scope_notes or "No additional notes."
        domain = _safe_domain(normalized.domain or "", field_name="Email domain", ui=self)
        m365 = normalized.m365_connector
        consent = normalized.consent_confirmed or True
        return AssessmentIntake(
            client_name=client,
            site=site,
            operator_name=operator,
            package=package,
            authorized_scope=scope,
            scope_notes=notes,
            consent_confirmed=consent,
            domain=domain or None,
            m365_connector=m365,
            host_allowlist=allowlist,
            host_denylist=denylist,
            ad_domain=ad_domain or None,
            business_unit=business_unit,
            scope_labels=dict(normalized.scope_labels),
            scanner_sources=list(normalized.scanner_sources),
            cloud_tenants=list(normalized.cloud_tenants),
        )

    def ask_approved_scope(self, package: str) -> str:
        """Ask for explicit approved scope when company mode cannot auto-detect one."""

        while True:
            scope = self._ask(
                f"Approved company scope CIDR required for {package.title()}",
                default="",
            )
            if not scope:
                self.error("Approved scope cannot be blank for Standard/Advanced company-level assessments.")
                continue
            try:
                parsed = ScopePolicy.parse(scope)
            except ValueError as exc:
                self.error(str(exc))
                continue
            if parsed.local_only:
                self.error("Standard/Advanced require a company CIDR scope, not local-host-only.")
                continue
            return scope

    def print_launch_summary(
        self,
        intake: AssessmentIntake,
        *,
        non_interactive: bool,
        report_mode: str,
        warnings: list[str] | None = None,
        context: dict[str, object] | None = None,
    ) -> None:
        warnings = warnings or []
        context = context or {}
        company = intake.client_name
        mode = str(context.get("assessment_mode", _mode_for_package(intake.package)))
        remote_strategy = str(context.get("remote_strategy", "not evaluated"))
        network_enabled = str(context.get("network_assessment", "enabled" if intake.package in {"standard", "advanced"} else "disabled"))
        if self.console and Panel and Table:
            table = Table(show_header=True, header_style="bold bright_cyan")
            table.add_column("Company")
            table.add_column("Package")
            table.add_column("Mode")
            table.add_column("Launch")
            table.add_column("Scope")
            table.add_column("Scope Source")
            table.add_column("Remote")
            table.add_column("Network")
            table.add_column("Operator")
            table.add_column("Report")
            table.add_row(
                company,
                intake.package,
                mode,
                "headless" if non_interactive else "interactive",
                intake.authorized_scope,
                str(context.get("scope_source", "config_or_manual")),
                remote_strategy,
                network_enabled,
                intake.operator_name,
                report_mode,
            )
            self.console.print(
                Panel.fit(
                    table,
                    title="Run Contract",
                    border_style="bright_green",
                )
            )
            if warnings:
                warning_table = Table(show_header=True, header_style="bold yellow")
                warning_table.add_column("Launch Warnings")
                for item in warnings:
                    warning_table.add_row(item)
                self.console.print(warning_table)
            self._print_auto_scope_context(context)
            return
        lines = [
            "Run Contract",
            f"Company: {company}",
            f"Package: {intake.package}",
            f"Mode: {mode}",
            f"Launch: {'headless' if non_interactive else 'interactive'}",
            f"Scope: {intake.authorized_scope}",
            f"Scope source: {context.get('scope_source', 'config_or_manual')}",
            f"Remote strategy: {remote_strategy}",
            f"Network assessment: {network_enabled}",
            f"Operator: {intake.operator_name}",
            f"Report: {report_mode}",
        ]
        for item in warnings:
            lines.append(f"Warning: {item}")
        lines.extend(_auto_scope_lines(context))
        self._print("\n".join(lines), style="white")

    def _print_auto_scope_context(self, context: dict[str, object]) -> None:
        diagnostics = context.get("adapter_diagnostics", [])
        if not diagnostics or not isinstance(diagnostics, list) or not self.console or not Table:
            return
        table = Table(title="Auto-Scope Adapter Decisions", header_style="bold bright_cyan")
        table.add_column("Adapter")
        table.add_column("IPv4")
        table.add_column("Subnet")
        table.add_column("Decision")
        table.add_column("Reason")
        table.add_column("Confidence")
        for item in diagnostics[:12]:
            if not isinstance(item, dict):
                continue
            table.add_row(
                str(item.get("name", "")),
                str(item.get("ip_address", "")),
                str(item.get("subnet", "")),
                str(item.get("decision", "")),
                str(item.get("reason", "")),
                str(item.get("confidence_score", "")),
            )
        self.console.print(table)

    def print_module_activation_plan(self, plan: list[dict[str, str]]) -> None:
        if not plan:
            return
        if self.console and Table:
            table = Table(title="Assessment Brain: Module Activation", header_style="bold bright_green")
            table.add_column("Phase")
            table.add_column("Module")
            table.add_column("State")
            table.add_column("Reason")
            for item in plan:
                table.add_row(
                    str(item.get("phase", "")),
                    str(item.get("module_name", "")),
                    str(item.get("activation", "")),
                    str(item.get("reason", "")),
                )
            self.console.print(table)
            return
        lines = ["Module Activation Plan"]
        for item in plan:
            lines.append(
                f"- {item.get('phase')} / {item.get('module_name')}: {item.get('activation')} ({item.get('reason')})"
            )
        self._print("\n".join(lines), style="white")

    def print_phase(self, phase: str, detail: str = "") -> None:
        message = f"[{phase}] {detail}".strip()
        if self.console and Panel:
            self.console.print(Panel(message, border_style="bright_black"))
        else:
            self._print(message, style="cyan")

    def print_estate_dashboard(self, session: AssessmentSession) -> None:
        estate = session.database.get_metadata("estate_summary", {})
        coverage = estate.get("coverage", {}) if isinstance(estate, dict) else {}
        remote = session.database.get_metadata("remote_collection_summary", {})
        remote = remote if isinstance(remote, dict) else {}
        network = session.database.get_metadata("network_assessment_summary", {})
        network = network if isinstance(network, dict) else {}
        network_score = network.get("network_score", {})
        network_score_value = (
            network_score.get("network_score", "not scored")
            if isinstance(network_score, dict)
            else "not scored"
        )
        plan = session.database.get_metadata("module_activation_plan", [])
        findings = session.database.list_findings()
        active = sum(1 for item in plan if isinstance(item, dict) and item.get("activation") in {"active", "limited"})
        skipped = sum(1 for item in plan if isinstance(item, dict) and item.get("activation") in {"skipped", "not_configured"})
        severity = {key: 0 for key in ["critical", "high", "medium", "low", "info"]}
        for finding in findings:
            severity[finding.severity] = severity.get(finding.severity, 0) + 1
        if self.console and Table and Panel:
            table = Table(show_header=False)
            table.add_column("Metric", style="bold bright_cyan")
            table.add_column("Value", style="white")
            table.add_row("Phase", "reporting complete")
            table.add_row("Assets discovered", str(coverage.get("total_assets", 0)))
            table.add_row("Assessed", str(coverage.get("assessed", 0)))
            table.add_row("Partial", str(coverage.get("partial", 0)))
            table.add_row("Unreachable", str(coverage.get("unreachable", 0)))
            table.add_row("Discovery-only", str(coverage.get("discovery_only", 0)))
            table.add_row("Imported-only", str(coverage.get("imported_evidence_only", 0)))
            table.add_row("Remote strategy", str(remote.get("strategy", "not evaluated")))
            table.add_row("Windows candidates", str(remote.get("windows_candidates", 0)))
            table.add_row("Remote attempted", str(remote.get("collection_attempted", 0)))
            table.add_row("Remote successful", str(remote.get("collection_successful", 0)))
            table.add_row("Remote failed", str(remote.get("collection_failed", 0)))
            table.add_row("Top failure reason", str(remote.get("top_failure_reason", "none") or "none"))
            table.add_row("Network score", str(network_score_value))
            table.add_row("Services discovered", str(_list_count(network.get("services"))))
            table.add_row("Network devices", str(_list_count(network.get("network_devices"))))
            table.add_row("Management exposures", str(_list_count(network.get("management_exposures"))))
            table.add_row("Insecure protocols", str(_list_count(network.get("insecure_protocols"))))
            table.add_row("Segmentation observations", str(_list_count(network.get("segmentation_observations"))))
            table.add_row("Active modules", str(active))
            table.add_row("Skipped/not configured", str(skipped))
            table.add_row(
                "Findings",
                "C:{critical} H:{high} M:{medium} L:{low} I:{info}".format(**severity),
            )
            self.console.print(Panel(table, title="Assessment Console", border_style="bright_green"))
            return
        lines = [
            "Assessment Console",
            f"Assets discovered: {coverage.get('total_assets', 0)}",
            f"Assessed: {coverage.get('assessed', 0)}",
            f"Partial: {coverage.get('partial', 0)}",
            f"Unreachable: {coverage.get('unreachable', 0)}",
            f"Discovery-only: {coverage.get('discovery_only', 0)}",
            f"Imported-only: {coverage.get('imported_evidence_only', 0)}",
            f"Remote strategy: {remote.get('strategy', 'not evaluated')}",
            f"Windows candidates: {remote.get('windows_candidates', 0)}",
            f"Remote attempted: {remote.get('collection_attempted', 0)}",
            f"Remote successful: {remote.get('collection_successful', 0)}",
            f"Remote failed: {remote.get('collection_failed', 0)}",
            f"Top failure reason: {remote.get('top_failure_reason', 'none') or 'none'}",
            f"Network score: {network_score_value}",
            f"Services discovered: {_list_count(network.get('services'))}",
            f"Network devices: {_list_count(network.get('network_devices'))}",
            f"Management exposures: {_list_count(network.get('management_exposures'))}",
            f"Insecure protocols: {_list_count(network.get('insecure_protocols'))}",
            f"Segmentation observations: {_list_count(network.get('segmentation_observations'))}",
            f"Active modules: {active}",
            f"Skipped/not configured: {skipped}",
            "Findings: C:{critical} H:{high} M:{medium} L:{low} I:{info}".format(**severity),
        ]
        self._print("\n".join(lines), style="white")

    def info(self, message: str) -> None:
        self._print(message, style="cyan")

    def warn(self, message: str) -> None:
        self._print(message, style="yellow")

    def error(self, message: str) -> None:
        self._print(message, style="bold red")

    def success(self, message: str) -> None:
        self._print(message, style="green")

    def print_result(self, result: AssessmentResult) -> None:
        if self.console and Table and Panel:
            table = Table(show_header=False, box=None)
            table.add_column("Key", style="bold bright_cyan")
            table.add_column("Value", style="white")
            table.add_row("Version", result.app_version)
            table.add_row("Package", result.package)
            table.add_row("Session", result.session_id)
            table.add_row("Findings", str(result.findings_count))
            table.add_row("PDF report", str(result.report_pdf))
            table.add_row("CSV action plan", str(result.action_csv))
            table.add_row("JSON findings", str(result.findings_json))
            table.add_row("Encrypted bundle", str(result.encrypted_bundle))
            table.add_row("Callback", result.callback_status)
            for artifact in result.additional_artifacts:
                table.add_row("Additional artifact", str(artifact))
            self.console.print(Panel(table, title="Assessment Output", border_style="bright_green"))
            return
        lines = [
            f"Version: {result.app_version}",
            f"Session: {result.session_id}",
            f"Findings: {result.findings_count}",
            f"PDF report: {result.report_pdf}",
            f"CSV action plan: {result.action_csv}",
            f"JSON findings: {result.findings_json}",
            f"Encrypted bundle: {result.encrypted_bundle}",
            f"Callback: {result.callback_status}",
        ]
        for artifact in result.additional_artifacts:
            lines.append(f"Additional artifact: {artifact}")
        self._print("\n".join(lines), style="white")

    def print_preflight(self, report: PreflightReport, compact: bool = False) -> None:
        if self.console and Table and Panel:
            table = Table(
                title="Preflight Validation" if not compact else "Healthcheck",
                header_style="bold bright_cyan",
            )
            table.add_column("Check")
            table.add_column("Status")
            table.add_column("Detail")
            table.add_row("overall", report.overall_status, "startup validation summary")
            table.add_row("config_path", "ok", str(report.config_path or "defaults"))
            table.add_row("data_dir", "ok", str(report.data_dir))
            table.add_row("log_dir", "ok", str(report.log_dir))
            if not compact:
                for check in report.checks:
                    table.add_row(check.name, check.status, check.detail)
            self.console.print(Panel(table, border_style="bright_cyan"))
            return
        lines = [
            f"Preflight: {report.overall_status}",
            f"Config path: {report.config_path or 'defaults'}",
            f"Data dir: {report.data_dir}",
            f"Log dir: {report.log_dir}",
        ]
        if not compact:
            for check in report.checks:
                lines.append(f"({check.status}) {check.name}: {check.detail}")
        self._print("\n".join(lines), style="white")

    def print_queue(self, items: list[dict[str, object]], title: str = "Callback Queue") -> None:
        if not items:
            self._print(f"{title}: empty", style="white")
            return
        if self.console and Table:
            table = Table(title=title, header_style="bold bright_green")
            table.add_column("Status")
            table.add_column("Delivery")
            table.add_column("Provider")
            table.add_column("Session")
            table.add_column("Attempts")
            table.add_column("Next Attempt")
            table.add_column("Reason")
            for item in items:
                table.add_row(
                    str(item.get("status", "")),
                    str(item.get("delivery_type", "")),
                    str(item.get("provider", "")),
                    str(item.get("session_id", "")),
                    str(item.get("attempts", "")),
                    str(item.get("next_attempt_at", "")),
                    str(item.get("last_error", "")),
                )
            self.console.print(table)
            return
        lines = [title]
        for item in items:
            lines.append(
                f"- {item.get('status')} {item.get('delivery_type')} via {item.get('provider')} "
                f"session={item.get('session_id')} attempts={item.get('attempts')} "
                f"next={item.get('next_attempt_at')} reason={item.get('last_error', '')}"
            )
        self._print("\n".join(lines), style="white")

    def _ask(self, prompt: str, default: str | None = None) -> str:
        if self.console and Prompt:
            value = normalize_prompt_value(Prompt.ask(prompt, default=default))
        else:
            value = normalize_prompt_value(input(f"{prompt}{f' [{default}]' if default else ''}: "))
        return value or normalize_prompt_value(default)

    def _confirm(self, prompt: str, default: bool = False) -> bool:
        if self.console and Confirm:
            value = Confirm.ask(prompt, default=default)
            return default if value is None else bool(value)
        suffix = "Y/n" if default else "y/N"
        while True:
            value = normalize_prompt_value(input(f"{prompt} [{suffix}]: ")).lower()
            if not value:
                return default
            if value in YES_VALUES:
                return True
            if value in NO_VALUES:
                return False
            self.error(f"{prompt} expects yes or no.")

    def _ask_required(self, prompt: str) -> str:
        while True:
            value = self._ask(prompt)
            if value:
                return value
            self.error(f"{prompt} cannot be blank.")

    def _ask_package(self) -> str:
        while True:
            self._print(
                "\nAssessment package:\n"
                "[1] Basic\n"
                "    Local endpoint validation and light network exposure review.\n"
                "    Best for quick workstation/server baseline.\n\n"
                "[2] Standard\n"
                "    Company-level network discovery, exposure assessment, endpoint posture where available, and prioritized remediation roadmap.\n"
                "    Best for normal client assessment.\n\n"
                "[3] Advanced\n"
                "    Standard assessment plus business continuity, ransomware readiness, policy/SOP gaps, recovery priorities, and 30/60/90-day plan.\n"
                "    Best for management-level full assessment.",
                style="bright_cyan",
            )
            package = self._ask("Select package", default="standard").lower()
            mapped = {
                "1": "basic",
                "basic": "basic",
                "2": "standard",
                "standard": "standard",
                "3": "advanced",
                "advanced": "advanced",
            }.get(package, "")
            if mapped:
                return mapped
            self.error("Invalid package selection. Enter 1/basic, 2/standard, or 3/advanced.")

    def _ask_scope(self) -> str:
        while True:
            scope = self._ask("Authorized scope/subnet")
            if not scope:
                self.error("Authorized scope/subnet cannot be blank.")
                continue
            if scope.lower() == "config":
                return scope
            try:
                ScopePolicy.parse(scope)
            except ValueError as exc:
                self.error(str(exc))
                continue
            return scope

    def _ask_host_list(self, prompt: str) -> list[str]:
        while True:
            value = self._ask(prompt, default="")
            entries = _split_csv(value)
            error = _validate_host_list(entries)
            if error:
                self.error(error)
                continue
            return entries

    def _ask_domain_like(self, prompt: str, *, field_name: str, allow_blank: bool) -> str:
        while True:
            value = self._ask(prompt, default="" if allow_blank else None)
            error = _validate_domain_like(value, field_name=field_name, allow_blank=allow_blank)
            if error:
                self.error(error)
                continue
            return value

    def _ask_business_unit(self, prompt: str) -> str:
        while True:
            value = self._ask(prompt, default="")
            error = _validate_business_unit(value)
            if error:
                self.error(error)
                continue
            return value

    def _resolve_host_list(
        self,
        current: list[str],
        *,
        prompt: str,
        prompt_optional: bool,
    ) -> list[str]:
        error = _validate_host_list(current)
        if error and not prompt_optional:
            self.error(error)
            return []
        if error:
            return self._ask_host_list(prompt)
        if current or not prompt_optional:
            return current
        return self._ask_host_list(prompt)

    def _resolve_domain_value(
        self,
        current: str,
        *,
        prompt: str,
        field_name: str,
        prompt_optional: bool,
    ) -> str:
        error = _validate_domain_like(current, field_name=field_name, allow_blank=True)
        if error and not prompt_optional:
            self.error(error)
            return ""
        if error:
            return self._ask_domain_like(prompt, field_name=field_name, allow_blank=True)
        if current or not prompt_optional:
            return current
        return self._ask_domain_like(prompt, field_name=field_name, allow_blank=True)

    def _resolve_business_unit(
        self,
        current: str,
        *,
        prompt: str,
        prompt_optional: bool,
    ) -> str:
        error = _validate_business_unit(current)
        if error and not prompt_optional:
            self.error(error)
            return ""
        if error:
            return self._ask_business_unit(prompt)
        if current or not prompt_optional:
            return current
        return self._ask_business_unit(prompt)

    def _print(self, message: str, style: str = "white") -> None:
        if self.console:
            self.console.print(message, style=style)
        else:
            print(message)


def _split_csv(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = value.replace(";", ",").split(",")
    elif isinstance(value, (list, tuple, set)):
        items = [normalize_prompt_value(item) for item in value]
    else:
        items = normalize_prompt_value(value).replace(";", ",").split(",")
    return [item.strip() for item in items if item.strip()]


def _validate_host_list(entries: list[str]) -> str | None:
    for entry in entries:
        if not _is_valid_host_entry(entry):
            return (
                f"Invalid host entry '{entry}'. Expected IP address, hostname, or FQDN. "
                "Put CIDR ranges in Authorized scope/subnet."
            )
    return None


def _is_valid_host_entry(value: str) -> bool:
    candidate = normalize_prompt_value(value).rstrip(".")
    if not candidate:
        return False
    if candidate.lower() in RESERVED_HOST_TOKENS:
        return False
    if candidate.lower() in {"localhost", *LOCAL_ONLY_MARKERS}:
        return True
    if "/" in candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return _is_hostname(candidate)


def _validate_domain_like(value: str, *, field_name: str, allow_blank: bool) -> str | None:
    candidate = normalize_prompt_value(value)
    if not candidate:
        return None if allow_blank else f"{field_name} cannot be blank."
    if _is_hostname(candidate):
        return None
    return f"{field_name} must be a domain name like example.com or corp.local."


def _validate_business_unit(value: str) -> str | None:
    candidate = normalize_prompt_value(value)
    if "\x00" in candidate:
        return "Business unit contains invalid control characters."
    return None


def _is_hostname(value: str) -> bool:
    candidate = normalize_prompt_value(value).rstrip(".")
    if not candidate or ".." in candidate or len(candidate) > 253:
        return False
    labels = candidate.split(".")
    return all(DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels)


def _blank_intake() -> AssessmentIntake:
    return AssessmentIntake(
        client_name="",
        site="",
        operator_name="",
        package="",
        authorized_scope="",
        scope_notes="",
        consent_confirmed=False,
        domain=None,
        m365_connector=False,
        host_allowlist=[],
        host_denylist=[],
        ad_domain=None,
        business_unit="",
        scope_labels={},
        scanner_sources=[],
        cloud_tenants=[],
    )


def _normalize_intake_seed(seed: AssessmentIntake) -> AssessmentIntake:
    return AssessmentIntake(
        client_name=normalize_prompt_value(seed.client_name),
        site=normalize_prompt_value(seed.site),
        operator_name=normalize_prompt_value(seed.operator_name),
        package=normalize_prompt_value(seed.package).lower(),
        authorized_scope=normalize_prompt_value(seed.authorized_scope),
        scope_notes=normalize_prompt_value(seed.scope_notes),
        consent_confirmed=bool(seed.consent_confirmed),
        domain=normalize_prompt_value(seed.domain) or None,
        m365_connector=bool(seed.m365_connector),
        host_allowlist=_split_csv(seed.host_allowlist),
        host_denylist=_split_csv(seed.host_denylist),
        ad_domain=normalize_prompt_value(seed.ad_domain) or None,
        business_unit=normalize_prompt_value(seed.business_unit),
        scope_labels=dict(seed.scope_labels),
        scanner_sources=[normalize_prompt_value(item) for item in seed.scanner_sources if normalize_prompt_value(item)],
        cloud_tenants=[normalize_prompt_value(item) for item in seed.cloud_tenants if normalize_prompt_value(item)],
    )


def _validated_package(value: str) -> str:
    package = normalize_prompt_value(value).lower()
    return package if package in VALID_PACKAGES else ""


def _validated_scope(value: str) -> str:
    scope = normalize_prompt_value(value)
    if not scope:
        return ""
    if scope.lower() == "config":
        return scope
    try:
        ScopePolicy.parse(scope)
    except ValueError:
        return ""
    return scope


def _safe_host_list(values: list[str], *, ui: ConsoleUi) -> list[str]:
    error = _validate_host_list(values)
    if error:
        ui.error(error)
        return []
    return values


def _safe_domain(value: str, *, field_name: str, ui: ConsoleUi) -> str:
    error = _validate_domain_like(value, field_name=field_name, allow_blank=True)
    if error:
        ui.error(error)
        return ""
    return value


def _safe_business_unit(value: str, *, ui: ConsoleUi) -> str:
    error = _validate_business_unit(value)
    if error:
        ui.error(error)
        return ""
    return value


def _auto_scope_lines(context: dict[str, object]) -> list[str]:
    diagnostics = context.get("adapter_diagnostics", [])
    if not isinstance(diagnostics, list) or not diagnostics:
        return []
    lines = ["Auto-scope adapter decisions:"]
    for item in diagnostics[:12]:
        if not isinstance(item, dict):
            continue
        lines.append(
            "- {name} {ip}/{prefix} -> {subnet}: {decision} ({reason})".format(
                name=item.get("name", ""),
                ip=item.get("ip_address", ""),
                prefix=item.get("prefix_length", ""),
                subnet=item.get("subnet", ""),
                decision=item.get("decision", ""),
                reason=f"{item.get('reason', '')}; confidence={item.get('confidence_score', '')}",
            )
        )
    return lines


def _mode_for_package(package: str) -> str:
    if package == "basic":
        return "Basic local"
    if package == "advanced":
        return "Advanced company-level"
    return "Standard company-level"


def _list_count(value: object) -> int:
    return len(value) if isinstance(value, list) else 0
