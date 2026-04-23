"""Rich-based terminal UI with safe fallback."""

from __future__ import annotations

from app.core.preflight import PreflightReport
from app.core.models import AssessmentResult
from app.core.session import AssessmentIntake

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
except ImportError:  # pragma: no cover - fallback for minimal environments.
    Console = None
    Panel = None
    Confirm = None
    Prompt = None


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


class ConsoleUi:
    """Terminal-style operator interface."""

    def __init__(self, app_version: str = "unknown") -> None:
        self.app_version = app_version
        self.console = Console() if Console else None

    def banner(self) -> None:
        text = (
            f"Soun Al Hosn Assessment Runner v{self.app_version}\n"
            "Read-only local assessment. No stealth. No exploitation. No auto-remediation."
        )
        if self.console and Panel:
            self.console.print(HEADER_ART, style="bold cyan", overflow="ignore", crop=False)
            self.console.print(Panel(text, title="Authorized Use Only"))
        else:
            print(HEADER_ART)
            print(text)

    def collect_intake(self) -> AssessmentIntake:
        client = self._ask("Client/entity name")
        site = self._ask("Site/branch")
        operator = self._ask("Operator name")
        package = self._ask("Assessment package [basic/standard/advanced]", default="basic").lower()
        scope = self._ask("Authorized scope/subnet")
        allowlist = self._ask("Optional host allowlist (comma-separated IP/FQDN)", default="")
        denylist = self._ask("Optional host denylist (comma-separated IP/FQDN)", default="")
        ad_domain = self._ask("Optional AD domain", default="")
        business_unit = self._ask("Optional business unit label", default="")
        notes = self._ask("Scope notes", default="No additional notes.")
        domain = self._ask("Optional email domain for SPF/DKIM/DMARC", default="")
        m365 = self._confirm("M365/Entra connector available?", default=False)
        consent = self._confirm(
            "Confirm written authorization and approved scope are present",
            default=False,
        )
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
            host_allowlist=_split_csv(allowlist),
            host_denylist=_split_csv(denylist),
            ad_domain=ad_domain or None,
            business_unit=business_unit,
        )

    def info(self, message: str) -> None:
        self._print(message, style="cyan")

    def warn(self, message: str) -> None:
        self._print(message, style="yellow")

    def error(self, message: str) -> None:
        self._print(message, style="bold red")

    def success(self, message: str) -> None:
        self._print(message, style="green")

    def print_result(self, result: AssessmentResult) -> None:
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
            return Prompt.ask(prompt, default=default)
        value = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
        return value or (default or "")

    def _confirm(self, prompt: str, default: bool = False) -> bool:
        if self.console and Confirm:
            return Confirm.ask(prompt, default=default)
        suffix = "Y/n" if default else "y/N"
        value = input(f"{prompt} [{suffix}]: ").strip().lower()
        if not value:
            return default
        return value in {"y", "yes", "true", "1"}

    def _print(self, message: str, style: str = "white") -> None:
        if self.console:
            self.console.print(message, style=style)
        else:
            print(message)


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]
