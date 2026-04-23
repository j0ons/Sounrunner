"""Rich-based terminal UI with safe fallback."""

from __future__ import annotations

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
            self.console.print(Panel(text, title="Authorized Use Only"))
        else:
            print(text)

    def collect_intake(self) -> AssessmentIntake:
        client = self._ask("Client/entity name")
        site = self._ask("Site/branch")
        operator = self._ask("Operator name")
        package = self._ask("Assessment package [basic/standard/advanced]", default="basic").lower()
        scope = self._ask("Authorized scope/subnet")
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
        ]
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
