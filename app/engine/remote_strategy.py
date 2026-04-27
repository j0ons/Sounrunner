"""Remote collection strategy planning for company-wide assessment runs."""

from __future__ import annotations

import copy
import getpass
from dataclasses import asdict, dataclass

from app.collectors.windows import is_windows, powershell_available
from app.core.config import AppConfig, RemoteWindowsConfig
from app.core.session import AssessmentSession


@dataclass(slots=True)
class RemoteCollectionStrategy:
    """Run-level remote collection strategy without exposing secrets."""

    mode: str
    enabled: bool
    auth: str
    port: int
    use_ssl: bool
    reason: str
    operator_name: str
    domain_joined: bool
    domain_name: str
    configured_username: bool = False
    secret_reference_configured: bool = False
    current_user_context: bool = False
    require_winrm_port_observed: bool = True
    max_auto_attempts: int = 50

    def to_metadata(self) -> dict[str, object]:
        """Return a sanitized metadata payload suitable for reports and logs."""

        payload = asdict(self)
        payload["operator_name"] = self.operator_name
        return payload


def plan_remote_collection_strategy(
    *,
    session: AssessmentSession,
    config: AppConfig,
) -> RemoteCollectionStrategy:
    """Select the safest available remote Windows collection strategy."""

    auto_context = session.database.get_metadata("auto_context", {})
    domain_joined = _domain_joined(auto_context)
    domain_name = _domain_name(auto_context, session, config)
    operator = str(auto_context.get("operator_name", "")) if isinstance(auto_context, dict) else ""
    operator = operator or getpass.getuser()
    windows_runtime = is_windows()
    powershell_ready = powershell_available()
    secret_ref = bool(config.remote_windows.password_env or config.remote_windows.password_file)

    if config.remote_windows.enabled and config.remote_windows.username and secret_ref:
        return RemoteCollectionStrategy(
            mode="configured_credentials",
            enabled=True,
            auth=config.remote_windows.auth,
            port=config.remote_windows.port,
            use_ssl=config.remote_windows.use_ssl,
            reason="remote_windows.enabled with configured username and secret reference.",
            operator_name=operator,
            domain_joined=domain_joined,
            domain_name=domain_name,
            configured_username=True,
            secret_reference_configured=secret_ref,
            current_user_context=False,
            require_winrm_port_observed=config.remote_windows.require_winrm_port_observed,
            max_auto_attempts=config.remote_windows.max_auto_attempts,
        )

    if config.remote_windows.enabled and not config.remote_windows.username:
        return RemoteCollectionStrategy(
            mode="current_user_integrated_auth",
            enabled=True,
            auth=_current_user_auth(config.remote_windows),
            port=config.remote_windows.port,
            use_ssl=config.remote_windows.use_ssl,
            reason="remote_windows.enabled without explicit credentials; using current Windows security context.",
            operator_name=operator,
            domain_joined=domain_joined,
            domain_name=domain_name,
            current_user_context=True,
            require_winrm_port_observed=config.remote_windows.require_winrm_port_observed,
            max_auto_attempts=config.remote_windows.max_auto_attempts,
        )

    if (
        config.remote_windows.auto_current_user
        and config.remote_windows.attempt_current_user_when_domain_joined
        and windows_runtime
        and powershell_ready
        and (domain_joined or domain_name)
    ):
        return RemoteCollectionStrategy(
            mode="current_user_integrated_auth",
            enabled=True,
            auth=_current_user_auth(config.remote_windows),
            port=config.remote_windows.port,
            use_ssl=config.remote_windows.use_ssl,
            reason="Domain context detected; current-user WinRM collection is eligible without stored credentials.",
            operator_name=operator,
            domain_joined=domain_joined,
            domain_name=domain_name,
            current_user_context=True,
            require_winrm_port_observed=config.remote_windows.require_winrm_port_observed,
            max_auto_attempts=config.remote_windows.max_auto_attempts,
        )

    blocker = "No configured credentials or current-user domain auth context is available."
    if not windows_runtime:
        blocker = "Current-user WinRM collection requires the runner to execute on Windows."
    elif not powershell_ready:
        blocker = "PowerShell is unavailable, so WinRM collection cannot run."
    elif not (domain_joined or domain_name):
        blocker = "No domain context was detected for current-user integrated WinRM."
    return RemoteCollectionStrategy(
        mode="discovery_only_fallback",
        enabled=False,
        auth=config.remote_windows.auth,
        port=config.remote_windows.port,
        use_ssl=config.remote_windows.use_ssl,
        reason=blocker,
        operator_name=operator,
        domain_joined=domain_joined,
        domain_name=domain_name,
        configured_username=bool(config.remote_windows.username),
        secret_reference_configured=secret_ref,
        current_user_context=False,
        require_winrm_port_observed=config.remote_windows.require_winrm_port_observed,
        max_auto_attempts=config.remote_windows.max_auto_attempts,
    )


def effective_remote_windows_config(
    config: RemoteWindowsConfig,
    strategy: RemoteCollectionStrategy,
) -> RemoteWindowsConfig:
    """Build an effective collector config for the selected strategy."""

    effective = copy.copy(config)
    effective.enabled = strategy.enabled
    effective.auth = strategy.auth
    effective.port = strategy.port
    effective.use_ssl = strategy.use_ssl
    if strategy.mode == "current_user_integrated_auth":
        effective.username = ""
        effective.password_file = ""
    return effective


def _domain_joined(auto_context: object) -> bool:
    if isinstance(auto_context, dict):
        return bool(auto_context.get("domain_joined"))
    return False


def _domain_name(
    auto_context: object,
    session: AssessmentSession,
    config: AppConfig,
) -> str:
    if isinstance(auto_context, dict):
        value = str(auto_context.get("ad_domain") or auto_context.get("domain_name") or "").strip()
        if value:
            return value
    return (config.active_directory.domain or session.intake.ad_domain or "").strip()


def _current_user_auth(config: RemoteWindowsConfig) -> str:
    if config.auth in {"kerberos", "negotiate"}:
        return config.auth
    return "negotiate"
