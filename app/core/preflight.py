"""Startup dependency validation and operator preflight checks."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.core.config import AppConfig
from app.collectors.shell import run_command
from app.collectors.windows import detect_windows_admin, is_windows, powershell_available, run_powershell
from app.core.secrets import has_plaintext_secret_config, resolve_secret


@dataclass(slots=True)
class PreflightCheck:
    """One startup validation result."""

    name: str
    status: str
    detail: str
    fatal: bool = False


@dataclass(slots=True)
class PreflightReport:
    """Operator-facing preflight status summary."""

    executed_at_utc: str
    overall_status: str
    checks: list[PreflightCheck]
    config_loaded: bool
    config_path: str
    data_dir: str
    log_dir: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "executed_at_utc": self.executed_at_utc,
            "overall_status": self.overall_status,
            "config_loaded": self.config_loaded,
            "config_path": self.config_path,
            "data_dir": self.data_dir,
            "log_dir": self.log_dir,
            "checks": [asdict(check) for check in self.checks],
        }


def run_preflight(
    *,
    config_path: Path | None,
    data_dir: Path | None,
    log_dir: Path | None,
) -> tuple[AppConfig | None, PreflightReport]:
    """Validate runtime dependencies without modifying assessment targets."""

    checks: list[PreflightCheck] = []
    checks.append(_runtime_check())
    config, config_check = _load_config_check(config_path, data_dir, log_dir)
    checks.append(config_check)

    effective_data_dir = (
        data_dir
        or (config.workspace_root if config else Path(".soun_runner_workspace"))
    )
    effective_log_dir = (
        log_dir
        or (config.log_root if config and config.log_root else effective_data_dir / "logs")
    )
    checks.append(_write_access_check("data_directory", effective_data_dir))
    checks.append(_write_access_check("log_directory", effective_log_dir))
    checks.append(_powershell_check())
    checks.append(_admin_context_check())
    checks.append(_nmap_check(config))
    checks.append(_secret_sources_check(config))
    checks.extend(_remote_windows_checks(config))
    checks.append(_estate_readiness_check(config))
    checks.append(_callback_check(config))
    checks.append(_scope_defaults_check(config))

    overall_status = _overall_status(checks)
    report = PreflightReport(
        executed_at_utc=_utc_now(),
        overall_status=overall_status,
        checks=checks,
        config_loaded=config is not None,
        config_path=str(config_path) if config_path else "",
        data_dir=str(effective_data_dir),
        log_dir=str(effective_log_dir),
    )
    return config, report


def preflight_exit_code(report: PreflightReport) -> int:
    """Return non-zero only for fatal preflight failures."""

    return 1 if any(check.fatal and check.status == "failed" for check in report.checks) else 0


def _runtime_check() -> PreflightCheck:
    runtime = "PyInstaller EXE" if getattr(sys, "frozen", False) else "Python interpreter"
    detail = (
        f"{runtime} on {platform.system()} {platform.release()} using Python {platform.python_version()}."
    )
    return PreflightCheck(name="runtime", status="ok", detail=detail)


def _load_config_check(
    config_path: Path | None,
    data_dir: Path | None,
    log_dir: Path | None,
) -> tuple[AppConfig | None, PreflightCheck]:
    if config_path and not config_path.exists():
        return None, PreflightCheck(
            name="config",
            status="failed",
            detail=f"Config file not found: {config_path}",
            fatal=True,
        )
    try:
        config = AppConfig.load(config_path, data_dir=data_dir, log_dir=log_dir)
    except Exception as exc:  # noqa: BLE001 - preflight must surface exact failure.
        return None, PreflightCheck(
            name="config",
            status="failed",
            detail=f"Config load failed: {exc}",
            fatal=True,
        )
    source = str(config_path) if config_path else "defaults"
    return config, PreflightCheck(
        name="config",
        status="ok",
        detail=f"Config loaded successfully from {source}.",
    )


def _write_access_check(name: str, path: Path) -> PreflightCheck:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".soun_runner_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return PreflightCheck(
            name=name,
            status="failed",
            detail=f"Write access failed for {path}: {exc}",
            fatal=True,
        )
    return PreflightCheck(name=name, status="ok", detail=f"Writable: {path}")


def _powershell_check() -> PreflightCheck:
    if not is_windows():
        return PreflightCheck(
            name="powershell",
            status="skipped",
            detail="PowerShell validation skipped on non-Windows host.",
        )
    if not powershell_available():
        return PreflightCheck(
            name="powershell",
            status="warning",
            detail="PowerShell was not found. Windows-native collectors will degrade to partial/skipped.",
        )
    result = run_powershell("$PSVersionTable.PSVersion.ToString()", timeout_seconds=15)
    if result.returncode != 0:
        return PreflightCheck(
            name="powershell",
            status="warning",
            detail=f"PowerShell is present but execution failed: {result.stderr or result.stdout}",
        )
    policy = run_powershell("Get-ExecutionPolicy -Scope Process", timeout_seconds=15)
    suffix = f" Process execution policy: {policy.stdout}." if policy.returncode == 0 else ""
    return PreflightCheck(
        name="powershell",
        status="ok",
        detail=f"PowerShell available. Version: {result.stdout.strip()}.{suffix}",
    )


def _admin_context_check() -> PreflightCheck:
    if is_windows():
        is_admin = detect_windows_admin()
        detail = "Running with administrative privileges." if is_admin else (
            "Running without administrative privileges. Some collectors may return partial evidence."
        )
        return PreflightCheck(
            name="admin_context",
            status="ok" if is_admin else "warning",
            detail=detail,
        )
    uid = getattr(os, "geteuid", lambda: -1)()
    return PreflightCheck(
        name="admin_context",
        status="skipped",
        detail=f"Admin-context check is Windows-focused. Current effective UID: {uid}.",
    )


def _nmap_check(config: AppConfig | None) -> PreflightCheck:
    if not config or not config.nmap.enabled:
        return PreflightCheck(
            name="nmap",
            status="skipped",
            detail="Nmap is disabled in config.",
        )
    resolved = shutil.which(config.nmap.path)
    if not resolved:
        return PreflightCheck(
            name="nmap",
            status="warning",
            detail=(
                f"Nmap executable '{config.nmap.path}' was not found. "
                "Network discovery modules will be skipped or partial."
            ),
        )
    version = run_command([resolved, "--version"], timeout_seconds=20)
    first_line = version.stdout.splitlines()[0] if version.stdout else resolved
    return PreflightCheck(
        name="nmap",
        status="ok",
        detail=f"Nmap available: {first_line}",
    )


def _callback_check(config: AppConfig | None) -> PreflightCheck:
    if not config or not config.callback.enabled:
        return PreflightCheck(
            name="callback",
            status="skipped",
            detail="Callback pipeline not enabled.",
        )

    messages: list[str] = []
    warnings: list[str] = []
    providers = 0

    if config.callback.send_smtp_summary or config.smtp_enabled:
        providers += 1
        smtp_secret = resolve_secret(
            env_name=config.smtp.password_env,
            file_path=config.smtp.password_file,
            direct_value=config.smtp.password,
            description="SMTP password",
            allow_plaintext=True,
        )
        if config.smtp.is_complete and (not config.smtp.username or smtp_secret.present):
            messages.append("SMTP summary configured.")
        else:
            warnings.append("SMTP summary enabled but SMTP settings are incomplete.")

    if config.callback.upload_bundle:
        if config.callback.https.enabled:
            providers += 1
            if config.callback.https.url:
                messages.append("HTTPS bundle upload configured.")
            else:
                warnings.append("HTTPS upload enabled but URL is empty.")
        if config.callback.s3.enabled:
            providers += 1
            access_key = resolve_secret(
                env_name=config.callback.s3.access_key_env,
                file_path=config.callback.s3.access_key_file,
                description="S3 access key",
            )
            secret_key = resolve_secret(
                env_name=config.callback.s3.secret_key_env,
                file_path=config.callback.s3.secret_key_file,
                description="S3 secret key",
            )
            if config.callback.s3.bucket and access_key.present and secret_key.present:
                messages.append("S3 bundle upload configured.")
            else:
                warnings.append("S3 upload enabled but bucket or credential environment variables are missing.")
        if config.callback.sftp.enabled:
            providers += 1
            password = resolve_secret(
                env_name=config.callback.sftp.password_env,
                file_path=config.callback.sftp.password_file,
                description="SFTP password",
            )
            if (
                config.callback.sftp.host
                and config.callback.sftp.username
                and password.present
            ):
                messages.append("SFTP bundle upload configured.")
            else:
                warnings.append("SFTP upload enabled but host, username, or password environment variable is missing.")

    if providers == 0:
        return PreflightCheck(
            name="callback",
            status="warning",
            detail="Callback enabled but no callback provider is configured.",
        )
    if warnings:
        return PreflightCheck(
            name="callback",
            status="warning",
            detail=" ".join([*messages, *warnings]).strip(),
        )
    return PreflightCheck(
        name="callback",
        status="ok",
        detail=" ".join(messages),
    )


def _scope_defaults_check(config: AppConfig | None) -> PreflightCheck:
    scopes = _configured_scopes(config)
    if not config or not scopes:
        return PreflightCheck(
            name="scope_defaults",
            status="skipped",
            detail="No approved scope default is configured. Operator intake must provide scope.",
        )
    return PreflightCheck(
        name="scope_defaults",
        status="ok",
        detail=f"Default approved scopes present: {', '.join(scopes)}",
    )


def _estate_readiness_check(config: AppConfig | None) -> PreflightCheck:
    if not config:
        return PreflightCheck(
            name="estate_readiness",
            status="skipped",
            detail="Config unavailable. Estate readiness could not be evaluated.",
        )
    scopes = _configured_scopes(config)
    connectors = []
    if config.remote_windows.enabled:
        connectors.append("remote_windows")
    if config.active_directory.enabled:
        connectors.append("active_directory")
    if config.firewall_vpn_import.enabled and config.firewall_vpn_import.import_paths:
        connectors.append("firewall_vpn_import")
    if config.backup_platform_import.enabled and config.backup_platform_import.import_paths:
        connectors.append("backup_platform_import")
    if config.scanner_integrations.nessus_import_path or config.scanner_integrations.greenbone_import_path:
        connectors.append("scanner_file_import")
    if config.scanner_integrations.nessus_api.enabled or config.scanner_integrations.greenbone_api.enabled:
        connectors.append("scanner_api")
    if config.m365_entra.enabled or config.m365_entra.evidence_json_path:
        connectors.append("m365_entra")
    if not scopes:
        return PreflightCheck(
            name="estate_readiness",
            status="warning",
            detail="No approved scopes are configured. Standard/Advanced cannot run headless without an approved scope.",
        )
    if not connectors:
        return PreflightCheck(
            name="estate_readiness",
            status="warning",
            detail=(
                f"Approved scopes present ({', '.join(scopes)}), but no estate connector is configured. "
                "Standard/Advanced coverage will be discovery-heavy or local-only."
            ),
        )
    return PreflightCheck(
        name="estate_readiness",
        status="ok",
        detail=(
            f"Approved scopes present ({', '.join(scopes)}). "
            f"Estate connectors configured: {', '.join(connectors)}."
        ),
    )


def _secret_sources_check(config: AppConfig | None) -> PreflightCheck:
    if not config:
        return PreflightCheck(name="secret_sources", status="skipped", detail="Config unavailable.")
    warnings: list[str] = []
    messages: list[str] = []

    if has_plaintext_secret_config(config.smtp.password):
        warnings.append("SMTP password is set inline in config. Prefer env var or secret file reference.")
    if config.remote_windows.enabled:
        secret = resolve_secret(
            env_name=config.remote_windows.password_env,
            file_path=config.remote_windows.password_file,
            description="Remote Windows password",
        )
        if config.remote_windows.username and secret.present:
            messages.append("Remote Windows secret reference resolved.")
        elif config.remote_windows.username:
            warnings.append(secret.detail)
    if config.m365_entra.enabled:
        secret = resolve_secret(
            env_name=config.m365_entra.client_secret_env,
            file_path=config.m365_entra.client_secret_file,
            description="M365 client secret",
        )
        if secret.present:
            messages.append("M365 client secret reference resolved.")
        else:
            warnings.append(secret.detail)
    if config.scanner_integrations.nessus_api.enabled:
        access = resolve_secret(
            env_name=config.scanner_integrations.nessus_api.access_key_env,
            file_path=config.scanner_integrations.nessus_api.access_key_file,
            description="Nessus access key",
        )
        secret = resolve_secret(
            env_name=config.scanner_integrations.nessus_api.secret_key_env,
            file_path=config.scanner_integrations.nessus_api.secret_key_file,
            description="Nessus secret key",
        )
        if access.present and secret.present:
            messages.append("Nessus API secret references resolved.")
        else:
            warnings.append("Nessus API secret references are incomplete.")
    if config.scanner_integrations.greenbone_api.enabled:
        secret = resolve_secret(
            env_name=config.scanner_integrations.greenbone_api.password_env,
            file_path=config.scanner_integrations.greenbone_api.password_file,
            description="Greenbone password",
        )
        if secret.present:
            messages.append("Greenbone API secret reference resolved.")
        else:
            warnings.append(secret.detail)

    if warnings:
        return PreflightCheck(
            name="secret_sources",
            status="warning",
            detail=" ".join([*messages, *warnings]).strip(),
        )
    return PreflightCheck(
        name="secret_sources",
        status="ok" if messages else "skipped",
        detail=" ".join(messages) if messages else "No secret-backed connectors enabled.",
    )


def _remote_windows_checks(config: AppConfig | None) -> list[PreflightCheck]:
    if not config or not config.remote_windows.enabled:
        return [
            PreflightCheck(
                name="remote_windows",
                status="skipped",
                detail="Remote Windows collection not enabled.",
            )
        ]
    if not is_windows():
        return [
            PreflightCheck(
                name="remote_windows",
                status="warning",
                detail="Remote Windows collection is configured but the runner is not executing on Windows.",
            )
        ]
    checks = [
        PreflightCheck(
            name="remote_windows",
            status="ok",
            detail=(
                f"Remote Windows collection configured for WinRM on port {config.remote_windows.port} "
                f"auth={config.remote_windows.auth} ssl={config.remote_windows.use_ssl}."
            ),
        )
    ]
    checks.extend(_remote_windows_sample_checks(config))
    return checks


def _remote_windows_sample_checks(config: AppConfig) -> list[PreflightCheck]:
    if not config.field_validation.enable_winrm_sample_checks:
        return [
            PreflightCheck(
                name="remote_windows_samples",
                status="skipped",
                detail="WinRM sample connectivity checks disabled in field_validation config.",
            )
        ]
    targets = list(config.field_validation.winrm_sample_targets or config.assessment.host_allowlist)
    if not targets:
        return [
            PreflightCheck(
                name="remote_windows_samples",
                status="skipped",
                detail="No WinRM sample targets configured. Add field_validation.winrm_sample_targets or host_allowlist.",
            )
        ]
    checks: list[PreflightCheck] = []
    for target in targets[: config.field_validation.max_samples]:
        result = run_powershell(
            (
                f"try {{ Test-WSMan -ComputerName '{target}' -ErrorAction Stop | Out-String }} "
                "catch { $_.Exception.Message }"
            ),
            timeout_seconds=min(20, config.remote_windows.connection_timeout_seconds + 10),
        )
        output = " ".join([result.stdout, result.stderr]).strip()
        status, hint = _winrm_sample_status(output)
        checks.append(
            PreflightCheck(
                name=f"remote_windows_sample:{target}",
                status=status,
                detail=hint,
            )
        )
    return checks


def _overall_status(checks: list[PreflightCheck]) -> str:
    if any(check.fatal and check.status == "failed" for check in checks):
        return "failed"
    if any(check.status == "warning" for check in checks):
        return "degraded"
    return "ready"


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _configured_scopes(config: AppConfig | None) -> list[str]:
    if not config:
        return []
    if config.assessment.approved_scopes:
        return list(config.assessment.approved_scopes)
    if config.assessment.approved_scope:
        return [config.assessment.approved_scope]
    return []


def _winrm_sample_status(output: str) -> tuple[str, str]:
    lowered = output.lower()
    if not output:
        return "warning", "No response from WinRM sample check."
    if "wsmid" in lowered or "protocolversion" in lowered:
        return "ok", "WinRM sample target responded."
    if "access is denied" in lowered:
        return "warning", "WinRM reachable but access denied. Confirm approved credentials and host authorization."
    if "the client cannot connect" in lowered or "firewall exception" in lowered:
        return "warning", "WinRM connection failed. Likely service unavailable or firewall blocked."
    if "cannot resolve the server name" in lowered or "name was not resolved" in lowered:
        return "warning", "WinRM target name could not be resolved. Check DNS or host naming."
    if "timed out" in lowered:
        return "warning", "WinRM sample check timed out. Check routing, firewall, or host availability."
    return "warning", f"WinRM sample check returned: {output[:180]}"
