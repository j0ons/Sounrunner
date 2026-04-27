"""Configuration loading for the assessment runner."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class SmtpConfig:
    """Optional SMTP settings for sanitized summary email."""

    host: str = ""
    port: int = 587
    username: str = ""
    password_env: str = "SOUN_RUNNER_SMTP_PASSWORD"
    password_file: str = ""
    password: str = ""
    sender: str = ""
    recipient: str = ""

    @property
    def is_complete(self) -> bool:
        return bool(self.host and self.sender and self.recipient)


@dataclass(slots=True)
class EmailSecurityConfig:
    """Email security check settings."""

    dkim_selectors: list[str] = field(default_factory=list)
    dns_timeout_seconds: int = 10


@dataclass(slots=True)
class NmapConfig:
    """Safe Nmap execution settings."""

    enabled: bool = True
    path: str = "nmap"
    profile: str = "top-ports"
    service_version_detection: bool = False
    timeout_seconds: int = 180
    top_ports: int = 100


@dataclass(slots=True)
class StandardConfig:
    """Standard package settings."""

    enabled: bool = True
    backup_process_prompt_enabled: bool = True
    ransomware_score_warn_threshold: int = 70
    privileged_access_prompt_enabled: bool = True
    incident_prompt_enabled: bool = True
    extended_nmap_top_ports: int = 200
    import_scanner_results: bool = True


@dataclass(slots=True)
class AdvancedConfig:
    """Advanced guided assessment settings."""

    enabled: bool = True
    questionnaire_enabled: bool = True
    generate_30_60_90_plan: bool = True


@dataclass(slots=True)
class CallbackS3Config:
    """S3-compatible encrypted bundle upload settings."""

    enabled: bool = False
    endpoint_url: str = ""
    bucket: str = ""
    key_prefix: str = "soun-runner"
    access_key_env: str = "SOUN_RUNNER_S3_ACCESS_KEY"
    access_key_file: str = ""
    secret_key_env: str = "SOUN_RUNNER_S3_SECRET_KEY"
    secret_key_file: str = ""
    region_name: str = "us-east-1"


@dataclass(slots=True)
class CallbackSftpConfig:
    """SFTP encrypted bundle upload settings."""

    enabled: bool = False
    host: str = ""
    port: int = 22
    username: str = ""
    password_env: str = "SOUN_RUNNER_SFTP_PASSWORD"
    password_file: str = ""
    remote_dir: str = "/"


@dataclass(slots=True)
class CallbackHttpsConfig:
    """HTTPS POST encrypted bundle upload settings."""

    enabled: bool = False
    url: str = ""
    token_env: str = "SOUN_RUNNER_HTTPS_TOKEN"
    token_file: str = ""
    timeout_seconds: int = 30


@dataclass(slots=True)
class CallbackConfig:
    """Failure-safe callback settings."""

    enabled: bool = False
    queue_dir: str = ""
    send_smtp_summary: bool = False
    upload_bundle: bool = False
    max_retry_attempts: int = 3
    base_retry_delay_seconds: int = 60
    max_retry_delay_seconds: int = 3600
    s3: CallbackS3Config = field(default_factory=CallbackS3Config)
    sftp: CallbackSftpConfig = field(default_factory=CallbackSftpConfig)
    https: CallbackHttpsConfig = field(default_factory=CallbackHttpsConfig)


@dataclass(slots=True)
class M365EntraConfig:
    """Safe M365/Entra evidence settings."""

    enabled: bool = False
    tenant_id: str = ""
    client_id: str = ""
    client_secret_env: str = "SOUN_RUNNER_M365_CLIENT_SECRET"
    client_secret_file: str = ""
    authority_host: str = "login.microsoftonline.com"
    graph_base_url: str = "https://graph.microsoft.com"
    timeout_seconds: int = 30
    user_registration_limit: int = 50
    legacy_sign_in_lookback_days: int = 14
    evidence_json_path: str = ""


@dataclass(slots=True)
class NessusApiConfig:
    """Read-only Nessus/Tenable export settings."""

    enabled: bool = False
    base_url: str = ""
    access_key_env: str = "SOUN_RUNNER_NESSUS_ACCESS_KEY"
    access_key_file: str = ""
    secret_key_env: str = "SOUN_RUNNER_NESSUS_SECRET_KEY"
    secret_key_file: str = ""
    scan_id: str = ""
    history_id: str = ""
    export_format: str = "nessus"
    timeout_seconds: int = 60
    verify_tls: bool = True


@dataclass(slots=True)
class GreenboneApiConfig:
    """Read-only Greenbone API settings."""

    enabled: bool = False
    host: str = ""
    port: int = 9390
    username: str = ""
    password_env: str = "SOUN_RUNNER_GREENBONE_PASSWORD"
    password_file: str = ""
    connection_type: str = "tls"
    task_id: str = ""
    report_id: str = ""
    timeout_seconds: int = 60
    verify_tls: bool = True


@dataclass(slots=True)
class AssessmentDefaults:
    """Optional defaults operators may set in external config."""

    client_name: str = ""
    site: str = ""
    operator_name: str = ""
    package: str = ""
    consent_confirmed: bool = False
    approved_scope: str = ""
    approved_scopes: list[str] = field(default_factory=list)
    host_allowlist: list[str] = field(default_factory=list)
    host_denylist: list[str] = field(default_factory=list)
    ad_domain: str = ""
    business_unit: str = ""
    scope_notes: str = "No additional notes."
    scope_labels: dict[str, str] = field(default_factory=dict)
    cloud_tenants: list[str] = field(default_factory=list)
    scanner_sources: list[str] = field(default_factory=list)
    client_domain: str = ""
    auto_scope_allowed_adapter_keywords: list[str] = field(default_factory=list)


@dataclass(slots=True)
class OrchestrationConfig:
    """Company-wide collection orchestration settings."""

    enabled: bool = True
    max_workers: int = 5
    per_host_timeout_seconds: int = 90
    retry_count: int = 1
    ad_computer_timeout_seconds: int = 120


@dataclass(slots=True)
class RemoteWindowsConfig:
    """Read-only remote Windows collection settings."""

    enabled: bool = False
    auto_current_user: bool = True
    attempt_current_user_when_domain_joined: bool = True
    require_winrm_port_observed: bool = True
    max_auto_attempts: int = 50
    transport: str = "winrm"
    username: str = ""
    password_env: str = "SOUN_RUNNER_REMOTE_WINDOWS_PASSWORD"
    password_file: str = ""
    auth: str = "default"
    use_ssl: bool = False
    port: int = 5985
    connection_timeout_seconds: int = 30
    operation_timeout_seconds: int = 60
    require_discovery_match: bool = True


@dataclass(slots=True)
class ActiveDirectoryConfig:
    """Read-only Active Directory evidence settings."""

    enabled: bool = False
    domain: str = ""
    computer_limit: int = 1000
    user_limit: int = 500
    stale_account_days: int = 90
    include_ou_mapping: bool = True
    query_timeout_seconds: int = 90
    privileged_groups: list[str] = field(
        default_factory=lambda: [
            "Domain Admins",
            "Enterprise Admins",
            "Administrators",
        ]
    )


@dataclass(slots=True)
class AssetClassificationConfig:
    """Operator overrides and criticality defaults for inventory classification."""

    critical_assets: list[str] = field(default_factory=list)
    criticality_by_asset: dict[str, str] = field(default_factory=dict)
    criticality_by_subnet: dict[str, str] = field(default_factory=dict)
    criticality_by_site: dict[str, str] = field(default_factory=dict)
    role_overrides: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class FirewallVpnImportConfig:
    """Imported firewall/VPN evidence settings."""

    enabled: bool = False
    import_paths: list[str] = field(default_factory=list)


@dataclass(slots=True)
class BackupPlatformImportConfig:
    """Imported backup platform evidence settings."""

    enabled: bool = False
    import_paths: list[str] = field(default_factory=list)
    stale_success_days: int = 7


@dataclass(slots=True)
class FieldValidationConfig:
    """Remote field-readiness checks."""

    enable_winrm_sample_checks: bool = True
    winrm_sample_targets: list[str] = field(default_factory=list)
    max_samples: int = 3


@dataclass(slots=True)
class ScannerIntegrationConfig:
    """Future scanner import settings.

    These are intentionally configuration-only in this sprint except Nmap.
    """

    nessus_import_path: str = ""
    greenbone_import_path: str = ""
    nessus_api: NessusApiConfig = field(default_factory=NessusApiConfig)
    greenbone_api: GreenboneApiConfig = field(default_factory=GreenboneApiConfig)


@dataclass(slots=True)
class ReportConfig:
    """Report generation settings."""

    mode: str = "auto"


@dataclass(slots=True)
class AppConfig:
    """Runtime configuration.

    The MVP is read-only by design. Attempts to disable read-only mode are rejected.
    """

    workspace_root: Path = Path(".soun_runner_workspace")
    log_root: Path | None = None
    read_only: bool = True
    log_level: str = "INFO"
    report_company_name: str = "Soun Al Hosn Cybersecurity LLC"
    smtp_enabled: bool = False
    smtp: SmtpConfig = field(default_factory=SmtpConfig)
    email_security: EmailSecurityConfig = field(default_factory=EmailSecurityConfig)
    nmap: NmapConfig = field(default_factory=NmapConfig)
    standard: StandardConfig = field(default_factory=StandardConfig)
    advanced: AdvancedConfig = field(default_factory=AdvancedConfig)
    callback: CallbackConfig = field(default_factory=CallbackConfig)
    m365_entra: M365EntraConfig = field(default_factory=M365EntraConfig)
    assessment: AssessmentDefaults = field(default_factory=AssessmentDefaults)
    orchestration: OrchestrationConfig = field(default_factory=OrchestrationConfig)
    remote_windows: RemoteWindowsConfig = field(default_factory=RemoteWindowsConfig)
    active_directory: ActiveDirectoryConfig = field(default_factory=ActiveDirectoryConfig)
    asset_classification: AssetClassificationConfig = field(default_factory=AssetClassificationConfig)
    firewall_vpn_import: FirewallVpnImportConfig = field(default_factory=FirewallVpnImportConfig)
    backup_platform_import: BackupPlatformImportConfig = field(default_factory=BackupPlatformImportConfig)
    field_validation: FieldValidationConfig = field(default_factory=FieldValidationConfig)
    scanner_integrations: ScannerIntegrationConfig = field(default_factory=ScannerIntegrationConfig)
    report: ReportConfig = field(default_factory=ReportConfig)

    @classmethod
    def load(
        cls,
        path: Path | None = None,
        data_dir: Path | None = None,
        log_dir: Path | None = None,
    ) -> "AppConfig":
        data: dict[str, Any] = {}
        if path:
            if not path.exists():
                raise FileNotFoundError(f"Config file not found: {path}")
            data = _load_mapping(path)

        config = cls(
            workspace_root=Path(data.get("workspace_root", ".soun_runner_workspace")),
            log_root=Path(data["log_root"]) if data.get("log_root") else None,
            read_only=bool(data.get("read_only", True)),
            log_level=str(data.get("log_level", "INFO")).upper(),
            report_company_name=str(
                data.get("report_company_name", "Soun Al Hosn Cybersecurity LLC")
            ),
            smtp_enabled=bool(data.get("smtp_enabled", False)),
            smtp=SmtpConfig(**dict(data.get("smtp", {}))),
            email_security=EmailSecurityConfig(**dict(data.get("email_security", {}))),
            nmap=NmapConfig(**dict(data.get("nmap", {}))),
            standard=StandardConfig(**dict(data.get("standard", {}))),
            advanced=AdvancedConfig(**dict(data.get("advanced", {}))),
            callback=_callback_config(dict(data.get("callback", {}))),
            m365_entra=M365EntraConfig(**dict(data.get("m365_entra", {}))),
            assessment=AssessmentDefaults(**dict(data.get("assessment", {}))),
            orchestration=OrchestrationConfig(**dict(data.get("orchestration", {}))),
            remote_windows=RemoteWindowsConfig(**dict(data.get("remote_windows", {}))),
            active_directory=ActiveDirectoryConfig(**dict(data.get("active_directory", {}))),
            asset_classification=AssetClassificationConfig(
                **dict(data.get("asset_classification", {}))
            ),
            firewall_vpn_import=FirewallVpnImportConfig(
                **dict(data.get("firewall_vpn_import", {}))
            ),
            backup_platform_import=BackupPlatformImportConfig(
                **dict(data.get("backup_platform_import", {}))
            ),
            field_validation=FieldValidationConfig(**dict(data.get("field_validation", {}))),
            scanner_integrations=_scanner_integration_config(
                dict(data.get("scanner_integrations", {}))
            ),
            report=ReportConfig(**dict(data.get("report", {}))),
        )
        config.apply_env()
        if data_dir:
            config.workspace_root = data_dir
        if log_dir:
            config.log_root = log_dir
        config.validate()
        return config

    def apply_env(self) -> None:
        """Overlay optional environment settings."""

        self.smtp.host = os.getenv("SOUN_RUNNER_SMTP_HOST", self.smtp.host)
        self.smtp.port = int(os.getenv("SOUN_RUNNER_SMTP_PORT", str(self.smtp.port)))
        self.smtp.username = os.getenv("SOUN_RUNNER_SMTP_USERNAME", self.smtp.username)
        self.smtp.password = os.getenv(self.smtp.password_env, self.smtp.password)
        self.smtp.sender = os.getenv("SOUN_RUNNER_SMTP_FROM", self.smtp.sender)
        self.smtp.recipient = os.getenv("SOUN_RUNNER_SMTP_TO", self.smtp.recipient)
        if os.getenv("SOUN_RUNNER_DATA_DIR"):
            self.workspace_root = Path(os.environ["SOUN_RUNNER_DATA_DIR"])
        if os.getenv("SOUN_RUNNER_LOG_DIR"):
            self.log_root = Path(os.environ["SOUN_RUNNER_LOG_DIR"])

    def validate(self) -> None:
        if not self.read_only:
            raise ValueError("Read-only mode is mandatory in the MVP.")
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"Unsupported log level: {self.log_level}")
        if self.email_security.dns_timeout_seconds <= 0:
            raise ValueError("DNS timeout must be greater than zero.")
        if self.nmap.profile not in {"host-discovery", "top-ports"}:
            raise ValueError("Nmap profile must be 'host-discovery' or 'top-ports'.")
        if self.nmap.timeout_seconds <= 0:
            raise ValueError("Nmap timeout must be greater than zero.")
        if self.nmap.top_ports < 1 or self.nmap.top_ports > 1000:
            raise ValueError("Nmap top_ports must be between 1 and 1000.")
        if self.standard.extended_nmap_top_ports < 1 or self.standard.extended_nmap_top_ports > 1000:
            raise ValueError("standard.extended_nmap_top_ports must be between 1 and 1000.")
        if self.callback.max_retry_attempts < 1:
            raise ValueError("callback.max_retry_attempts must be at least one.")
        if self.callback.base_retry_delay_seconds <= 0:
            raise ValueError("callback.base_retry_delay_seconds must be greater than zero.")
        if self.callback.max_retry_delay_seconds < self.callback.base_retry_delay_seconds:
            raise ValueError(
                "callback.max_retry_delay_seconds must be greater than or equal to base_retry_delay_seconds."
            )
        if self.callback.https.timeout_seconds <= 0:
            raise ValueError("callback.https.timeout_seconds must be greater than zero.")
        if self.m365_entra.timeout_seconds <= 0:
            raise ValueError("m365_entra.timeout_seconds must be greater than zero.")
        if self.orchestration.max_workers < 1 or self.orchestration.max_workers > 64:
            raise ValueError("orchestration.max_workers must be between 1 and 64.")
        if self.orchestration.per_host_timeout_seconds <= 0:
            raise ValueError("orchestration.per_host_timeout_seconds must be greater than zero.")
        if self.orchestration.retry_count < 0 or self.orchestration.retry_count > 10:
            raise ValueError("orchestration.retry_count must be between 0 and 10.")
        if self.orchestration.ad_computer_timeout_seconds <= 0:
            raise ValueError("orchestration.ad_computer_timeout_seconds must be greater than zero.")
        if self.remote_windows.transport not in {"winrm"}:
            raise ValueError("remote_windows.transport must be winrm.")
        if self.remote_windows.max_auto_attempts < 1 or self.remote_windows.max_auto_attempts > 1000:
            raise ValueError("remote_windows.max_auto_attempts must be between 1 and 1000.")
        if self.remote_windows.auth not in {"default", "negotiate", "kerberos", "basic"}:
            raise ValueError(
                "remote_windows.auth must be default, negotiate, kerberos, or basic."
            )
        if self.remote_windows.port < 1 or self.remote_windows.port > 65535:
            raise ValueError("remote_windows.port must be between 1 and 65535.")
        if self.remote_windows.connection_timeout_seconds <= 0:
            raise ValueError(
                "remote_windows.connection_timeout_seconds must be greater than zero."
            )
        if self.remote_windows.operation_timeout_seconds <= 0:
            raise ValueError(
                "remote_windows.operation_timeout_seconds must be greater than zero."
            )
        if self.active_directory.computer_limit < 1:
            raise ValueError("active_directory.computer_limit must be at least one.")
        if self.active_directory.user_limit < 1:
            raise ValueError("active_directory.user_limit must be at least one.")
        if self.active_directory.stale_account_days < 1:
            raise ValueError("active_directory.stale_account_days must be at least one.")
        if self.active_directory.query_timeout_seconds <= 0:
            raise ValueError("active_directory.query_timeout_seconds must be greater than zero.")
        if self.backup_platform_import.stale_success_days < 1:
            raise ValueError("backup_platform_import.stale_success_days must be at least one.")
        if self.field_validation.max_samples < 1 or self.field_validation.max_samples > 20:
            raise ValueError("field_validation.max_samples must be between 1 and 20.")
        if self.m365_entra.user_registration_limit < 1:
            raise ValueError("m365_entra.user_registration_limit must be at least one.")
        if self.m365_entra.legacy_sign_in_lookback_days < 1:
            raise ValueError("m365_entra.legacy_sign_in_lookback_days must be at least one.")
        if self.scanner_integrations.nessus_api.export_format not in {"nessus"}:
            raise ValueError("scanner_integrations.nessus_api.export_format must be 'nessus'.")
        if self.scanner_integrations.nessus_api.timeout_seconds <= 0:
            raise ValueError("scanner_integrations.nessus_api.timeout_seconds must be greater than zero.")
        if self.scanner_integrations.greenbone_api.connection_type not in {"tls", "ssh"}:
            raise ValueError(
                "scanner_integrations.greenbone_api.connection_type must be tls or ssh."
            )
        if self.scanner_integrations.greenbone_api.timeout_seconds <= 0:
            raise ValueError(
                "scanner_integrations.greenbone_api.timeout_seconds must be greater than zero."
            )
        if self.report.mode not in {"auto", "basic", "standard", "advanced"}:
            raise ValueError("report.mode must be auto, basic, standard, or advanced.")
        if self.assessment.package and self.assessment.package not in {"basic", "standard", "advanced"}:
            raise ValueError("assessment.package must be basic, standard, or advanced when set.")


def _load_mapping(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    raw = path.read_text(encoding="utf-8")
    if suffix in {".yaml", ".yml"}:
        loaded = yaml.safe_load(raw) or {}
    elif suffix == ".json":
        loaded = json.loads(raw)
    else:
        raise ValueError("Config must be YAML or JSON.")
    if not isinstance(loaded, dict):
        raise ValueError("Config root must be a mapping.")
    return loaded


def _callback_config(data: dict[str, Any]) -> CallbackConfig:
    return CallbackConfig(
        enabled=bool(data.get("enabled", False)),
        queue_dir=str(data.get("queue_dir", "")),
        send_smtp_summary=bool(data.get("send_smtp_summary", False)),
        upload_bundle=bool(data.get("upload_bundle", False)),
        max_retry_attempts=int(data.get("max_retry_attempts", 3)),
        base_retry_delay_seconds=int(data.get("base_retry_delay_seconds", 60)),
        max_retry_delay_seconds=int(data.get("max_retry_delay_seconds", 3600)),
        s3=CallbackS3Config(**dict(data.get("s3", {}))),
        sftp=CallbackSftpConfig(**dict(data.get("sftp", {}))),
        https=CallbackHttpsConfig(**dict(data.get("https", {}))),
    )


def _scanner_integration_config(data: dict[str, Any]) -> ScannerIntegrationConfig:
    return ScannerIntegrationConfig(
        nessus_import_path=str(data.get("nessus_import_path", "")),
        greenbone_import_path=str(data.get("greenbone_import_path", "")),
        nessus_api=NessusApiConfig(**dict(data.get("nessus_api", {}))),
        greenbone_api=GreenboneApiConfig(**dict(data.get("greenbone_api", {}))),
    )
