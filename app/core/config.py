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
    password: str = ""
    sender: str = ""
    recipient: str = ""

    @property
    def is_complete(self) -> bool:
        return bool(self.host and self.sender and self.recipient)


@dataclass(slots=True)
class EmailSecurityConfig:
    """Email security check settings."""

    dkim_selectors: list[str] = field(default_factory=lambda: ["selector1", "selector2"])


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
        self.smtp.password = os.getenv("SOUN_RUNNER_SMTP_PASSWORD", self.smtp.password)
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
        if not self.email_security.dkim_selectors:
            raise ValueError("At least one DKIM selector must be configured.")


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
