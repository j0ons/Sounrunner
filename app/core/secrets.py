"""Secret resolution, masking, and validation helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SENSITIVE_KEY_MARKERS = (
    "password",
    "secret",
    "token",
    "key",
    "credential",
)


@dataclass(slots=True)
class SecretResolution:
    """Resolved secret without exposing the secret value in status messages."""

    value: str = ""
    source_type: str = "missing"
    reference: str = ""
    detail: str = ""

    @property
    def present(self) -> bool:
        return bool(self.value)


def resolve_secret(
    *,
    env_name: str = "",
    file_path: str = "",
    direct_value: str = "",
    description: str = "secret",
    allow_plaintext: bool = False,
) -> SecretResolution:
    """Resolve a secret from env var, file reference, or optional plaintext fallback."""

    if env_name:
        value = os.getenv(env_name, "")
        if value:
            return SecretResolution(
                value=value.strip(),
                source_type="environment",
                reference=env_name,
                detail=f"{description} resolved from environment variable {env_name}.",
            )
    if file_path:
        path = Path(file_path).expanduser()
        if path.exists() and path.is_file():
            return SecretResolution(
                value=path.read_text(encoding="utf-8").strip(),
                source_type="file",
                reference=str(path),
                detail=f"{description} resolved from file reference {path}.",
            )
        return SecretResolution(
            value="",
            source_type="missing",
            reference=str(path),
            detail=f"{description} file reference not found: {path}",
        )
    if direct_value and allow_plaintext:
        return SecretResolution(
            value=direct_value,
            source_type="plaintext_config",
            reference="inline",
            detail=f"{description} resolved from inline config value.",
        )
    refs = ", ".join(item for item in [env_name, file_path] if item)
    return SecretResolution(
        value="",
        source_type="missing",
        reference=refs,
        detail=f"{description} was not provided via approved secret sources.",
    )


def mask_secret(value: str) -> str:
    """Return a short masked representation suitable for logs or UI."""

    cleaned = value.strip()
    if not cleaned:
        return ""
    if len(cleaned) <= 4:
        return "*" * len(cleaned)
    return cleaned[:2] + ("*" * max(4, len(cleaned) - 4)) + cleaned[-2:]


def mask_sensitive_mapping(value: Any) -> Any:
    """Recursively mask likely secret values for logs or UI output."""

    if isinstance(value, dict):
        masked: dict[str, Any] = {}
        for key, item in value.items():
            if _looks_sensitive_key(str(key)):
                if isinstance(item, str):
                    masked[key] = mask_secret(item)
                else:
                    masked[key] = "***"
            else:
                masked[key] = mask_sensitive_mapping(item)
        return masked
    if isinstance(value, list):
        return [mask_sensitive_mapping(item) for item in value]
    return value


def has_plaintext_secret_config(value: str) -> bool:
    return bool(value.strip())


def _looks_sensitive_key(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SENSITIVE_KEY_MARKERS)
