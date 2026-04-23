"""Read-only remote Windows evidence collection."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.collectors.windows import is_windows, powershell_available, run_powershell
from app.collectors.windows_native import (
    WindowsCommandEvidence,
    WindowsEvidence,
    WindowsNativeCollector,
    _try_json,
)
from app.core.config import RemoteWindowsConfig
from app.core.evidence import utc_now
from app.core.secrets import resolve_secret
from app.core.session import AssessmentSession


@dataclass(slots=True)
class RemoteWindowsCollectionResult:
    target: str
    status: str
    detail: str
    evidence: WindowsEvidence
    evidence_path: Path | None = None
    failure_category: str = ""
    operator_hint: str = ""


class RemoteWindowsCollector:
    """Collect remote Windows evidence over PowerShell remoting."""

    name = "windows_remote_collection"

    def __init__(
        self,
        session: AssessmentSession,
        config: RemoteWindowsConfig,
    ) -> None:
        self.session = session
        self.config = config

    def collect(self, *, target: str, asset_id: str) -> RemoteWindowsCollectionResult:
        evidence = WindowsEvidence(
            supported=is_windows() and powershell_available() and self.config.enabled,
            collected_at=utc_now(),
        )
        evidence_path = self.session.evidence_dir / "hosts" / asset_id / "windows_remote_evidence.json"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.config.enabled:
            evidence.raw_evidence_path = self.session.crypto.write_text(
                evidence_path,
                json.dumps(evidence.to_dict(), indent=2, sort_keys=True),
            )
            return RemoteWindowsCollectionResult(
                target=target,
                status="skipped",
                detail="Remote Windows collection disabled in config.",
                evidence=evidence,
                evidence_path=evidence.raw_evidence_path,
            )

        if not is_windows() or not powershell_available():
            evidence.raw_evidence_path = self.session.crypto.write_text(
                evidence_path,
                json.dumps(evidence.to_dict(), indent=2, sort_keys=True),
            )
            return RemoteWindowsCollectionResult(
                target=target,
                status="partial",
                detail="Remote Windows collection requires execution from a Windows host with PowerShell available.",
                evidence=evidence,
                evidence_path=evidence.raw_evidence_path,
            )

        password_ref = resolve_secret(
            env_name=self.config.password_env,
            file_path=self.config.password_file,
            description="Remote Windows password",
        )
        if self.config.username and not password_ref.present:
            evidence.raw_evidence_path = self.session.crypto.write_text(
                evidence_path,
                json.dumps(evidence.to_dict(), indent=2, sort_keys=True),
            )
            return RemoteWindowsCollectionResult(
                target=target,
                status="partial",
                detail=(
                    f"Remote username configured for {target} but password reference is unavailable. "
                    f"{password_ref.detail}"
                ),
                evidence=evidence,
                evidence_path=evidence.raw_evidence_path,
                failure_category="missing_secret",
                operator_hint="Provide the approved WinRM credential through the configured environment variable or secret file.",
            )

        success_count = 0
        for name, command in WindowsNativeCollector.COMMANDS.items():
            result = run_powershell(
                _remote_wrapper(
                    target=target,
                    command=command,
                    config=self.config,
                    password=password_ref.value,
                ),
                timeout_seconds=max(
                    self.config.connection_timeout_seconds,
                    self.config.operation_timeout_seconds,
                )
                + 15,
                env={"SOUN_RUNNER_REMOTE_SECRET": password_ref.value} if password_ref.present else None,
            )
            evidence.sections[name] = WindowsCommandEvidence(
                name=name,
                command=command,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                timed_out=result.timed_out,
                parsed_json=_try_json(result.stdout),
            )
            if result.returncode == 0 and not result.timed_out:
                success_count += 1

        evidence.raw_evidence_path = self.session.crypto.write_text(
            evidence_path,
            json.dumps(evidence.to_dict(), indent=2, sort_keys=True),
        )
        if success_count == 0:
            category, hint = _categorize_remote_failure(evidence)
            return RemoteWindowsCollectionResult(
                target=target,
                status="partial",
                detail=f"Remote collection did not return usable evidence from {target}.",
                evidence=evidence,
                evidence_path=evidence.raw_evidence_path,
                failure_category=category,
                operator_hint=hint,
            )
        if success_count < len(WindowsNativeCollector.COMMANDS):
            category, hint = _categorize_remote_failure(evidence)
            return RemoteWindowsCollectionResult(
                target=target,
                status="partial",
                detail=(
                    f"Remote collection completed with partial evidence for {target}. "
                    f"{success_count}/{len(WindowsNativeCollector.COMMANDS)} commands succeeded."
                ),
                evidence=evidence,
                evidence_path=evidence.raw_evidence_path,
                failure_category=category,
                operator_hint=hint,
            )
        return RemoteWindowsCollectionResult(
            target=target,
            status="complete",
            detail=f"Remote Windows evidence collected for {target}.",
            evidence=evidence,
            evidence_path=evidence.raw_evidence_path,
        )


def _remote_wrapper(
    *,
    target: str,
    command: str,
    config: RemoteWindowsConfig,
    password: str,
) -> str:
    params: list[str] = [
        f"$params = @{{ ComputerName = '{target}'; ErrorAction = 'Stop'; Port = {config.port}; ",
        "SessionOption = (New-PSSessionOption "
        f"-OpenTimeout {config.connection_timeout_seconds * 1000} "
        f"-OperationTimeout {config.operation_timeout_seconds * 1000}) }}",
    ]
    if config.auth != "default":
        params.append(f"$params.Authentication = '{config.auth}'")
    if config.use_ssl:
        params.append("$params.UseSSL = $true")
    if config.username:
        params.extend(
            [
                "$secure = ConvertTo-SecureString $env:SOUN_RUNNER_REMOTE_SECRET -AsPlainText -Force",
                f"$cred = New-Object System.Management.Automation.PSCredential('{config.username}', $secure)",
                "$params.Credential = $cred",
            ]
        )
    params.extend(
        [
            "$scriptBlock = [ScriptBlock]::Create(@'",
            command,
            "'@)",
            "Invoke-Command @params -ScriptBlock $scriptBlock",
        ]
    )
    return "\n".join(params)


def _categorize_remote_failure(evidence: WindowsEvidence) -> tuple[str, str]:
    blob = " ".join(
        [
            section.stderr
            for section in evidence.sections.values()
            if section.stderr
        ]
    ).lower()
    if "access is denied" in blob or "unauthorized" in blob:
        return "access_denied", "Confirm the approved credential has WinRM and read access on the remote host."
    if "cannot resolve" in blob or "name could not be resolved" in blob:
        return "dns_resolution", "Check DNS resolution or use an approved IP-based target."
    if "timed out" in blob or "timeout" in blob:
        return "timeout", "Check routing, host responsiveness, and WinRM timeouts."
    if "firewall" in blob:
        return "firewall_blocked", "Review host or network firewall rules for WinRM."
    if "winrm" in blob or "cannot connect" in blob or "network path was not found" in blob:
        return "winrm_unavailable", "Confirm WinRM is enabled and reachable on the remote host."
    return "partial_remote_evidence", "Review command stderr in the host evidence file for access or module limitations."
