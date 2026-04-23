"""Windows-native read-only collectors."""

from __future__ import annotations

import json
import platform
import shutil
from typing import Mapping

from app.collectors.shell import CommandResult, run_command


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def find_powershell_executable() -> str:
    for candidate in ("powershell.exe", "pwsh.exe", "powershell", "pwsh"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return ""


def powershell_available() -> bool:
    return bool(find_powershell_executable())


def detect_windows_admin() -> bool:
    if not is_windows():
        return False
    result = run_command(["whoami", "/groups"], timeout_seconds=15)
    return "S-1-5-32-544" in result.stdout or "BUILTIN\\Administrators" in result.stdout


def run_powershell(
    script: str,
    timeout_seconds: int = 30,
    *,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Execute a read-only PowerShell command with profile loading disabled."""

    executable = find_powershell_executable()
    if not executable:
        return CommandResult(
            command=["powershell"],
            returncode=127,
            stdout="",
            stderr="PowerShell executable not found.",
        )
    command = [
        executable,
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ]
    if not is_windows():
        return CommandResult(
            command=command,
            returncode=0,
            stdout="",
            stderr="Skipped: not running on Windows.",
        )
    return run_command(command, timeout_seconds=timeout_seconds, env=env)


def powershell_json(
    script: str,
    timeout_seconds: int = 30,
    *,
    env: Mapping[str, str] | None = None,
) -> tuple[dict[str, object], CommandResult]:
    wrapped = f"{script} | ConvertTo-Json -Depth 6"
    result = run_powershell(wrapped, timeout_seconds=timeout_seconds, env=env)
    if result.returncode != 0 or not result.stdout:
        return {}, result
    try:
        decoded = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}, result
    if isinstance(decoded, dict):
        return decoded, result
    return {"items": decoded}, result
