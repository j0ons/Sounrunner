"""Windows-native read-only collectors."""

from __future__ import annotations

import json
import platform

from app.collectors.shell import CommandResult, run_command


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def run_powershell(script: str, timeout_seconds: int = 30) -> CommandResult:
    """Execute a read-only PowerShell command with profile loading disabled."""

    command = [
        "powershell.exe",
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
    return run_command(command, timeout_seconds=timeout_seconds)


def powershell_json(script: str, timeout_seconds: int = 30) -> tuple[dict[str, object], CommandResult]:
    wrapped = f"{script} | ConvertTo-Json -Depth 6"
    result = run_powershell(wrapped, timeout_seconds=timeout_seconds)
    if result.returncode != 0 or not result.stdout:
        return {}, result
    try:
        decoded = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}, result
    if isinstance(decoded, dict):
        return decoded, result
    return {"items": decoded}, result
