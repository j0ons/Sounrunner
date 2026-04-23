"""Safe subprocess helpers for read-only collectors."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Mapping


@dataclass(slots=True)
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_command(
    command: list[str],
    timeout_seconds: int = 20,
    *,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run a read-only command and capture output without invoking a shell."""

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
            env=dict(env) if env is not None else None,
        )
        return CommandResult(
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return CommandResult(
            command=command,
            returncode=124,
            stdout=stdout.strip(),
            stderr=stderr.strip(),
            timed_out=True,
        )
    except OSError as exc:
        return CommandResult(
            command=command,
            returncode=127,
            stdout="",
            stderr=str(exc),
        )
