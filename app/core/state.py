"""Encrypted checkpoint state management."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.crypto import CryptoWorkspace


class StateManager:
    """Persists resumable checkpoint state in an encrypted JSON file."""

    def __init__(self, path: Path, crypto: CryptoWorkspace) -> None:
        self.path = path
        self.crypto = crypto

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        raw = self.crypto.read_text(self.path)
        return json.loads(raw)

    def save(self, state: dict[str, Any]) -> None:
        self.crypto.write_text(
            self.path,
            json.dumps(state, indent=2, sort_keys=True),
        )

    def update(self, updates: dict[str, Any]) -> dict[str, Any]:
        state = self.load()
        state.update(updates)
        self.save(state)
        return state

    def completed_modules(self) -> set[str]:
        return set(self.load().get("completed_modules", []))

    def mark_module_complete(self, module_name: str) -> None:
        state = self.load()
        completed = list(state.get("completed_modules", []))
        if module_name not in completed:
            completed.append(module_name)
        state["completed_modules"] = completed
        state["phase"] = f"completed:{module_name}"
        self.save(state)

    def mark_module_failed(self, module_name: str, error: str) -> None:
        state = self.load()
        failed = list(state.get("failed_modules", []))
        failed.append({"module": module_name, "error": error})
        state["failed_modules"] = failed
        state["phase"] = f"failed:{module_name}"
        self.save(state)
