from pathlib import Path

from app.core.crypto import CryptoWorkspace
from app.core.state import StateManager


def test_crypto_workspace_round_trip(tmp_path: Path) -> None:
    crypto = CryptoWorkspace(tmp_path)
    encrypted_path = crypto.write_text(tmp_path / "evidence.json", '{"ok": true}')

    assert encrypted_path.suffix == ".enc"
    assert b'"ok": true' not in encrypted_path.read_bytes()
    assert crypto.read_text(encrypted_path) == '{"ok": true}'


def test_state_manager_updates_encrypted_checkpoint(tmp_path: Path) -> None:
    crypto = CryptoWorkspace(tmp_path)
    state = StateManager(tmp_path / "checkpoint.json.enc", crypto)

    state.update({"phase": "created"})
    state.mark_module_complete("environment_profile")

    loaded = state.load()
    assert loaded["phase"] == "completed:environment_profile"
    assert loaded["completed_modules"] == ["environment_profile"]
