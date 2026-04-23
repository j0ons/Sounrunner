"""Encrypted workspace helpers."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class CryptoWorkspace:
    """Encrypts evidence, checkpoints, and sensitive session blobs.

    If SOUN_RUNNER_WORKSPACE_KEY is not set, a local key file is created. That is
    acceptable for this MVP but not equivalent to hardware-backed or DPAPI-backed
    protection.
    """

    KEY_ENV = "SOUN_RUNNER_WORKSPACE_KEY"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.key_path = self.root / ".workspace_key"
        self._fernet = Fernet(self._load_or_create_key())

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt_bytes(self, data: bytes) -> bytes:
        try:
            return self._fernet.decrypt(data)
        except InvalidToken as exc:
            raise ValueError("Encrypted workspace key does not match this data.") from exc

    def write_encrypted(self, path: Path, data: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        encrypted_path = path if path.suffix == ".enc" else path.with_suffix(path.suffix + ".enc")
        encrypted_path.write_bytes(self.encrypt_bytes(data))
        return encrypted_path

    def read_encrypted(self, path: Path) -> bytes:
        return self.decrypt_bytes(path.read_bytes())

    def write_text(self, path: Path, text: str) -> Path:
        return self.write_encrypted(path, text.encode("utf-8"))

    def read_text(self, path: Path) -> str:
        return self.read_encrypted(path).decode("utf-8")

    def _load_or_create_key(self) -> bytes:
        env_key = os.getenv(self.KEY_ENV)
        if env_key:
            return env_key.encode("utf-8")
        if self.key_path.exists():
            return self.key_path.read_bytes().strip()
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        try:
            self.key_path.chmod(0o600)
        except OSError:
            # Windows ACL hardening is outside this Python-only MVP.
            pass
        return key
