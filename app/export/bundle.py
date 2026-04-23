"""Encrypted ZIP bundle export."""

from __future__ import annotations

import os
from pathlib import Path

import pyzipper

from app.core.session import AssessmentSession


class BundleExporter:
    """Creates an AES-encrypted ZIP result bundle."""

    def __init__(self, session: AssessmentSession) -> None:
        self.session = session

    def export(self, files: list[Path]) -> Path:
        output = self.session.export_dir / "results_bundle.zip"
        password = self._bundle_password()
        seen: set[Path] = set()
        with pyzipper.AESZipFile(
            output,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as archive:
            archive.setpassword(password)
            for file_path in files:
                if file_path in seen or not file_path.exists() or not file_path.is_file():
                    continue
                seen.add(file_path)
                archive.write(file_path, arcname=self._archive_name(file_path))
        return output

    def _bundle_password(self) -> bytes:
        supplied = os.getenv("SOUN_RUNNER_BUNDLE_PASSWORD")
        if supplied:
            return supplied.encode("utf-8")
        return self.session.session_id.encode("utf-8")

    def _archive_name(self, file_path: Path) -> str:
        try:
            return str(file_path.relative_to(self.session.root))
        except ValueError:
            return file_path.name
