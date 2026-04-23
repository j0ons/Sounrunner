"""Audit trail and evidence integrity helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.session import AssessmentSession


@dataclass(slots=True)
class ManifestEntry:
    """Hash metadata for one assessment artifact."""

    relative_path: str
    sha256: str
    size_bytes: int
    modified_utc: str
    source_module: str


@dataclass(slots=True)
class EvidenceManifest:
    """Session evidence manifest."""

    generated_at: str
    session_id: str
    package: str
    entries: list[ManifestEntry]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "session_id": self.session_id,
            "package": self.package,
            "entry_count": len(self.entries),
            "entries": [asdict(entry) for entry in self.entries],
        }


class SessionAuditor:
    """Encrypted JSONL audit log for session execution."""

    def __init__(self, session: AssessmentSession) -> None:
        self.session = session

    def record_event(self, event_type: str, payload: dict[str, Any]) -> None:
        entry = {
            "event_type": event_type,
            "event_time_utc": _utc_now(),
            **payload,
        }
        lines = self._read_lines()
        lines.append(json.dumps(entry, sort_keys=True))
        self.session.crypto.write_text(self.session.audit_log_path, "\n".join(lines) + "\n")

    def read_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for line in self._read_lines():
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                events.append(parsed)
        return events

    def _read_lines(self) -> list[str]:
        if not self.session.audit_log_path.exists():
            return []
        return self.session.crypto.read_text(self.session.audit_log_path).splitlines()


def initialize_session_audit(session: AssessmentSession) -> None:
    """Persist consent, operator, scope, and version metadata."""

    session.database.set_metadata(
        "session_context",
        {
            "session_id": session.session_id,
            "client_name": session.intake.client_name,
            "site": session.intake.site,
            "operator_name": session.intake.operator_name,
            "package": session.intake.package,
            "authorized_scope": session.intake.authorized_scope,
            "scope_notes": session.intake.scope_notes,
            "host_allowlist": list(session.intake.host_allowlist),
            "host_denylist": list(session.intake.host_denylist),
            "ad_domain": session.intake.ad_domain,
            "business_unit": session.intake.business_unit,
            "cloud_tenants": list(session.intake.cloud_tenants),
            "scanner_sources": list(session.intake.scanner_sources),
            "scope_policy": session.scope.scope_summary(),
            "consent_confirmed": session.intake.consent_confirmed,
            "created_at": _utc_now(),
            "app_version": session.app_version,
            "read_only": True,
        },
    )
    SessionAuditor(session).record_event(
        "session_created",
        {
            "client_name": session.intake.client_name,
            "site": session.intake.site,
            "operator_name": session.intake.operator_name,
            "package": session.intake.package,
            "authorized_scope": session.intake.authorized_scope,
            "scope_notes": session.intake.scope_notes,
            "host_allowlist": list(session.intake.host_allowlist),
            "host_denylist": list(session.intake.host_denylist),
            "ad_domain": session.intake.ad_domain,
            "business_unit": session.intake.business_unit,
            "cloud_tenants": list(session.intake.cloud_tenants),
            "scanner_sources": list(session.intake.scanner_sources),
            "consent_confirmed": session.intake.consent_confirmed,
            "app_version": session.app_version,
        },
    )


def store_preflight_report(session: AssessmentSession, payload: dict[str, Any]) -> Path:
    """Persist startup validation results for the session."""

    path = session.crypto.write_text(
        session.preflight_path,
        json.dumps(payload, indent=2, sort_keys=True),
    )
    session.database.set_metadata("preflight", {"path": str(path), **payload})
    SessionAuditor(session).record_event(
        "preflight_recorded",
        {
            "status": payload.get("overall_status", "unknown"),
            "check_count": len(payload.get("checks", [])),
            "path": str(path),
        },
    )
    return path


def generate_evidence_manifest(
    session: AssessmentSession,
    *,
    package: str,
) -> tuple[Path, EvidenceManifest]:
    """Generate an encrypted evidence manifest for the session."""

    file_map = _file_source_map(SessionAuditor(session).read_events())
    entries: list[ManifestEntry] = []
    for path in _manifest_files(session):
        if not path.exists() or not path.is_file():
            continue
        relative_path = str(path.relative_to(session.root))
        entries.append(
            ManifestEntry(
                relative_path=relative_path,
                sha256=sha256_file(path),
                size_bytes=path.stat().st_size,
                modified_utc=datetime.fromtimestamp(
                    path.stat().st_mtime,
                    tz=timezone.utc,
                ).isoformat(),
                source_module=file_map.get(str(path), _default_source_module(session, path)),
            )
        )

    manifest = EvidenceManifest(
        generated_at=_utc_now(),
        session_id=session.session_id,
        package=package,
        entries=sorted(entries, key=lambda item: item.relative_path),
    )
    path = session.crypto.write_text(
        session.manifest_path,
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True),
    )
    session.database.set_metadata(
        "evidence_manifest",
        {
            "path": str(path),
            "generated_at": manifest.generated_at,
            "entry_count": len(manifest.entries),
        },
    )
    SessionAuditor(session).record_event(
        "manifest_generated",
        {
            "path": str(path),
            "entry_count": len(manifest.entries),
        },
    )
    return path, manifest


def store_bundle_hash(session: AssessmentSession, bundle_path: Path) -> Path:
    """Hash the final encrypted bundle and persist the result."""

    payload = {
        "bundle_path": str(bundle_path),
        "bundle_filename": bundle_path.name,
        "sha256": sha256_file(bundle_path),
        "size_bytes": bundle_path.stat().st_size,
        "hashed_at": _utc_now(),
    }
    path = session.crypto.write_text(
        session.bundle_hash_path,
        json.dumps(payload, indent=2, sort_keys=True),
    )
    session.database.set_metadata("bundle_hash", {"path": str(path), **payload})
    SessionAuditor(session).record_event("bundle_hashed", payload)
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_files(session: AssessmentSession) -> list[Path]:
    files: set[Path] = set()
    for candidate in [
        session.root / "runner.sqlite3",
        session.root / "checkpoint.json.enc",
        session.root / "session_intake.json.enc",
        session.audit_log_path,
        session.preflight_path,
        session.callback_status_path,
        session.manifest_path,
        session.bundle_hash_path,
    ]:
        files.add(candidate)

    for directory in (session.evidence_dir, session.report_dir, session.export_dir):
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            if path.is_dir():
                continue
            if path == session.export_dir / "results_bundle.zip":
                continue
            files.add(path)
    return sorted(files)


def _file_source_map(events: list[dict[str, Any]]) -> dict[str, str]:
    file_map: dict[str, str] = {}
    for event in events:
        source_module = str(event.get("source_module") or "")
        evidence_files = event.get("evidence_files", [])
        if not source_module or not isinstance(evidence_files, list):
            continue
        for path in evidence_files:
            file_map[str(path)] = source_module
    return file_map


def _default_source_module(session: AssessmentSession, path: Path) -> str:
    if path == session.audit_log_path or path.parent == session.audit_dir:
        return "audit"
    if path.parent == session.report_dir:
        return "reporting"
    if path.parent == session.export_dir:
        return "export"
    if path.parent == session.evidence_dir or session.evidence_dir in path.parents:
        return "evidence"
    return "session"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
