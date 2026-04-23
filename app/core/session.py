"""Assessment session creation and workspace layout."""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path

from app import __version__
from app.core.config import AppConfig
from app.core.crypto import CryptoWorkspace
from app.core.database import LocalDatabase
from app.core.logger import configure_logger
from app.core.scope import ScopePolicy
from app.core.state import StateManager


@dataclass(slots=True)
class AssessmentIntake:
    """Operator intake for authorized assessment scope."""

    client_name: str
    site: str
    operator_name: str
    package: str
    authorized_scope: str
    scope_notes: str
    consent_confirmed: bool
    domain: str | None = None
    m365_connector: bool = False
    host_allowlist: list[str] = field(default_factory=list)
    host_denylist: list[str] = field(default_factory=list)
    ad_domain: str | None = None
    business_unit: str = ""
    scope_labels: dict[str, str] = field(default_factory=dict)
    scanner_sources: list[str] = field(default_factory=list)
    cloud_tenants: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AssessmentSession:
    session_id: str
    app_version: str
    intake: AssessmentIntake
    scope: ScopePolicy
    root: Path
    audit_dir: Path
    evidence_dir: Path
    report_dir: Path
    export_dir: Path
    log_dir: Path
    audit_log_path: Path
    preflight_path: Path
    manifest_path: Path
    bundle_hash_path: Path
    callback_status_path: Path
    database: LocalDatabase
    crypto: CryptoWorkspace
    state: StateManager


class SessionManager:
    """Creates authorized, scoped, read-only assessment sessions."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def create_session(self, intake: AssessmentIntake) -> AssessmentSession:
        scope = self._validate_intake(intake)
        session_id = self._build_session_id(intake.client_name)
        root = self.config.workspace_root / "sessions" / session_id
        audit_dir = root / "audit"
        evidence_dir = root / "evidence"
        report_dir = root / "reports"
        export_dir = root / "export"
        log_dir = (
            self.config.log_root / "sessions" / session_id
            if self.config.log_root
            else root / "logs"
        )
        for directory in (audit_dir, evidence_dir, report_dir, export_dir, log_dir):
            directory.mkdir(parents=True, exist_ok=True)

        crypto = CryptoWorkspace(root)
        audit_log_path = crypto.write_text(audit_dir / "module_audit.jsonl.enc", "")
        state = StateManager(root / "checkpoint.json.enc", crypto)
        database = LocalDatabase(root / "runner.sqlite3", crypto)
        logger = configure_logger(log_dir, self.config.log_level)
        logger.info("Session created: %s", session_id)

        session_payload = {
            **asdict(intake),
            "session_id": session_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "app_version": __version__,
            "read_only": self.config.read_only,
            "scope_policy": scope.scope_summary(),
            "scope_local_only": scope.local_only,
            "data_root": str(self.config.workspace_root),
            "log_root": str(self.config.log_root) if self.config.log_root else str(log_dir),
        }
        database.insert_session(session_id, session_payload)
        crypto.write_text(root / "session_intake.json", _json_dumps(session_payload))

        state.update(
            {
                "session_id": session_id,
                "app_version": __version__,
                "phase": "created",
                "completed_modules": [],
                "failed_modules": [],
            }
        )

        session = AssessmentSession(
            session_id=session_id,
            app_version=__version__,
            intake=intake,
            scope=scope,
            root=root,
            audit_dir=audit_dir,
            evidence_dir=evidence_dir,
            report_dir=report_dir,
            export_dir=export_dir,
            log_dir=log_dir,
            audit_log_path=audit_log_path,
            preflight_path=audit_dir / "preflight.json.enc",
            manifest_path=audit_dir / "evidence_manifest.json.enc",
            bundle_hash_path=export_dir / "bundle_hash.json.enc",
            callback_status_path=export_dir / "callback_status.json.enc",
            database=database,
            crypto=crypto,
            state=state,
        )
        from app.core.integrity import initialize_session_audit

        initialize_session_audit(session)
        return session

    def load_session(self, session_id: str) -> AssessmentSession:
        root = self.config.workspace_root / "sessions" / session_id
        if not root.exists():
            raise FileNotFoundError(f"Session not found: {root}")

        crypto = CryptoWorkspace(root)
        intake_payload = json.loads(crypto.read_text(root / "session_intake.json.enc"))
        intake = AssessmentIntake(
            client_name=str(intake_payload["client_name"]),
            site=str(intake_payload["site"]),
            operator_name=str(intake_payload["operator_name"]),
            package=str(intake_payload["package"]),
            authorized_scope=str(intake_payload["authorized_scope"]),
            scope_notes=str(intake_payload["scope_notes"]),
            consent_confirmed=bool(intake_payload["consent_confirmed"]),
            domain=intake_payload.get("domain"),
            m365_connector=bool(intake_payload.get("m365_connector", False)),
            host_allowlist=list(intake_payload.get("host_allowlist", []) or []),
            host_denylist=list(intake_payload.get("host_denylist", []) or []),
            ad_domain=(str(intake_payload["ad_domain"]) if intake_payload.get("ad_domain") else None),
            business_unit=str(intake_payload.get("business_unit", "")),
            scope_labels=dict(intake_payload.get("scope_labels", {}) or {}),
            scanner_sources=list(intake_payload.get("scanner_sources", []) or []),
            cloud_tenants=list(intake_payload.get("cloud_tenants", []) or []),
        )
        log_dir = self._load_log_dir(root, intake_payload)
        database = LocalDatabase(root / "runner.sqlite3", crypto)
        state = StateManager(root / "checkpoint.json.enc", crypto)
        return AssessmentSession(
            session_id=session_id,
            app_version=str(intake_payload.get("app_version", __version__)),
            intake=intake,
            scope=ScopePolicy.parse(
                intake.authorized_scope,
                host_allowlist=intake.host_allowlist,
                host_denylist=intake.host_denylist,
                ad_domain=intake.ad_domain or "",
                business_unit=intake.business_unit,
                scope_labels=intake.scope_labels,
            ),
            root=root,
            audit_dir=root / "audit",
            evidence_dir=root / "evidence",
            report_dir=root / "reports",
            export_dir=root / "export",
            log_dir=log_dir,
            audit_log_path=root / "audit" / "module_audit.jsonl.enc",
            preflight_path=root / "audit" / "preflight.json.enc",
            manifest_path=root / "audit" / "evidence_manifest.json.enc",
            bundle_hash_path=root / "export" / "bundle_hash.json.enc",
            callback_status_path=root / "export" / "callback_status.json.enc",
            database=database,
            crypto=crypto,
            state=state,
        )

    def _validate_intake(self, intake: AssessmentIntake) -> ScopePolicy:
        if not intake.consent_confirmed:
            raise ValueError("Consent/authorization confirmation is mandatory.")
        if intake.package not in {"basic", "standard", "advanced"}:
            raise ValueError(f"Unsupported package: {intake.package}")
        required = {
            "client_name": intake.client_name,
            "site": intake.site,
            "operator_name": intake.operator_name,
        }
        missing = [name for name, value in required.items() if not value.strip()]
        if missing:
            raise ValueError(f"Missing required intake field(s): {', '.join(missing)}")
        return ScopePolicy.parse(
            intake.authorized_scope,
            host_allowlist=intake.host_allowlist,
            host_denylist=intake.host_denylist,
            ad_domain=intake.ad_domain or "",
            business_unit=intake.business_unit,
            scope_labels=intake.scope_labels,
        )

    @staticmethod
    def _build_session_id(client_name: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", client_name.strip().lower()).strip("-")
        slug = slug[:40] or "client"
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"{timestamp}-{slug}-{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _load_log_dir(root: Path, intake_payload: dict[str, object]) -> Path:
        payload_value = str(intake_payload.get("log_root", ""))
        if not payload_value:
            return root / "logs"
        candidate = Path(payload_value)
        if candidate.name == Path(root.name).name and candidate.exists():
            return candidate
        session_candidate = candidate / "sessions" / str(intake_payload.get("session_id", root.name))
        if session_candidate.exists():
            return session_candidate
        return candidate


def _json_dumps(payload: dict[str, object]) -> str:
    import json

    return json.dumps(payload, indent=2, sort_keys=True)
