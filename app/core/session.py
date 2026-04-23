"""Assessment session creation and workspace layout."""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
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


@dataclass(slots=True)
class AssessmentSession:
    session_id: str
    intake: AssessmentIntake
    scope: ScopePolicy
    root: Path
    evidence_dir: Path
    report_dir: Path
    export_dir: Path
    log_dir: Path
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
        evidence_dir = root / "evidence"
        report_dir = root / "reports"
        export_dir = root / "export"
        log_dir = (
            self.config.log_root / "sessions" / session_id
            if self.config.log_root
            else root / "logs"
        )
        for directory in (evidence_dir, report_dir, export_dir, log_dir):
            directory.mkdir(parents=True, exist_ok=True)

        crypto = CryptoWorkspace(root)
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

        return AssessmentSession(
            session_id=session_id,
            intake=intake,
            scope=scope,
            root=root,
            evidence_dir=evidence_dir,
            report_dir=report_dir,
            export_dir=export_dir,
            log_dir=log_dir,
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
        return ScopePolicy.parse(intake.authorized_scope)

    @staticmethod
    def _build_session_id(client_name: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", client_name.strip().lower()).strip("-")
        slug = slug[:40] or "client"
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"{timestamp}-{slug}-{uuid.uuid4().hex[:8]}"


def _json_dumps(payload: dict[str, object]) -> str:
    import json

    return json.dumps(payload, indent=2, sort_keys=True)
