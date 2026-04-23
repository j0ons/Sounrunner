"""SQLite storage for local structured assessment data."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from app.core.crypto import CryptoWorkspace
from app.core.models import Finding, ModuleStatus


class LocalDatabase:
    """Thin SQLite wrapper for session metadata, findings, and module status.

    SQLite stores structured workflow data. Sensitive raw evidence and intake blobs
    are encrypted by CryptoWorkspace before storage.
    """

    def __init__(self, path: Path, crypto: CryptoWorkspace) -> None:
        self.path = path
        self.crypto = crypto
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        self.connection.close()

    def insert_session(self, session_id: str, payload: dict[str, object]) -> None:
        encrypted_payload = self.crypto.encrypt_bytes(
            json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        )
        self.connection.execute(
            """
            INSERT INTO sessions(session_id, encrypted_payload)
            VALUES (?, ?)
            """,
            (session_id, encrypted_payload),
        )
        self.connection.commit()

    def upsert_module_status(self, status: ModuleStatus) -> None:
        self.connection.execute(
            """
            INSERT INTO module_status(module_name, status, detail)
            VALUES (?, ?, ?)
            ON CONFLICT(module_name) DO UPDATE SET
                status=excluded.status,
                detail=excluded.detail,
                updated_at=CURRENT_TIMESTAMP
            """,
            (status.module_name, status.status, status.detail),
        )
        self.connection.commit()

    def insert_findings(self, findings: Iterable[Finding]) -> None:
        rows = [
            (
                finding.finding_id,
                finding.title,
                finding.category,
                finding.package,
                finding.severity,
                finding.confidence,
                finding.asset,
                finding.evidence_summary,
                json.dumps(finding.evidence_files),
                finding.why_it_matters,
                finding.likely_business_impact,
                json.dumps(finding.remediation_steps),
                json.dumps(finding.validation_steps),
                finding.owner_role,
                finding.effort,
                finding.status,
                finding.risk_score,
            )
            for finding in findings
        ]
        self.connection.executemany(
            """
            INSERT OR REPLACE INTO findings(
                finding_id, title, category, package, severity, confidence, asset,
                evidence_summary, evidence_files_json, why_it_matters,
                likely_business_impact, remediation_steps_json, validation_steps_json,
                owner_role, effort, status, risk_score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.connection.commit()

    def list_findings(self) -> list[Finding]:
        rows = self.connection.execute(
            "SELECT * FROM findings ORDER BY risk_score DESC, finding_id ASC"
        ).fetchall()
        findings: list[Finding] = []
        for row in rows:
            findings.append(
                Finding(
                    finding_id=row["finding_id"],
                    title=row["title"],
                    category=row["category"],
                    package=row["package"],
                    severity=row["severity"],
                    confidence=row["confidence"],
                    asset=row["asset"],
                    evidence_summary=row["evidence_summary"],
                    evidence_files=json.loads(row["evidence_files_json"]),
                    why_it_matters=row["why_it_matters"],
                    likely_business_impact=row["likely_business_impact"],
                    remediation_steps=json.loads(row["remediation_steps_json"]),
                    validation_steps=json.loads(row["validation_steps_json"]),
                    owner_role=row["owner_role"],
                    effort=row["effort"],
                    status=row["status"],
                    risk_score=row["risk_score"],
                )
            )
        return findings

    def module_completed(self, module_name: str) -> bool:
        row = self.connection.execute(
            "SELECT status FROM module_status WHERE module_name = ?",
            (module_name,),
        ).fetchone()
        return bool(row and row["status"] in {"complete", "partial", "skipped"})

    def _init_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                encrypted_payload BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS module_status (
                module_name TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                package TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                asset TEXT NOT NULL,
                evidence_summary TEXT NOT NULL,
                evidence_files_json TEXT NOT NULL,
                why_it_matters TEXT NOT NULL,
                likely_business_impact TEXT NOT NULL,
                remediation_steps_json TEXT NOT NULL,
                validation_steps_json TEXT NOT NULL,
                owner_role TEXT NOT NULL,
                effort TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score INTEGER NOT NULL
            );
            """
        )
        self.connection.commit()
