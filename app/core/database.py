"""SQLite storage for local structured assessment data."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
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

    def set_metadata(self, key: str, value: Any) -> None:
        self.connection.execute(
            """
            INSERT INTO metadata(metadata_key, value_json)
            VALUES (?, ?)
            ON CONFLICT(metadata_key) DO UPDATE SET
                value_json=excluded.value_json,
                updated_at=CURRENT_TIMESTAMP
            """,
            (key, json.dumps(value, indent=2, sort_keys=True)),
        )
        self.connection.commit()

    def get_metadata(self, key: str, default: Any | None = None) -> Any:
        row = self.connection.execute(
            "SELECT value_json FROM metadata WHERE metadata_key = ?",
            (key,),
        ).fetchone()
        if not row:
            return default
        return json.loads(row["value_json"])

    def list_metadata(self) -> dict[str, Any]:
        rows = self.connection.execute(
            "SELECT metadata_key, value_json FROM metadata ORDER BY metadata_key ASC"
        ).fetchall()
        return {
            row["metadata_key"]: json.loads(row["value_json"])
            for row in rows
        }

    def upsert_asset(self, payload: dict[str, Any]) -> None:
        self.connection.execute(
            """
            INSERT INTO assets(
                asset_id, hostname, fqdn, ip_address, mac_address, os_family, os_guess,
                asset_type, asset_role, role_source, criticality, criticality_source,
                subnet_label, site_label, business_unit, directory_site, directory_ou,
                discovery_source, first_seen, last_seen, assessment_status, collector_status, error_state
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_id) DO UPDATE SET
                hostname=excluded.hostname,
                fqdn=excluded.fqdn,
                ip_address=excluded.ip_address,
                mac_address=excluded.mac_address,
                os_family=excluded.os_family,
                os_guess=excluded.os_guess,
                asset_type=excluded.asset_type,
                asset_role=excluded.asset_role,
                role_source=excluded.role_source,
                criticality=excluded.criticality,
                criticality_source=excluded.criticality_source,
                subnet_label=excluded.subnet_label,
                site_label=excluded.site_label,
                business_unit=excluded.business_unit,
                directory_site=excluded.directory_site,
                directory_ou=excluded.directory_ou,
                discovery_source=excluded.discovery_source,
                last_seen=excluded.last_seen,
                assessment_status=excluded.assessment_status,
                collector_status=excluded.collector_status,
                error_state=excluded.error_state
            """,
            (
                payload.get("asset_id", ""),
                payload.get("hostname", ""),
                payload.get("fqdn", ""),
                payload.get("ip_address", ""),
                payload.get("mac_address", ""),
                payload.get("os_family", ""),
                payload.get("os_guess", ""),
                payload.get("asset_type", ""),
                payload.get("asset_role", ""),
                payload.get("role_source", ""),
                payload.get("criticality", ""),
                payload.get("criticality_source", ""),
                payload.get("subnet_label", ""),
                payload.get("site_label", ""),
                payload.get("business_unit", ""),
                payload.get("directory_site", ""),
                payload.get("directory_ou", ""),
                payload.get("discovery_source", ""),
                payload.get("first_seen", ""),
                payload.get("last_seen", ""),
                payload.get("assessment_status", ""),
                payload.get("collector_status", ""),
                payload.get("error_state", ""),
            ),
        )
        self.connection.commit()

    def get_asset_by_address(self, address: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT * FROM assets
            WHERE ip_address = ? OR hostname = ? OR fqdn = ?
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (address, address, address),
        ).fetchone()
        return dict(row) if row else None

    def get_asset_by_id(self, asset_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM assets WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_assets(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT * FROM assets
            ORDER BY
                CASE assessment_status
                    WHEN 'assessed' THEN 0
                    WHEN 'partial' THEN 1
                    WHEN 'unreachable' THEN 2
                    WHEN 'discovery_only' THEN 3
                    ELSE 4
                END,
                COALESCE(site_label, ''),
                COALESCE(ip_address, ''),
                asset_id ASC
            """
        ).fetchall()
        return [dict(row) for row in rows]

    def replace_asset_services(
        self,
        asset_id: str,
        services: Iterable[dict[str, Any]],
        *,
        source: str,
    ) -> None:
        self.connection.execute(
            "DELETE FROM asset_services WHERE asset_id = ? AND source = ?",
            (asset_id, source),
        )
        rows = [
            (
                asset_id,
                str(item.get("protocol", "")),
                int(item.get("port", 0)),
                str(item.get("state", "")),
                str(item.get("service_name", "")),
                str(item.get("product", "")),
                str(item.get("version", "")),
                str(item.get("extra_info", "")),
                source,
            )
            for item in services
        ]
        if rows:
            self.connection.executemany(
                """
                INSERT INTO asset_services(
                    asset_id, protocol, port, state, service_name, product, version, extra_info, source
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        self.connection.commit()

    def list_asset_services(self, asset_id: str | None = None) -> list[dict[str, Any]]:
        if asset_id:
            rows = self.connection.execute(
                "SELECT * FROM asset_services WHERE asset_id = ? ORDER BY port ASC",
                (asset_id,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM asset_services ORDER BY asset_id ASC, port ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def add_asset_evidence(
        self,
        asset_id: str,
        evidence_path: str,
        source_module: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO asset_evidence(
                asset_id, evidence_path, source_module
            )
            VALUES (?, ?, ?)
            """,
            (asset_id, evidence_path, source_module),
        )
        self.connection.commit()

    def list_asset_evidence(self, asset_id: str | None = None) -> list[dict[str, Any]]:
        if asset_id:
            rows = self.connection.execute(
                """
                SELECT * FROM asset_evidence
                WHERE asset_id = ?
                ORDER BY recorded_at ASC, evidence_path ASC
                """,
                (asset_id,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT * FROM asset_evidence
                ORDER BY asset_id ASC, recorded_at ASC, evidence_path ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_asset_module_status(
        self,
        asset_id: str,
        module_name: str,
        status: str,
        detail: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO asset_module_status(asset_id, module_name, status, detail)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(asset_id, module_name) DO UPDATE SET
                status=excluded.status,
                detail=excluded.detail,
                updated_at=CURRENT_TIMESTAMP
            """,
            (asset_id, module_name, status, detail),
        )
        self.connection.commit()

    def list_asset_module_statuses(self, asset_id: str | None = None) -> list[dict[str, Any]]:
        if asset_id:
            rows = self.connection.execute(
                """
                SELECT * FROM asset_module_status
                WHERE asset_id = ?
                ORDER BY module_name ASC
                """,
                (asset_id,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT * FROM asset_module_status
                ORDER BY asset_id ASC, module_name ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]

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
                finding.evidence_source_type,
                finding.evidence_collected_at,
                finding.raw_evidence_path,
                finding.finding_basis,
                finding.correlation_key,
                json.dumps(finding.merged_finding_ids),
                json.dumps(finding.merged_evidence_sources),
                finding.asset_role,
                finding.asset_criticality,
                finding.asset_classification_source,
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
                owner_role, effort, evidence_source_type, evidence_collected_at,
                raw_evidence_path, finding_basis, correlation_key,
                merged_finding_ids_json, merged_evidence_sources_json,
                asset_role, asset_criticality,
                asset_classification_source, status, risk_score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    evidence_source_type=row["evidence_source_type"],
                    evidence_collected_at=row["evidence_collected_at"],
                    raw_evidence_path=row["raw_evidence_path"],
                    finding_basis=row["finding_basis"],
                    correlation_key=row["correlation_key"],
                    merged_finding_ids=json.loads(row["merged_finding_ids_json"]),
                    merged_evidence_sources=json.loads(row["merged_evidence_sources_json"]),
                    asset_role=row["asset_role"],
                    asset_criticality=row["asset_criticality"],
                    asset_classification_source=row["asset_classification_source"],
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

    def list_module_statuses(self) -> list[ModuleStatus]:
        rows = self.connection.execute(
            "SELECT module_name, status, detail FROM module_status ORDER BY module_name ASC"
        ).fetchall()
        return [
            ModuleStatus(
                module_name=row["module_name"],
                status=row["status"],
                detail=row["detail"],
            )
            for row in rows
        ]

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

            CREATE TABLE IF NOT EXISTS metadata (
                metadata_key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
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
                evidence_source_type TEXT NOT NULL DEFAULT 'unknown',
                evidence_collected_at TEXT NOT NULL DEFAULT '',
                raw_evidence_path TEXT NOT NULL DEFAULT '',
                finding_basis TEXT NOT NULL DEFAULT 'inferred_partial',
                correlation_key TEXT NOT NULL DEFAULT '',
                merged_finding_ids_json TEXT NOT NULL DEFAULT '[]',
                merged_evidence_sources_json TEXT NOT NULL DEFAULT '[]',
                asset_role TEXT NOT NULL DEFAULT '',
                asset_criticality TEXT NOT NULL DEFAULT '',
                asset_classification_source TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                risk_score INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL DEFAULT '',
                fqdn TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT '',
                mac_address TEXT NOT NULL DEFAULT '',
                os_family TEXT NOT NULL DEFAULT '',
                os_guess TEXT NOT NULL DEFAULT '',
                asset_type TEXT NOT NULL DEFAULT 'unknown',
                asset_role TEXT NOT NULL DEFAULT 'unknown',
                role_source TEXT NOT NULL DEFAULT '',
                criticality TEXT NOT NULL DEFAULT 'medium',
                criticality_source TEXT NOT NULL DEFAULT 'default',
                subnet_label TEXT NOT NULL DEFAULT '',
                site_label TEXT NOT NULL DEFAULT '',
                business_unit TEXT NOT NULL DEFAULT '',
                directory_site TEXT NOT NULL DEFAULT '',
                directory_ou TEXT NOT NULL DEFAULT '',
                discovery_source TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                assessment_status TEXT NOT NULL DEFAULT 'discovery_only',
                collector_status TEXT NOT NULL DEFAULT 'not_started',
                error_state TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS asset_services (
                asset_id TEXT NOT NULL,
                protocol TEXT NOT NULL,
                port INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT '',
                service_name TEXT NOT NULL DEFAULT '',
                product TEXT NOT NULL DEFAULT '',
                version TEXT NOT NULL DEFAULT '',
                extra_info TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                observed_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS asset_evidence (
                asset_id TEXT NOT NULL,
                evidence_path TEXT NOT NULL,
                source_module TEXT NOT NULL DEFAULT '',
                recorded_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(asset_id, evidence_path)
            );

            CREATE TABLE IF NOT EXISTS asset_module_status (
                asset_id TEXT NOT NULL,
                module_name TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(asset_id, module_name)
            );
            """
        )
        self._ensure_finding_columns()
        self.connection.commit()

    def _ensure_finding_columns(self) -> None:
        existing = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(findings)").fetchall()
        }
        columns = {
            "evidence_source_type": "TEXT NOT NULL DEFAULT 'unknown'",
            "evidence_collected_at": "TEXT NOT NULL DEFAULT ''",
            "raw_evidence_path": "TEXT NOT NULL DEFAULT ''",
            "finding_basis": "TEXT NOT NULL DEFAULT 'inferred_partial'",
            "correlation_key": "TEXT NOT NULL DEFAULT ''",
            "merged_finding_ids_json": "TEXT NOT NULL DEFAULT '[]'",
            "merged_evidence_sources_json": "TEXT NOT NULL DEFAULT '[]'",
            "asset_role": "TEXT NOT NULL DEFAULT ''",
            "asset_criticality": "TEXT NOT NULL DEFAULT ''",
            "asset_classification_source": "TEXT NOT NULL DEFAULT ''",
        }
        for name, definition in columns.items():
            if name not in existing:
                self.connection.execute(
                    f"ALTER TABLE findings ADD COLUMN {name} {definition}"
                )
        self._ensure_asset_columns()

    def _ensure_asset_columns(self) -> None:
        existing = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(assets)").fetchall()
        }
        columns = {
            "asset_role": "TEXT NOT NULL DEFAULT 'unknown'",
            "role_source": "TEXT NOT NULL DEFAULT ''",
            "criticality": "TEXT NOT NULL DEFAULT 'medium'",
            "criticality_source": "TEXT NOT NULL DEFAULT 'default'",
            "directory_site": "TEXT NOT NULL DEFAULT ''",
            "directory_ou": "TEXT NOT NULL DEFAULT ''",
        }
        for name, definition in columns.items():
            if name not in existing:
                self.connection.execute(
                    f"ALTER TABLE assets ADD COLUMN {name} {definition}"
                )
