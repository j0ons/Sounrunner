"""Read-only Greenbone/GMP API foundation."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass

from app.core.config import GreenboneApiConfig
from app.core.secrets import resolve_secret
from app.core.session import AssessmentSession
from app.scanners.base import ScannerResult
from app.scanners.greenbone_import import parse_greenbone_xml


class GreenboneApiError(RuntimeError):
    """Raised for Greenbone API failures."""


@dataclass(slots=True)
class GreenboneApiClient:
    """Fetch completed Greenbone reports through GMP."""

    session: AssessmentSession
    config: GreenboneApiConfig

    name: str = "greenbone_api"

    def fetch_report(self) -> ScannerResult:
        if not self.config.enabled:
            return ScannerResult(
                scanner_name=self.name,
                status="skipped",
                detail="Greenbone API connector disabled.",
            )
        if not self.config.host or not self.config.username:
            return ScannerResult(
                scanner_name=self.name,
                status="skipped",
                detail="Greenbone API connector requires host and username.",
            )
        password = resolve_secret(
            env_name=self.config.password_env,
            file_path=self.config.password_file,
            description="Greenbone password",
        )
        if not password.present:
            return ScannerResult(
                scanner_name=self.name,
                status="partial",
                detail=password.detail,
            )

        try:
            report_xml = self._download_report_xml(password.value)
        except GreenboneApiError as exc:
            return ScannerResult(
                scanner_name=self.name,
                status="partial",
                detail=f"Greenbone API collection failed cleanly: {exc}",
            )

        evidence_path = self.session.crypto.write_text(
            self.session.evidence_dir / "greenbone_api_report.xml.enc",
            report_xml,
        )
        findings = parse_greenbone_xml(report_xml, raw_evidence_path=str(evidence_path))
        return ScannerResult(
            scanner_name=self.name,
            status="complete",
            detail="Fetched and parsed Greenbone report through GMP.",
            findings=findings,
            raw_evidence_path=evidence_path,
        )

    def _download_report_xml(self, password: str) -> str:
        try:
            from gvm.connections import SSHConnection, TLSConnection  # type: ignore[import-not-found]
            from gvm.protocols.gmp import GMP  # type: ignore[import-not-found]
        except ImportError as exc:
            raise GreenboneApiError(
                "Greenbone API foundation requires optional dependency python-gvm."
            ) from exc

        connection: object
        if self.config.connection_type == "ssh":
            connection = SSHConnection(
                hostname=self.config.host,
                port=self.config.port,
                username=self.config.username,
                password=password,
                timeout=self.config.timeout_seconds,
                auto_accept_host=True,
            )
        else:
            # TODO: expose cafile/certfile paths if TLS validation customization is required.
            connection = TLSConnection(
                hostname=self.config.host,
                port=self.config.port,
                timeout=self.config.timeout_seconds,
            )

        try:
            with GMP(connection=connection) as gmp:
                gmp.authenticate(self.config.username, password)
                report_id = self.config.report_id or self._resolve_report_id(str(gmp.get_tasks()))
                if not report_id:
                    raise GreenboneApiError(
                        "Greenbone API connector requires report_id or task_id with a resolvable last report."
                    )
                return str(gmp.get_report(report_id, details=True))
        except Exception as exc:  # noqa: BLE001 - optional dependency surface is broad.
            raise GreenboneApiError(str(exc)) from exc

    def _resolve_report_id(self, tasks_xml: str) -> str:
        if not self.config.task_id:
            return ""
        root = ET.fromstring(tasks_xml)
        for task in root.findall(".//task"):
            if task.attrib.get("id") != self.config.task_id:
                continue
            report = task.find("./last_report/report")
            if report is not None and report.attrib.get("id"):
                return str(report.attrib["id"])
            last_report = task.find("./last_report")
            if last_report is not None and last_report.attrib.get("id"):
                return str(last_report.attrib["id"])
        return ""
