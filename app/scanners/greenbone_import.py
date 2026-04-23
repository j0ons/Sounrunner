"""Greenbone/OpenVAS XML import parser."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from app.core.evidence import confidence_for_basis, utc_now
from app.core.models import Finding
from app.core.session import AssessmentSession
from app.scanners.base import ScannerResult


@dataclass(slots=True)
class GreenboneImportAdapter:
    """Import legitimate Greenbone/OpenVAS XML exports. This does not run scans."""

    session: AssessmentSession | None = None

    name: str = "greenbone_import"

    def import_file(self, path: Path) -> ScannerResult:
        if not path.exists():
            return ScannerResult(
                scanner_name=self.name,
                status="skipped",
                detail=f"Greenbone import file not found: {path}",
            )
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        evidence_path = path
        if self.session:
            evidence_path = self.session.crypto.write_text(
                self.session.evidence_dir / f"greenbone_import_{path.name}.xml",
                raw_text,
            )
        findings = parse_greenbone_xml(raw_text, raw_evidence_path=str(evidence_path))
        return ScannerResult(
            scanner_name=self.name,
            status="complete",
            detail=f"Imported {len(findings)} Greenbone finding(s) from {path.name}.",
            findings=findings,
            raw_evidence_path=evidence_path,
        )


def parse_greenbone_xml(xml_text: str, raw_evidence_path: str) -> list[Finding]:
    root = ET.fromstring(xml_text)
    collected_at = utc_now()
    findings: list[Finding] = []
    for result in root.findall(".//result"):
        host = _text(result, "host") or "unknown-host"
        port = _text(result, "port")
        name = _text(result, "name") or _text(result, "nvt/name") or "Greenbone finding"
        threat = _text(result, "threat")
        severity = _greenbone_severity(_text(result, "severity"), threat)
        if severity == "info":
            continue
        description = _text(result, "description") or name
        solution = _text(result, "solution") or _text(result, "nvt/solution")
        findings.append(
            Finding(
                finding_id=f"GREENBONE-{host}-{port}-{name}".replace(" ", "-").replace(".", "-")[:120],
                title=name,
                category="Imported Scanner",
                package="standard",
                severity=severity,  # type: ignore[arg-type]
                confidence=confidence_for_basis("imported_scanner_evidence"),
                asset=host,
                evidence_summary=f"Greenbone reported {threat or severity} finding on {host} {port}.",
                evidence_files=[raw_evidence_path],
                why_it_matters=description[:1200],
                likely_business_impact="Imported scanner evidence indicates a condition requiring validation and remediation.",
                remediation_steps=[solution or "Review scanner evidence and remediate per vendor guidance."],
                validation_steps=["Re-import a fresh scanner export after remediation."],
                owner_role="Vulnerability Management Owner",
                effort="medium",
                evidence_source_type="greenbone",
                evidence_collected_at=collected_at,
                raw_evidence_path=raw_evidence_path,
                finding_basis="imported_scanner_evidence",
            )
        )
    return findings


def _text(root: ET.Element, path: str) -> str:
    child = root.find(path)
    return (child.text or "").strip() if child is not None else ""


def _greenbone_severity(value: str, threat: str) -> str:
    threat_l = threat.lower().strip()
    if threat_l in {"critical", "high", "medium", "low"}:
        return threat_l
    try:
        score = float(value)
    except ValueError:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"
