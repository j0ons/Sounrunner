"""Nessus .nessus import parser."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from app.core.evidence import confidence_for_basis, utc_now
from app.core.models import Finding
from app.core.session import AssessmentSession
from app.scanners.base import ScannerResult


@dataclass(slots=True)
class NessusImportAdapter:
    """Import legitimate Nessus XML exports. This does not run Nessus."""

    session: AssessmentSession | None = None

    name: str = "nessus_import"

    def import_file(self, path: Path) -> ScannerResult:
        if not path.exists():
            return ScannerResult(
                scanner_name=self.name,
                status="skipped",
                detail=f"Nessus import file not found: {path}",
            )
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        evidence_path = path
        if self.session:
            evidence_path = self.session.crypto.write_text(
                self.session.evidence_dir / f"nessus_import_{path.name}.xml",
                raw_text,
            )
        findings = parse_nessus_xml(raw_text, raw_evidence_path=str(evidence_path))
        return ScannerResult(
            scanner_name=self.name,
            status="complete",
            detail=f"Imported {len(findings)} Nessus finding(s) from {path.name}.",
            findings=findings,
            raw_evidence_path=evidence_path,
        )


def parse_nessus_xml(xml_text: str, raw_evidence_path: str) -> list[Finding]:
    root = ET.fromstring(xml_text)
    collected_at = utc_now()
    findings: list[Finding] = []
    for host in root.findall(".//ReportHost"):
        host_name = host.attrib.get("name", "unknown-host")
        host_ip = _host_property(host, "host-ip") or host_name
        for item in host.findall("ReportItem"):
            severity = _nessus_severity(item.attrib.get("severity", "0"))
            if severity == "info":
                continue
            plugin_id = item.attrib.get("pluginID", "unknown")
            plugin_name = item.attrib.get("pluginName", "Nessus finding")
            port = item.attrib.get("port", "0")
            protocol = item.attrib.get("protocol", "")
            description = _child_text(item, "description") or plugin_name
            solution = _child_text(item, "solution") or "Review scanner evidence and remediate per vendor guidance."
            risk_factor = _child_text(item, "risk_factor") or severity
            findings.append(
                Finding(
                    finding_id=f"NESSUS-{plugin_id}-{host_ip}-{port}".replace(".", "-"),
                    title=plugin_name,
                    category="Imported Scanner",
                    package="standard",
                    severity=severity,  # type: ignore[arg-type]
                    confidence=confidence_for_basis("imported_scanner_evidence"),
                    asset=host_ip,
                    evidence_summary=(
                        f"Nessus plugin {plugin_id} reported {risk_factor} on {host_name} "
                        f"{protocol}/{port}."
                    ),
                    evidence_files=[raw_evidence_path],
                    why_it_matters=description[:1200],
                    likely_business_impact="Imported scanner evidence indicates a condition requiring validation and remediation.",
                    remediation_steps=[solution],
                    validation_steps=["Re-import a fresh authenticated scanner export after remediation."],
                    owner_role="Vulnerability Management Owner",
                    effort="medium",
                    evidence_source_type="nessus",
                    evidence_collected_at=collected_at,
                    raw_evidence_path=raw_evidence_path,
                    finding_basis="imported_scanner_evidence",
                )
            )
    return findings


def _host_property(host: ET.Element, name: str) -> str:
    for tag in host.findall("./HostProperties/tag"):
        if tag.attrib.get("name") == name:
            return (tag.text or "").strip()
    return ""


def _child_text(item: ET.Element, name: str) -> str:
    child = item.find(name)
    return (child.text or "").strip() if child is not None else ""


def _nessus_severity(value: str) -> str:
    return {
        "4": "critical",
        "3": "high",
        "2": "medium",
        "1": "low",
        "0": "info",
    }.get(str(value).strip(), "info")
