"""PDF, CSV, and JSON report generation."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.inventory import AssetInventory
from app.core.models import Finding, FindingBasis
from app.core.session import AssessmentSession


EVIDENCE_SECTION_LABELS: dict[FindingBasis, str] = {
    "direct_system_evidence": "Direct System Evidence Findings",
    "directory_evidence": "Active Directory Evidence Findings",
    "network_discovery_evidence": "Network Discovery Findings",
    "imported_scanner_evidence": "Imported Scanner Findings",
    "imported_configuration_evidence": "Imported Configuration Findings",
    "advisory_questionnaire": "Advisory / Questionnaire Findings",
    "inferred_partial": "Partial or Inferred Findings",
}


class ReportGenerator:
    """Generates professional assessment outputs from normalized findings."""

    def __init__(
        self,
        session: AssessmentSession,
        company_name: str,
        app_version: str,
        report_mode: str = "basic",
        callback_status: str = "not_configured",
    ) -> None:
        self.session = session
        self.company_name = company_name
        self.app_version = app_version
        self.report_mode = report_mode
        self.callback_status = callback_status

    def generate_pdf(self, findings: list[Finding]) -> Path:
        output = self.session.report_dir / "assessment_report.pdf"
        doc = SimpleDocTemplate(str(output), pagesize=LETTER)
        styles = getSampleStyleSheet()
        story: list[object] = []

        story.append(Paragraph("Soun Al Hosn Assessment Runner", styles["Title"]))
        story.append(Paragraph(_report_title(self.report_mode), styles["Heading2"]))
        story.append(Paragraph(f"Prepared by: {self.company_name}", styles["Normal"]))
        story.append(Paragraph(f"Client: {self.session.intake.client_name}", styles["Normal"]))
        story.append(Paragraph(f"Site: {self.session.intake.site}", styles["Normal"]))
        story.append(Paragraph(f"Operator: {self.session.intake.operator_name}", styles["Normal"]))
        story.append(Paragraph(f"Session: {self.session.session_id}", styles["Normal"]))
        story.append(Paragraph(f"Package: {self.session.intake.package}", styles["Normal"]))
        story.append(Paragraph(f"Runner version: {self.app_version}", styles["Normal"]))
        story.append(Paragraph(f"Callback status: {self.callback_status}", styles["Normal"]))
        story.append(Paragraph(f"Generated UTC: {datetime.now(timezone.utc).isoformat()}", styles["Normal"]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Scope Control", styles["Heading2"]))
        story.append(Paragraph(f"Authorized scope: {self.session.intake.authorized_scope}", styles["Normal"]))
        story.append(Paragraph(f"Scope notes: {self.session.intake.scope_notes}", styles["Normal"]))
        story.append(Paragraph("Mode: read-only. No remediation or exploitation performed.", styles["Normal"]))
        story.append(Spacer(1, 12))

        estate = self.session.database.get_metadata("estate_summary", {})
        severity_counts = _severity_counts(findings)
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(
            Paragraph(
                "Critical: "
                f"{severity_counts['critical']} | High: {severity_counts['high']} | "
                f"Medium: {severity_counts['medium']} | Low: {severity_counts['low']} | "
                f"Info: {severity_counts['info']}",
                styles["Normal"],
            )
        )
        if estate and self.report_mode in {"standard", "advanced"}:
            story.append(Paragraph(_estate_posture_text(estate), styles["Normal"]))
        story.append(
            Paragraph(
                "Evidence-backed findings are separated from advisory or partial items in the sections below.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 12))

        if estate and self.report_mode in {"standard", "advanced"}:
            story.append(Paragraph("Organization Coverage Summary", styles["Heading2"]))
            coverage = estate.get("coverage", {})
            story.append(
                Paragraph(
                    "Total discovered: "
                    f"{coverage.get('total_assets', 0)} | Assessed: {coverage.get('assessed', 0)} | "
                    f"Partial: {coverage.get('partial', 0)} | Unreachable: {coverage.get('unreachable', 0)} | "
                    f"Discovery-only: {coverage.get('discovery_only', 0)} | "
                    f"Imported-evidence-only: {coverage.get('imported_evidence_only', 0)}",
                    styles["Normal"],
                )
            )
            site_rows = _coverage_rows(estate.get("by_site", {}), "Site")
            if site_rows:
                story.append(Paragraph("Coverage By Site", styles["Heading3"]))
                site_table = Table(site_rows, repeatRows=1)
                site_table.setStyle(_table_style("#1F2937"))
                story.append(site_table)
                story.append(Spacer(1, 8))
            subnet_rows = _coverage_rows(estate.get("by_subnet", {}), "Subnet")
            if subnet_rows:
                story.append(Paragraph("Coverage By Subnet", styles["Heading3"]))
                subnet_table = Table(subnet_rows, repeatRows=1)
                subnet_table.setStyle(_table_style("#374151"))
                story.append(subnet_table)
                story.append(Spacer(1, 8))
            business_unit_rows = _coverage_rows(estate.get("by_business_unit", {}), "Business Unit")
            if business_unit_rows:
                story.append(Paragraph("Coverage By Business Unit", styles["Heading3"]))
                business_unit_table = Table(business_unit_rows, repeatRows=1)
                business_unit_table.setStyle(_table_style("#475569"))
                story.append(business_unit_table)
                story.append(Spacer(1, 8))
            role_rows = _count_rows(estate.get("finding_counts_by_role", {}), "Asset Role", "Finding Count")
            if role_rows:
                story.append(Paragraph("Findings By Asset Role", styles["Heading3"]))
                role_table = Table(role_rows, repeatRows=1)
                role_table.setStyle(_table_style("#0F766E"))
                story.append(role_table)
                story.append(Spacer(1, 8))
            criticality_rows = _count_rows(
                estate.get("finding_counts_by_criticality", {}),
                "Criticality",
                "Finding Count",
            )
            if criticality_rows:
                story.append(Paragraph("Findings By Asset Criticality", styles["Heading3"]))
                criticality_table = Table(criticality_rows, repeatRows=1)
                criticality_table.setStyle(_table_style("#7C2D12"))
                story.append(criticality_table)
                story.append(Spacer(1, 8))
            site_finding_rows = _count_rows(estate.get("finding_counts_by_site", {}), "Site", "Finding Count")
            if site_finding_rows:
                story.append(Paragraph("Findings By Site", styles["Heading3"]))
                site_finding_table = Table(site_finding_rows, repeatRows=1)
                site_finding_table.setStyle(_table_style("#334155"))
                story.append(site_finding_table)
                story.append(Spacer(1, 8))
            remoting_rows = _count_rows(
                estate.get("remoting_failures", {}),
                "Remoting Failure Category",
                "Host Count",
            )
            if remoting_rows:
                story.append(Paragraph("Remote Collection Failure Summary", styles["Heading3"]))
                remoting_table = Table(remoting_rows, repeatRows=1)
                remoting_table.setStyle(_table_style("#7F1D1D"))
                story.append(remoting_table)
                story.append(Spacer(1, 8))
            repeated = estate.get("top_repeated_findings", [])
            if isinstance(repeated, list) and repeated:
                repeated_rows = [["Risk", "Severity", "Scope", "Finding", "Summary"]]
                for item in repeated[:8]:
                    repeated_rows.append(
                        [
                            str(item.get("risk_score", "")),
                            str(item.get("severity", "")),
                            str(item.get("asset", "")),
                            str(item.get("title", "")),
                            str(item.get("evidence_summary", ""))[:70],
                        ]
                    )
                story.append(Paragraph("Top Repeated Findings Across The Estate", styles["Heading3"]))
                repeated_table = Table(repeated_rows, repeatRows=1)
                repeated_table.setStyle(_table_style("#111827"))
                story.append(repeated_table)
                story.append(Spacer(1, 8))
            repeated_critical = estate.get("top_repeated_findings_on_critical_assets", [])
            if isinstance(repeated_critical, list) and repeated_critical:
                repeated_critical_rows = [["Risk", "Severity", "Role", "Finding", "Summary"]]
                for item in repeated_critical[:8]:
                    repeated_critical_rows.append(
                        [
                            str(item.get("risk_score", "")),
                            str(item.get("severity", "")),
                            str(item.get("asset_role", "")),
                            str(item.get("title", "")),
                            str(item.get("evidence_summary", ""))[:70],
                        ]
                    )
                story.append(Paragraph("Top Repeated Findings On Critical Assets", styles["Heading3"]))
                repeated_critical_table = Table(repeated_critical_rows, repeatRows=1)
                repeated_critical_table.setStyle(_table_style("#7C2D12"))
                story.append(repeated_critical_table)
                story.append(Spacer(1, 12))

        module_statuses = self.session.database.list_module_statuses()
        if module_statuses:
            story.append(Paragraph("Module Status / Not Assessed", styles["Heading2"]))
            status_rows = [["Module", "Status", "Detail"]]
            for status in module_statuses:
                status_rows.append([status.module_name, status.status, status.detail])
            status_table = Table(status_rows, repeatRows=1)
            status_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(status_table)
            story.append(Spacer(1, 12))

        story.append(Paragraph("Priority Action List", styles["Heading2"]))
        if findings:
            table_data = [["Risk", "Severity", "Evidence", "Finding", "Confidence", "Owner"]]
            for finding in findings[:12]:
                table_data.append(
                        [
                            str(finding.risk_score),
                            finding.severity,
                            _basis_display(finding.finding_basis),
                            finding.title,
                            finding.confidence,
                            finding.owner_role,
                    ]
                )
            table = Table(table_data, repeatRows=1)
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(table)
        else:
            story.append(Paragraph("No open findings were generated by the MVP checks.", styles["Normal"]))

        story.append(Spacer(1, 12))
        story.append(Paragraph("Findings Detail By Evidence Basis", styles["Heading2"]))
        grouped = group_findings_by_basis(findings)
        for basis, label in EVIDENCE_SECTION_LABELS.items():
            section_findings = grouped.get(basis, [])
            if not section_findings:
                continue
            story.append(Paragraph(label, styles["Heading2"]))
            if basis in {"advisory_questionnaire", "inferred_partial"}:
                story.append(
                    Paragraph(
                        "These items are not confirmed technical vulnerabilities. Treat them as advisory or partial evidence requiring validation.",
                        styles["Italic"],
                    )
                )
            for finding in section_findings:
                story.append(Paragraph(f"{finding.finding_id}: {finding.title}", styles["Heading3"]))
                story.append(
                    Paragraph(
                        "Severity: "
                        f"{finding.severity} | Confidence: {finding.confidence} | "
                        f"Evidence source: {finding.evidence_source_type} | Basis: {_basis_display(finding.finding_basis)}",
                        styles["Normal"],
                    )
                )
                asset_line = f"Asset: {finding.asset}"
                if finding.asset_role:
                    asset_line += f" | Role: {finding.asset_role}"
                if finding.asset_criticality:
                    asset_line += f" | Criticality: {finding.asset_criticality}"
                if finding.asset_classification_source:
                    asset_line += f" | Classification source: {finding.asset_classification_source}"
                story.append(Paragraph(asset_line, styles["Normal"]))
                story.append(Paragraph(f"Evidence: {finding.evidence_summary}", styles["Normal"]))
                story.append(Paragraph(f"Raw evidence: {finding.raw_evidence_path}", styles["Normal"]))
                if finding.merged_evidence_sources:
                    story.append(
                        Paragraph(
                            "Correlated sources: " + "; ".join(finding.merged_evidence_sources),
                            styles["Normal"],
                        )
                    )
                if finding.merged_finding_ids:
                    story.append(
                        Paragraph(
                            "Merged finding IDs: " + ", ".join(finding.merged_finding_ids),
                            styles["Normal"],
                        )
                    )
                story.append(Paragraph(f"Why it matters: {finding.why_it_matters}", styles["Normal"]))
                story.append(Paragraph(f"Business impact: {finding.likely_business_impact}", styles["Normal"]))
                story.append(Paragraph("Remediation: " + "; ".join(finding.remediation_steps), styles["Normal"]))
                story.append(Paragraph("Validation: " + "; ".join(finding.validation_steps), styles["Normal"]))
                story.append(Spacer(1, 8))

        appendix = _appendix_payload(self.session, findings, self.callback_status)
        story.append(Spacer(1, 12))
        story.append(Paragraph("Appendix", styles["Heading2"]))
        story.append(Paragraph(f"Consent confirmed: {appendix['consent_confirmed']}", styles["Normal"]))
        story.append(Paragraph(f"Operator: {appendix['operator_name']}", styles["Normal"]))
        story.append(Paragraph(f"Assessment timestamp: {appendix['assessment_timestamp']}", styles["Normal"]))
        story.append(Paragraph(f"Tool version: {appendix['tool_version']}", styles["Normal"]))
        story.append(Paragraph(f"Business unit: {appendix['business_unit']}", styles["Normal"]))
        story.append(Paragraph(f"Host allowlist: {appendix['host_allowlist']}", styles["Normal"]))
        story.append(Paragraph(f"Host denylist: {appendix['host_denylist']}", styles["Normal"]))
        story.append(Paragraph(f"AD domain: {appendix['ad_domain']}", styles["Normal"]))
        story.append(Paragraph(f"Import sources used: {appendix['import_sources']}", styles["Normal"]))
        story.append(Paragraph(f"Callback/export status: {appendix['callback_summary']}", styles["Normal"]))
        story.append(Paragraph(f"Evidence manifest entries: {appendix['manifest_entry_count']}", styles["Normal"]))
        story.append(Paragraph(f"Finding correlation: {appendix['correlation_summary']}", styles["Normal"]))
        if appendix["activation_plan"]:
            activation_rows = [["Module", "Activation", "Reason"]]
            for entry in appendix["activation_plan"]:
                activation_rows.append(
                    [
                        str(entry.get("module_name", "")),
                        str(entry.get("activation", "")),
                        str(entry.get("reason", "")),
                    ]
                )
            activation_table = Table(activation_rows, repeatRows=1)
            activation_table.setStyle(_table_style("#0F766E"))
            story.append(activation_table)
            story.append(Spacer(1, 8))
        if appendix["manifest_entries"]:
            manifest_rows = [["File", "Module", "SHA-256"]]
            for entry in appendix["manifest_entries"]:
                manifest_rows.append(
                    [
                        str(entry.get("relative_path", "")),
                        str(entry.get("source_module", "")),
                        str(entry.get("sha256", ""))[:16] + "...",
                    ]
                )
            manifest_table = Table(manifest_rows, repeatRows=1)
            manifest_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(manifest_table)
        asset_rows = _asset_appendix_rows(self.session)
        if asset_rows:
            story.append(Spacer(1, 12))
            story.append(Paragraph("Host Appendix", styles["Heading2"]))
            asset_table = Table(asset_rows, repeatRows=1)
            asset_table.setStyle(_table_style("#0F172A"))
            story.append(asset_table)

        doc.build(story)
        return output

    def generate_action_csv(self, findings: list[Finding]) -> Path:
        output = self.session.report_dir / "action_plan.csv"
        with output.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "finding_id",
                    "app_version",
                    "package",
                    "title",
                    "severity",
                    "confidence",
                    "risk_score",
                    "evidence_source_type",
                    "finding_basis",
                    "correlation_key",
                    "merged_finding_ids",
                    "merged_evidence_sources",
                    "evidence_collected_at",
                    "raw_evidence_path",
                    "asset_role",
                    "asset_criticality",
                    "asset_classification_source",
                    "owner_role",
                    "effort",
                    "status",
                    "remediation_steps",
                    "validation_steps",
                ],
            )
            writer.writeheader()
            for finding in findings:
                writer.writerow(
                    {
                        "finding_id": finding.finding_id,
                        "app_version": self.app_version,
                        "package": self.session.intake.package,
                        "title": finding.title,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "risk_score": finding.risk_score,
                        "evidence_source_type": finding.evidence_source_type,
                        "finding_basis": finding.finding_basis,
                        "correlation_key": finding.correlation_key,
                        "merged_finding_ids": " | ".join(finding.merged_finding_ids),
                        "merged_evidence_sources": " | ".join(finding.merged_evidence_sources),
                        "evidence_collected_at": finding.evidence_collected_at,
                        "raw_evidence_path": finding.raw_evidence_path,
                        "asset_role": finding.asset_role,
                        "asset_criticality": finding.asset_criticality,
                        "asset_classification_source": finding.asset_classification_source,
                        "owner_role": finding.owner_role,
                        "effort": finding.effort,
                        "status": finding.status,
                        "remediation_steps": " | ".join(finding.remediation_steps),
                        "validation_steps": " | ".join(finding.validation_steps),
                    }
                )
        return output

    def generate_findings_json(self, findings: list[Finding]) -> Path:
        output = self.session.report_dir / "findings.json"
        output.write_text(
            json.dumps(
                {
                    "metadata": {
                        "app_version": self.app_version,
                        "session_id": self.session.session_id,
                        "client_name": self.session.intake.client_name,
                        "site": self.session.intake.site,
                        "generated_utc": datetime.now(timezone.utc).isoformat(),
                        "read_only": True,
                        "package": self.session.intake.package,
                        "report_mode": self.report_mode,
                        "callback_status": self.callback_status,
                        "preflight": self.session.database.get_metadata("preflight", {}),
                        "evidence_manifest": self.session.database.get_metadata("evidence_manifest", {}),
                        "bundle_hash": self.session.database.get_metadata("bundle_hash", {}),
                        "session_context": self.session.database.get_metadata("session_context", {}),
                        "callback_status_detail": self.session.database.get_metadata("callback_status", {}),
                        "estate_summary": self.session.database.get_metadata("estate_summary", {}),
                        "finding_correlation": self.session.database.get_metadata("finding_correlation", {}),
                        "module_activation_plan": self.session.database.get_metadata("module_activation_plan", []),
                        "inventory_assets": self.session.database.get_metadata("inventory_assets", []),
                        "module_statuses": [
                            {
                                "module_name": status.module_name,
                                "status": status.status,
                                "detail": status.detail,
                            }
                            for status in self.session.database.list_module_statuses()
                        ],
                    },
                    "findings": [finding.to_dict() for finding in findings],
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return output

    def generate_roadmap_csv(self, findings: list[Finding]) -> Path:
        output = self.session.report_dir / "prioritized_roadmap.csv"
        with output.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "phase",
                    "finding_id",
                    "title",
                    "severity",
                    "confidence",
                    "risk_score",
                    "owner_role",
                    "primary_action",
                ],
            )
            writer.writeheader()
            for finding in findings:
                writer.writerow(
                    {
                        "phase": roadmap_phase(finding),
                        "finding_id": finding.finding_id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "risk_score": finding.risk_score,
                        "owner_role": finding.owner_role,
                        "primary_action": finding.remediation_steps[0]
                        if finding.remediation_steps
                        else "",
                    }
                )
        return output

    def generate_30_60_90_plan(self, findings: list[Finding]) -> Path:
        output = self.session.report_dir / "30_60_90_day_plan.csv"
        with output.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["period", "finding_id", "title", "owner_role", "action"],
            )
            writer.writeheader()
            for finding in findings:
                writer.writerow(
                    {
                        "period": roadmap_period(finding),
                        "finding_id": finding.finding_id,
                        "title": finding.title,
                        "owner_role": finding.owner_role,
                        "action": finding.remediation_steps[0]
                        if finding.remediation_steps
                        else "",
                    }
                )
        return output


def group_findings_by_basis(findings: list[Finding]) -> dict[FindingBasis, list[Finding]]:
    grouped: dict[FindingBasis, list[Finding]] = {
        basis: [] for basis in EVIDENCE_SECTION_LABELS
    }
    for finding in findings:
        grouped.setdefault(finding.finding_basis, []).append(finding)
    return grouped


def _report_title(report_mode: str) -> str:
    return {
        "basic": "Basic Cybersecurity Assessment Report",
        "standard": "Standard Executive Summary Assessment Report",
        "advanced": "Advanced Full Cybersecurity Assessment Report",
    }.get(report_mode, "Cybersecurity Assessment Report")


def roadmap_phase(finding: Finding) -> str:
    if finding.severity in {"critical", "high"} or finding.risk_score >= 70:
        return "Immediate"
    if finding.severity == "medium" or finding.risk_score >= 40:
        return "Short-term"
    return "Planned"


def roadmap_period(finding: Finding) -> str:
    if finding.severity in {"critical", "high"} or finding.risk_score >= 70:
        return "30 days"
    if finding.severity == "medium" or finding.risk_score >= 40:
        return "60 days"
    return "90 days"


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _appendix_payload(
    session: AssessmentSession,
    findings: list[Finding],
    callback_status: str,
) -> dict[str, object]:
    session_context = session.database.get_metadata("session_context", {})
    preflight = session.database.get_metadata("preflight", {})
    callback_detail = session.database.get_metadata("callback_status", {})
    manifest_summary = session.database.get_metadata("evidence_manifest", {})
    scanner_sources = session.database.get_metadata("scanner_sources", [])
    correlation = session.database.get_metadata("finding_correlation", {})
    activation_plan = session.database.get_metadata("module_activation_plan", [])
    manifest_entries = _manifest_entries(session)
    import_sources = sorted(
        {
            finding.evidence_source_type
            for finding in findings
            if finding.finding_basis in {"imported_scanner_evidence", "imported_configuration_evidence"}
        }
    )
    if isinstance(scanner_sources, list):
        for item in scanner_sources:
            if isinstance(item, dict) and item.get("source"):
                import_sources.append(str(item["source"]))
    return {
        "consent_confirmed": session_context.get("consent_confirmed", session.intake.consent_confirmed),
        "operator_name": session_context.get("operator_name", session.intake.operator_name),
        "assessment_timestamp": session_context.get("created_at", preflight.get("executed_at_utc", "")),
        "tool_version": session_context.get("app_version", session.app_version),
        "business_unit": session_context.get("business_unit", session.intake.business_unit),
        "host_allowlist": ", ".join(session_context.get("host_allowlist", []) or []) or "None",
        "host_denylist": ", ".join(session_context.get("host_denylist", []) or []) or "None",
        "ad_domain": session_context.get("ad_domain", session.intake.ad_domain or "None"),
        "import_sources": ", ".join(sorted(set(import_sources))) if import_sources else "None",
        "callback_summary": callback_detail.get("status_message", callback_status),
        "manifest_entry_count": manifest_summary.get("entry_count", len(manifest_entries)),
        "manifest_entries": manifest_entries[:8],
        "correlation_summary": (
            f"merged={correlation.get('merged_count', 0)} suppressed={correlation.get('suppressed_count', 0)}"
        ),
        "activation_plan": activation_plan if isinstance(activation_plan, list) else [],
    }


def _manifest_entries(session: AssessmentSession) -> list[dict[str, object]]:
    if not session.manifest_path.exists():
        return []
    try:
        payload = json.loads(session.crypto.read_text(session.manifest_path))
    except (OSError, ValueError, json.JSONDecodeError):
        return []
    entries = payload.get("entries", [])
    return entries if isinstance(entries, list) else []


def _coverage_rows(payload: object, label: str) -> list[list[str]]:
    if not isinstance(payload, dict) or not payload:
        return []
    rows = [[label, "Assessed", "Partial", "Unreachable", "Discovery-only", "Imported-evidence-only"]]
    for key, value in payload.items():
        if not isinstance(value, dict):
            continue
        rows.append(
            [
                str(key),
                str(value.get("assessed", 0)),
                str(value.get("partial", 0)),
                str(value.get("unreachable", 0)),
                str(value.get("discovery_only", 0)),
                str(value.get("imported_evidence_only", 0)),
            ]
        )
    return rows


def _asset_appendix_rows(session: AssessmentSession) -> list[list[str]]:
    inventory = AssetInventory(session).list_assets()
    if not inventory:
        return []
    rows = [["Host", "IP", "Role", "Criticality", "Type", "Site", "Assessment", "Collector", "Error"]]
    for asset in inventory[:25]:
        rows.append(
            [
                asset.display_name,
                asset.ip_address,
                asset.asset_role,
                asset.criticality,
                asset.asset_type,
                asset.site_label or asset.subnet_label or asset.business_unit,
                asset.assessment_status,
                asset.collector_status,
                asset.error_state[:40],
            ]
        )
    return rows


def _count_rows(payload: object, label: str, value_label: str) -> list[list[str]]:
    if not isinstance(payload, dict) or not payload:
        return []
    rows = [[label, value_label]]
    for key, value in payload.items():
        rows.append([str(key), str(value)])
    return rows


def _basis_display(basis: str) -> str:
    return {
        "direct_system_evidence": "Direct system evidence",
        "directory_evidence": "Active Directory evidence",
        "network_discovery_evidence": "Network discovery evidence",
        "imported_scanner_evidence": "Imported scanner evidence",
        "imported_configuration_evidence": "Imported configuration evidence",
        "advisory_questionnaire": "Advisory / questionnaire",
        "inferred_partial": "Partial / inferred",
    }.get(basis, basis)


def _estate_posture_text(estate: dict[str, object]) -> str:
    coverage = estate.get("coverage", {}) if isinstance(estate, dict) else {}
    if not isinstance(coverage, dict):
        return ""
    return (
        "Estate posture summary: "
        f"{coverage.get('total_assets', 0)} assets were tracked, "
        f"{coverage.get('assessed', 0)} were directly assessed, "
        f"{coverage.get('partial', 0)} were partially assessed, "
        f"{coverage.get('unreachable', 0)} were unreachable, "
        f"{coverage.get('discovery_only', 0)} remained discovery-only, and "
        f"{coverage.get('imported_evidence_only', 0)} relied only on imported evidence."
    )


def _table_style(header_color: str) -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_color)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
    )
