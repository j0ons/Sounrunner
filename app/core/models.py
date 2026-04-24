"""Shared dataclasses for normalized findings and module results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["confirmed", "strong", "weak", "unknown"]
FindingStatus = Literal["open", "accepted_risk", "remediated", "not_applicable"]
ModuleRunStatus = Literal["complete", "partial", "skipped", "failed"]
FindingBasis = Literal[
    "direct_system_evidence",
    "directory_evidence",
    "network_discovery_evidence",
    "imported_scanner_evidence",
    "imported_configuration_evidence",
    "advisory_questionnaire",
    "inferred_partial",
]


@dataclass(slots=True)
class Finding:
    """Normalized assessment finding schema."""

    finding_id: str
    title: str
    category: str
    package: str
    severity: Severity
    confidence: Confidence
    asset: str
    evidence_summary: str
    evidence_files: list[str]
    why_it_matters: str
    likely_business_impact: str
    remediation_steps: list[str]
    validation_steps: list[str]
    owner_role: str
    effort: str
    evidence_source_type: str = "unknown"
    evidence_collected_at: str = ""
    raw_evidence_path: str = ""
    finding_basis: FindingBasis = "inferred_partial"
    correlation_key: str = ""
    merged_finding_ids: list[str] = field(default_factory=list)
    merged_evidence_sources: list[str] = field(default_factory=list)
    asset_role: str = ""
    asset_criticality: str = ""
    asset_classification_source: str = ""
    status: FindingStatus = "open"
    risk_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ModuleStatus:
    module_name: str
    status: ModuleRunStatus
    detail: str


@dataclass(slots=True)
class ModuleResult:
    module_name: str
    status: ModuleRunStatus
    detail: str
    findings: list[Finding] = field(default_factory=list)
    evidence_files: list[Path] = field(default_factory=list)

    def to_status(self) -> ModuleStatus:
        return ModuleStatus(
            module_name=self.module_name,
            status=self.status,
            detail=self.detail,
        )


@dataclass(slots=True)
class AssessmentResult:
    app_version: str
    package: str
    session_id: str
    report_pdf: Path
    action_csv: Path
    findings_json: Path
    encrypted_bundle: Path
    findings_count: int
    callback_status: str = "not_configured"
    additional_artifacts: list[Path] = field(default_factory=list)
