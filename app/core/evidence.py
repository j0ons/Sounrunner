"""Evidence quality helpers for normalized findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from app.core.models import Confidence, FindingBasis

EvidenceSourceType = Literal[
    "windows_native",
    "active_directory",
    "dns",
    "nmap",
    "nessus",
    "greenbone",
    "firewall_vpn_import",
    "backup_platform_import",
    "m365_entra",
    "aggregate",
    "operator_questionnaire",
    "unknown",
]


BASIS_CONFIDENCE: dict[FindingBasis, Confidence] = {
    "direct_system_evidence": "confirmed",
    "directory_evidence": "confirmed",
    "network_discovery_evidence": "strong",
    "imported_scanner_evidence": "strong",
    "imported_configuration_evidence": "strong",
    "advisory_questionnaire": "weak",
    "inferred_partial": "weak",
}


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp for evidence metadata."""

    return datetime.now(timezone.utc).isoformat()


def confidence_for_basis(basis: FindingBasis) -> Confidence:
    """Derive default confidence from the evidence basis."""

    return BASIS_CONFIDENCE[basis]
