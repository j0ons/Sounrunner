"""Normalized network assessment models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


ServiceCategory = Literal[
    "remote_admin",
    "file_sharing",
    "directory_identity",
    "web_admin",
    "database",
    "insecure_cleartext",
    "network_infrastructure",
    "backup_storage",
    "unknown_exposed",
]


EvidenceClassification = Literal[
    "observed_network_exposure",
    "inferred_network_posture",
    "confirmed_network_configuration",
]


@dataclass(slots=True)
class ClassifiedNetworkService:
    """One observed network service with assessment classification."""

    asset_id: str
    asset: str
    ip_address: str
    hostname: str
    subnet: str
    site: str
    asset_role: str
    asset_criticality: str
    protocol: str
    port: int
    service_name: str
    product: str = ""
    version: str = ""
    category: ServiceCategory = "unknown_exposed"
    exposure_type: EvidenceClassification = "observed_network_exposure"
    evidence_source: str = "asset_services"
    confidence: str = "strong"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SegmentationObservation:
    """Inferred or confirmed network segmentation observation."""

    observation_id: str
    title: str
    subnet: str
    site: str
    evidence_type: EvidenceClassification
    confidence: str
    summary: str
    supporting_assets: list[str] = field(default_factory=list)
    recommended_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FirewallRule:
    """Vendor-neutral imported firewall/VPN rule evidence."""

    device_name: str
    vendor: str = ""
    zone_or_interface: str = ""
    rule_id: str = ""
    rule_name: str = ""
    source_zone: str = ""
    source: str = ""
    destination_zone: str = ""
    destination: str = ""
    service: str = ""
    port: str = ""
    action: str = ""
    enabled: bool = True
    remote_access_vpn_enabled: bool = False
    admin_interface_exposure: bool = False
    any_any: bool = False
    broad_inbound: bool = False
    management_exposure: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FirewallVpnEvidence:
    """Normalized imported firewall/VPN posture evidence."""

    source_path: str
    rules: list[FirewallRule] = field(default_factory=list)
    partial: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "rules": [rule.to_dict() for rule in self.rules],
            "partial": self.partial,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class NetworkScore:
    """Network posture score and explanation."""

    network_score: int
    confidence: str
    key_drivers: list[str]
    top_actions: list[str]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class NetworkAssessmentSummary:
    """Organization-level network assessment summary."""

    scope: list[str]
    scan_profile: str
    assessed_subnets: dict[str, int]
    services_by_category: dict[str, int]
    services: list[ClassifiedNetworkService]
    management_exposures: list[ClassifiedNetworkService]
    insecure_protocols: list[ClassifiedNetworkService]
    network_devices: list[dict[str, Any]]
    segmentation_observations: list[SegmentationObservation]
    firewall_evidence: list[FirewallVpnEvidence]
    network_score: NetworkScore

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": list(self.scope),
            "scan_profile": self.scan_profile,
            "assessed_subnets": dict(self.assessed_subnets),
            "services_by_category": dict(self.services_by_category),
            "services": [service.to_dict() for service in self.services],
            "management_exposures": [service.to_dict() for service in self.management_exposures],
            "insecure_protocols": [service.to_dict() for service in self.insecure_protocols],
            "network_devices": list(self.network_devices),
            "segmentation_observations": [
                observation.to_dict() for observation in self.segmentation_observations
            ],
            "firewall_evidence": [evidence.to_dict() for evidence in self.firewall_evidence],
            "network_score": self.network_score.to_dict(),
        }
