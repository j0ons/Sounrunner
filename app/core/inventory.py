"""Asset inventory model and datastore helpers."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from typing import Any

from app.core.config import AppConfig
from app.core.evidence import utc_now
from app.core.models import Finding
from app.core.session import AssessmentSession
from app.profiling.environment import EnvironmentProfile
from app.scanners.base import NetworkAsset


@dataclass(slots=True)
class AssetRecord:
    asset_id: str
    hostname: str = ""
    fqdn: str = ""
    ip_address: str = ""
    mac_address: str = ""
    os_family: str = ""
    os_guess: str = ""
    asset_type: str = "unknown"
    asset_role: str = "unknown"
    role_source: str = ""
    criticality: str = "medium"
    criticality_source: str = "default"
    subnet_label: str = ""
    site_label: str = ""
    business_unit: str = ""
    directory_site: str = ""
    directory_ou: str = ""
    discovery_source: str = ""
    first_seen: str = ""
    last_seen: str = ""
    assessment_status: str = "discovery_only"
    collector_status: str = "not_started"
    error_state: str = ""
    evidence_references: list[str] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return self.hostname or self.fqdn or self.ip_address or self.asset_id

    def to_db_payload(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "fqdn": self.fqdn,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "os_family": self.os_family,
            "os_guess": self.os_guess,
            "asset_type": self.asset_type,
            "asset_role": self.asset_role,
            "role_source": self.role_source,
            "criticality": self.criticality,
            "criticality_source": self.criticality_source,
            "subnet_label": self.subnet_label,
            "site_label": self.site_label,
            "business_unit": self.business_unit,
            "directory_site": self.directory_site,
            "directory_ou": self.directory_ou,
            "discovery_source": self.discovery_source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "assessment_status": self.assessment_status,
            "collector_status": self.collector_status,
            "error_state": self.error_state,
        }

    @classmethod
    def from_row(
        cls,
        row: dict[str, Any],
        evidence_references: list[str] | None = None,
    ) -> "AssetRecord":
        return cls(
            asset_id=str(row.get("asset_id", "")),
            hostname=str(row.get("hostname", "")),
            fqdn=str(row.get("fqdn", "")),
            ip_address=str(row.get("ip_address", "")),
            mac_address=str(row.get("mac_address", "")),
            os_family=str(row.get("os_family", "")),
            os_guess=str(row.get("os_guess", "")),
            asset_type=str(row.get("asset_type", "unknown")),
            asset_role=str(row.get("asset_role", row.get("asset_type", "unknown"))),
            role_source=str(row.get("role_source", "")),
            criticality=str(row.get("criticality", "medium")),
            criticality_source=str(row.get("criticality_source", "default")),
            subnet_label=str(row.get("subnet_label", "")),
            site_label=str(row.get("site_label", "")),
            business_unit=str(row.get("business_unit", "")),
            directory_site=str(row.get("directory_site", "")),
            directory_ou=str(row.get("directory_ou", "")),
            discovery_source=str(row.get("discovery_source", "")),
            first_seen=str(row.get("first_seen", "")),
            last_seen=str(row.get("last_seen", "")),
            assessment_status=str(row.get("assessment_status", "")),
            collector_status=str(row.get("collector_status", "")),
            error_state=str(row.get("error_state", "")),
            evidence_references=list(evidence_references or []),
        )


class AssetInventory:
    """Inventory helper over the local session database."""

    def __init__(self, session: AssessmentSession, config: AppConfig | None = None) -> None:
        self.session = session
        self.config = config or AppConfig()

    def record_local_profile(
        self,
        profile: EnvironmentProfile,
        *,
        evidence_paths: list[str] | None = None,
    ) -> AssetRecord:
        ip_address = _first_profile_address(profile)
        label = self.session.scope.label_for_ip(ip_address) if ip_address else ""
        asset = AssetRecord(
            asset_id=build_asset_id(ip_address or profile.hostname),
            hostname=profile.hostname,
            fqdn=profile.hostname,
            ip_address=ip_address,
            os_family=profile.os_name,
            os_guess=f"{profile.os_name} {profile.os_version}".strip(),
            asset_type=_guess_asset_type(profile.os_name, profile.hostname, []),
            subnet_label=label or _subnet_from_scope(ip_address, self.session.scope.scan_targets()),
            site_label=label or self.session.intake.site,
            business_unit=self.session.scope.business_unit or self.session.intake.business_unit,
            discovery_source="local_environment_profile",
            first_seen=utc_now(),
            last_seen=utc_now(),
            assessment_status="assessed",
            collector_status="complete",
        )
        asset = self.classify_asset(asset)
        self.upsert(asset)
        for path in evidence_paths or []:
            self.attach_evidence(asset.asset_id, path, "environment_profile")
        return asset

    def record_discovery(self, network_asset: NetworkAsset, *, source: str = "nmap") -> AssetRecord:
        now = utc_now()
        existing = self.find_asset(network_asset.address or network_asset.primary_hostname)
        label = self.session.scope.label_for_ip(network_asset.address)
        hostname = network_asset.primary_hostname
        record = AssetRecord(
            asset_id=existing.asset_id if existing else build_asset_id(network_asset.address or hostname),
            hostname=hostname or (existing.hostname if existing else ""),
            fqdn=hostname or (existing.fqdn if existing else ""),
            ip_address=network_asset.address or (existing.ip_address if existing else ""),
            mac_address=network_asset.mac_address or (existing.mac_address if existing else ""),
            os_family=network_asset.os_family or (existing.os_family if existing else ""),
            os_guess=network_asset.os_guess or (existing.os_guess if existing else ""),
            asset_type=(existing.asset_type if existing else "unknown"),
            asset_role=(existing.asset_role if existing else "unknown"),
            role_source=(existing.role_source if existing else ""),
            criticality=(existing.criticality if existing else "medium"),
            criticality_source=(existing.criticality_source if existing else "default"),
            subnet_label=label or (existing.subnet_label if existing else _subnet_from_scope(network_asset.address, self.session.scope.scan_targets())),
            site_label=label or (existing.site_label if existing else self.session.intake.site),
            business_unit=(existing.business_unit if existing else (self.session.scope.business_unit or self.session.intake.business_unit)),
            directory_site=existing.directory_site if existing else "",
            directory_ou=existing.directory_ou if existing else "",
            discovery_source=source,
            first_seen=existing.first_seen if existing else now,
            last_seen=now,
            assessment_status=existing.assessment_status if existing else "discovery_only",
            collector_status=existing.collector_status if existing else "not_started",
            error_state=existing.error_state if existing else "",
        )
        record = self.classify_asset(
            record,
            discovery_ports=network_asset.service_ports,
            metadata_source=source,
        )
        self.upsert(record)
        self.session.database.replace_asset_services(
            record.asset_id,
            [service.to_dict() for service in network_asset.services],
            source=source,
        )
        return record

    def record_directory_asset(self, computer: dict[str, Any], domain_controllers: set[str]) -> AssetRecord:
        hostname = str(computer.get("Name", "")).strip()
        fqdn = str(computer.get("DNSHostName", "")).strip() or hostname
        address = str(computer.get("IPv4Address", "")).strip()
        existing = self.find_asset(address or fqdn or hostname)
        dn = str(computer.get("DistinguishedName", "")).strip()
        directory_site = str(computer.get("Site", "")).strip()
        role_hint = "domain_controller" if fqdn.lower() in domain_controllers or hostname.lower() in domain_controllers else ""
        record = AssetRecord(
            asset_id=existing.asset_id if existing else build_asset_id(address or fqdn or hostname),
            hostname=hostname or (existing.hostname if existing else ""),
            fqdn=fqdn or (existing.fqdn if existing else ""),
            ip_address=address or (existing.ip_address if existing else ""),
            mac_address=existing.mac_address if existing else "",
            os_family=str(computer.get("OperatingSystem", "")).strip() or (existing.os_family if existing else ""),
            os_guess=str(computer.get("OperatingSystem", "")).strip() or (existing.os_guess if existing else ""),
            asset_type=(existing.asset_type if existing else "unknown"),
            asset_role=role_hint or (existing.asset_role if existing else "unknown"),
            role_source="ad_derived" if role_hint else (existing.role_source if existing else ""),
            criticality=(existing.criticality if existing else "medium"),
            criticality_source=(existing.criticality_source if existing else "default"),
            subnet_label=existing.subnet_label if existing else _subnet_from_scope(address, self.session.scope.scan_targets()),
            site_label=directory_site or (existing.site_label if existing else self.session.intake.site),
            business_unit=(existing.business_unit if existing else (self.session.scope.business_unit or self.session.intake.business_unit)),
            directory_site=directory_site or (existing.directory_site if existing else ""),
            directory_ou=_ou_from_dn(dn),
            discovery_source="active_directory",
            first_seen=existing.first_seen if existing else utc_now(),
            last_seen=utc_now(),
            assessment_status=existing.assessment_status if existing else "imported_evidence_only",
            collector_status=existing.collector_status if existing else "directory_only",
            error_state=existing.error_state if existing else "",
        )
        record = self.classify_asset(
            record,
            metadata_source="active_directory",
            operating_system=str(computer.get("OperatingSystem", "")),
        )
        self.upsert(record)
        return record

    def record_imported_asset(
        self,
        *,
        hostname: str = "",
        ip_address: str = "",
        role_hint: str = "",
        criticality_hint: str = "",
        source: str,
        site_label: str = "",
        business_unit: str = "",
    ) -> AssetRecord:
        existing = self.find_asset(ip_address or hostname)
        record = AssetRecord(
            asset_id=existing.asset_id if existing else build_asset_id(ip_address or hostname),
            hostname=hostname or (existing.hostname if existing else ""),
            fqdn=existing.fqdn if existing else hostname,
            ip_address=ip_address or (existing.ip_address if existing else ""),
            mac_address=existing.mac_address if existing else "",
            os_family=existing.os_family if existing else "",
            os_guess=existing.os_guess if existing else "",
            asset_type=existing.asset_type if existing else "unknown",
            asset_role=role_hint or (existing.asset_role if existing else "unknown"),
            role_source="imported_metadata" if role_hint else (existing.role_source if existing else ""),
            criticality=criticality_hint or (existing.criticality if existing else "medium"),
            criticality_source="imported_metadata" if criticality_hint else (existing.criticality_source if existing else "default"),
            subnet_label=existing.subnet_label if existing else _subnet_from_scope(ip_address, self.session.scope.scan_targets()),
            site_label=site_label or (existing.site_label if existing else self.session.intake.site),
            business_unit=business_unit or (existing.business_unit if existing else (self.session.scope.business_unit or self.session.intake.business_unit)),
            directory_site=existing.directory_site if existing else "",
            directory_ou=existing.directory_ou if existing else "",
            discovery_source=source,
            first_seen=existing.first_seen if existing else utc_now(),
            last_seen=utc_now(),
            assessment_status=existing.assessment_status if existing else "imported_evidence_only",
            collector_status=existing.collector_status if existing else "import_only",
            error_state=existing.error_state if existing else "",
        )
        record = self.classify_asset(record, metadata_source=source)
        self.upsert(record)
        return record

    def classify_asset(
        self,
        asset: AssetRecord,
        *,
        discovery_ports: list[int] | None = None,
        metadata_source: str = "",
        operating_system: str = "",
    ) -> AssetRecord:
        role_override = _mapping_match(self.config.asset_classification.role_overrides, asset)
        if role_override:
            asset.asset_role = role_override
            asset.role_source = "operator_provided"
        elif asset.asset_role and asset.asset_role != "unknown" and asset.role_source in {
            "imported_metadata",
            "operator_provided",
            "ad_derived",
        }:
            asset.role_source = asset.role_source or "imported_metadata"
        elif asset.asset_role == "domain_controller":
            asset.role_source = asset.role_source or "ad_derived"
        else:
            guessed = _guess_asset_role(
                asset=asset,
                discovery_ports=discovery_ports or [],
                operating_system=operating_system or asset.os_guess or asset.os_family,
                metadata_source=metadata_source or asset.discovery_source,
            )
            asset.asset_role = guessed["role"]
            asset.role_source = guessed["source"]
        asset.asset_type = asset.asset_role if asset.asset_role != "domain_controller" else "server"

        criticality_override = _criticality_for_asset(self.config, asset)
        if criticality_override:
            asset.criticality = criticality_override["criticality"]
            asset.criticality_source = criticality_override["source"]
        elif asset.criticality and asset.criticality != "medium" and asset.criticality_source in {
            "imported_metadata",
            "operator_provided",
            "ad_derived",
        }:
            asset.criticality_source = asset.criticality_source or "imported_metadata"
        elif asset.asset_role == "domain_controller":
            asset.criticality = "critical"
            asset.criticality_source = "ad_derived"
        else:
            asset.criticality = _default_criticality(asset.asset_role)
            asset.criticality_source = asset.criticality_source or "naming_subnet_heuristic"

        if asset.directory_site and not asset.site_label:
            asset.site_label = asset.directory_site
        if asset.directory_ou and not asset.business_unit:
            asset.business_unit = _business_unit_from_ou(asset.directory_ou)
        return asset

    def enrich_finding(self, finding: Finding) -> Finding:
        asset = self.find_asset(finding.asset)
        if not asset:
            return finding
        finding.asset_role = asset.asset_role
        finding.asset_criticality = asset.criticality
        finding.asset_classification_source = (
            asset.criticality_source if asset.criticality_source == "operator_provided" else asset.role_source or asset.criticality_source
        )
        return finding

    def upsert(self, asset: AssetRecord) -> None:
        self.session.database.upsert_asset(asset.to_db_payload())

    def attach_evidence(self, asset_id: str, evidence_path: str, source_module: str) -> None:
        self.session.database.add_asset_evidence(asset_id, evidence_path, source_module)

    def mark_status(
        self,
        asset_id: str,
        *,
        assessment_status: str | None = None,
        collector_status: str | None = None,
        error_state: str | None = None,
    ) -> None:
        current = self.session.database.get_asset_by_id(asset_id) or {
            "asset_id": asset_id,
            "hostname": "",
            "fqdn": "",
            "ip_address": "",
            "mac_address": "",
            "os_family": "",
            "os_guess": "",
            "asset_type": "unknown",
            "asset_role": "unknown",
            "role_source": "",
            "criticality": "medium",
            "criticality_source": "default",
            "subnet_label": "",
            "site_label": "",
            "business_unit": "",
            "directory_site": "",
            "directory_ou": "",
            "discovery_source": "",
            "first_seen": utc_now(),
            "last_seen": utc_now(),
            "assessment_status": "discovery_only",
            "collector_status": "not_started",
            "error_state": "",
        }
        payload = dict(current)
        payload["assessment_status"] = assessment_status or payload.get("assessment_status", "discovery_only")
        payload["collector_status"] = collector_status or payload.get("collector_status", "not_started")
        payload["error_state"] = error_state if error_state is not None else payload.get("error_state", "")
        payload["last_seen"] = utc_now()
        self.session.database.upsert_asset(payload)

    def find_asset(self, key: str) -> AssetRecord | None:
        if not key.strip():
            return None
        row = self.session.database.get_asset_by_address(key.strip()) or self.session.database.get_asset_by_id(key.strip())
        if not row:
            for asset in self.list_assets():
                aliases = {asset.asset_id, asset.hostname, asset.fqdn, asset.ip_address, asset.display_name}
                if key.strip().lower() in {value.strip().lower() for value in aliases if value.strip()}:
                    return asset
            return None
        evidence_refs = [
            str(item.get("evidence_path", ""))
            for item in self.session.database.list_asset_evidence(str(row.get("asset_id", "")))
        ]
        return AssetRecord.from_row(row, evidence_references=evidence_refs)

    def list_assets(self) -> list[AssetRecord]:
        evidence_map: dict[str, list[str]] = {}
        for row in self.session.database.list_asset_evidence():
            evidence_map.setdefault(str(row.get("asset_id", "")), []).append(str(row.get("evidence_path", "")))
        return [
            AssetRecord.from_row(row, evidence_references=evidence_map.get(str(row.get("asset_id", "")), []))
            for row in self.session.database.list_assets()
        ]

    def coverage_summary(self) -> dict[str, Any]:
        assets = self.list_assets()
        totals = {
            "total_assets": len(assets),
            "assessed": 0,
            "partial": 0,
            "unreachable": 0,
            "discovery_only": 0,
            "imported_evidence_only": 0,
            "not_started": 0,
        }
        by_site: dict[str, dict[str, int]] = {}
        by_subnet: dict[str, dict[str, int]] = {}
        by_role: dict[str, int] = {}
        by_criticality: dict[str, int] = {}
        for asset in assets:
            status = asset.assessment_status or "not_started"
            totals[status] = totals.get(status, 0) + 1
            by_role[asset.asset_role] = by_role.get(asset.asset_role, 0) + 1
            by_criticality[asset.criticality] = by_criticality.get(asset.criticality, 0) + 1
            if asset.site_label:
                bucket = by_site.setdefault(asset.site_label, _status_bucket())
                bucket[status] = bucket.get(status, 0) + 1
            if asset.subnet_label:
                bucket = by_subnet.setdefault(asset.subnet_label, _status_bucket())
                bucket[status] = bucket.get(status, 0) + 1
        return {
            **totals,
            "sites": dict(sorted((key, sum(value.values())) for key, value in by_site.items())),
            "subnets": dict(sorted((key, sum(value.values())) for key, value in by_subnet.items())),
            "by_site": dict(sorted(by_site.items())),
            "by_subnet": dict(sorted(by_subnet.items())),
            "by_role": dict(sorted(by_role.items())),
            "by_criticality": dict(sorted(by_criticality.items())),
        }


def build_asset_id(value: str) -> str:
    normalized = value.strip().lower() or "unknown-asset"
    return "asset-" + hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]


def _first_profile_address(profile: EnvironmentProfile) -> str:
    for interface in profile.network_interfaces:
        ipv4 = interface.get("ipv4")
        if isinstance(ipv4, dict) and ipv4.get("IPAddress"):
            return str(ipv4["IPAddress"])
        if isinstance(ipv4, list):
            for item in ipv4:
                if isinstance(item, dict) and item.get("IPAddress"):
                    return str(item["IPAddress"])
    return ""


def _guess_asset_type(os_hint: str, hostname: str, ports: list[int]) -> str:
    return _guess_asset_role(
        asset=AssetRecord(asset_id="temp", hostname=hostname, os_guess=os_hint),
        discovery_ports=ports,
        operating_system=os_hint,
        metadata_source="naming_subnet_heuristic",
    )["role"]


def _guess_asset_role(
    *,
    asset: AssetRecord,
    discovery_ports: list[int],
    operating_system: str,
    metadata_source: str,
) -> dict[str, str]:
    hint = f"{operating_system} {asset.hostname} {asset.fqdn}".lower()
    if any(token in hint for token in ["domain controller", "domaincontrollers", "ou=domain controllers"]):
        return {"role": "domain_controller", "source": "ad_derived"}
    if any(token in hint for token in ["dc-", "-dc", "dc0", "dc1"]) and "windows" in hint:
        return {"role": "domain_controller", "source": "naming_subnet_heuristic"}
    if any(token in hint for token in ["server", "srv", "sql", "exchange", "hyper-v"]):
        return {"role": "server", "source": "naming_subnet_heuristic"}
    if any(token in hint for token in ["switch", "router", "firewall", "ap", "printer", "vpn"]):
        return {"role": "network_device", "source": "naming_subnet_heuristic"}
    if any(port in discovery_ports for port in [22, 443, 5985, 5986, 3389, 445]) and metadata_source in {"nmap", "nessus", "greenbone"}:
        return {"role": "server", "source": "imported_scanner_metadata"}
    if "windows" in hint:
        return {"role": "workstation", "source": "naming_subnet_heuristic"}
    return {"role": "unknown", "source": "naming_subnet_heuristic"}


def _criticality_for_asset(config: AppConfig, asset: AssetRecord) -> dict[str, str] | None:
    targets = {asset.hostname.lower(), asset.fqdn.lower(), asset.ip_address.lower(), asset.asset_id.lower()}
    for item in config.asset_classification.critical_assets:
        if item.strip().lower() in targets:
            return {"criticality": "critical", "source": "operator_provided"}
    asset_override = _mapping_match(config.asset_classification.criticality_by_asset, asset)
    if asset_override:
        return {"criticality": asset_override, "source": "operator_provided"}
    for subnet, criticality in config.asset_classification.criticality_by_subnet.items():
        try:
            candidate = ipaddress.ip_network(subnet, strict=False)
            if asset.ip_address and ipaddress.ip_address(asset.ip_address) in candidate:
                return {"criticality": criticality, "source": "operator_provided"}
        except ValueError:
            continue
    if asset.site_label:
        site_value = config.asset_classification.criticality_by_site.get(asset.site_label)
        if site_value:
            return {"criticality": site_value, "source": "operator_provided"}
    return None


def _default_criticality(role: str) -> str:
    return {
        "domain_controller": "critical",
        "server": "high",
        "network_device": "high",
        "workstation": "medium",
    }.get(role, "medium")


def _mapping_match(mapping: dict[str, str], asset: AssetRecord) -> str:
    targets = {
        asset.hostname.lower(),
        asset.fqdn.lower(),
        asset.ip_address.lower(),
        asset.asset_id.lower(),
    }
    for key, value in mapping.items():
        if key.strip().lower() in targets:
            return value
    return ""


def _subnet_from_scope(address: str, networks: list[str]) -> str:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ""
    for network in networks:
        try:
            candidate = ipaddress.ip_network(network, strict=False)
        except ValueError:
            continue
        if ip in candidate:
            return network
    return ""


def _ou_from_dn(distinguished_name: str) -> str:
    if not distinguished_name:
        return ""
    parts = [part[3:] for part in distinguished_name.split(",") if part.upper().startswith("OU=")]
    return "/".join(reversed(parts))


def _business_unit_from_ou(directory_ou: str) -> str:
    if not directory_ou:
        return ""
    return directory_ou.split("/")[0]


def _status_bucket() -> dict[str, int]:
    return {
        "assessed": 0,
        "partial": 0,
        "unreachable": 0,
        "discovery_only": 0,
        "imported_evidence_only": 0,
    }
