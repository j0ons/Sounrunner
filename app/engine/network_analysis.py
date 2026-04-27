"""Enterprise network posture analysis from read-only evidence."""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.core.config import AppConfig
from app.core.evidence import confidence_for_basis, utc_now
from app.core.inventory import AssetInventory, AssetRecord
from app.core.models import Finding
from app.core.network_models import (
    ClassifiedNetworkService,
    FirewallRule,
    FirewallVpnEvidence,
    NetworkAssessmentSummary,
    NetworkScore,
    SegmentationObservation,
    ServiceCategory,
)
from app.core.session import AssessmentSession


REMOTE_ADMIN_PORTS = {22, 3389, 5985, 5986, 5900}
FILE_SHARING_PORTS = {445, 139, 2049, 21}
DIRECTORY_PORTS = {53, 88, 389, 636, 3268, 3269, 445}
WEB_ADMIN_PORTS = {80, 443, 8080, 8443, 8000, 9443}
INSECURE_PORTS = {21, 23, 80, 110, 143, 161}
NETWORK_INFRA_PORTS = {22, 23, 80, 443, 161, 830}
BACKUP_STORAGE_PORTS = {2049, 445, 548, 873, 10000, 9392}
NETWORK_DEVICE_TOKENS = {
    "fw": "firewall",
    "firewall": "firewall",
    "router": "router",
    "rtr": "router",
    "switch": "switch",
    "sw": "switch",
    "core": "switch",
    "wlc": "wireless_controller",
    "wlan": "wireless_controller",
    "ap": "access_point",
    "printer": "printer",
    "nas": "storage",
    "storage": "storage",
}


def classify_service(
    *,
    port: int,
    service_name: str = "",
    product: str = "",
    asset_role: str = "",
) -> tuple[ServiceCategory, str]:
    """Classify an observed service without claiming exploitability."""

    blob = f"{service_name} {product} {asset_role}".lower()
    if port in {23, 21, 110, 143} or "telnet" in blob or "ftp" == service_name.lower():
        return "insecure_cleartext", "strong"
    if port == 161 or "snmp" in blob:
        return "insecure_cleartext", "weak"
    if port in REMOTE_ADMIN_PORTS or any(token in blob for token in ["ssh", "rdp", "winrm", "vnc"]):
        return "remote_admin", "strong"
    if port in {445, 139, 2049} or any(token in blob for token in ["microsoft-ds", "smb", "nfs"]):
        return "file_sharing", "strong"
    if port in {53, 88, 389, 636, 3268, 3269} or any(token in blob for token in ["ldap", "kerberos", "domain"]):
        return "directory_identity", "strong"
    if port in {1433, 3306, 5432, 6379, 27017, 9200} or any(
        token in blob for token in ["mysql", "postgres", "mssql", "mongodb", "redis", "elasticsearch"]
    ):
        return "database", "strong"
    if port in WEB_ADMIN_PORTS or "http" in blob:
        return "web_admin", "weak"
    if port in NETWORK_INFRA_PORTS and asset_role == "network_device":
        return "network_infrastructure", "weak"
    if port in BACKUP_STORAGE_PORTS or any(token in blob for token in ["backup", "nas", "storage"]):
        return "backup_storage", "weak"
    return "unknown_exposed", "weak"


def build_network_assessment_summary(
    *,
    session: AssessmentSession,
    config: AppConfig,
    inventory: AssetInventory,
) -> NetworkAssessmentSummary:
    """Build topology, service, segmentation, and score summaries."""

    assets = {asset.asset_id: asset for asset in inventory.list_assets()}
    services: list[ClassifiedNetworkService] = []
    for row in session.database.list_asset_services():
        asset = assets.get(str(row.get("asset_id", "")))
        if not asset:
            continue
        category, confidence = classify_service(
            port=int(row.get("port", 0)),
            service_name=str(row.get("service_name", "")),
            product=str(row.get("product", "")),
            asset_role=asset.asset_role,
        )
        services.append(
            ClassifiedNetworkService(
                asset_id=asset.asset_id,
                asset=asset.display_name,
                ip_address=asset.ip_address,
                hostname=asset.hostname or asset.fqdn,
                subnet=asset.subnet_label,
                site=asset.site_label or asset.business_unit,
                asset_role=asset.asset_role,
                asset_criticality=asset.criticality,
                protocol=str(row.get("protocol", "")) or "tcp",
                port=int(row.get("port", 0)),
                service_name=str(row.get("service_name", "")),
                product=str(row.get("product", "")),
                version=str(row.get("version", "")),
                category=category,
                confidence=confidence,
                evidence_source=str(row.get("source", "asset_services")),
            )
        )

    network_devices = _network_device_inventory(assets.values(), services)
    if config.network_assessment.classify_network_devices:
        _apply_network_device_classification(inventory, assets, network_devices)

    firewall_evidence = load_firewall_vpn_evidence(session)
    segmentation = (
        infer_segmentation_observations(assets.values(), services, firewall_evidence)
        if config.network_assessment.infer_segmentation
        else []
    )
    services_by_category = dict(Counter(service.category for service in services))
    assessed_subnets = _assessed_subnets(assets.values())
    score = calculate_network_score(
        services=services,
        segmentation_observations=segmentation,
        firewall_evidence=firewall_evidence,
        assets=list(assets.values()),
    )
    return NetworkAssessmentSummary(
        scope=session.scope.scan_targets(),
        scan_profile=config.network_assessment.profile,
        assessed_subnets=assessed_subnets,
        services_by_category=services_by_category,
        services=services,
        management_exposures=[
            service for service in services if service.category in {"remote_admin", "web_admin"}
        ],
        insecure_protocols=[service for service in services if service.category == "insecure_cleartext"],
        network_devices=network_devices,
        segmentation_observations=segmentation,
        firewall_evidence=firewall_evidence,
        network_score=score,
    )


def build_network_findings(
    *,
    summary: NetworkAssessmentSummary,
    package: str,
    evidence_path: Path,
) -> list[Finding]:
    """Normalize network posture findings from observed and imported evidence."""

    findings: list[Finding] = []
    collected_at = utc_now()
    findings.extend(_management_exposure_findings(summary, package, evidence_path, collected_at))
    findings.extend(_insecure_protocol_findings(summary, package, evidence_path, collected_at))
    findings.extend(_segmentation_findings(summary, package, evidence_path, collected_at))
    findings.extend(_firewall_config_findings(summary, package, evidence_path, collected_at))
    return findings


def infer_segmentation_observations(
    assets: Any,
    services: list[ClassifiedNetworkService],
    firewall_evidence: list[FirewallVpnEvidence],
) -> list[SegmentationObservation]:
    """Infer segmentation posture without claiming confirmed config issues."""

    observations: list[SegmentationObservation] = []
    by_subnet: dict[str, list[ClassifiedNetworkService]] = defaultdict(list)
    asset_by_subnet: dict[str, list[AssetRecord]] = defaultdict(list)
    for asset in assets:
        subnet = asset.subnet_label or "unlabeled"
        asset_by_subnet[subnet].append(asset)
    for service in services:
        by_subnet[service.subnet or "unlabeled"].append(service)

    for subnet, subnet_assets in sorted(asset_by_subnet.items()):
        roles = {asset.asset_role for asset in subnet_assets}
        subnet_services = by_subnet.get(subnet, [])
        management_count = sum(1 for service in subnet_services if service.category == "remote_admin")
        server_services_on_workstations = [
            service for service in subnet_services if service.category in {"database", "directory_identity"} and service.asset_role in {"workstation", "unknown"}
        ]
        mixed_critical = any(asset.criticality in {"critical", "high"} for asset in subnet_assets) and any(
            asset.asset_role == "workstation" for asset in subnet_assets
        )
        if len(roles & {"server", "domain_controller"}) > 0 and "workstation" in roles and management_count:
            observations.append(
                SegmentationObservation(
                    observation_id=f"SEG-FLAT-{_safe_id(subnet)}",
                    title="Inferred flat network or weak zone separation",
                    subnet=subnet,
                    site=_first_site(subnet_assets),
                    evidence_type="inferred_network_posture",
                    confidence="weak",
                    summary=(
                        f"{subnet} contains workstation and server/DC-like assets with "
                        f"{management_count} observed remote management service(s)."
                    ),
                    supporting_assets=[asset.display_name for asset in subnet_assets[:10]],
                    recommended_action="Validate VLAN/ACL design and restrict management services to an admin segment.",
                )
            )
        if server_services_on_workstations:
            observations.append(
                SegmentationObservation(
                    observation_id=f"SEG-SERVER-SVC-{_safe_id(subnet)}",
                    title="Inferred server services on workstation or unknown subnet",
                    subnet=subnet,
                    site=_first_site(subnet_assets),
                    evidence_type="inferred_network_posture",
                    confidence="weak",
                    summary=(
                        f"{len(server_services_on_workstations)} database or directory service(s) "
                        "were observed on workstation/unknown assets."
                    ),
                    supporting_assets=[service.asset for service in server_services_on_workstations[:10]],
                    recommended_action="Validate asset role and move server services into controlled server segments if confirmed.",
                )
            )
        if mixed_critical:
            observations.append(
                SegmentationObservation(
                    observation_id=f"SEG-CRIT-MIX-{_safe_id(subnet)}",
                    title="Inferred critical assets mixed with user endpoint network",
                    subnet=subnet,
                    site=_first_site(subnet_assets),
                    evidence_type="inferred_network_posture",
                    confidence="weak",
                    summary="Critical or high-value assets appear in the same subnet as workstation assets.",
                    supporting_assets=[asset.display_name for asset in subnet_assets[:10]],
                    recommended_action="Validate business role and isolate critical systems from user endpoint VLANs where practical.",
                )
            )

    if firewall_evidence:
        for evidence in firewall_evidence:
            for rule in evidence.rules:
                if rule.management_exposure or rule.any_any:
                    observations.append(
                        SegmentationObservation(
                            observation_id=f"SEG-CFG-{_safe_id(rule.device_name or rule.rule_name)}",
                            title="Confirmed broad management or any-any policy from imported configuration",
                            subnet=rule.destination or rule.destination_zone or "configuration-import",
                            site=rule.zone_or_interface,
                            evidence_type="confirmed_network_configuration",
                            confidence="strong",
                            summary=(
                                f"Imported rule {rule.rule_name or rule.rule_id or 'unknown'} "
                                f"allows {rule.service or rule.port or 'unspecified service'} from "
                                f"{rule.source or rule.source_zone or 'unknown source'}."
                            ),
                            supporting_assets=[rule.device_name] if rule.device_name else [],
                            recommended_action="Review and narrow the imported firewall/VPN rule to approved sources, destinations, and services.",
                        )
                    )
    return observations


def calculate_network_score(
    *,
    services: list[ClassifiedNetworkService],
    segmentation_observations: list[SegmentationObservation],
    firewall_evidence: list[FirewallVpnEvidence],
    assets: list[AssetRecord],
) -> NetworkScore:
    """Calculate a defensible posture score from available evidence."""

    score = 100
    key_drivers: list[str] = []
    top_actions: list[str] = []
    management = [service for service in services if service.category in {"remote_admin", "web_admin"}]
    insecure = [service for service in services if service.category == "insecure_cleartext"]
    critical_management = [
        service for service in management if service.asset_criticality in {"critical", "high"}
    ]
    if management:
        penalty = min(25, 3 + len(management))
        score -= penalty
        key_drivers.append(f"{len(management)} management-plane service exposure(s) observed.")
        top_actions.append("Restrict RDP/SSH/WinRM/web admin access to an approved management subnet or jump host.")
    if insecure:
        penalty = min(20, 5 + len(insecure) * 2)
        score -= penalty
        key_drivers.append(f"{len(insecure)} insecure cleartext or weak management service(s) observed.")
        top_actions.append("Disable Telnet/FTP and replace weak SNMP exposure with SNMPv3 or restricted monitoring paths.")
    if segmentation_observations:
        inferred = [item for item in segmentation_observations if item.evidence_type == "inferred_network_posture"]
        confirmed = [item for item in segmentation_observations if item.evidence_type == "confirmed_network_configuration"]
        score -= min(15, len(inferred) * 3)
        score -= min(20, len(confirmed) * 8)
        key_drivers.append(
            f"{len(inferred)} inferred and {len(confirmed)} confirmed segmentation/configuration observation(s)."
        )
        top_actions.append("Validate VLAN/ACL boundaries and enforce explicit segmentation between user, server, and management zones.")
    if critical_management:
        score -= min(10, len(critical_management) * 2)
        key_drivers.append(f"{len(critical_management)} management exposure(s) involve high/critical assets.")
        top_actions.append("Prioritize management-plane restrictions on critical and high-value systems.")
    if not firewall_evidence:
        key_drivers.append("Firewall/VPN configuration evidence was not provided; segmentation is inferred, not confirmed.")
        top_actions.append("Import firewall/VPN configuration evidence to confirm ACL and zone posture.")
    if not services and assets:
        key_drivers.append("Asset inventory exists but no open services were recorded for network analysis.")
    confidence = "strong" if firewall_evidence else ("weak" if segmentation_observations else "strong")
    final_score = max(0, min(100, score))
    explanation = (
        "Score reflects observed exposure and imported configuration evidence. "
        "Missing firewall/VPN evidence lowers confidence but is not treated as confirmed failure."
    )
    return NetworkScore(
        network_score=final_score,
        confidence=confidence,
        key_drivers=key_drivers,
        top_actions=_dedupe(top_actions)[:10],
        explanation=explanation,
    )


def load_firewall_vpn_evidence(session: AssessmentSession) -> list[FirewallVpnEvidence]:
    """Load normalized firewall/VPN evidence persisted by the import module."""

    payload = session.database.get_metadata("firewall_vpn_normalized", [])
    if not isinstance(payload, list):
        return []
    evidence_items: list[FirewallVpnEvidence] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        rules = []
        for rule in item.get("rules", []):
            if not isinstance(rule, dict):
                continue
            rules.append(FirewallRule(**{key: rule.get(key) for key in FirewallRule.__dataclass_fields__ if key in rule}))
        evidence_items.append(
            FirewallVpnEvidence(
                source_path=str(item.get("source_path", "")),
                rules=rules,
                partial=bool(item.get("partial", False)),
                warnings=[str(warning) for warning in item.get("warnings", [])],
            )
        )
    return evidence_items


def _management_exposure_findings(
    summary: NetworkAssessmentSummary,
    package: str,
    evidence_path: Path,
    collected_at: str,
) -> list[Finding]:
    findings: list[Finding] = []
    by_port: dict[int, list[ClassifiedNetworkService]] = defaultdict(list)
    for service in summary.management_exposures:
        by_port[service.port].append(service)
    for port, services in sorted(by_port.items()):
        if len(services) < 2 and port not in {23, 3389, 5985, 5986}:
            continue
        label = _port_label(port)
        severity = "high" if port in {23, 3389} or len(services) >= 10 else "medium"
        findings.append(
            _finding(
                finding_id=f"NET-MGMT-{port}",
                title=f"{label} management-plane exposure observed across approved scope",
                category="Network Assessment",
                package=package,
                severity=severity,
                confidence=confidence_for_basis("network_discovery_evidence"),
                asset="organization",
                evidence_summary=(
                    f"{label} was observed on {len(services)} asset(s): "
                    + ", ".join(service.asset for service in services[:8])
                ),
                evidence_files=[str(evidence_path)],
                why_it_matters="Broadly reachable management services increase the practical attack surface if credentials or host controls fail.",
                impact="Attackers can focus on reachable administration paths for credential replay, remote access attempts, and operational disruption.",
                remediation=[
                    "Restrict management services to approved admin VLANs, jump hosts, or VPN source ranges.",
                    "Disable unused management listeners on endpoints and servers.",
                    "Monitor management service access centrally.",
                ],
                validation=[
                    "Re-run approved-scope discovery and confirm management services are only reachable from approved admin networks.",
                    "Validate firewall ACLs or host firewall policy from configuration evidence.",
                ],
                evidence_source_type="network_assessment",
                finding_basis="network_discovery_evidence",
                collected_at=collected_at,
                raw_evidence_path=str(evidence_path),
            )
        )
    smb_workstations = [
        service for service in summary.services if service.port in {139, 445} and service.asset_role in {"workstation", "unknown"}
    ]
    if len(smb_workstations) >= 3:
        findings.append(
            _finding(
                finding_id="NET-SMB-WORKSTATION-BROAD",
                title="SMB/file-sharing exposure observed across workstation or unknown assets",
                category="Network Assessment",
                package=package,
                severity="medium",
                confidence=confidence_for_basis("network_discovery_evidence"),
                asset="organization",
                evidence_summary=f"SMB/NetBIOS was observed on {len(smb_workstations)} workstation or unknown asset(s).",
                evidence_files=[str(evidence_path)],
                why_it_matters="Broad SMB reachability across endpoints increases exposure to credential abuse and file-sharing risk if controls fail.",
                impact="Weak segmentation or host firewall policy can make endpoint compromise paths easier to scale.",
                remediation=[
                    "Restrict SMB between user endpoints and only allow required server file-sharing paths.",
                    "Review workstation firewall policy and disable unnecessary file sharing.",
                ],
                validation=[
                    "Confirm SMB is no longer broadly reachable between workstation ranges.",
                ],
                evidence_source_type="network_assessment",
                finding_basis="network_discovery_evidence",
                collected_at=collected_at,
                raw_evidence_path=str(evidence_path),
            )
        )
    database_non_server = [
        service for service in summary.services if service.category == "database" and service.asset_role not in {"server", "domain_controller"}
    ]
    if database_non_server:
        findings.append(
            _finding(
                finding_id="NET-DB-NONSERVER-EXPOSURE",
                title="Database services observed outside clear server roles",
                category="Network Assessment",
                package=package,
                severity="medium",
                confidence=confidence_for_basis("network_discovery_evidence"),
                asset="organization",
                evidence_summary=f"{len(database_non_server)} database service(s) were observed on non-server or unknown-role assets.",
                evidence_files=[str(evidence_path)],
                why_it_matters="Database listeners on unexpected assets can indicate weak service placement or incomplete segmentation.",
                impact="Sensitive data services may be reachable from broader network zones than intended.",
                remediation=[
                    "Validate asset ownership and move database services to approved server subnets.",
                    "Restrict database ports to application servers and admin networks only.",
                ],
                validation=[
                    "Confirm database ports are not reachable from unauthorized user or workstation subnets.",
                ],
                evidence_source_type="network_assessment",
                finding_basis="network_discovery_evidence",
                collected_at=collected_at,
                raw_evidence_path=str(evidence_path),
            )
        )
    return findings


def _insecure_protocol_findings(
    summary: NetworkAssessmentSummary,
    package: str,
    evidence_path: Path,
    collected_at: str,
) -> list[Finding]:
    findings: list[Finding] = []
    by_port: dict[int, list[ClassifiedNetworkService]] = defaultdict(list)
    for service in summary.insecure_protocols:
        by_port[service.port].append(service)
    for port, services in sorted(by_port.items()):
        severity = "high" if port == 23 else "medium"
        findings.append(
            _finding(
                finding_id=f"NET-INSECURE-{port}",
                title=f"{_port_label(port)} insecure or weak protocol exposure observed",
                category="Network Assessment",
                package=package,
                severity=severity,
                confidence=confidence_for_basis("network_discovery_evidence"),
                asset="organization",
                evidence_summary=(
                    f"{_port_label(port)} was observed on {len(services)} asset(s): "
                    + ", ".join(service.asset for service in services[:8])
                ),
                evidence_files=[str(evidence_path)],
                why_it_matters="Cleartext or weak management protocols can expose credentials or sensitive operational data.",
                impact="If reachable by unauthorized systems, these services create avoidable compromise paths.",
                remediation=[
                    "Disable the service if not required.",
                    "Replace with encrypted alternatives and restrict source networks where required.",
                    "Use SNMPv3 and restricted monitoring paths for network monitoring.",
                ],
                validation=[
                    "Re-run approved discovery and confirm the insecure service is closed or source-restricted.",
                ],
                evidence_source_type="network_assessment",
                finding_basis="network_discovery_evidence",
                collected_at=collected_at,
                raw_evidence_path=str(evidence_path),
            )
        )
    return findings


def _segmentation_findings(
    summary: NetworkAssessmentSummary,
    package: str,
    evidence_path: Path,
    collected_at: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for observation in summary.segmentation_observations:
        basis = (
            "imported_configuration_evidence"
            if observation.evidence_type == "confirmed_network_configuration"
            else "inferred_partial"
        )
        findings.append(
            _finding(
                finding_id=observation.observation_id,
                title=observation.title,
                category="Network Segmentation",
                package=package,
                severity="high" if basis == "imported_configuration_evidence" else "medium",
                confidence=observation.confidence,
                asset=observation.subnet or "organization",
                evidence_summary=observation.summary,
                evidence_files=[str(evidence_path)],
                why_it_matters="Segmentation controls limit attacker movement and reduce blast radius when an endpoint or service is compromised.",
                impact="Weak or flat segmentation can let a single access point expose broader server, admin, or critical asset zones.",
                remediation=[
                    observation.recommended_action or "Validate VLAN/ACL boundaries and enforce zone-specific access controls.",
                ],
                validation=[
                    "Confirm segmentation posture with firewall/router/switch configuration evidence.",
                    "Re-run approved discovery from allowed vantage points after ACL changes.",
                ],
                evidence_source_type=(
                    "firewall_vpn_import" if basis == "imported_configuration_evidence" else "network_assessment_inference"
                ),
                finding_basis=basis,
                collected_at=collected_at,
                raw_evidence_path=str(evidence_path),
            )
        )
    return findings


def _firewall_config_findings(
    summary: NetworkAssessmentSummary,
    package: str,
    evidence_path: Path,
    collected_at: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for evidence in summary.firewall_evidence:
        for rule in evidence.rules:
            if not any([rule.any_any, rule.broad_inbound, rule.management_exposure, rule.admin_interface_exposure]):
                continue
            rule_name = rule.rule_name or rule.rule_id or "unnamed rule"
            findings.append(
                _finding(
                    finding_id=f"NET-FW-{_safe_id(rule.device_name)}-{_safe_id(rule_name)}",
                    title="Confirmed broad firewall/VPN policy from imported configuration evidence",
                    category="Network Configuration",
                    package=package,
                    severity="high" if rule.any_any or rule.management_exposure else "medium",
                    confidence=confidence_for_basis("imported_configuration_evidence"),
                    asset=rule.device_name or "firewall-vpn-policy",
                    evidence_summary=(
                        f"Imported rule {rule_name} allows {rule.service or rule.port or 'unspecified service'} "
                        f"from {rule.source or rule.source_zone or 'unknown source'} to "
                        f"{rule.destination or rule.destination_zone or 'unknown destination'}."
                    ),
                    evidence_files=[evidence.source_path or str(evidence_path), str(evidence_path)],
                    why_it_matters="Broad allow policies and exposed management paths weaken segmentation and increase reachable attack surface.",
                    impact="Over-broad access rules can expose critical systems or management services beyond intended trust zones.",
                    remediation=[
                        "Replace broad allow rules with explicit source, destination, service, and logging requirements.",
                        "Restrict management services to approved admin networks or VPN groups.",
                    ],
                    validation=[
                        "Review the current firewall/VPN export and confirm broad rules have been narrowed or removed.",
                    ],
                    evidence_source_type="firewall_vpn_import",
                    finding_basis="imported_configuration_evidence",
                    collected_at=collected_at,
                    raw_evidence_path=evidence.source_path or str(evidence_path),
                )
            )
    return findings


def _network_device_inventory(
    assets: Any,
    services: list[ClassifiedNetworkService],
) -> list[dict[str, Any]]:
    service_map: dict[str, list[ClassifiedNetworkService]] = defaultdict(list)
    for service in services:
        service_map[service.asset_id].append(service)
    devices: list[dict[str, Any]] = []
    for asset in assets:
        services_for_asset = service_map.get(asset.asset_id, [])
        role = _network_device_role(asset, services_for_asset)
        if not role:
            continue
        devices.append(
            {
                "asset_id": asset.asset_id,
                "asset": asset.display_name,
                "ip_address": asset.ip_address,
                "role": role,
                "classification_source": "network_service_hostname_heuristic",
                "management_ports": sorted(
                    {
                        service.port
                        for service in services_for_asset
                        if service.category in {"remote_admin", "web_admin", "insecure_cleartext"}
                    }
                ),
            }
        )
    return devices


def _apply_network_device_classification(
    inventory: AssetInventory,
    assets: dict[str, AssetRecord],
    devices: list[dict[str, Any]],
) -> None:
    for device in devices:
        asset = assets.get(str(device.get("asset_id", "")))
        if not asset or asset.asset_role not in {"unknown", "server", "network_device"}:
            continue
        asset.asset_role = "network_device"
        asset.asset_type = "network_device"
        asset.role_source = str(device.get("classification_source", "network_service_hostname_heuristic"))
        asset.criticality = "high" if asset.criticality == "medium" else asset.criticality
        asset.criticality_source = asset.criticality_source or "network_service_hostname_heuristic"
        inventory.upsert(asset)


def _network_device_role(
    asset: AssetRecord,
    services: list[ClassifiedNetworkService],
) -> str:
    hint = f"{asset.hostname} {asset.fqdn} {asset.os_guess} {asset.os_family}".lower()
    hint_tokens = {token for token in "".join(char if char.isalnum() else " " for char in hint).split() if token}
    for token, role in NETWORK_DEVICE_TOKENS.items():
        if (len(token) <= 3 and token in hint_tokens) or (len(token) > 3 and token in hint):
            return role
    ports = {service.port for service in services}
    products = " ".join(service.product for service in services).lower()
    if any(token in products for token in ["router", "switch", "firewall", "cisco", "juniper", "fortinet", "palo alto"]):
        return "unknown_network_device"
    if {161, 22, 443} & ports and asset.asset_role == "network_device":
        return "unknown_network_device"
    if {161, 830} & ports and not any(service.category == "database" for service in services):
        return "unknown_network_device"
    return ""


def _assessed_subnets(assets: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for asset in assets:
        subnet = asset.subnet_label or _subnet_from_ip(asset.ip_address) or "unlabeled"
        counts[subnet] = counts.get(subnet, 0) + 1
    return dict(sorted(counts.items()))


def _subnet_from_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if ip.version != 4:
        return ""
    return f"{ipaddress.ip_network(f'{value}/24', strict=False)}"


def _first_site(assets: list[AssetRecord]) -> str:
    for asset in assets:
        if asset.site_label:
            return asset.site_label
    return ""


def _port_label(port: int) -> str:
    return {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS/SMB",
        143: "IMAP",
        161: "SNMP",
        443: "HTTPS",
        445: "SMB",
        5900: "VNC",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS",
        3389: "RDP",
    }.get(port, f"TCP/{port}")


def _finding(
    *,
    finding_id: str,
    title: str,
    category: str,
    package: str,
    severity: str,
    confidence: str,
    asset: str,
    evidence_summary: str,
    evidence_files: list[str],
    why_it_matters: str,
    impact: str,
    remediation: list[str],
    validation: list[str],
    evidence_source_type: str,
    finding_basis: str,
    collected_at: str,
    raw_evidence_path: str,
) -> Finding:
    return Finding(
        finding_id=finding_id[:120],
        title=title,
        category=category,
        package=package,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        asset=asset,
        evidence_summary=evidence_summary,
        evidence_files=evidence_files,
        why_it_matters=why_it_matters,
        likely_business_impact=impact,
        remediation_steps=remediation,
        validation_steps=validation,
        owner_role="Network Security Owner",
        effort="medium",
        evidence_source_type=evidence_source_type,
        evidence_collected_at=collected_at,
        raw_evidence_path=raw_evidence_path,
        finding_basis=finding_basis,  # type: ignore[arg-type]
    )


def _safe_id(value: str) -> str:
    cleaned = "".join(char if char.isalnum() else "-" for char in value.strip().lower())
    return cleaned.strip("-") or "unknown"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
