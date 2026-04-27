"""Imported firewall and VPN evidence foundation."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.core.config import AppConfig
from app.core.evidence import confidence_for_basis, utc_now
from app.core.inventory import AssetInventory
from app.core.models import Finding, ModuleResult
from app.core.network_models import FirewallRule, FirewallVpnEvidence
from app.core.session import AssessmentSession


SUPPORTED_FIREWALL_VPN_FORMATS = [
    "vendor-neutral JSON with management_exposures / vpn_endpoints / policies arrays",
    "flat CSV with asset, exposure_type, service, port, internet_exposed, admin_interface, policy_name",
    "vendor-neutral YAML with the same fields as JSON",
]


@dataclass(slots=True)
class FirewallVpnImportModule:
    session: AssessmentSession
    config: AppConfig

    name: str = "firewall_vpn_import"

    def run(self) -> ModuleResult:
        if not self.config.firewall_vpn_import.enabled or not self.config.firewall_vpn_import.import_paths:
            return ModuleResult(
                module_name=self.name,
                status="skipped",
                detail="Firewall/VPN import foundation disabled or no import paths configured.",
            )

        inventory = AssetInventory(self.session, self.config)
        findings: list[Finding] = []
        evidence_files: list[Path] = []
        parsed_files = 0
        summary_items: list[dict[str, Any]] = []
        normalized_items: list[dict[str, Any]] = []

        for configured_path in self.config.firewall_vpn_import.import_paths:
            path = Path(configured_path)
            if not path.exists():
                continue
            payload = _load_firewall_vpn_payload(path)
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            evidence_path = self.session.crypto.write_text(
                self.session.evidence_dir / f"firewall_vpn_import_{path.name}",
                raw_text,
            )
            evidence_files.append(evidence_path)
            parsed_files += 1
            normalized = _normalized_firewall_vpn_evidence(payload, str(evidence_path))
            normalized_items.append(normalized.to_dict())
            summary_items.append(
                {
                    "path": str(evidence_path),
                    "management_exposure_count": len(payload["management_exposures"]),
                    "vpn_endpoint_count": len(payload["vpn_endpoints"]),
                    "policy_count": len(payload["policies"]),
                    "normalized_rule_count": len(normalized.rules),
                    "partial": normalized.partial,
                }
            )
            findings.extend(
                _findings_from_firewall_vpn_payload(
                    session=self.session,
                    inventory=inventory,
                    payload=payload,
                    evidence_path=str(evidence_path),
                )
            )

        self.session.database.set_metadata(
            "firewall_vpn_import_summary",
            {
                "supported_formats": SUPPORTED_FIREWALL_VPN_FORMATS,
                "parsed_files": parsed_files,
                "items": summary_items,
            },
        )
        self.session.database.set_metadata("firewall_vpn_normalized", normalized_items)
        if not parsed_files:
            return ModuleResult(
                module_name=self.name,
                status="partial",
                detail="Firewall/VPN import paths were configured but no readable evidence files were found.",
            )
        return ModuleResult(
            module_name=self.name,
            status="complete",
            detail=f"Parsed {parsed_files} firewall/VPN evidence file(s).",
            findings=findings,
            evidence_files=evidence_files,
        )


def _load_firewall_vpn_payload(path: Path) -> dict[str, list[dict[str, Any]]]:
    if path.suffix.lower() in {".json", ".yaml", ".yml"}:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        loaded = json.loads(raw_text) if path.suffix.lower() == ".json" else yaml.safe_load(raw_text)
        if not isinstance(loaded, dict):
            raise ValueError(f"Unsupported firewall/VPN import root in {path.name}")
        return {
            "management_exposures": _dict_items(loaded.get("management_exposures")),
            "vpn_endpoints": _dict_items(loaded.get("vpn_endpoints")),
            "policies": _dict_items(loaded.get("policies")),
        }
    if path.suffix.lower() == ".csv":
        management: list[dict[str, Any]] = []
        vpn: list[dict[str, Any]] = []
        policies: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                normalized = {str(key): value for key, value in row.items()}
                exposure_type = str(normalized.get("exposure_type", "")).strip().lower()
                if exposure_type in {"management", "admin_interface"}:
                    management.append(normalized)
                elif exposure_type in {"vpn", "remote_access"}:
                    vpn.append(normalized)
                else:
                    policies.append(normalized)
        return {
            "management_exposures": management,
            "vpn_endpoints": vpn,
            "policies": policies,
        }
    raise ValueError(f"Unsupported firewall/VPN import format: {path.name}")


def _normalized_firewall_vpn_evidence(
    payload: dict[str, list[dict[str, Any]]],
    evidence_path: str,
) -> FirewallVpnEvidence:
    rules: list[FirewallRule] = []
    warnings: list[str] = []
    for exposure in payload["management_exposures"]:
        rules.append(
            _firewall_rule_from_item(
                exposure,
                default_service=str(exposure.get("service") or exposure.get("port") or "management"),
                management_exposure=True,
            )
        )
    for endpoint in payload["vpn_endpoints"]:
        rules.append(
            _firewall_rule_from_item(
                endpoint,
                default_service=str(endpoint.get("service") or endpoint.get("port") or "vpn"),
                remote_access=True,
            )
        )
    for policy in payload["policies"]:
        rules.append(_firewall_rule_from_item(policy, default_service=str(policy.get("service") or policy.get("port") or "any")))
    for rule in rules:
        if not rule.source or not rule.destination or not (rule.service or rule.port):
            warnings.append(
                f"Partial rule evidence for {rule.device_name or rule.rule_name or 'unknown rule'}; source/destination/service fields are incomplete."
            )
    return FirewallVpnEvidence(
        source_path=evidence_path,
        rules=rules,
        partial=bool(warnings),
        warnings=warnings,
    )


def _firewall_rule_from_item(
    item: dict[str, Any],
    *,
    default_service: str,
    management_exposure: bool = False,
    remote_access: bool = False,
) -> FirewallRule:
    source = str(item.get("source") or item.get("source_subnet") or item.get("source_zone") or "").strip()
    destination = str(item.get("destination") or item.get("destination_subnet") or item.get("destination_zone") or "").strip()
    service = str(item.get("service") or default_service).strip()
    port = str(item.get("port", "")).strip()
    action = str(item.get("action", "allow")).strip().lower()
    any_any = source.lower() == "any" and destination.lower() == "any" and action in {"allow", "accept", "permit"}
    broad_source = source.lower() in {"any", "0.0.0.0/0", "internet", "vpn", "remote_access"}
    broad_destination = destination.lower() in {"any", "internal", "lan", "corp", "inside"} or destination.endswith("/16")
    admin_interface = _is_true(item.get("admin_interface")) or str(item.get("exposure_type", "")).lower() == "admin_interface"
    mgmt_exposure = management_exposure or admin_interface or _is_management_service(service, port)
    return FirewallRule(
        device_name=str(item.get("device_name") or item.get("device") or item.get("asset") or "firewall-vpn-device"),
        vendor=str(item.get("vendor", "")),
        zone_or_interface=str(item.get("zone") or item.get("interface") or item.get("zone_or_interface") or ""),
        rule_id=str(item.get("rule_id") or item.get("id") or ""),
        rule_name=str(item.get("rule_name") or item.get("policy_name") or item.get("name") or ""),
        source_zone=str(item.get("source_zone", "")),
        source=source,
        destination_zone=str(item.get("destination_zone", "")),
        destination=destination,
        service=service,
        port=port,
        action=action,
        enabled=not _is_false(item.get("enabled", True)),
        remote_access_vpn_enabled=remote_access or _is_true(item.get("remote_access_vpn_enabled")),
        admin_interface_exposure=admin_interface or _is_true(item.get("internet_exposed")),
        any_any=any_any,
        broad_inbound=broad_source and broad_destination and action in {"allow", "accept", "permit"},
        management_exposure=mgmt_exposure and action in {"allow", "accept", "permit"},
        raw=dict(item),
    )


def _findings_from_firewall_vpn_payload(
    *,
    session: AssessmentSession,
    inventory: AssetInventory,
    payload: dict[str, list[dict[str, Any]]],
    evidence_path: str,
) -> list[Finding]:
    findings: list[Finding] = []
    collected_at = utc_now()
    for exposure in payload["management_exposures"]:
        asset = inventory.record_imported_asset(
            hostname=str(exposure.get("asset") or exposure.get("device") or "network-device"),
            ip_address=str(exposure.get("ip_address", "")),
            role_hint="network_device",
            source="firewall_vpn_import",
            site_label=str(exposure.get("site", "")),
            business_unit=str(exposure.get("business_unit", "")),
        )
        inventory.attach_evidence(asset.asset_id, evidence_path, "firewall_vpn_import")
        if _is_true(exposure.get("internet_exposed")) and (
            _is_true(exposure.get("admin_interface")) or str(exposure.get("exposure_type", "")).lower() == "admin_interface"
        ):
            service = str(exposure.get("service") or exposure.get("port") or "management service")
            findings.append(
                _finding(
                    finding_id=f"FWVPN-ADMIN-{asset.asset_id}-{service}".replace(" ", "-"),
                    title="Administrative interface exposure imported from firewall/VPN evidence",
                    severity="high",
                    asset=asset.display_name,
                    summary=f"{service} appears internet-exposed for {asset.display_name} based on imported configuration evidence.",
                    why="Externally reachable administrative interfaces materially expand remote attack surface.",
                    impact="An exposed management plane increases the risk of unauthorized administrative access if perimeter or identity controls fail.",
                    remediation=[
                        "Restrict administrative interfaces to approved management networks or VPN paths only.",
                        "Review firewall policy and interface bindings for management services.",
                    ],
                    validation=[
                        "Confirm the imported configuration no longer exposes the management service externally.",
                    ],
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    package=session.intake.package,
                )
            )

    for endpoint in payload["vpn_endpoints"]:
        asset = inventory.record_imported_asset(
            hostname=str(endpoint.get("asset") or endpoint.get("device") or "vpn-endpoint"),
            ip_address=str(endpoint.get("ip_address", "")),
            role_hint="network_device",
            source="firewall_vpn_import",
            site_label=str(endpoint.get("site", "")),
            business_unit=str(endpoint.get("business_unit", "")),
        )
        inventory.attach_evidence(asset.asset_id, evidence_path, "firewall_vpn_import")
        if _is_true(endpoint.get("internet_exposed")):
            findings.append(
                _finding(
                    finding_id=f"FWVPN-VPN-{asset.asset_id}",
                    title="VPN or remote access endpoint exposure imported from configuration evidence",
                    severity="medium",
                    asset=asset.display_name,
                    summary=f"Imported evidence shows an external VPN or remote access endpoint for {asset.display_name}.",
                    why="Remote access exposure is expected in some environments and still requires strong control review.",
                    impact="If remote access controls are weak, attackers can target a high-value entry point.",
                    remediation=[
                        "Confirm ownership, MFA, logging, and source restrictions for the remote access endpoint.",
                    ],
                    validation=[
                        "Review the current firewall/VPN export and confirm the endpoint remains intentional and controlled.",
                    ],
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    package=session.intake.package,
                )
            )

    for policy in payload["policies"]:
        source = str(policy.get("source", "")).lower()
        destination = str(policy.get("destination", "")).lower()
        action = str(policy.get("action", "allow")).lower()
        any_any = source == "any" and destination == "any" and action in {"allow", "accept", "permit"}
        service = str(policy.get("service") or policy.get("port") or "any").lower()
        management_service = any(token in service for token in ["ssh", "https", "rdp", "winrm", "telnet", "management"])
        if any_any or management_service:
            asset_name = str(policy.get("asset") or policy.get("device") or "firewall-policy")
            asset = inventory.record_imported_asset(
                hostname=asset_name,
                role_hint="network_device",
                source="firewall_vpn_import",
                site_label=str(policy.get("site", "")),
                business_unit=str(policy.get("business_unit", "")),
            )
            inventory.attach_evidence(asset.asset_id, evidence_path, "firewall_vpn_import")
            findings.append(
                _finding(
                    finding_id=f"FWVPN-POLICY-{asset.asset_id}-{service}".replace(" ", "-"),
                    title="Broad firewall/VPN allow policy imported from configuration evidence",
                    severity="high" if any_any else "medium",
                    asset=asset.display_name,
                    summary=f"Policy {policy.get('policy_name', 'unknown')} allows broad management service exposure.",
                    why="Broad inbound management rules reduce segmentation and can expose high-value services to unauthorized sources.",
                    impact="Weak policy boundaries can permit attacker reachability to management interfaces and internal systems.",
                    remediation=[
                        "Constrain management policies to approved source networks, destinations, and services.",
                    ],
                    validation=[
                        "Review the exported policy set and confirm management access is narrowly scoped.",
                    ],
                    evidence_path=evidence_path,
                    collected_at=collected_at,
                    package=session.intake.package,
                )
            )
    return findings


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    asset: str,
    summary: str,
    why: str,
    impact: str,
    remediation: list[str],
    validation: list[str],
    evidence_path: str,
    collected_at: str,
    package: str,
) -> Finding:
    return Finding(
        finding_id=finding_id[:120],
        title=title,
        category="Firewall / VPN",
        package=package,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence_for_basis("imported_configuration_evidence"),
        asset=asset,
        evidence_summary=summary,
        evidence_files=[evidence_path],
        why_it_matters=why,
        likely_business_impact=impact,
        remediation_steps=remediation,
        validation_steps=validation,
        owner_role="Network Security Owner",
        effort="medium",
        evidence_source_type="firewall_vpn_import",
        evidence_collected_at=collected_at,
        raw_evidence_path=evidence_path,
        finding_basis="imported_configuration_evidence",
    )


def _dict_items(value: object) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _is_true(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _is_false(value: object) -> bool:
    return str(value).strip().lower() in {"0", "false", "no", "n", "disabled"}


def _is_management_service(service: str, port: str) -> bool:
    blob = f"{service} {port}".lower()
    tokens = {"ssh", "https", "http", "rdp", "winrm", "telnet", "vnc", "management", "admin"}
    if any(token in blob for token in tokens):
        return True
    try:
        return int(str(port).strip()) in {22, 23, 80, 443, 3389, 5985, 5986, 5900, 8080, 8443}
    except ValueError:
        return False
