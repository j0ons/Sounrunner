"""Imported firewall and VPN evidence foundation."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.config import AppConfig
from app.core.evidence import confidence_for_basis, utc_now
from app.core.inventory import AssetInventory
from app.core.models import Finding, ModuleResult
from app.core.session import AssessmentSession


SUPPORTED_FIREWALL_VPN_FORMATS = [
    "vendor-neutral JSON with management_exposures / vpn_endpoints / policies arrays",
    "flat CSV with asset, exposure_type, service, port, internet_exposed, admin_interface, policy_name",
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
            summary_items.append(
                {
                    "path": str(evidence_path),
                    "management_exposure_count": len(payload["management_exposures"]),
                    "vpn_endpoint_count": len(payload["vpn_endpoints"]),
                    "policy_count": len(payload["policies"]),
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
    if path.suffix.lower() == ".json":
        loaded = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(loaded, dict):
            raise ValueError(f"Unsupported firewall/VPN JSON root in {path.name}")
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
        any_any = str(policy.get("source", "")).lower() == "any" and str(policy.get("destination", "")).lower() == "any"
        service = str(policy.get("service", "")).lower()
        if any_any and any(token in service for token in ["ssh", "https", "rdp", "winrm", "telnet"]):
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
                    title="Broad inbound management policy imported from firewall evidence",
                    severity="high",
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
