"""Safe Nmap adapter and XML parser."""

from __future__ import annotations

import logging
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from app.core.config import NmapConfig
from app.core.evidence import confidence_for_basis, utc_now
from app.core.models import Finding
from app.core.scope import ScopePolicy
from app.core.session import AssessmentSession
from app.scanners.base import NetworkAsset, NetworkService, ScannerResult


RISKY_EXPOSURE_PORTS: dict[int, tuple[str, str, str]] = {
    3389: ("RDP service exposed in approved scope", "high", "Infrastructure Administrator"),
    445: ("SMB service exposed in approved scope", "medium", "Infrastructure Administrator"),
    139: ("NetBIOS/SMB legacy service exposed in approved scope", "medium", "Infrastructure Administrator"),
    5985: ("WinRM HTTP service exposed in approved scope", "medium", "Infrastructure Administrator"),
    5986: ("WinRM HTTPS service exposed in approved scope", "medium", "Infrastructure Administrator"),
    22: ("SSH service exposed in approved scope", "low", "Infrastructure Administrator"),
    23: ("Telnet service exposed in approved scope", "high", "Infrastructure Administrator"),
}


@dataclass(slots=True)
class NmapAdapter:
    """Run Nmap against approved scope using non-stealth profiles."""

    session: AssessmentSession
    config: NmapConfig
    package: str = "basic"

    name: str = "nmap"

    def scan(self, scope: ScopePolicy) -> ScannerResult:
        if not self.config.enabled:
            return ScannerResult(
                scanner_name=self.name,
                status="skipped",
                detail="Nmap scanning disabled in config.",
            )

        targets = scope.scan_targets()
        try:
            scope.validate_scan_targets(targets)
        except ValueError as exc:
            return ScannerResult(
                scanner_name=self.name,
                status="skipped",
                detail=str(exc),
            )

        raw_xml = self.session.evidence_dir / "nmap_scan.xml"
        command = self._build_command(targets, raw_xml)
        logger = logging.getLogger("soun_runner")
        logger.info("Running Nmap with safe profile: %s", self.config.profile)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=self.config.timeout_seconds,
            )
        except FileNotFoundError:
            return ScannerResult(
                scanner_name=self.name,
                status="skipped",
                detail=f"Nmap executable not found: {self.config.path}",
            )
        except subprocess.TimeoutExpired:
            return ScannerResult(
                scanner_name=self.name,
                status="partial",
                detail=f"Nmap timed out after {self.config.timeout_seconds} seconds.",
            )

        command_evidence = self.session.crypto.write_text(
            self.session.evidence_dir / "nmap_command_output.json",
            _command_evidence(command, completed.returncode, completed.stdout, completed.stderr),
        )

        if completed.returncode not in {0, 1}:
            return ScannerResult(
                scanner_name=self.name,
                status="failed",
                detail=f"Nmap failed with exit code {completed.returncode}. Evidence: {command_evidence}",
                raw_evidence_path=command_evidence,
            )

        if not raw_xml.exists():
            return ScannerResult(
                scanner_name=self.name,
                status="failed",
                detail="Nmap completed but did not create XML output.",
                raw_evidence_path=command_evidence,
            )

        encrypted_xml = self.session.crypto.write_encrypted(
            self.session.evidence_dir / "nmap_scan.xml",
            raw_xml.read_bytes(),
        )
        raw_xml.unlink(missing_ok=True)
        assets = parse_nmap_xml(self.session.crypto.read_text(encrypted_xml))
        findings = findings_from_nmap_assets(
            assets=assets,
            raw_evidence_path=encrypted_xml,
            package=self.package,
        )
        status = "complete" if assets else "partial"
        detail = f"Nmap parsed {len(assets)} asset(s) from approved scope."
        return ScannerResult(
            scanner_name=self.name,
            status=status,
            detail=detail,
            assets=assets,
            findings=findings,
            raw_evidence_path=encrypted_xml,
        )

    def _build_command(self, targets: list[str], output_xml: Path) -> list[str]:
        command = [
            self.config.path,
            "-oX",
            str(output_xml),
            "--host-timeout",
            f"{self.config.timeout_seconds}s",
        ]
        if self.config.profile == "host-discovery":
            command.extend(["-sn"])
        elif self.config.profile == "top-ports":
            command.extend(["-sT", "--top-ports", str(self.config.top_ports), "--open"])
            if self.config.service_version_detection:
                command.extend(["-sV", "--version-light"])
        else:
            raise ValueError(f"Unsupported Nmap profile: {self.config.profile}")
        command.extend(targets)
        return command


def parse_nmap_xml(xml_text: str) -> list[NetworkAsset]:
    """Parse Nmap XML into normalized assets and open services."""

    root = ET.fromstring(xml_text)
    assets: list[NetworkAsset] = []
    for host in root.findall("host"):
        status_node = host.find("status")
        status = status_node.attrib.get("state", "unknown") if status_node is not None else "unknown"
        address = _host_address(host)
        if not address:
            continue
        hostnames = [
            node.attrib.get("name", "")
            for node in host.findall("./hostnames/hostname")
            if node.attrib.get("name")
        ]
        services: list[NetworkService] = []
        for port_node in host.findall("./ports/port"):
            state_node = port_node.find("state")
            state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
            if state != "open":
                continue
            service_node = port_node.find("service")
            services.append(
                NetworkService(
                    protocol=port_node.attrib.get("protocol", ""),
                    port=int(port_node.attrib.get("portid", "0")),
                    state=state,
                    service_name=service_node.attrib.get("name", "") if service_node is not None else "",
                    product=service_node.attrib.get("product", "") if service_node is not None else "",
                    version=service_node.attrib.get("version", "") if service_node is not None else "",
                    extra_info=service_node.attrib.get("extrainfo", "") if service_node is not None else "",
                )
            )
        assets.append(
            NetworkAsset(
                address=address,
                hostnames=hostnames,
                status=status,
                services=services,
                mac_address=_host_mac_address(host),
                os_family=_host_os_family(host),
                os_guess=_host_os_guess(host),
            )
        )
    return assets


def findings_from_nmap_assets(
    assets: list[NetworkAsset],
    raw_evidence_path: Path,
    *,
    package: str = "basic",
) -> list[Finding]:
    """Create exposure findings from observed open services only."""

    findings: list[Finding] = []
    collected_at = utc_now()
    for asset in assets:
        for service in asset.services:
            if service.port not in RISKY_EXPOSURE_PORTS:
                continue
            title, severity, owner = RISKY_EXPOSURE_PORTS[service.port]
            service_label = _service_label(service)
            findings.append(
                Finding(
                    finding_id=f"{package.upper()}-NMAP-{asset.address}-{service.port}".replace(".", "-"),
                    title=title,
                    category="Network Discovery",
                    package=package,
                    severity=severity,  # type: ignore[arg-type]
                    confidence=confidence_for_basis("network_discovery_evidence"),
                    asset=asset.primary_hostname or asset.address,
                    evidence_summary=(
                        f"Nmap observed open {service.protocol}/{service.port}"
                        f"{' (' + service_label + ')' if service_label else ''}."
                    ),
                    evidence_files=[str(raw_evidence_path)],
                    why_it_matters=(
                        "Exposed administrative or file-sharing services increase the reachable attack surface. "
                        "This is an exposure finding, not a vulnerability claim."
                    ),
                    likely_business_impact=(
                        "Unauthorized or poorly controlled access to this service can support intrusion, "
                        "data access, or operational disruption if other controls fail."
                    ),
                    remediation_steps=[
                        "Confirm the service is required for the approved business process.",
                        "Restrict access to approved management networks or VPN paths.",
                        "Verify authentication, logging, and MFA controls where applicable.",
                    ],
                    validation_steps=[
                        "Re-run approved-scope Nmap discovery and confirm the service is closed or restricted.",
                        "Validate firewall and access-control rules from an approved source network.",
                    ],
                    owner_role=owner,
                    effort="medium",
                    evidence_source_type="nmap",
                    evidence_collected_at=collected_at,
                    raw_evidence_path=str(raw_evidence_path),
                    finding_basis="network_discovery_evidence",
                )
            )
    return findings


def _host_address(host: ET.Element) -> str:
    ipv4 = host.find("./address[@addrtype='ipv4']")
    if ipv4 is not None:
        return ipv4.attrib.get("addr", "")
    ipv6 = host.find("./address[@addrtype='ipv6']")
    if ipv6 is not None:
        return ipv6.attrib.get("addr", "")
    address = host.find("address")
    return address.attrib.get("addr", "") if address is not None else ""


def _service_label(service: NetworkService) -> str:
    parts = [
        service.service_name,
        service.product,
        service.version,
        service.extra_info,
    ]
    return " ".join(part for part in parts if part).strip()


def _host_mac_address(host: ET.Element) -> str:
    mac = host.find("./address[@addrtype='mac']")
    return mac.attrib.get("addr", "") if mac is not None else ""


def _host_os_family(host: ET.Element) -> str:
    osclass = host.find("./os/osmatch/osclass")
    if osclass is None:
        osclass = host.find("./os/osclass")
    return osclass.attrib.get("osfamily", "") if osclass is not None else ""


def _host_os_guess(host: ET.Element) -> str:
    match = host.find("./os/osmatch")
    if match is not None:
        return match.attrib.get("name", "")
    return ""


def _command_evidence(command: list[str], returncode: int, stdout: str, stderr: str) -> str:
    import json

    return json.dumps(
        {
            "command": command,
            "returncode": returncode,
            "stdout": stdout,
            "stderr": stderr,
        },
        indent=2,
        sort_keys=True,
    )
