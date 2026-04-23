"""Environment profiling orchestration."""

from __future__ import annotations

import getpass
import json
import os
import platform
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.collectors.shell import run_command
from app.collectors.windows import detect_windows_admin, is_windows, powershell_json, run_powershell
from app.core.models import ModuleResult
from app.core.session import AssessmentSession


@dataclass(slots=True)
class EnvironmentProfile:
    os_name: str
    os_version: str
    hostname: str
    domain_joined: bool
    domain_or_workgroup: str
    network_interfaces: list[dict[str, object]]
    local_subnets: list[str]
    current_user: str
    is_admin: bool
    av_indicators: list[str]
    firewall_status: str
    backup_indicators: list[str]
    remote_access_indicators: list[str]
    m365_connector_available: bool
    rdp_enabled: bool
    smb_enabled: bool
    evidence_files: list[Path] = field(default_factory=list)


class EnvironmentProfiler:
    """Collects read-only host posture and stores encrypted evidence."""

    name = "environment_profile"

    def __init__(self, session: AssessmentSession) -> None:
        self.session = session
        self.profile = EnvironmentProfile(
            os_name="unknown",
            os_version="unknown",
            hostname="unknown",
            domain_joined=False,
            domain_or_workgroup="unknown",
            network_interfaces=[],
            local_subnets=[],
            current_user="unknown",
            is_admin=False,
            av_indicators=[],
            firewall_status="unknown",
            backup_indicators=[],
            remote_access_indicators=[],
            m365_connector_available=session.intake.m365_connector,
            rdp_enabled=False,
            smb_enabled=False,
        )

    def collect(self) -> ModuleResult:
        if is_windows():
            self.profile = self._collect_windows()
            status = "complete"
            detail = "Windows environment profile collected."
        else:
            self.profile = self._collect_non_windows()
            status = "partial"
            detail = "Non-Windows host detected. Windows-native checks skipped cleanly."

        evidence_file = self.session.crypto.write_text(
            self.session.evidence_dir / "environment_profile.json",
            json.dumps(_json_safe(asdict(self.profile)), indent=2, sort_keys=True),
        )
        self.profile.evidence_files.append(evidence_file)
        return ModuleResult(
            module_name=self.name,
            status=status,
            detail=detail,
            evidence_files=[evidence_file],
        )

    def load_existing(self) -> EnvironmentProfile:
        evidence_file = self.session.evidence_dir / "environment_profile.json.enc"
        if not evidence_file.exists():
            raise FileNotFoundError("Environment profile checkpoint is marked complete but evidence is missing.")
        payload = json.loads(self.session.crypto.read_text(evidence_file))
        payload["evidence_files"] = [Path(item) for item in payload.get("evidence_files", [])]
        self.profile = EnvironmentProfile(**payload)
        return self.profile

    def _collect_windows(self) -> EnvironmentProfile:
        computer_info, _ = powershell_json(
            "Get-CimInstance Win32_ComputerSystem | "
            "Select-Object Domain,PartOfDomain,Workgroup,Manufacturer,Model"
        )
        os_info, _ = powershell_json(
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Caption,Version,BuildNumber"
        )
        net_info, _ = powershell_json(
            "Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv4DefaultGateway"
        )
        defender_info, _ = powershell_json(
            "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled",
            timeout_seconds=20,
        )
        firewall_info, _ = powershell_json(
            "Get-NetFirewallProfile | Select-Object Name,Enabled"
        )
        services, _ = powershell_json(
            "Get-Service | Where-Object {$_.Name -match 'WinDefend|Sense|Veeam|Acronis|Backup|AnyDesk|TeamViewer|ScreenConnect|Splashtop|RustDesk'} | "
            "Select-Object Name,DisplayName,Status"
        )
        listeners = run_powershell(
            "Get-NetTCPConnection -State Listen | "
            "Where-Object {$_.LocalPort -in 3389,445} | "
            "Select-Object LocalAddress,LocalPort,State | ConvertTo-Json -Depth 4",
            timeout_seconds=20,
        )

        interfaces = _normalize_network_interfaces(net_info)
        service_items = _ensure_list(services.get("items", services if services else []))
        service_names = [
            str(item.get("Name", "")) + " " + str(item.get("DisplayName", ""))
            for item in service_items
            if isinstance(item, dict)
        ]
        av = [
            name
            for name in service_names
            if any(marker.lower() in name.lower() for marker in ["windefend", "sense"])
        ]
        backups = [
            name
            for name in service_names
            if any(marker.lower() in name.lower() for marker in ["veeam", "acronis", "backup"])
        ]
        remote = [
            name
            for name in service_names
            if any(
                marker.lower() in name.lower()
                for marker in ["anydesk", "teamviewer", "screenconnect", "splashtop", "rustdesk"]
            )
        ]

        firewall_status = _summarize_firewall(firewall_info)
        rdp_enabled = "3389" in listeners.stdout
        smb_enabled = "445" in listeners.stdout

        return EnvironmentProfile(
            os_name=str(os_info.get("Caption") or platform.system()),
            os_version=str(os_info.get("Version") or platform.version()),
            hostname=socket.gethostname(),
            domain_joined=bool(computer_info.get("PartOfDomain", False)),
            domain_or_workgroup=str(
                computer_info.get("Domain")
                or computer_info.get("Workgroup")
                or "unknown"
            ),
            network_interfaces=interfaces,
            local_subnets=_local_subnets_from_interfaces(interfaces),
            current_user=getpass.getuser(),
            is_admin=_is_admin_windows(),
            av_indicators=av or _defender_indicators(defender_info),
            firewall_status=firewall_status,
            backup_indicators=backups,
            remote_access_indicators=remote,
            m365_connector_available=self.session.intake.m365_connector
            or os.getenv("SOUN_RUNNER_M365_CONNECTOR", "").lower() == "true",
            rdp_enabled=rdp_enabled,
            smb_enabled=smb_enabled,
        )

    def _collect_non_windows(self) -> EnvironmentProfile:
        return EnvironmentProfile(
            os_name=platform.system(),
            os_version=platform.version(),
            hostname=socket.gethostname(),
            domain_joined=False,
            domain_or_workgroup="unsupported-non-windows",
            network_interfaces=[],
            local_subnets=[],
            current_user=getpass.getuser(),
            is_admin=os.geteuid() == 0 if hasattr(os, "geteuid") else False,
            av_indicators=[],
            firewall_status="unknown",
            backup_indicators=[],
            remote_access_indicators=[],
            m365_connector_available=self.session.intake.m365_connector,
            rdp_enabled=False,
            smb_enabled=False,
        )


def _is_admin_windows() -> bool:
    return detect_windows_admin()


def _normalize_network_interfaces(net_info: dict[str, object]) -> list[dict[str, object]]:
    raw = net_info.get("items", net_info)
    items = _ensure_list(raw)
    normalized: list[dict[str, object]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "interface": item.get("InterfaceAlias", "unknown"),
                "ipv4": item.get("IPv4Address"),
                "gateway": item.get("IPv4DefaultGateway"),
            }
        )
    return normalized


def _local_subnets_from_interfaces(interfaces: list[dict[str, object]]) -> list[str]:
    subnets: list[str] = []
    for interface in interfaces:
        ipv4 = interface.get("ipv4")
        if isinstance(ipv4, dict):
            address = ipv4.get("IPAddress")
            prefix = ipv4.get("PrefixLength")
            if address and prefix:
                subnets.append(f"{address}/{prefix}")
        elif isinstance(ipv4, list):
            for item in ipv4:
                if isinstance(item, dict) and item.get("IPAddress") and item.get("PrefixLength"):
                    subnets.append(f"{item['IPAddress']}/{item['PrefixLength']}")
    return subnets


def _summarize_firewall(firewall_info: dict[str, object]) -> str:
    items = _ensure_list(firewall_info.get("items", firewall_info))
    if not items:
        return "unknown"
    enabled_values = [
        bool(item.get("Enabled"))
        for item in items
        if isinstance(item, dict) and "Enabled" in item
    ]
    if enabled_values and all(enabled_values):
        return "enabled"
    if enabled_values and not any(enabled_values):
        return "disabled"
    return "partial"


def _defender_indicators(defender_info: dict[str, object]) -> list[str]:
    if any(bool(value) for value in defender_info.values()):
        return ["Microsoft Defender indicators present"]
    return []


def _ensure_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _json_safe(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return value
