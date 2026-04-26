"""Automatic enterprise context detection for launch planning."""

from __future__ import annotations

import getpass
import ipaddress
import json
import platform
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.collectors.shell import run_command
from app.collectors.windows import is_windows, powershell_json
from app.core.config import AppConfig


@dataclass(slots=True)
class DetectedInterface:
    """Minimal connected interface context used for automatic scope decisions."""

    name: str
    ip_address: str
    prefix_length: int
    subnet: str
    gateway: str = ""
    dns_suffix: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class AutoEnterpriseContext:
    """Auto-detected launch context for company-wide assessment modes."""

    hostname: str
    fqdn: str
    operator_name: str
    os_name: str
    domain_joined: bool
    domain_name: str
    dns_suffixes: list[str]
    interfaces: list[DetectedInterface]
    private_subnets: list[str]
    scope_source: str
    default_scope: str
    site_label: str
    business_unit: str
    email_domain: str
    ad_domain: str
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["interfaces"] = [item.to_dict() for item in self.interfaces]
        return payload


def detect_enterprise_context(config: AppConfig | None = None) -> AutoEnterpriseContext:
    """Detect read-only local enterprise context before an assessment session exists."""

    hostname = socket.gethostname()
    fqdn = socket.getfqdn() or hostname
    operator = getpass.getuser()
    os_name = platform.system()
    domain_joined = False
    domain_name = _domain_from_fqdn(fqdn)
    dns_suffixes: list[str] = []
    interfaces: list[DetectedInterface] = []

    if is_windows():
        windows_context = _detect_windows_context()
        domain_joined = windows_context["domain_joined"]
        domain_name = windows_context["domain_name"] or domain_name
        dns_suffixes = windows_context["dns_suffixes"]
        interfaces = windows_context["interfaces"]
    else:
        interfaces = _detect_non_windows_interfaces()
        dns_suffixes = [domain_name] if domain_name else []

    private_subnets = _unique_sorted(
        [
            item.subnet
            for item in interfaces
            if _is_private_unicast(item.ip_address)
        ]
    )
    configured_scopes = _configured_scopes(config)
    warnings: list[str] = []
    if configured_scopes:
        scope_source = "config_scope"
        default_scope = ",".join(configured_scopes)
    elif private_subnets:
        scope_source = "auto_detected_local_subnets"
        default_scope = ",".join(private_subnets)
    else:
        scope_source = "localhost_only_fallback"
        default_scope = "local-host-only"
        warnings.append(
            "Only loopback or non-private interfaces were detected. Company-wide coverage will not be representative."
        )

    site_label = _site_label_from_scope(config, private_subnets) or _site_label_from_domain(domain_name)
    email_domain = _public_email_domain(config, domain_name, dns_suffixes)
    ad_domain = _ad_domain(config, domain_joined, domain_name)
    business_unit = config.assessment.business_unit if config else ""

    return AutoEnterpriseContext(
        hostname=hostname,
        fqdn=fqdn,
        operator_name=operator,
        os_name=os_name,
        domain_joined=domain_joined,
        domain_name=domain_name,
        dns_suffixes=dns_suffixes,
        interfaces=interfaces,
        private_subnets=private_subnets,
        scope_source=scope_source,
        default_scope=default_scope,
        site_label=site_label or "Auto-detected",
        business_unit=business_unit,
        email_domain=email_domain,
        ad_domain=ad_domain,
        warnings=warnings,
    )


def apply_auto_context_to_config(config: AppConfig, context: AutoEnterpriseContext) -> None:
    """Enable safe connector defaults from detected context without inventing evidence."""

    if context.ad_domain and not config.active_directory.domain:
        config.active_directory.domain = context.ad_domain
    if context.domain_joined and context.ad_domain:
        config.active_directory.enabled = True
    if context.email_domain and not config.assessment.client_domain:
        config.assessment.client_domain = context.email_domain


def write_auto_context(root: Path, context: AutoEnterpriseContext) -> Path:
    """Write unencrypted context for local debugging when no session crypto exists yet."""

    root.mkdir(parents=True, exist_ok=True)
    output = root / "auto_context.json"
    output.write_text(json.dumps(context.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return output


def _detect_windows_context() -> dict[str, object]:
    computer_info, _ = powershell_json(
        "Get-CimInstance Win32_ComputerSystem | Select-Object Domain,PartOfDomain,Workgroup",
        timeout_seconds=20,
    )
    net_info, _ = powershell_json(
        "Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv4DefaultGateway,DnsSuffix",
        timeout_seconds=20,
    )
    domain_joined = bool(computer_info.get("PartOfDomain", False))
    domain_name = str(computer_info.get("Domain") or "").strip()
    interfaces = _interfaces_from_windows_payload(net_info)
    suffixes = _unique_sorted([item.dns_suffix for item in interfaces if item.dns_suffix])
    if domain_name and domain_name not in suffixes:
        suffixes.append(domain_name)
    return {
        "domain_joined": domain_joined,
        "domain_name": domain_name,
        "dns_suffixes": suffixes,
        "interfaces": interfaces,
    }


def _detect_non_windows_interfaces() -> list[DetectedInterface]:
    if platform.system().lower() == "darwin":
        return _interfaces_from_ifconfig()
    return _interfaces_from_ip_addr()


def _interfaces_from_windows_payload(payload: dict[str, object]) -> list[DetectedInterface]:
    items = _ensure_list(payload.get("items", payload))
    interfaces: list[DetectedInterface] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("InterfaceAlias", "") or "unknown")
        gateway = _gateway_value(item.get("IPv4DefaultGateway"))
        suffix = str(item.get("DnsSuffix", "") or "").strip()
        for ipv4 in _ensure_list(item.get("IPv4Address")):
            if not isinstance(ipv4, dict):
                continue
            address = str(ipv4.get("IPAddress", "") or "").strip()
            prefix = _safe_int(ipv4.get("PrefixLength"))
            subnet = _subnet(address, prefix)
            if subnet:
                interfaces.append(
                    DetectedInterface(
                        name=name,
                        ip_address=address,
                        prefix_length=prefix,
                        subnet=subnet,
                        gateway=gateway,
                        dns_suffix=suffix,
                    )
                )
    return interfaces


def _interfaces_from_ip_addr() -> list[DetectedInterface]:
    result = run_command(["ip", "-j", "addr"], timeout_seconds=10)
    if result.returncode != 0 or not result.stdout:
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    interfaces: list[DetectedInterface] = []
    if not isinstance(payload, list):
        return []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("ifname", "") or "unknown")
        for addr in item.get("addr_info", []) or []:
            if not isinstance(addr, dict) or addr.get("family") != "inet":
                continue
            address = str(addr.get("local", "") or "").strip()
            prefix = _safe_int(addr.get("prefixlen"))
            subnet = _subnet(address, prefix)
            if subnet:
                interfaces.append(DetectedInterface(name=name, ip_address=address, prefix_length=prefix, subnet=subnet))
    return interfaces


def _interfaces_from_ifconfig() -> list[DetectedInterface]:
    result = run_command(["ifconfig"], timeout_seconds=10)
    if result.returncode != 0 or not result.stdout:
        return []
    interfaces: list[DetectedInterface] = []
    current_name = ""
    for raw_line in result.stdout.splitlines():
        if raw_line and not raw_line.startswith(("\t", " ")):
            current_name = raw_line.split(":", 1)[0].strip()
            continue
        line = raw_line.strip()
        if not line.startswith("inet "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        address = parts[1]
        prefix = 24
        if "netmask" in parts:
            idx = parts.index("netmask")
            if idx + 1 < len(parts):
                prefix = _prefix_from_netmask(parts[idx + 1])
        subnet = _subnet(address, prefix)
        if subnet:
            interfaces.append(
                DetectedInterface(
                    name=current_name or "unknown",
                    ip_address=address,
                    prefix_length=prefix,
                    subnet=subnet,
                )
            )
    return interfaces


def _configured_scopes(config: AppConfig | None) -> list[str]:
    if not config:
        return []
    scopes = [item for item in config.assessment.approved_scopes if item]
    if config.assessment.approved_scope:
        scopes.append(config.assessment.approved_scope)
    return _unique_sorted(scopes)


def _is_private_unicast(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return bool(ip.version == 4 and ip.is_private and not ip.is_loopback and not ip.is_link_local)


def _subnet(address: str, prefix: int) -> str:
    if not address or prefix <= 0:
        return ""
    try:
        return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
    except ValueError:
        return ""


def _prefix_from_netmask(value: str) -> int:
    text = value.strip()
    try:
        if text.startswith("0x"):
            number = int(text, 16)
            mask = ".".join(str((number >> offset) & 0xFF) for offset in (24, 16, 8, 0))
        else:
            mask = text
        return ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return 24


def _gateway_value(value: object) -> str:
    for item in _ensure_list(value):
        if isinstance(item, dict) and item.get("NextHop"):
            return str(item["NextHop"])
        if isinstance(item, str) and item.strip():
            return item.strip()
    return ""


def _ensure_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _safe_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _domain_from_fqdn(fqdn: str) -> str:
    parts = [part for part in fqdn.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[1:])
    return ""


def _site_label_from_scope(config: AppConfig | None, private_subnets: list[str]) -> str:
    if not config:
        return ""
    for subnet in private_subnets:
        if subnet in config.assessment.scope_labels:
            return config.assessment.scope_labels[subnet]
    return config.assessment.site


def _site_label_from_domain(domain_name: str) -> str:
    if not domain_name:
        return "Local Network"
    first = domain_name.split(".", 1)[0].strip()
    return first.upper() if first else "Local Network"


def _public_email_domain(config: AppConfig | None, domain_name: str, suffixes: list[str]) -> str:
    configured = config.assessment.client_domain if config else ""
    if configured:
        return configured
    for candidate in [domain_name, *suffixes]:
        cleaned = candidate.strip().lower()
        if cleaned and "." in cleaned and not cleaned.endswith(".local"):
            return cleaned
    return ""


def _ad_domain(config: AppConfig | None, domain_joined: bool, domain_name: str) -> str:
    configured = ""
    if config:
        configured = config.assessment.ad_domain or config.active_directory.domain
    if configured:
        return configured
    return domain_name if domain_joined else ""


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted({item.strip() for item in values if item and item.strip()})
