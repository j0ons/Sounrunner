"""Automatic enterprise context detection for launch planning."""

from __future__ import annotations

import getpass
import ipaddress
import json
import platform
import re
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.collectors.shell import run_command
from app.collectors.windows import find_powershell_executable, is_windows, powershell_json, run_powershell
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
    interface_index: int = 0
    description: str = ""
    status: str = ""
    adapter_type: str = ""
    has_default_gateway: bool = False
    is_primary_route: bool = False
    route_metric: int = 999999
    interface_metric: int = 999999
    confidence_score: int = 0

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
    adapter_diagnostics: list[dict[str, object]] = field(default_factory=list)
    selected_interface_alias: str = ""
    selected_ip: str = ""
    selected_prefix_length: int = 0
    selected_cidr: str = ""
    auto_scope_confidence: int = 0
    auto_scope_debug: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["interfaces"] = [item.to_dict() for item in self.interfaces]
        return payload


RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

VIRTUAL_ADAPTER_KEYWORDS = (
    "docker",
    "wsl",
    "hyper-v",
    "vethernet",
    "vmware",
    "virtualbox",
    "tailscale",
    "zerotier",
    "vpn",
    "wireguard",
    "openvpn",
    "tap",
    "tun",
    "loopback",
    "default switch",
    "host-only",
    "host only",
    "nat-only",
    "nat only",
    "vmnet",
)

DOWN_STATUS_VALUES = {"down", "disconnected", "disabled", "not present", "notpresent"}


def detect_enterprise_context(config: AppConfig | None = None) -> AutoEnterpriseContext:
    """Detect read-only local enterprise context before an assessment session exists."""

    hostname = socket.gethostname()
    fqdn = socket.getfqdn() or hostname
    operator = getpass.getuser()
    os_name = platform.system()
    domain_joined = False
    domain_name = _domain_from_fqdn(fqdn)
    dns_suffixes: list[str] = []
    detected_interfaces: list[DetectedInterface] = []
    auto_scope_debug: dict[str, object] = {
        "platform_system": platform.system(),
        "is_windows": is_windows(),
        "powershell_executable": find_powershell_executable(),
        "collector_attempts": [],
        "raw_rows": [],
    }

    if is_windows():
        windows_context = _detect_windows_context()
        domain_joined = windows_context["domain_joined"]
        domain_name = windows_context["domain_name"] or domain_name
        dns_suffixes = windows_context["dns_suffixes"]
        detected_interfaces = windows_context["interfaces"]
        auto_scope_debug = dict(windows_context.get("adapter_debug") or auto_scope_debug)
    else:
        detected_interfaces = _detect_non_windows_interfaces()
        dns_suffixes = [domain_name] if domain_name else []

    interfaces, adapter_diagnostics = _select_auto_scope_interfaces(detected_interfaces, config)
    private_subnets = _unique_preserve_order([item.subnet for item in interfaces])
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
    selected_interface = interfaces[0] if interfaces else None

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
        adapter_diagnostics=adapter_diagnostics,
        selected_interface_alias=selected_interface.name if selected_interface else "",
        selected_ip=selected_interface.ip_address if selected_interface else "",
        selected_prefix_length=selected_interface.prefix_length if selected_interface else 0,
        selected_cidr=selected_interface.subnet if selected_interface else "",
        auto_scope_confidence=selected_interface.confidence_score if selected_interface else 0,
        auto_scope_debug=auto_scope_debug,
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
    adapter_rows, adapter_debug = collect_windows_adapter_rows()
    domain_joined = bool(computer_info.get("PartOfDomain", False))
    domain_name = str(computer_info.get("Domain") or "").strip()
    interfaces = _interfaces_from_windows_payload({"items": adapter_rows})
    suffixes = _unique_sorted([item.dns_suffix for item in interfaces if item.dns_suffix])
    if domain_name and domain_name not in suffixes:
        suffixes.append(domain_name)
    return {
        "domain_joined": domain_joined,
        "domain_name": domain_name,
        "dns_suffixes": suffixes,
        "interfaces": interfaces,
        "adapter_debug": adapter_debug,
    }


def collect_windows_adapter_rows(timeout_seconds: int = 25) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Collect Windows adapter rows with diagnostics and production-safe fallbacks."""

    debug: dict[str, object] = {
        "platform_system": platform.system(),
        "is_windows": is_windows(),
        "powershell_executable": find_powershell_executable(),
        "collector_attempts": [],
        "raw_rows": [],
    }
    attempts: list[dict[str, object]] = []
    debug["collector_attempts"] = attempts

    rows, attempt = _run_powershell_json_array_collector(
        "merged_get_netipaddress_get_netadapter_get_netroute_get_dnsclient",
        _WINDOWS_MERGED_ADAPTER_SCRIPT,
        timeout_seconds=timeout_seconds,
    )
    attempts.append(attempt)
    if rows:
        normalized = _normalize_windows_adapter_rows(rows)
        debug["raw_rows"] = _raw_row_summary(normalized)
        return normalized, debug

    fallback_rows, attempt = _run_powershell_json_array_collector(
        "fallback_get_netipaddress",
        """
$rows = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressState)
@($rows) | ConvertTo-Json -Depth 8
        """,
        timeout_seconds=timeout_seconds,
    )
    attempts.append(attempt)

    route_info, route_attempt = _collect_route_print_defaults(timeout_seconds=timeout_seconds)
    attempts.append(route_attempt)
    if fallback_rows:
        normalized = _normalize_windows_adapter_rows(fallback_rows)
        _apply_route_print_defaults(normalized, route_info)
        debug["raw_rows"] = _raw_row_summary(normalized)
        return normalized, debug

    ipconfig_rows, ipconfig_attempt = _collect_ipconfig_rows(timeout_seconds=timeout_seconds)
    attempts.append(ipconfig_attempt)
    if ipconfig_rows:
        _apply_route_print_defaults(ipconfig_rows, route_info)
        debug["raw_rows"] = _raw_row_summary(ipconfig_rows)
        return ipconfig_rows, debug

    debug["raw_rows"] = []
    return [], debug


_WINDOWS_MERGED_ADAPTER_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ipRows = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)
$routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric)
$primary = $routes | Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | Select-Object -First 1
if (-not $primary) {
    $primary = $routes | Select-Object -First 1
}
$adapters = @{}
@(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue) | ForEach-Object {
    if ($_.ifIndex -ne $null) {
        $adapters[[int]$_.ifIndex] = $_
    }
}
$dns = @{}
@(Get-DnsClient -ErrorAction SilentlyContinue) | ForEach-Object {
    if ($_.InterfaceIndex -ne $null) {
        $dns[[int]$_.InterfaceIndex] = $_
    }
}
$rows = foreach ($ip in $ipRows) {
    $ifIndex = [int]$ip.InterfaceIndex
    $adapter = $adapters[$ifIndex]
    $dnsClient = $dns[$ifIndex]
    $route = $routes | Where-Object { $_.InterfaceIndex -eq $ifIndex } | Select-Object -First 1
    $gateway = ''
    if ($route -and $route.NextHop -and $route.NextHop -ne '0.0.0.0') {
        $gateway = [string]$route.NextHop
    }
    if ($ip.IPAddress) {
        [pscustomobject]@{
            Source = 'merged_get_netipaddress'
            InterfaceAlias = [string]$ip.InterfaceAlias
            InterfaceIndex = $ifIndex
            InterfaceDescription = if ($adapter) { [string]$adapter.InterfaceDescription } else { '' }
            Status = if ($adapter) { [string]$adapter.Status } else { '' }
            AdapterType = if ($adapter) { [string]$adapter.MediaType } else { '' }
            IPv4Address = [string]$ip.IPAddress
            PrefixLength = [int]$ip.PrefixLength
            IPv4DefaultGateway = $gateway
            DnsSuffix = if ($dnsClient) { [string]$dnsClient.ConnectionSpecificSuffix } else { '' }
            HasDefaultGateway = [bool]$gateway
            IsPrimaryRoute = [bool]($primary -and $primary.InterfaceIndex -eq $ifIndex)
            RouteMetric = if ($route) { [int]$route.RouteMetric } else { 999999 }
            InterfaceMetric = if ($route) { [int]$route.InterfaceMetric } else { 999999 }
            AddressState = [string]$ip.AddressState
        }
    }
}
@($rows) | ConvertTo-Json -Depth 8
"""


def _detect_non_windows_interfaces() -> list[DetectedInterface]:
    if platform.system().lower() == "darwin":
        return _interfaces_from_ifconfig()
    return _interfaces_from_ip_addr()


def _run_powershell_json_array_collector(
    name: str,
    script: str,
    *,
    timeout_seconds: int,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    result = run_powershell(script, timeout_seconds=timeout_seconds)
    rows, parse_error = _json_rows_from_stdout(result.stdout)
    attempt = {
        "name": name,
        "returncode": result.returncode,
        "stdout_length": len(result.stdout or ""),
        "stderr_preview": _preview(result.stderr),
        "stdout_preview": _preview(result.stdout),
        "parsed_rows": len(rows),
        "json_error": parse_error,
        "timed_out": result.timed_out,
    }
    return rows, attempt


def _json_rows_from_stdout(stdout: str) -> tuple[list[dict[str, object]], str]:
    cleaned = (stdout or "").strip()
    if not cleaned or cleaned.lower() == "null":
        return [], ""
    try:
        decoded = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        return [], f"{exc.msg} at line {exc.lineno} column {exc.colno}"
    rows: list[dict[str, object]] = []
    for item in _ensure_list(decoded):
        if isinstance(item, dict):
            rows.append(item)
    return rows, ""


def _normalize_windows_adapter_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    for item in rows:
        row = dict(item)
        if "IPv4Address" not in row and row.get("IPAddress"):
            row["IPv4Address"] = row.get("IPAddress")
        if "Status" not in row:
            row["Status"] = ""
        if "IPv4DefaultGateway" not in row and row.get("DefaultGateway"):
            row["IPv4DefaultGateway"] = row.get("DefaultGateway")
        if "HasDefaultGateway" not in row:
            row["HasDefaultGateway"] = bool(row.get("IPv4DefaultGateway"))
        if "IsPrimaryRoute" not in row:
            row["IsPrimaryRoute"] = False
        if "RouteMetric" not in row:
            row["RouteMetric"] = 999999
        if "InterfaceMetric" not in row:
            row["InterfaceMetric"] = 999999
        normalized.append(row)
    return normalized


def _collect_route_print_defaults(timeout_seconds: int) -> tuple[dict[str, dict[str, object]], dict[str, object]]:
    result = run_command(["route", "print", "-4"], timeout_seconds=timeout_seconds)
    routes = _parse_route_print_defaults(result.stdout)
    attempt = {
        "name": "fallback_route_print",
        "returncode": result.returncode,
        "stdout_length": len(result.stdout or ""),
        "stderr_preview": _preview(result.stderr),
        "stdout_preview": _preview(result.stdout),
        "parsed_rows": len(routes),
        "json_error": "",
        "timed_out": result.timed_out,
    }
    return routes, attempt


def _parse_route_print_defaults(stdout: str) -> dict[str, dict[str, object]]:
    defaults: dict[str, dict[str, object]] = {}
    for raw_line in (stdout or "").splitlines():
        match = re.match(
            r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(?P<gateway>\S+)\s+(?P<interface>\S+)\s+(?P<metric>\d+)",
            raw_line,
        )
        if not match:
            continue
        interface_ip = match.group("interface").strip()
        try:
            ipaddress.ip_address(interface_ip)
        except ValueError:
            continue
        metric = _safe_int(match.group("metric"), default=999999)
        current = defaults.get(interface_ip)
        if current and _safe_int(current.get("route_metric"), default=999999) <= metric:
            continue
        defaults[interface_ip] = {
            "gateway": match.group("gateway").strip(),
            "route_metric": metric,
            "is_primary_route": False,
        }
    if defaults:
        best_ip = min(
            defaults,
            key=lambda address: _safe_int(defaults[address].get("route_metric"), default=999999),
        )
        defaults[best_ip]["is_primary_route"] = True
    return defaults


def _apply_route_print_defaults(
    rows: list[dict[str, object]],
    route_info: dict[str, dict[str, object]],
) -> None:
    for row in rows:
        ip = str(row.get("IPv4Address") or row.get("IPAddress") or "").strip()
        route = route_info.get(ip)
        if not route:
            continue
        gateway = str(route.get("gateway") or "").strip()
        if gateway and gateway != "0.0.0.0":
            row["IPv4DefaultGateway"] = gateway
            row["HasDefaultGateway"] = True
        row["IsPrimaryRoute"] = bool(route.get("is_primary_route"))
        row["RouteMetric"] = _safe_int(route.get("route_metric"), default=999999)


def _collect_ipconfig_rows(timeout_seconds: int) -> tuple[list[dict[str, object]], dict[str, object]]:
    result = run_command(["ipconfig", "/all"], timeout_seconds=timeout_seconds)
    rows = _parse_ipconfig_all(result.stdout)
    attempt = {
        "name": "fallback_ipconfig_all",
        "returncode": result.returncode,
        "stdout_length": len(result.stdout or ""),
        "stderr_preview": _preview(result.stderr),
        "stdout_preview": _preview(result.stdout),
        "parsed_rows": len(rows),
        "json_error": "",
        "timed_out": result.timed_out,
    }
    return rows, attempt


def _parse_ipconfig_all(stdout: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for raw_line in (stdout or "").splitlines():
        line = raw_line.rstrip()
        adapter_match = re.match(r"^\s*(?:Ethernet|Wireless LAN|Unknown|PPP|Tunnel).+adapter\s+(.+):\s*$", line)
        if adapter_match:
            if current:
                _append_ipconfig_row(rows, current)
            current = {
                "Source": "ipconfig_all",
                "InterfaceAlias": adapter_match.group(1).strip(),
                "InterfaceDescription": "",
                "Status": "",
                "AdapterType": "",
                "IPv4Address": "",
                "PrefixLength": 0,
                "IPv4DefaultGateway": "",
            }
            continue
        if current is None:
            continue
        if "Description" in line and ":" in line and not current.get("InterfaceDescription"):
            current["InterfaceDescription"] = line.split(":", 1)[1].strip()
        elif "IPv4 Address" in line and ":" in line:
            current["IPv4Address"] = _clean_ipconfig_value(line.split(":", 1)[1])
        elif "Subnet Mask" in line and ":" in line:
            current["PrefixLength"] = _prefix_from_netmask(_clean_ipconfig_value(line.split(":", 1)[1]))
        elif "Default Gateway" in line and ":" in line:
            gateway = _clean_ipconfig_value(line.split(":", 1)[1])
            if gateway:
                current["IPv4DefaultGateway"] = gateway
    if current:
        _append_ipconfig_row(rows, current)
    return rows


def _append_ipconfig_row(rows: list[dict[str, object]], current: dict[str, object]) -> None:
    if not current.get("IPv4Address") or not current.get("PrefixLength"):
        return
    current["HasDefaultGateway"] = bool(current.get("IPv4DefaultGateway"))
    current["IsPrimaryRoute"] = False
    current["RouteMetric"] = 999999
    current["InterfaceMetric"] = 999999
    rows.append(dict(current))


def _clean_ipconfig_value(value: str) -> str:
    cleaned = value.strip()
    cleaned = re.sub(r"\(.*?\)", "", cleaned).strip()
    return cleaned


def _raw_row_summary(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    summary: list[dict[str, object]] = []
    for row in rows:
        address = str(row.get("IPv4Address") or row.get("IPAddress") or "").strip()
        prefix = _safe_int(row.get("PrefixLength"))
        summary.append(
            {
                "source": row.get("Source", ""),
                "interface_alias": row.get("InterfaceAlias", ""),
                "interface_index": row.get("InterfaceIndex", ""),
                "description": row.get("InterfaceDescription", ""),
                "status": row.get("Status", ""),
                "ip_address": address,
                "prefix_length": prefix,
                "calculated_cidr": _subnet(address, prefix),
                "gateway": row.get("IPv4DefaultGateway", ""),
                "has_default_gateway": bool(row.get("HasDefaultGateway")),
                "is_primary_route": bool(row.get("IsPrimaryRoute")),
                "route_metric": row.get("RouteMetric", ""),
                "interface_metric": row.get("InterfaceMetric", ""),
            }
        )
    return summary


def _preview(value: str, *, limit: int = 500) -> str:
    cleaned = (value or "").strip().replace("\r", "")
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit] + "...<truncated>"


def _interfaces_from_windows_payload(payload: dict[str, object]) -> list[DetectedInterface]:
    items = _ensure_list(payload.get("items", payload))
    interfaces: list[DetectedInterface] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("InterfaceAlias", "") or "unknown")
        gateway = _gateway_value(item.get("IPv4DefaultGateway", item.get("DefaultGateway")))
        suffix = str(item.get("DnsSuffix", "") or "").strip()
        description = str(item.get("InterfaceDescription", "") or "").strip()
        status = str(item.get("Status", "") or "").strip()
        adapter_type = str(item.get("AdapterType", "") or "").strip()
        interface_index = _safe_int(item.get("InterfaceIndex"))
        has_gateway = bool(item.get("HasDefaultGateway")) or bool(gateway)
        is_primary = bool(item.get("IsPrimaryRoute"))
        route_metric = _safe_int(item.get("RouteMetric"), default=999999)
        interface_metric = _safe_int(item.get("InterfaceMetric"), default=999999)
        raw_ipv4 = item.get("IPv4Address", item.get("IPAddress"))
        if isinstance(raw_ipv4, str):
            address = raw_ipv4.strip()
            prefix = _safe_int(item.get("PrefixLength"))
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
                        interface_index=interface_index,
                        description=description,
                        status=status,
                        adapter_type=adapter_type,
                        has_default_gateway=has_gateway,
                        is_primary_route=is_primary,
                        route_metric=route_metric,
                        interface_metric=interface_metric,
                        confidence_score=0,
                    )
                )
            continue
        for ipv4 in _ensure_list(raw_ipv4):
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
                        interface_index=interface_index,
                        description=description,
                        status=status,
                        adapter_type=adapter_type,
                        has_default_gateway=has_gateway,
                        is_primary_route=is_primary,
                        route_metric=route_metric,
                        interface_metric=interface_metric,
                        confidence_score=0,
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
        status = str(item.get("operstate", "") or "").strip()
        for addr in item.get("addr_info", []) or []:
            if not isinstance(addr, dict) or addr.get("family") != "inet":
                continue
            address = str(addr.get("local", "") or "").strip()
            prefix = _safe_int(addr.get("prefixlen"))
            subnet = _subnet(address, prefix)
            if subnet:
                interfaces.append(
                    DetectedInterface(
                        name=name,
                        ip_address=address,
                        prefix_length=prefix,
                        subnet=subnet,
                        status=status,
                    )
                )
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


def _select_auto_scope_interfaces(
    interfaces: list[DetectedInterface],
    config: AppConfig | None,
) -> tuple[list[DetectedInterface], list[dict[str, object]]]:
    allowed_keywords = _allowed_adapter_keywords(config)
    candidates: list[DetectedInterface] = []
    diagnostics: list[dict[str, object]] = []
    for interface in interfaces:
        reason = _ignore_reason(interface, allowed_keywords)
        if reason:
            diagnostics.append(_adapter_diagnostic(interface, selected=False, reason=reason))
            continue
        interface.confidence_score = _confidence_score(interface)
        candidates.append(interface)
    candidates.sort(key=_interface_priority)
    selected = candidates[:1]
    for interface in candidates:
        is_selected = bool(selected and interface is selected[0])
        reason = (
            "selected primary/default-route company LAN candidate"
            if is_selected
            else "valid private candidate but lower confidence than selected interface"
        )
        decision = "selected" if is_selected else "candidate"
        diagnostics.append(_adapter_diagnostic(interface, decision=decision, reason=reason))
    return selected, diagnostics


def _ignore_reason(interface: DetectedInterface, allowed_keywords: list[str]) -> str:
    status = interface.status.strip().lower()
    if status in DOWN_STATUS_VALUES:
        return f"adapter status is {interface.status}"
    try:
        ip = ipaddress.ip_address(interface.ip_address)
    except ValueError:
        return "invalid IPv4 address"
    if ip.version != 4:
        return "not IPv4"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "APIPA/link-local"
    if ip in CGNAT_NETWORK:
        return "CGNAT/Tailscale address"
    if not _is_rfc1918_private(ip):
        return "not RFC1918 private"
    if not interface.subnet:
        return "missing CIDR subnet"
    if _is_excluded_adapter(interface, allowed_keywords):
        return "virtual/VPN adapter"
    return ""


def _is_excluded_adapter(interface: DetectedInterface, allowed_keywords: list[str]) -> bool:
    haystack = " ".join(
        [
            interface.name,
            interface.description,
            interface.adapter_type,
        ]
    ).lower()
    if any(keyword.lower() in haystack for keyword in allowed_keywords):
        return False
    return any(keyword in haystack for keyword in VIRTUAL_ADAPTER_KEYWORDS)


def _looks_physical_lan(interface: DetectedInterface) -> bool:
    haystack = " ".join([interface.name, interface.description, interface.adapter_type]).lower()
    return any(
        keyword in haystack
        for keyword in [
            "ethernet",
            "wi-fi",
            "wifi",
            "wireless",
            "802.11",
            "intel",
            "realtek",
            "broadcom",
            "qualcomm",
        ]
    )


def _allowed_adapter_keywords(config: AppConfig | None) -> list[str]:
    if not config:
        return []
    return [
        str(item).strip().lower()
        for item in config.assessment.auto_scope_allowed_adapter_keywords
        if str(item).strip()
    ]


def _interface_priority(interface: DetectedInterface) -> tuple[int, int, int, int, str]:
    return (
        -interface.confidence_score,
        0 if interface.is_primary_route else 1,
        0 if interface.has_default_gateway or interface.gateway else 1,
        interface.route_metric,
        interface.interface_metric,
        interface.name.lower(),
    )


def _confidence_score(interface: DetectedInterface) -> int:
    score = 20
    if interface.is_primary_route:
        score += 55
    if interface.has_default_gateway or interface.gateway:
        score += 25
    if interface.status.strip().lower() == "up":
        score += 10
    if _looks_physical_lan(interface):
        score += 10
    if interface.dns_suffix.strip():
        score += 5
    if interface.route_metric < 999999:
        score += max(0, 5 - min(5, interface.route_metric // 20))
    return score


def _adapter_diagnostic(
    interface: DetectedInterface,
    *,
    decision: str = "",
    selected: bool | None = None,
    reason: str,
) -> dict[str, object]:
    if not decision:
        decision = "selected" if selected else "ignored"
    return {
        "name": interface.name,
        "description": interface.description,
        "adapter_type": interface.adapter_type,
        "ip_address": interface.ip_address,
        "prefix_length": interface.prefix_length,
        "subnet": interface.subnet,
        "gateway": interface.gateway,
        "status": interface.status,
        "has_default_gateway": interface.has_default_gateway,
        "is_primary_route": interface.is_primary_route,
        "route_metric": interface.route_metric,
        "interface_metric": interface.interface_metric,
        "confidence_score": interface.confidence_score,
        "decision": decision,
        "reason": reason,
    }


def _selected_order(selected: list[DetectedInterface], subnet: str, name: str) -> int:
    for index, interface in enumerate(selected, start=1):
        if interface.subnet == subnet and interface.name == name:
            return index
    return 0


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
    return bool(ip.version == 4 and _is_rfc1918_private(ip) and not ip.is_loopback and not ip.is_link_local)


def _is_rfc1918_private(ip: ipaddress._BaseAddress) -> bool:
    if ip.version != 4:
        return False
    return any(ip in network for network in RFC1918_NETWORKS)


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


def _safe_int(value: object, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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


def _unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        cleaned = value.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            output.append(cleaned)
    return output


def auto_scope_debug_summary(context: AutoEnterpriseContext) -> str:
    """Return one-line operator debug context for preflight output."""

    selected = [
        f"{item.get('name')} {item.get('ip_address')}/{item.get('prefix_length')} -> "
        f"{item.get('subnet')} confidence={item.get('confidence_score', 0)}"
        for item in context.adapter_diagnostics
        if item.get("decision") == "selected"
    ]
    candidates = [
        f"{item.get('name')} {item.get('ip_address')}: {item.get('reason')} "
        f"confidence={item.get('confidence_score', 0)}"
        for item in context.adapter_diagnostics
        if item.get("decision") == "candidate"
    ]
    ignored = [
        f"{item.get('name')} {item.get('ip_address')}: {item.get('reason')}"
        for item in context.adapter_diagnostics
        if item.get("decision") == "ignored"
    ]
    attempts = context.auto_scope_debug.get("collector_attempts", [])
    collector_summary = []
    if isinstance(attempts, list):
        for item in attempts:
            if isinstance(item, dict):
                collector_summary.append(
                    f"{item.get('name')} rc={item.get('returncode')} "
                    f"stdout_len={item.get('stdout_length')} parsed={item.get('parsed_rows')}"
                )
    return (
        f"scope_source={context.scope_source}; selected_scope={context.default_scope}; "
        f"selected_interface={context.selected_interface_alias}; selected_ip={context.selected_ip}; "
        f"selected_prefix={context.selected_prefix_length}; selected_cidr={context.selected_cidr}; "
        f"confidence={context.auto_scope_confidence}; "
        f"detected_adapters={len(context.adapter_diagnostics)}; "
        f"collector_attempts={'; '.join(collector_summary[:4]) if collector_summary else 'none'}; "
        f"selected_adapters={'; '.join(selected) if selected else 'none'}; "
        f"candidate_adapters={'; '.join(candidates[:5]) if candidates else 'none'}; "
        f"ignored_adapters={'; '.join(ignored[:8]) if ignored else 'none'}"
    )


def auto_scope_debug_report(context: AutoEnterpriseContext) -> str:
    """Return multi-line raw auto-scope debug output for operator troubleshooting."""

    lines = [
        "Auto-scope debug",
        f"platform.system()={context.auto_scope_debug.get('platform_system', platform.system())}",
        f"is_windows()={context.auto_scope_debug.get('is_windows', is_windows())}",
        f"powershell_executable={context.auto_scope_debug.get('powershell_executable', find_powershell_executable())}",
        f"scope_source={context.scope_source}",
        f"final_selected_scope={context.default_scope}",
        f"selected_interface={context.selected_interface_alias}",
        f"selected_ip={context.selected_ip}",
        f"selected_prefix={context.selected_prefix_length}",
        f"selected_cidr={context.selected_cidr}",
        f"confidence={context.auto_scope_confidence}",
        "",
        "Collector attempts:",
    ]
    attempts = context.auto_scope_debug.get("collector_attempts", [])
    if isinstance(attempts, list) and attempts:
        for item in attempts:
            if not isinstance(item, dict):
                continue
            lines.append(
                "- name={name}; returncode={returncode}; stdout_length={stdout_length}; "
                "parsed_rows={parsed_rows}; timed_out={timed_out}; json_error={json_error}; "
                "stderr_preview={stderr_preview}".format(
                    name=item.get("name", ""),
                    returncode=item.get("returncode", ""),
                    stdout_length=item.get("stdout_length", ""),
                    parsed_rows=item.get("parsed_rows", ""),
                    timed_out=item.get("timed_out", False),
                    json_error=item.get("json_error", ""),
                    stderr_preview=item.get("stderr_preview", ""),
                )
            )
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "Raw adapter rows from Get-NetIPAddress/Get-NetAdapter/Get-NetRoute/Get-DnsClient:",
        ]
    )
    raw_rows = context.auto_scope_debug.get("raw_rows", [])
    if isinstance(raw_rows, list) and raw_rows:
        for row in raw_rows:
            if not isinstance(row, dict):
                continue
            lines.append(
                "- source={source}; adapter={adapter}; description={description}; status={status}; "
                "ip={ip}/{prefix}; calculated_cidr={cidr}; gateway={gateway}; "
                "default_route={primary}; route_metric={route_metric}; interface_metric={interface_metric}".format(
                    source=row.get("source", ""),
                    adapter=row.get("interface_alias", ""),
                    description=row.get("description", ""),
                    status=row.get("status", ""),
                    ip=row.get("ip_address", ""),
                    prefix=row.get("prefix_length", ""),
                    cidr=row.get("calculated_cidr", ""),
                    gateway=row.get("gateway", ""),
                    primary=row.get("is_primary_route", False),
                    route_metric=row.get("route_metric", ""),
                    interface_metric=row.get("interface_metric", ""),
                )
            )
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "Adapter decisions:",
        ]
    )
    for item in context.adapter_diagnostics:
        lines.append(
            "- adapter={name}; description={description}; status={status}; "
            "ip={ip}/{prefix}; calculated_cidr={cidr}; gateway={gateway}; "
            "default_route={primary}; route_metric={route_metric}; interface_metric={interface_metric}; "
            "decision={decision}; reason={reason}; confidence={confidence}".format(
                name=item.get("name", ""),
                description=item.get("description", ""),
                status=item.get("status", ""),
                ip=item.get("ip_address", ""),
                prefix=item.get("prefix_length", ""),
                cidr=item.get("subnet", ""),
                gateway=item.get("gateway", ""),
                primary=item.get("is_primary_route", False),
                route_metric=item.get("route_metric", ""),
                interface_metric=item.get("interface_metric", ""),
                decision=item.get("decision", ""),
                reason=item.get("reason", ""),
                confidence=item.get("confidence_score", ""),
            )
        )
    return "\n".join(lines)
