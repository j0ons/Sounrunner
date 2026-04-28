from __future__ import annotations

import json

from app.core import auto_context
from app.collectors.shell import CommandResult
from app.core.auto_context import DetectedInterface
from app.core.config import AppConfig


def test_auto_context_uses_config_scope_over_detected_interfaces(monkeypatch) -> None:
    config = AppConfig()
    config.assessment.approved_scopes = ["10.0.0.0/24"]
    _patch_detection(
        monkeypatch,
        [
            DetectedInterface(
                name="Ethernet",
                ip_address="192.168.50.10",
                prefix_length=24,
                subnet="192.168.50.0/24",
            )
        ],
    )

    context = auto_context.detect_enterprise_context(config)

    assert context.scope_source == "config_scope"
    assert context.default_scope == "10.0.0.0/24"
    assert context.private_subnets == ["192.168.50.0/24"]


def test_auto_context_builds_scope_from_private_interfaces(monkeypatch) -> None:
    _patch_detection(
        monkeypatch,
        [
            DetectedInterface(
                name="Ethernet",
                ip_address="10.20.30.42",
                prefix_length=24,
                subnet="10.20.30.0/24",
                dns_suffix="corp.example.com",
            ),
            DetectedInterface(
                name="Loopback",
                ip_address="127.0.0.1",
                prefix_length=8,
                subnet="127.0.0.0/8",
            ),
        ],
    )

    context = auto_context.detect_enterprise_context(AppConfig())

    assert context.scope_source == "auto_detected_local_subnets"
    assert context.default_scope == "10.20.30.0/24"
    assert context.email_domain == "corp.example.com"


def test_auto_context_physical_wifi_to_cidr(monkeypatch) -> None:
    _patch_detection(
        monkeypatch,
        [
            DetectedInterface(
                name="Wi-Fi",
                description="Intel(R) Wi-Fi 6 AX201",
                ip_address="10.0.169.50",
                prefix_length=24,
                subnet="10.0.169.0/24",
                gateway="10.0.169.1",
                has_default_gateway=True,
                is_primary_route=True,
                status="Up",
            )
        ],
    )

    context = auto_context.detect_enterprise_context(AppConfig())

    assert context.scope_source == "auto_detected_local_subnets"
    assert context.default_scope == "10.0.169.0/24"
    assert context.adapter_diagnostics[0]["decision"] == "selected"


def test_auto_context_physical_ethernet_to_cidr(monkeypatch) -> None:
    _patch_detection(
        monkeypatch,
        [
            DetectedInterface(
                name="Ethernet",
                description="Intel(R) Ethernet Connection",
                ip_address="192.168.1.20",
                prefix_length=24,
                subnet="192.168.1.0/24",
                gateway="192.168.1.1",
                has_default_gateway=True,
                is_primary_route=True,
                status="Up",
            )
        ],
    )

    context = auto_context.detect_enterprise_context(AppConfig())

    assert context.scope_source == "auto_detected_local_subnets"
    assert context.default_scope == "192.168.1.0/24"


def test_auto_context_falls_back_to_localhost_when_no_private_scope(monkeypatch) -> None:
    _patch_detection(
        monkeypatch,
        [
            DetectedInterface(
                name="Loopback",
                ip_address="127.0.0.1",
                prefix_length=8,
                subnet="127.0.0.0/8",
            )
        ],
    )

    context = auto_context.detect_enterprise_context(AppConfig())

    assert context.scope_source == "localhost_only_fallback"
    assert context.default_scope == "local-host-only"
    assert context.warnings


def test_auto_context_ignores_virtual_adapters(monkeypatch) -> None:
    _patch_detection(
        monkeypatch,
        [
            DetectedInterface(
                name="vEthernet (WSL)",
                description="Hyper-V Virtual Ethernet Adapter",
                ip_address="172.22.16.1",
                prefix_length=20,
                subnet="172.22.16.0/20",
                status="Up",
            ),
            DetectedInterface(
                name="DockerNAT",
                description="Docker virtual adapter",
                ip_address="172.18.0.1",
                prefix_length=16,
                subnet="172.18.0.0/16",
                status="Up",
            ),
        ],
    )

    context = auto_context.detect_enterprise_context(AppConfig())

    assert context.scope_source == "localhost_only_fallback"
    assert all(item["decision"] == "ignored" for item in context.adapter_diagnostics)
    assert any("virtual/VPN" in str(item["reason"]) for item in context.adapter_diagnostics)


def test_auto_context_default_route_interface_preferred(monkeypatch) -> None:
    _patch_detection(
        monkeypatch,
        [
            DetectedInterface(
                name="Ethernet 2",
                description="USB Ethernet",
                ip_address="192.168.50.10",
                prefix_length=24,
                subnet="192.168.50.0/24",
                gateway="192.168.50.1",
                has_default_gateway=True,
                is_primary_route=False,
                route_metric=20,
                interface_metric=20,
                status="Up",
            ),
            DetectedInterface(
                name="Wi-Fi",
                description="Intel(R) Wi-Fi 6 AX201",
                ip_address="10.0.169.50",
                prefix_length=24,
                subnet="10.0.169.0/24",
                gateway="10.0.169.1",
                has_default_gateway=True,
                is_primary_route=True,
                route_metric=5,
                interface_metric=5,
                status="Up",
            ),
        ],
    )

    context = auto_context.detect_enterprise_context(AppConfig())

    assert context.scope_source == "auto_detected_local_subnets"
    assert context.default_scope == "10.0.169.0/24"
    assert context.private_subnets == ["10.0.169.0/24"]
    assert any(item["decision"] == "candidate" for item in context.adapter_diagnostics)


def test_auto_context_real_windows_lab_adapter_list_selects_physical_ethernet(monkeypatch) -> None:
    _patch_detection(
        monkeypatch,
        [
            DetectedInterface(
                name="Ethernet 2",
                description="VirtualBox Host-Only Ethernet Adapter",
                ip_address="192.168.56.1",
                prefix_length=24,
                subnet="192.168.56.0/24",
                status="Up",
            ),
            DetectedInterface(
                name="vEthernet (Default Switch)",
                description="Hyper-V Virtual Ethernet Adapter",
                ip_address="172.23.192.1",
                prefix_length=20,
                subnet="172.23.192.0/20",
                status="Up",
            ),
            DetectedInterface(
                name="VMware Network Adapter VMnet8",
                description="VMware Virtual Ethernet Adapter for VMnet8",
                ip_address="192.168.126.1",
                prefix_length=24,
                subnet="192.168.126.0/24",
                status="Up",
            ),
            DetectedInterface(
                name="VMware Network Adapter VMnet1",
                description="VMware Virtual Ethernet Adapter for VMnet1",
                ip_address="192.168.80.1",
                prefix_length=24,
                subnet="192.168.80.0/24",
                status="Up",
            ),
            DetectedInterface(
                name="Local Area Connection* 10",
                ip_address="169.254.80.225",
                prefix_length=16,
                subnet="169.254.0.0/16",
                status="Up",
            ),
            DetectedInterface(
                name="Local Area Connection* 9",
                ip_address="169.254.82.73",
                prefix_length=16,
                subnet="169.254.0.0/16",
                status="Up",
            ),
            DetectedInterface(
                name="Ethernet",
                description="Realtek PCIe GbE Family Controller",
                ip_address="10.0.180.153",
                prefix_length=24,
                subnet="10.0.180.0/24",
                gateway="10.0.180.1",
                has_default_gateway=True,
                is_primary_route=True,
                route_metric=10,
                interface_metric=10,
                status="Up",
            ),
            DetectedInterface(
                name="Wi-Fi",
                description="Intel(R) Wi-Fi 6 AX201",
                ip_address="169.254.187.87",
                prefix_length=16,
                subnet="169.254.0.0/16",
                status="Up",
            ),
            DetectedInterface(
                name="Tailscale",
                description="Tailscale Tunnel",
                ip_address="100.120.104.80",
                prefix_length=32,
                subnet="100.120.104.80/32",
                status="Up",
            ),
        ],
    )

    context = auto_context.detect_enterprise_context(AppConfig())
    diagnostics = {item["name"]: item for item in context.adapter_diagnostics}

    assert context.scope_source == "auto_detected_local_subnets"
    assert context.default_scope == "10.0.180.0/24"
    assert context.selected_interface_alias == "Ethernet"
    assert context.selected_ip == "10.0.180.153"
    assert context.selected_prefix_length == 24
    assert context.selected_cidr == "10.0.180.0/24"
    assert context.auto_scope_confidence > 0
    assert context.private_subnets == ["10.0.180.0/24"]
    assert diagnostics["Ethernet"]["decision"] == "selected"
    assert diagnostics["Tailscale"]["decision"] == "ignored"
    assert diagnostics["VMware Network Adapter VMnet8"]["decision"] == "ignored"
    assert diagnostics["VMware Network Adapter VMnet1"]["decision"] == "ignored"
    assert diagnostics["Ethernet 2"]["decision"] == "ignored"
    assert diagnostics["vEthernet (Default Switch)"]["decision"] == "ignored"
    assert diagnostics["Local Area Connection* 10"]["decision"] == "ignored"
    assert diagnostics["Local Area Connection* 9"]["decision"] == "ignored"
    assert diagnostics["Wi-Fi"]["decision"] == "ignored"
    assert context.scope_source != "localhost_only_fallback"


def test_windows_get_netipaddress_payload_selects_lab_ethernet_without_netipconfiguration() -> None:
    interfaces = auto_context._interfaces_from_windows_payload(
        {
            "items": [
                _win_row("Ethernet 2", "VirtualBox Host-Only Ethernet Adapter", "192.168.56.1", 24),
                _win_row("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", "172.23.192.1", 20),
                _win_row("VMware Network Adapter VMnet8", "VMware Virtual Ethernet Adapter", "192.168.126.1", 24),
                _win_row("VMware Network Adapter VMnet1", "VMware Virtual Ethernet Adapter", "192.168.80.1", 24),
                _win_row("Local Area Connection* 10", "", "169.254.80.225", 16),
                _win_row("Local Area Connection* 9", "", "169.254.82.73", 16),
                _win_row(
                    "Ethernet",
                    "Realtek PCIe GbE Family Controller",
                    "10.0.180.153",
                    24,
                    gateway="10.0.180.1",
                    primary=True,
                    route_metric=5,
                    interface_metric=10,
                ),
                _win_row("Wi-Fi", "Intel(R) Wi-Fi 6 AX201", "169.254.187.87", 16),
                _win_row("Tailscale", "Tailscale Tunnel", "100.120.104.80", 32),
            ]
        }
    )

    selected, diagnostics = auto_context._select_auto_scope_interfaces(interfaces, AppConfig())
    by_name = {item["name"]: item for item in diagnostics}

    assert selected[0].subnet == "10.0.180.0/24"
    assert selected[0].name == "Ethernet"
    assert by_name["Ethernet"]["decision"] == "selected"
    assert by_name["Tailscale"]["decision"] == "ignored"
    assert "CGNAT" in str(by_name["Tailscale"]["reason"]) or "virtual/VPN" in str(by_name["Tailscale"]["reason"])
    assert by_name["VMware Network Adapter VMnet8"]["decision"] == "ignored"
    assert by_name["vEthernet (Default Switch)"]["decision"] == "ignored"
    assert by_name["Local Area Connection* 10"]["decision"] == "ignored"
    assert by_name["Wi-Fi"]["decision"] == "ignored"


def test_windows_status_blank_valid_ethernet_with_default_route_is_selected() -> None:
    interfaces = auto_context._interfaces_from_windows_payload(
        {
            "items": [
                _win_row(
                    "Ethernet",
                    "Intel(R) Ethernet Connection",
                    "10.0.180.153",
                    24,
                    status="",
                    gateway="10.0.180.1",
                    primary=True,
                    route_metric=1,
                    interface_metric=1,
                )
            ]
        }
    )

    selected, diagnostics = auto_context._select_auto_scope_interfaces(interfaces, AppConfig())

    assert selected[0].subnet == "10.0.180.0/24"
    assert any(item["name"] == "Ethernet" and item["decision"] == "selected" for item in diagnostics)


def test_auto_scope_debug_report_includes_final_selected_scope(monkeypatch) -> None:
    _patch_detection(
        monkeypatch,
        [
            DetectedInterface(
                name="Ethernet",
                description="Realtek PCIe GbE Family Controller",
                ip_address="10.0.180.153",
                prefix_length=24,
                subnet="10.0.180.0/24",
                gateway="10.0.180.1",
                has_default_gateway=True,
                is_primary_route=True,
                status="Up",
            )
        ],
    )

    context = auto_context.detect_enterprise_context(AppConfig())
    report = auto_context.auto_scope_debug_report(context)

    assert "final_selected_scope=10.0.180.0/24" in report
    assert "adapter=Ethernet" in report
    assert "decision=selected" in report


def test_json_rows_from_stdout_accepts_top_level_array() -> None:
    rows, error = auto_context._json_rows_from_stdout(
        json.dumps([_win_row("Ethernet", "Realtek", "10.0.180.153", 24)])
    )

    assert error == ""
    assert len(rows) == 1
    assert rows[0]["InterfaceAlias"] == "Ethernet"


def test_json_rows_from_stdout_accepts_single_object() -> None:
    rows, error = auto_context._json_rows_from_stdout(
        json.dumps(_win_row("Ethernet", "Realtek", "10.0.180.153", 24))
    )

    assert error == ""
    assert len(rows) == 1
    assert rows[0]["InterfaceAlias"] == "Ethernet"


def test_empty_powershell_result_triggers_get_netipaddress_fallback(monkeypatch) -> None:
    calls: list[str] = []

    def fake_run_powershell(script: str, timeout_seconds: int = 30, **_kwargs) -> CommandResult:
        calls.append(script)
        if "Get-NetAdapter" in script:
            return CommandResult(["powershell"], 0, "", "")
        return CommandResult(
            ["powershell"],
            0,
            json.dumps(
                [
                    {
                        "Source": "fallback_get_netipaddress",
                        "InterfaceAlias": "Ethernet",
                        "InterfaceIndex": 12,
                        "IPAddress": "10.0.180.153",
                        "PrefixLength": 24,
                        "AddressState": "Preferred",
                    }
                ]
            ),
            "",
        )

    def fake_run_command(command: list[str], timeout_seconds: int = 20, **_kwargs) -> CommandResult:
        if command[:2] == ["route", "print"]:
            return CommandResult(command, 0, _route_print_output(), "")
        return CommandResult(command, 0, "", "")

    monkeypatch.setattr(auto_context, "run_powershell", fake_run_powershell)
    monkeypatch.setattr(auto_context, "run_command", fake_run_command)

    rows, debug = auto_context.collect_windows_adapter_rows()
    interfaces = auto_context._interfaces_from_windows_payload({"items": rows})
    selected, _diagnostics = auto_context._select_auto_scope_interfaces(interfaces, AppConfig())

    assert len(calls) == 2
    assert rows[0]["IPv4Address"] == "10.0.180.153"
    assert rows[0]["IPv4DefaultGateway"] == "10.0.180.1"
    assert rows[0]["IsPrimaryRoute"] is True
    assert selected[0].subnet == "10.0.180.0/24"
    assert [item["name"] for item in debug["collector_attempts"]] == [
        "merged_get_netipaddress_get_netadapter_get_netroute_get_dnsclient",
        "fallback_get_netipaddress",
        "fallback_route_print",
    ]


def test_ipconfig_fallback_parses_valid_ethernet(monkeypatch) -> None:
    def fake_run_powershell(_script: str, timeout_seconds: int = 30, **_kwargs) -> CommandResult:
        return CommandResult(["powershell"], 0, "[]", "")

    def fake_run_command(command: list[str], timeout_seconds: int = 20, **_kwargs) -> CommandResult:
        if command[:2] == ["route", "print"]:
            return CommandResult(command, 0, _route_print_output(), "")
        if command[:2] == ["ipconfig", "/all"]:
            return CommandResult(command, 0, _ipconfig_output(), "")
        return CommandResult(command, 0, "", "")

    monkeypatch.setattr(auto_context, "run_powershell", fake_run_powershell)
    monkeypatch.setattr(auto_context, "run_command", fake_run_command)

    rows, debug = auto_context.collect_windows_adapter_rows()
    interfaces = auto_context._interfaces_from_windows_payload({"items": rows})
    selected, diagnostics = auto_context._select_auto_scope_interfaces(interfaces, AppConfig())

    assert selected[0].name == "Ethernet"
    assert selected[0].subnet == "10.0.180.0/24"
    assert selected[0].gateway == "10.0.180.1"
    assert any(item["name"] == "Ethernet" and item["decision"] == "selected" for item in diagnostics)
    assert any(item["name"] == "fallback_ipconfig_all" for item in debug["collector_attempts"])


def test_debug_report_includes_collector_return_code_and_lengths(monkeypatch) -> None:
    _patch_detection(
        monkeypatch,
        [
            DetectedInterface(
                name="Ethernet",
                description="Realtek PCIe GbE Family Controller",
                ip_address="10.0.180.153",
                prefix_length=24,
                subnet="10.0.180.0/24",
            )
        ],
    )

    context = auto_context.detect_enterprise_context(AppConfig())
    context.auto_scope_debug = {
        "platform_system": "Windows",
        "is_windows": True,
        "powershell_executable": "powershell.exe",
        "collector_attempts": [
            {
                "name": "fallback_get_netipaddress",
                "returncode": 0,
                "stdout_length": 200,
                "stderr_preview": "",
                "parsed_rows": 1,
                "json_error": "",
                "timed_out": False,
            }
        ],
        "raw_rows": [],
    }
    report = auto_context.auto_scope_debug_report(context)

    assert "returncode=0" in report
    assert "stdout_length=200" in report
    assert "parsed_rows=1" in report


def _patch_detection(monkeypatch, interfaces: list[DetectedInterface]) -> None:
    monkeypatch.setattr(auto_context, "is_windows", lambda: False)
    monkeypatch.setattr(auto_context, "_detect_non_windows_interfaces", lambda: interfaces)
    monkeypatch.setattr(auto_context.socket, "gethostname", lambda: "runner01")
    monkeypatch.setattr(auto_context.socket, "getfqdn", lambda: "runner01.corp.example.com")
    monkeypatch.setattr(auto_context.getpass, "getuser", lambda: "Operator")


def _win_row(
    alias: str,
    description: str,
    ip: str,
    prefix: int,
    *,
    status: str = "Up",
    gateway: str = "",
    primary: bool = False,
    route_metric: int = 999999,
    interface_metric: int = 999999,
) -> dict[str, object]:
    return {
        "Source": "Get-NetIPAddress",
        "InterfaceAlias": alias,
        "InterfaceIndex": abs(hash(alias)) % 1000,
        "InterfaceDescription": description,
        "Status": status,
        "AdapterType": "Ethernet",
        "IPv4Address": ip,
        "PrefixLength": prefix,
        "IPv4DefaultGateway": gateway,
        "DnsSuffix": "corp.example.local" if gateway else "",
        "HasDefaultGateway": bool(gateway),
        "IsPrimaryRoute": primary,
        "RouteMetric": route_metric,
        "InterfaceMetric": interface_metric,
    }


def _route_print_output() -> str:
    return """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.0.180.1    10.0.180.153     25
===========================================================================
"""


def _ipconfig_output() -> str:
    return """
Windows IP Configuration

Ethernet adapter Ethernet:

   Description . . . . . . . . . . . : Realtek PCIe GbE Family Controller
   IPv4 Address. . . . . . . . . . . : 10.0.180.153(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.180.1

Ethernet adapter VMware Network Adapter VMnet8:

   Description . . . . . . . . . . . : VMware Virtual Ethernet Adapter for VMnet8
   IPv4 Address. . . . . . . . . . . : 192.168.126.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
"""
