from __future__ import annotations

from app.core import auto_context
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


def _patch_detection(monkeypatch, interfaces: list[DetectedInterface]) -> None:
    monkeypatch.setattr(auto_context, "is_windows", lambda: False)
    monkeypatch.setattr(auto_context, "_detect_non_windows_interfaces", lambda: interfaces)
    monkeypatch.setattr(auto_context.socket, "gethostname", lambda: "runner01")
    monkeypatch.setattr(auto_context.socket, "getfqdn", lambda: "runner01.corp.example.com")
    monkeypatch.setattr(auto_context.getpass, "getuser", lambda: "Operator")
