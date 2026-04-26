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


def _patch_detection(monkeypatch, interfaces: list[DetectedInterface]) -> None:
    monkeypatch.setattr(auto_context, "is_windows", lambda: False)
    monkeypatch.setattr(auto_context, "_detect_non_windows_interfaces", lambda: interfaces)
    monkeypatch.setattr(auto_context.socket, "gethostname", lambda: "runner01")
    monkeypatch.setattr(auto_context.socket, "getfqdn", lambda: "runner01.corp.example.com")
    monkeypatch.setattr(auto_context.getpass, "getuser", lambda: "Operator")
